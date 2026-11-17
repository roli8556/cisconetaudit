"""Tests for the management checks: hostname, domain name, logging synchronous, NTP, syslog."""

from netaudit.models import NtpStatus
from netaudit.parsers.ios import build_snapshot
from netaudit.scans import fix_inputs
from netaudit.scans.baseline import BaselineScan
from tests.sample_outputs import SW1, SW1_IP, SW2, SW2_IP, ntp_synced


def snapshots(sw1=SW1, sw2=SW2):
    return [build_snapshot(SW1_IP, "SW1", sw1), build_snapshot(SW2_IP, "SW2", sw2)]


def findings(snaps, check):
    found, _ = BaselineScan().run(snaps)
    return [f for f in found if f.check == check]


def commands_for(fixes, hostname):
    return [cmd for fix in fixes if fix.hostname == hostname for cmd in fix.commands]


def test_parsing():
    sw1, sw2 = snapshots()
    assert sw1.management.domain_name == "lab.local"
    assert sw2.management.domain_command == "ip domain name"  # newer syntax is kept
    assert sw1.management.logging_hosts == ["192.168.100.1"]  # "logging buffered" isn't a host
    assert sw1.ntp.synchronized and sw1.ntp.reference == "192.168.100.1"
    assert sw2.ntp is None  # "%NTP is not enabled."
    assert sw1.rsa_key_name == "SW1.lab.local"  # not the temporary ".server" key


def test_hostname():
    assert not findings(snapshots(), "hostname-not-set")
    no_name = {k: v.replace("hostname SW2\n", "") for k, v in SW2.items()}
    snaps = [build_snapshot(SW1_IP, "SW1", SW1), build_snapshot(SW2_IP, "Switch", no_name)]
    finding = findings(snaps, "hostname-not-set")[0]

    assert fix_inputs.validate(finding.fix_input, "Switch")  # the default
    assert fix_inputs.validate(finding.fix_input, "SW1")  # already taken in the project
    assert fix_inputs.validate(finding.fix_input, "2fast")  # must start with a letter
    assert fix_inputs.validate(finding.fix_input, "ACCESS-SW-02") is None
    resolved = fix_inputs.resolve(finding, "ACCESS-SW-02")
    # SSH key pinned BEFORE the rename, so SSH keeps using the existing key
    assert resolved.fixes[0].commands == ["ip ssh rsa keypair-name SW2.lab.example", "hostname ACCESS-SW-02"]


def test_domain_name():
    finding = findings(snapshots(), "domain-name-mismatch")[0]
    assert "SW1: lab.local" in finding.message and "SW2: lab.example" in finding.message
    resolved = fix_inputs.resolve(finding, "lab.local")
    assert commands_for(resolved.fixes, "SW1") == []  # already correct
    assert commands_for(resolved.fixes, "SW2") == ["ip ssh rsa keypair-name SW2.lab.example", "ip domain name lab.local"]
    assert fix_inputs.validate(finding.fix_input, "lab..local")
    assert fix_inputs.validate(finding.fix_input, "corp.example.com") is None


def test_same_domain_everywhere_is_fine():
    same = {k: v.replace("ip domain name lab.example", "ip domain name lab.local") for k, v in SW2.items()}
    assert not findings(snapshots(sw2=same), "domain-name-mismatch")


def test_logging_synchronous():
    sw1 = [f for f in findings(snapshots(), "logging-synchronous") if f.location.startswith("SW1")][0]
    assert sw1.fixes[0].commands == ["line vty 0 4", "logging synchronous"]  # con 0 already has it


def test_ntp_and_syslog():
    ntp = findings(snapshots(), "ntp-not-configured")[0]
    assert ntp.location == "SW2 NTP" and ntp.fix_input.default == "192.168.100.1"  # what SW1 uses
    assert fix_inputs.validate(ntp.fix_input, "ntp.lab.local")  # IP addresses only
    assert fix_inputs.resolve(ntp, "192.168.100.1").fixes[0].commands == ["ntp server 192.168.100.1"]

    syslog = findings(snapshots(), "no-syslog-server")[0]
    assert syslog.location == "SW2 syslog"
    assert fix_inputs.resolve(syslog, "192.168.100.1").fixes[0].commands == [
        "logging host 192.168.100.1", "logging trap informational"]


def test_ntp_not_synchronized():
    unsynced = {**SW1, "show ntp status": "Clock is unsynchronized, stratum 16, no reference clock\n"}
    finding = findings(snapshots(sw1=unsynced), "ntp-not-synchronized")[0]
    assert finding.location == "SW1 NTP" and "stratum 16" in finding.message


def test_time_sources():
    # SW2 syncs to SW1 (via SW1's Et1/0 address), SW1 to 192.168.100.1 -> one source, no finding
    sw2 = {**SW2, "show ntp status": ntp_synced("10.0.12.1"),
           "show running-config": SW2["show running-config"].replace("hostname SW2\n", "hostname SW2\nntp server 10.0.12.1\n")}
    assert not findings(snapshots(sw2=sw2), "ntp-different-sources")

    # SW2 syncs to a different outside server -> two sources
    sw2 = {**sw2, "show ntp status": ntp_synced("10.9.9.9")}
    finding = findings(snapshots(sw2=sw2), "ntp-different-sources")[0]
    assert "SW1 -> 192.168.100.1" in finding.message and "SW2 -> 10.9.9.9" in finding.message


def test_pinned_key_isnt_pinned_again():
    pinned = {k: v.replace("ip ssh version 2", "ip ssh version 2\nip ssh rsa keypair-name SW1.lab.local")
              for k, v in SW1.items()}
    finding = findings(snapshots(sw1=pinned), "domain-name-mismatch")[0]
    resolved = fix_inputs.resolve(finding, "lab.example")
    assert commands_for(resolved.fixes, "SW1") == ["ip domain-name lab.example"]
