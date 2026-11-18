"""Tests for the baseline scan: every deliberate fault in sample_outputs.py must be found."""

from datetime import datetime

import pytest

from netaudit.parsers.ios import build_snapshot
from netaudit.scans import fix_inputs
from netaudit.scans.baseline import BaselineScan
from netaudit.scans.remediation import commands_per_device
from netaudit.scans.report import BaselineReport, ScanReport
from tests.sample_outputs import SW1, SW1_IP, SW2, SW2_IP


def run_scan(sw1: dict, sw2: dict) -> dict:
    snapshots = [build_snapshot(SW1_IP, "SW1", sw1), build_snapshot(SW2_IP, "SW2", sw2)]
    findings, links = BaselineScan().run(snapshots)
    return {"findings": findings, "links": links}


# A pytest "fixture": a value that tests ask for by naming it as a parameter.
# scope="module" = computed once and shared by all tests in this file.
@pytest.fixture(scope="module")
def scan():
    return run_scan(SW1, SW2)


def find(scan, check, location_part=""):
    return [f for f in scan["findings"] if f.check == check and location_part in f.location]


def commands_for(fixes, hostname):
    return [cmd for fix in fixes if fix.hostname == hostname for cmd in fix.commands]


# ---------------------------------------------------------------- what is found


def test_links_found_once(scan):
    # 9 cables between SW1 and SW2, each seen from both sides -> 9 links. R3 isn't scanned.
    assert len(scan["links"]) == 9


def test_trunk_findings(scan):
    assert len(find(scan, "native-vlan-mismatch", "Et0/1")) == 1
    assert len(find(scan, "allowed-vlan-mismatch", "Et0/1")) == 1
    assert find(scan, "trunk-access-mismatch", "Et1/2")
    # Et2/2: both ends on VLAN 1 -> ONE link finding, not one per device
    assert len(find(scan, "native-vlan-1", "Et2/2")) == 1
    assert not find(scan, "native-vlan-1", "SW2 Et0/1")  # covered by the mismatch finding


def test_native_vlan_hopping(scan):
    # SW1: VLAN 99 is native on Et0/1 and Po1 (members Et0/2-0/3) and the access VLAN of Et0/0
    hopping = find(scan, "native-vlan-hopping")
    assert [f.location for f in hopping] == ["SW1 VLAN 99"]
    assert "Et0/1, Po1" in hopping[0].message and "of Et0/0." in hopping[0].message
    # SW2 uses native 99 too, but has no access port in VLAN 99; VLAN 1 is left to native-vlan-1


def test_native_vlan_tagging_prevents_hopping():
    tagged_ports = dict(SW1, **{"show interfaces switchport": SW1["show interfaces switchport"].replace(
        "Administrative Native VLAN tagging: disabled", "Administrative Native VLAN tagging: enabled")})
    assert not find(run_scan(tagged_ports, SW2), "native-vlan-hopping")
    # Same result from the global command alone (some IOS versions don't print the switchport line)
    tagged_config = dict(SW1, **{"show running-config": "vlan dot1q tag native\n" + SW1["show running-config"]})
    assert not find(run_scan(tagged_config, SW2), "native-vlan-hopping")


def test_etherchannel_findings(scan):
    modes = find(scan, "etherchannel-mode-mismatch")
    assert {f.location for f in modes} == {"SW1 Et0/2 <-> SW2 Et0/2", "SW1 Et0/3 <-> SW2 Et0/3"}
    assert modes[0].fixes[0].commands[1].endswith("mode active")

    groups = find(scan, "etherchannel-group-mismatch")
    assert any(f.severity == "high" and f.location == "SW1 Po1 -> SW2" for f in groups)
    # no "numbers differ but it works" note for a bundle that is actually split
    assert not any(f.severity == "low" for f in groups)
    assert len(find(scan, "etherchannel-member-not-bundled")) == 4


def test_physical_findings(scan):
    assert "1500 vs 1400" in find(scan, "mtu-mismatch", "Et1/0")[0].message
    duplex = find(scan, "duplex-mismatch", "Et1/1")[0]
    assert duplex.fixes[0].hostname == "SW1"  # only SW1 is hardcoded
    assert find(scan, "speed-mismatch", "Et1/1")[0].severity == "low"

    media = find(scan, "media-type-mismatch")
    assert [f.location for f in media] == ["SW1 Et2/2 <-> SW2 Et2/2"]  # "unknown" ends are skipped
    assert "10/100/1000basetx vs 1000baselx sfp" in media[0].message

    arp = find(scan, "arp-type-mismatch")
    assert [f.location for f in arp] == ["SW1 Et2/0 <-> SW2 Et2/0"]  # routed ports only
    assert [(fix.hostname, fix.commands) for fix in arp[0].fixes] == [("SW2", ["interface Ethernet2/0", "arp arpa"])]


def test_ospf_findings(scan):
    assert find(scan, "ospf-area-mismatch", "Et1/0")
    assert find(scan, "ospf-timer-mismatch", "Et1/0")[0].fix_input.default == "default"
    passive = find(scan, "ospf-passive-mismatch", "Et1/1")[0]
    assert passive.fixes[0].commands == ["router ospf 1", "no passive-interface Ethernet1/1"]
    assert find(scan, "ospf-version-mismatch", "Et2/0")
    assert find(scan, "ospf-should-be-passive", "SW1 Et1/3")
    assert "MTU" in find(scan, "ospf-neighbor-not-full", "SW1 Et2/1")[0].message


def test_no_false_positives(scan):
    # The loopback and the R3 link (has a neighbor, even if not FULL) aren't "should be passive"
    assert not find(scan, "ospf-should-be-passive", "Lo0")
    assert not find(scan, "ospf-should-be-passive", "Et2/1")
    # SW1 Et0/1 uses native VLAN 99 - not VLAN 1
    assert not find(scan, "native-vlan-1", "SW1 Et0/1")


def test_findings_sorted_by_severity(scan):
    order = {"high": 0, "medium": 1, "low": 2}
    severities = [order[f.severity] for f in scan["findings"]]
    assert severities == sorted(severities)


# ---------------------------------------------------------------- fixes that need a value


def test_native_vlan_input(scan):
    mismatch = find(scan, "native-vlan-mismatch", "Et0/1")[0]
    assert mismatch.fix_input.default == "99"  # the end that isn't on VLAN 1
    both_one = find(scan, "native-vlan-1", "Et2/2")[0]
    assert both_one.fix_input.default == ""  # no sensible default - the user must choose

    assert fix_inputs.validate(both_one.fix_input, "1")  # error: that's the problem we fix
    assert fix_inputs.validate(both_one.fix_input, "1002")  # reserved
    assert fix_inputs.validate(both_one.fix_input, "abc")
    assert fix_inputs.validate(both_one.fix_input, "666") is None

    # SW1 Et3/3 is an active access port in VLAN 10 -> warn, don't forbid
    assert "SW1" in fix_inputs.warning(both_one.fix_input, "10")
    assert fix_inputs.warning(both_one.fix_input, "666") is None

    resolved = fix_inputs.resolve(both_one, "666")
    assert resolved.fix_input is None and resolved.fixable
    for host in ("SW1", "SW2"):  # both ends get the same VLAN
        assert commands_for(resolved.fixes, host) == ["interface Ethernet2/2", "switchport trunk native vlan 666"]


def test_allowed_vlans_input(scan):
    finding = find(scan, "allowed-vlan-mismatch", "Et0/1")[0]
    assert finding.fix_input.default == "10,99"  # what both ends carry today
    assert "10,20,99" in finding.fix_description  # the union is offered as an alternative
    assert fix_inputs.validate(finding.fix_input, "10,20-x")
    assert fix_inputs.validate(finding.fix_input, "5000")
    assert "10,99" in fix_inputs.warning(finding.fix_input, "1")  # would cut working VLANs
    assert fix_inputs.warning(finding.fix_input, "10,20,99") is None  # adding is fine
    assert fix_inputs.warning(finding.fix_input, "all") is None
    resolved = fix_inputs.resolve(finding, "10, 20, 21, 22, 99")
    assert commands_for(resolved.fixes, "SW2") == ["interface Ethernet0/1", "switchport trunk allowed vlan 10,20-22,99"]


def test_ospf_timer_input(scan):
    finding = find(scan, "ospf-timer-mismatch", "Et1/0")[0]
    default = fix_inputs.resolve(finding, "default")
    assert commands_for(default.fixes, "SW2") == ["interface Ethernet1/0", "no ip ospf hello-interval", "no ip ospf dead-interval"]
    custom = fix_inputs.resolve(finding, "5/20")
    assert commands_for(custom.fixes, "SW1") == ["interface Ethernet1/0", "ip ospf hello-interval 5", "ip ospf dead-interval 20"]
    assert fix_inputs.validate(finding.fix_input, "20/5")  # dead must be longer than hello
    assert fix_inputs.validate(finding.fix_input, "fast")


def test_split_bundle_input(scan):
    finding = [f for f in find(scan, "etherchannel-group-mismatch") if f.severity == "high"][0]
    assert finding.fix_input.default == "1"
    resolved = fix_inputs.resolve(finding, "1")
    # SW1 already uses Po1 -> untouched. SW2: move Et0/3 from Po2 into Po1, remove the empty Po2.
    assert commands_for(resolved.fixes, "SW1") == []
    assert commands_for(resolved.fixes, "SW2") == [
        "interface Ethernet0/3", "no channel-group", "channel-group 1 mode passive",
        "no interface Port-channel2",
    ]


def test_renumber_input():
    # Variant: SW2 uses Po2 for BOTH members -> bundle works, only the numbers differ (low)
    sw2 = {k: v.replace("channel-group 1 mode passive", "channel-group 2 mode passive")
               .replace("1      Po1(SD)         LACP      Et0/2(I)\n", "")
               .replace("Et0/3(I)", "Et0/2(I)    Et0/3(I)") for k, v in SW2.items()}
    result = run_scan(SW1, sw2)
    finding = find(result, "etherchannel-group-mismatch")[0]
    assert finding.severity == "low" and finding.fix_input.default == "1"

    resolved = fix_inputs.resolve(finding, "1")
    sw2_commands = commands_for(resolved.fixes, "SW2")
    # new Po1 gets the old Po2's settings first, then the members move, then Po2 is removed
    assert sw2_commands[:4] == ["interface Port-channel1", "switchport trunk native vlan 99",
                                "switchport trunk allowed vlan 10,99", "switchport mode trunk"]
    assert sw2_commands[-1] == "no interface Port-channel2"
    assert sw2_commands.count("no channel-group") == 2

    both = fix_inputs.resolve(finding, "7")  # a new number -> both ends are renumbered
    assert {fix.hostname for fix in both.fixes} == {"SW1", "SW2"}


def test_channel_number_in_use_is_rejected():
    sw2 = {k: v + ("interface Ethernet3/0\n channel-group 7 mode active\n" if k == "show running-config" else "")
           for k, v in SW2.items()}
    finding = [f for f in find(run_scan(SW1, sw2), "etherchannel-group-mismatch") if f.severity == "high"][0]
    assert "already used" in fix_inputs.validate(finding.fix_input, "7")


# ---------------------------------------------------------------- DTP


def test_dtp_dynamic_link(scan):
    finding = find(scan, "dtp-dynamic", "Et3/2")[0]
    # Phase 1: explicit trunk on both ends (SW2 needs the encapsulation first - it's "negotiate")
    phase1 = [f for f in finding.fixes if f.phase == 1]
    assert commands_for(phase1, "SW1") == ["interface Ethernet3/2", "switchport mode trunk"]
    assert commands_for(phase1, "SW2") == ["interface Ethernet3/2", "switchport trunk encapsulation dot1q",
                                           "switchport mode trunk"]
    # Phase 2: only then DTP off, on both ends
    phase2 = [f for f in finding.fixes if f.phase == 2]
    assert {f.hostname for f in phase2} == {"SW1", "SW2"}
    assert all(f.commands[-1] == "switchport nonegotiate" for f in phase2)


def test_dtp_phases_are_applied_in_order(scan):
    finding = find(scan, "dtp-dynamic", "Et3/2")[0]
    step1 = commands_per_device([finding], phase=1)
    step2 = commands_per_device([finding], phase=2)
    assert "switchport nonegotiate" not in step1[SW1_IP][1]
    assert step2[SW1_IP][1] == ["interface Ethernet3/2", "switchport nonegotiate"]


def test_dtp_on_static_trunk(scan):
    finding = find(scan, "dtp-on-trunk", "Et0/1")[0]
    assert finding.severity == "low"
    assert commands_for(finding.fixes, "SW2") == ["interface Ethernet0/1", "switchport nonegotiate"]
    assert not find(scan, "dtp-on-trunk", "Et1/2")  # access vs trunk: reported as a mode mismatch instead


def test_dtp_edge_port(scan):
    finding = find(scan, "dtp-edge-port", "SW1 Et3/3")[0]
    assert finding.severity == "high"
    assert finding.fixes[0].commands == ["interface Ethernet3/3", "switchport mode access", "switchport nonegotiate"]
    assert not find(scan, "dtp-edge-port", "Et3/2")  # on a compared link -> dtp-dynamic handles it


# ---------------------------------------------------------------- unused ports


def test_unused_ports_found(scan):
    sw1 = find(scan, "unused-ports", "SW1")[0]
    ports = [t.interface for t in sw1.fix_input.targets if t.params["role"] == "port"]
    assert ports == ["Ethernet3/0"]  # Et3/1 is already parked; routed and up ports aren't "unused"
    assert sw1.fix_input.default == "999"  # SW1 already has a VLAN named PARKING
    sw2 = find(scan, "unused-ports", "SW2")[0]
    assert sw2.fix_input.default == ""  # no parking VLAN there - the user must choose


def test_parking_vlan_input(scan):
    sw2 = find(scan, "unused-ports", "SW2")[0]
    assert "used by active ports" in fix_inputs.validate(sw2.fix_input, "10")
    assert fix_inputs.validate(sw2.fix_input, "1")  # default VLAN isn't a parking VLAN
    assert fix_inputs.validate(sw2.fix_input, "999") is None

    resolved = fix_inputs.resolve(sw2, "999")
    # 999 doesn't exist on SW2 -> created first, so IOS doesn't print a "% ..." auto-create message
    assert commands_for(resolved.fixes, "SW2") == [
        "vlan 999", "name PARKING",
        "interface Ethernet3/0", "shutdown", "switchport mode access",
        "switchport access vlan 999", "switchport nonegotiate",
    ]
    sw1 = fix_inputs.resolve(find(scan, "unused-ports", "SW1")[0], "999")
    assert commands_for(sw1.fixes, "SW1")[0] == "interface Ethernet3/0"  # already exists - not created


def test_parking_vlan_warns_about_existing_vlan(scan):
    sw1 = find(scan, "unused-ports", "SW1")[0]
    assert "SERVERS" in fix_inputs.warning(sw1.fix_input, "20")  # exists, unused on SW1, but named SERVERS
    assert fix_inputs.warning(sw1.fix_input, "999") is None  # named PARKING - fine


# ---------------------------------------------------------------- plan + report


def test_commands_grouped_per_device(scan):
    ready = [f for f in scan["findings"] if f.fixes]
    native = fix_inputs.resolve(find(scan, "native-vlan-mismatch", "Et0/1")[0], "99")
    plan = commands_per_device(ready + [native])
    assert set(plan) == {SW1_IP, SW2_IP}
    hostname, commands = plan[SW2_IP]
    assert hostname == "SW2" and "switchport trunk native vlan 99" in commands


def test_renumber_keeps_mode_fix(scan):
    """Mode fix (passive -> active) + renumber to Po2 on the same ports: the renumber must not
    put "passive" back."""
    mode_fixes = find(scan, "etherchannel-mode-mismatch")
    split = [f for f in find(scan, "etherchannel-group-mismatch") if f.severity == "high"][0]
    _, sw1 = commands_per_device(mode_fixes + [fix_inputs.resolve(split, "2")])[SW1_IP]
    assert "channel-group 2 mode active" in sw1  # moved WITH the corrected mode
    assert "channel-group 2 mode passive" not in sw1
    assert "channel-group 1 mode active" not in sw1  # separate mode fix dropped - port moves anyway

    # Renumber to 1: SW1 isn't moved, so its mode fix must stay
    _, sw1 = commands_per_device(mode_fixes + [fix_inputs.resolve(split, "1")])[SW1_IP]
    assert "channel-group 1 mode active" in sw1


def test_report_roundtrip(scan):
    report = BaselineReport("baseline", datetime(2026, 11, 17, 12, 0), findings=scan["findings"], links=["SW1 Et0/1 <-> SW2 Et0/1"])
    again = ScanReport.from_dict(report.to_dict())
    assert again.findings == report.findings  # FixInputs and FixTargets survive the JSON trip
    assert type(again) is BaselineReport and again == report  # same subclass back, links included


def test_report_saved_before_subclasses_loads_as_baseline():
    old = BaselineReport("baseline", datetime(2026, 11, 17, 12, 0)).to_dict()
    del old["kind"]  # files written before report subclasses existed have no "kind"
    assert type(ScanReport.from_dict(old)) is BaselineReport
