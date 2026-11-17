"""Tests for edge-port security: port security, PortFast, BPDU Guard, DHCP snooping, DAI and
errdisable recovery - and the safety rules that keep netaudit from locking itself out."""

from netaudit.parsers.ios import build_snapshot
from netaudit.scans import fix_inputs, l2security
from netaudit.scans.baseline import BaselineScan, find_links
from tests.sample_outputs import SW1, SW1_IP, SW2, SW2_IP


def scan(sw1=SW1, sw2=SW2):
    snaps = [build_snapshot(SW1_IP, "SW1", sw1), build_snapshot(SW2_IP, "SW2", sw2)]
    findings, links = BaselineScan().run(snaps)
    return snaps, findings, links


def find(findings, check, host="SW1"):
    return [f for f in findings if f.check == check and f.location.startswith(host)]


def with_config(device: dict, extra_global: str = "", extra_output: dict | None = None) -> dict:
    """A copy of a sample device with extra global config lines (inserted before 'end')."""
    config = device["show running-config"].replace("\nend\n", f"\n{extra_global}\nend\n")
    return {**device, "show running-config": config, **(extra_output or {})}


SNOOPING_ON = "ip dhcp snooping\nip dhcp snooping vlan 10,99\nno ip dhcp snooping information option"
BINDINGS = """MacAddress          IpAddress        Lease(sec)  Type           VLAN  Interface
------------------  ---------------  ----------  -------------  ----  --------------------
00:50:79:66:68:05   10.10.10.5       86137       dhcp-snooping   10    Ethernet3/3
Total number of bindings: 1
"""


# ---------------------------------------------------------------- port roles


def test_edge_and_uplink_ports():
    snaps, _, links = scan()
    sw1 = snaps[0]
    assert {i.name for i in l2security.edge_ports(sw1, links)} == {"Ethernet0/0", "Ethernet3/3"}
    uplinks = l2security.uplink_ports(sw1, links)
    assert "Port-channel1" in uplinks and "Ethernet0/2" not in uplinks  # members -> their Po
    assert l2security.management_vlan(sw1) == 99  # Vlan99 has the IP netaudit connects to


# ---------------------------------------------------------------- PortFast / BPDU Guard


def test_portfast_and_bpduguard():
    _, findings, _ = scan()
    portfast = find(findings, "portfast-missing")[0]
    assert portfast.fixes[0].commands[:2] == ["interface Ethernet0/0", "spanning-tree portfast"]
    assert find(findings, "bpduguard-missing")[0].severity == "high"


def test_global_defaults_count():
    _, findings, _ = scan(sw1=with_config(SW1, "spanning-tree portfast default\nspanning-tree portfast bpduguard default"))
    assert not find(findings, "portfast-missing")
    assert not find(findings, "bpduguard-missing")


# ---------------------------------------------------------------- port security


def test_port_security_skips_management_vlan():
    _, findings, _ = scan()
    finding = find(findings, "port-security-missing")[0]
    ports = [t.interface for t in finding.fix_input.targets]
    assert ports == ["Ethernet3/3"]  # Et0/0 is in management VLAN 99
    assert "management VLAN 99" in finding.message


def test_port_security_questions():
    _, findings, _ = scan()
    finding = find(findings, "port-security-missing")[0]
    assert fix_inputs.validate(finding.fix_input, "drop")  # not a violation mode
    keys = [q.key for q in finding.fix_input.followups]
    assert keys == ["maximum", "sticky", "aging"]
    maximum = finding.fix_input.followups[0]
    assert fix_inputs.validate_followup(maximum, "0") and fix_inputs.validate_followup(maximum, "x")
    assert fix_inputs.validate_followup(maximum, "3") is None

    resolved = fix_inputs.resolve(finding, {"value": "restrict", "maximum": "3", "sticky": "n", "aging": "10"})
    assert resolved.fixes[0].commands == [
        "interface Ethernet3/3", "switchport mode access",
        "switchport port-security maximum 3", "switchport port-security violation restrict",
        "switchport port-security aging time 10", "switchport port-security aging type inactivity",
        "switchport port-security",  # switched on LAST, after maximum is raised
    ]
    defaults = fix_inputs.resolve(finding, "shutdown")  # follow-ups get their defaults
    assert "switchport port-security mac-address sticky" in defaults.fixes[0].commands
    assert not any("aging" in c for c in defaults.fixes[0].commands)  # 0 = no aging


# ---------------------------------------------------------------- DHCP snooping


def test_dhcp_snooping():
    _, findings, _ = scan()
    finding = find(findings, "dhcp-snooping")[0]
    assert finding.severity == "high"
    assert finding.fix_input.default == "10"  # management VLAN 99 left out
    assert "management VLAN" in fix_inputs.warning(finding.fix_input, "10,99")
    assert fix_inputs.validate(finding.fix_input, "all")  # must be explicit

    commands = fix_inputs.resolve(finding, {"value": "10", "rate": "20", "no_option82": "y"}).fixes[0].commands
    assert commands[0] == "ip dhcp snooping vlan 10"
    assert commands[1] == "no ip dhcp snooping information option"
    assert commands[-1] == "ip dhcp snooping"  # enabled LAST, after the uplinks are trusted
    trust = commands.index("interface Port-channel1")
    assert commands[trust + 1] == "ip dhcp snooping trust"
    assert commands[commands.index("interface Ethernet3/3") + 1] == "ip dhcp snooping limit rate 20"


def test_snooping_fully_configured_is_quiet():
    sw1 = with_config(SW1, SNOOPING_ON)
    # trust every uplink and rate-limit every edge port in the interface config
    config = sw1["show running-config"]
    for port in ("Ethernet0/1", "Ethernet1/2", "Ethernet2/2", "Ethernet3/2", "Port-channel1"):
        config = config.replace(f"interface {port}\n", f"interface {port}\n ip dhcp snooping trust\n", 1)
    for port in ("Ethernet0/0", "Ethernet3/3"):
        config = config.replace(f"interface {port}\n", f"interface {port}\n ip dhcp snooping limit rate 15\n", 1)
    _, findings, _ = scan(sw1={**sw1, "show running-config": config})
    assert not find(findings, "dhcp-snooping")


# ---------------------------------------------------------------- DAI


def test_dai_needs_snooping_first():
    _, findings, _ = scan()
    finding = find(findings, "dai-missing")[0]
    assert finding.fix_input is None and "Enable DHCP snooping first" in finding.fix_description


def test_dai_with_snooping():
    sw1 = with_config(SW1, SNOOPING_ON, {"show ip dhcp snooping binding": BINDINGS})
    _, findings, _ = scan(sw1=sw1)
    finding = find(findings, "dai-missing")[0]
    assert finding.fix_input.default == "10"  # Et3/3 has a binding; VLAN 99 is management
    assert "Et0/0" in finding.message  # active, no binding -> named
    assert "not fully enabled" in finding.message

    assert "aren't DHCP-snooped" in fix_inputs.validate(finding.fix_input, "10,20")
    assert "Et0/0" in fix_inputs.warning(finding.fix_input, "10,99")  # would lose ARP

    commands = fix_inputs.resolve(finding, {"value": "10", "rate": "30"}).fixes[0].commands
    assert commands[-2:] == ["ip arp inspection validate src-mac dst-mac ip", "ip arp inspection vlan 10"]
    assert commands[commands.index("interface Port-channel1") + 1] == "ip arp inspection trust"
    assert commands[commands.index("interface Ethernet3/3") + 1] == "ip arp inspection limit rate 30"


# ---------------------------------------------------------------- errdisable recovery


def test_errdisable_recovery():
    _, findings, _ = scan()
    finding = find(findings, "errdisable-recovery")[0]
    assert finding.fix_input.default == "300"
    assert fix_inputs.validate(finding.fix_input, "5")  # too short
    assert fix_inputs.resolve(finding, "600").fixes[0].commands == [
        "errdisable recovery cause psecure-violation", "errdisable recovery cause bpduguard",
        "errdisable recovery cause dhcp-rate-limit", "errdisable recovery cause arp-inspection",
        "errdisable recovery interval 600",
    ]


def test_errdisable_only_missing_causes():
    sw1 = with_config(SW1, "errdisable recovery cause bpduguard\nerrdisable recovery cause psecure-violation\n"
                           "errdisable recovery interval 120")
    _, findings, _ = scan(sw1=sw1)
    finding = find(findings, "errdisable-recovery")[0]
    assert finding.fix_input.default == "120"  # keeps the current interval as suggestion
    commands = fix_inputs.resolve(finding, "120").fixes[0].commands
    assert commands == ["errdisable recovery cause dhcp-rate-limit", "errdisable recovery cause arp-inspection",
                        "errdisable recovery interval 120"]
