"""Tests for netaudit/parsers/ios.py. Run all tests with:  python -m pytest"""

from netaudit.parsers.ios import (
    build_snapshot,
    format_vlan_list,
    normalize_interface,
    parse_vlan_list,
    short_interface,
)
from tests.sample_outputs import SW1, SW1_IP, SW2, SW2_IP


def test_normalize_interface():
    assert normalize_interface("Et0/1") == "Ethernet0/1"
    assert normalize_interface("Ethernet0/1") == "Ethernet0/1"
    assert normalize_interface("Gi1/0/24") == "GigabitEthernet1/0/24"
    assert normalize_interface("Te1/1/1") == "TenGigabitEthernet1/1/1"
    assert normalize_interface("Po1") == "Port-channel1"
    assert normalize_interface("Lo0") == "Loopback0"
    assert short_interface("Port-channel1") == "Po1"
    assert short_interface("GigabitEthernet1/0/24") == "Gi1/0/24"


def test_vlan_lists():
    assert parse_vlan_list("1,10-12,99") == {1, 10, 11, 12, 99}
    assert len(parse_vlan_list("ALL")) == 4094
    assert parse_vlan_list("NONE") == set()
    assert format_vlan_list({1, 10, 11, 12, 99}) == "1,10-12,99"
    assert format_vlan_list(set()) == ""


def test_wrapped_vlan_list_is_not_truncated():
    # ntc-templates loses VLANs here - the reason switchport is parsed by hand
    output = """Name: Po1
Switchport: Enabled
Administrative Mode: trunk
Operational Mode: trunk
Trunking Native Mode VLAN: 99 (MGMT)
Trunking VLANs Enabled: 1-9,11,13,49,51,53,55,
     57,59,61
"""
    snapshot = build_snapshot("1.1.1.1", "X", {"show interfaces switchport": output})
    assert parse_vlan_list(snapshot.interfaces["Port-channel1"].allowed_vlans) >= {51, 53, 55, 57, 61}


def test_sw1_snapshot():
    snap = build_snapshot(SW1_IP, "SW1", SW1)
    et01 = snap.interfaces["Ethernet0/1"]
    assert (et01.is_trunk, et01.native_vlan, et01.allowed_vlans) == (True, 99, "10,20,99")
    assert (et01.mtu, et01.duplex, et01.speed) == (1500, "full", "100mb/s")

    et02 = snap.interfaces["Ethernet0/2"]
    assert (et02.channel_group, et02.channel_mode, et02.channel_member_flags) == (1, "passive", "I")

    et11 = snap.interfaces["Ethernet1/1"]
    assert (et11.configured_speed, et11.configured_duplex) == ("100", "full")

    assert len(snap.cdp_neighbors) == 10
    assert snap.cdp_neighbors[0].device_id == "SW2.lab.local"
    assert snap.cdp_neighbors[0].local_interface == "Ethernet0/1"

    assert snap.ospf_interfaces["Ethernet1/0"].area == 0
    assert snap.ospf_interfaces["Ethernet1/0"].hello == 10
    assert snap.ospf_interfaces["Loopback0"].network_type == "LOOPBACK"
    assert snap.ospf_neighbors[0].state == "EXSTART/DR"


def test_sw2_snapshot():
    snap = build_snapshot(SW2_IP, "SW2", SW2)
    assert snap.ospf_interfaces["Ethernet1/0"].area == 1  # "0.0.0.1" == area 1
    assert snap.ospf_interfaces["Ethernet1/1"].passive is True
    assert snap.interfaces["Ethernet2/0"].ospfv3 is True
    assert snap.interfaces["Ethernet1/1"].duplex == "half"
    assert snap.interfaces["Ethernet0/3"].channel_group == 2


def test_error_output_is_ignored():
    snap = build_snapshot("1.1.1.1", "X", {
        "show cdp neighbors detail": "% CDP is not enabled",
        "show ip ospf interface": "% Invalid input detected at '^' marker.",
    })
    assert snap.cdp_neighbors == [] and snap.ospf_interfaces == {}
    assert any("CDP is not enabled" in note for note in snap.notes)
