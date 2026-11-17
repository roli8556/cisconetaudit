"""
Layer-2 edge security: port security, PortFast, BPDU Guard, DHCP snooping, Dynamic ARP
Inspection (DAI) and errdisable recovery.

Edge ports are where users and attackers plug in, so that's where these protections belong:
  - port security    limits how many MAC addresses a port accepts (stops MAC flooding, rogue hubs)
  - PortFast         edge ports start forwarding at once instead of after 30 s of STP states
  - BPDU Guard       shuts an edge port that receives STP BPDUs (someone plugged in a switch)
  - DHCP snooping    only trusted ports (uplinks) may send DHCP replies -> no rogue DHCP servers;
                     also builds the IP<->MAC<->port binding table that DAI uses
  - DAI              drops ARP packets that don't match the binding table -> no ARP spoofing / MITM
  - rate limits      DHCP and ARP floods from an edge port err-disable it instead of the CPU
  - errdisable recovery  ports shut down by these features come back by themselves after a while

Links are only used through their endpoints' attributes, so this module doesn't import
baseline.py (which imports this module) - that would be a circular import.
"""

from __future__ import annotations

from collections.abc import Iterator

from ..models import DeviceSnapshot, Finding, Fix, FixInput, FixQuestion, FixTarget, InterfaceState
from ..parsers.ios import format_vlan_list, parse_vlan_list, short_interface

RECOVERY_CAUSES = ["psecure-violation", "bpduguard", "dhcp-rate-limit", "arp-inspection"]
DAI_VALIDATION = ["src-mac", "dst-mac", "ip"]


# ---------------------------------------------------------------- port roles


def is_parked(intf: InterfaceState) -> bool:
    """Already hardened as unused: shut down, static access, no DTP, not in VLAN 1."""
    return (intf.status == "administratively down" and intf.admin_mode == "static access"
            and not intf.dtp and intf.access_vlan not in (None, 1))


def management_vlan(device: DeviceSnapshot) -> int | None:
    """The VLAN whose SVI has the IP netaudit connects to - changes there could lock us out."""
    for intf in device.interfaces.values():
        if intf.name.startswith("Vlan") and intf.ip_address == device.host_ip:
            return int(intf.name[4:])
    return None


def _l2_name(device: DeviceSnapshot, name: str) -> str:
    intf = device.interfaces.get(name)
    return f"Port-channel{intf.channel_group}" if intf and intf.channel_group else name


def uplink_ports(device: DeviceSnapshot, links: list) -> list[str]:
    """Ports towards other network devices: compared links, trunks, and ports with a switch or
    router behind them (CDP). These are the TRUSTED ports for DHCP snooping and DAI."""
    names = {e.l2_name for link in links for e in (link.a, link.b) if e.device is device}
    names |= {_l2_name(device, n.local_interface) for n in device.cdp_neighbors if n.is_network_device}
    names |= {_l2_name(device, i.name) for i in device.interfaces.values()
              if i.switchport and (i.admin_mode == "trunk" or i.oper_mode == "trunk")}
    return sorted(n for n in names if n in device.interfaces and device.interfaces[n].switchport)


def edge_ports(device: DeviceSnapshot, links: list) -> list[InterfaceState]:
    """Access ports where end devices (PCs, phones, printers) are - or could be - connected."""
    uplinks = set(uplink_ports(device, links))
    return [
        i for i in device.interfaces.values()
        if i.is_physical and i.switchport
        and (i.admin_mode == "static access" or i.oper_mode == "static access")
        and not i.channel_group and i.name not in uplinks and not is_parked(i)
    ]


def _sentence(parts: list[str]) -> str:
    """["a b", "c"] -> "A b; c". (str.capitalize() would also lowercase the rest: "DHCP" -> "Dhcp".)"""
    text = "; ".join(parts)
    return text[:1].upper() + text[1:]


def _ports(intfs: list[InterfaceState]) -> str:
    return ", ".join(short_interface(i.name) for i in intfs)


def _port_targets(device: DeviceSnapshot, names: list[str], role: str) -> list[FixTarget]:
    return [FixTarget(device.host_ip, device.hostname, n, {"role": role}) for n in names]


# ---------------------------------------------------------------- PortFast / BPDU Guard


def has_portfast(intf: InterfaceState, device: DeviceSnapshot) -> bool:
    """Configured on the port, or by the global default (unless disabled on the port)."""
    return intf.portfast == "enable" or (device.l2security.portfast_default and intf.portfast != "disable")


def has_bpduguard(intf: InterfaceState, device: DeviceSnapshot) -> bool:
    """The global bpduguard default only applies to PortFast ports."""
    return intf.bpduguard == "enable" or (
        device.l2security.bpduguard_default and has_portfast(intf, device) and intf.bpduguard != "disable")


def check_portfast(device: DeviceSnapshot, links: list) -> Iterator[Finding]:
    missing = [i for i in edge_ports(device, links) if not has_portfast(i, device)]
    if missing:
        yield Finding(
            "portfast-missing", "low", f"{device.hostname} edge ports",
            f"Edge ports without PortFast: {_ports(missing)}. After a link comes up they wait ~30 s in "
            "STP listening/learning (DHCP can time out), and every link flap floods the network with "
            "topology changes.",
            "Enable 'spanning-tree portfast' on these edge ports.",
            [_fix(device, [cmd for i in missing for cmd in (f"interface {i.name}", "spanning-tree portfast")])],
        )


def check_bpduguard(device: DeviceSnapshot, links: list) -> Iterator[Finding]:
    missing = [i for i in edge_ports(device, links) if not has_bpduguard(i, device)]
    if missing:
        yield Finding(
            "bpduguard-missing", "high", f"{device.hostname} edge ports",
            f"Edge ports without BPDU Guard: {_ports(missing)}. A switch plugged in there (by mistake "
            "or on purpose) joins STP - it can cause a loop or even become root bridge and pull "
            "traffic through itself.",
            "Enable 'spanning-tree bpduguard enable': the port is err-disabled when a BPDU arrives.",
            [_fix(device, [cmd for i in missing for cmd in (f"interface {i.name}", "spanning-tree bpduguard enable")])],
        )


def _fix(device: DeviceSnapshot, commands: list[str]) -> Fix:
    return Fix(device.host_ip, device.hostname, commands)


# ---------------------------------------------------------------- port security


def check_port_security(device: DeviceSnapshot, links: list) -> Iterator[Finding]:
    mgmt = management_vlan(device)
    edge = [i for i in edge_ports(device, links) if not i.port_security]
    candidates = [i for i in edge if i.access_vlan != mgmt]
    skipped = [i for i in edge if i.access_vlan == mgmt]
    if not candidates:
        return
    note = (f" Ports in the management VLAN {mgmt} ({_ports(skipped)}) are left out, so a violation "
            "can't cut off netaudit's own connection." if skipped else "")
    yield Finding(
        "port-security-missing", "medium", f"{device.hostname} edge ports",
        f"Edge ports without port security: {_ports(candidates)}. Any number of devices can connect "
        "through them (a hub, a rogue AP), and MAC flooding can overflow the switch's MAC table." + note,
        "Enable port security with your choice of violation mode, maximum MACs, sticky learning and aging.",
        fix_input=FixInput(
            "port-security",
            "Violation mode: shutdown (err-disable the port), restrict (drop + log) or protect (drop silently)",
            "shutdown",
            _port_targets(device, [i.name for i in candidates], "edge"),
            followups=[
                FixQuestion("maximum", "Maximum MAC addresses per port (2 = PC + IP phone)", "2",
                            min_value=1, max_value=132),
                FixQuestion("sticky", "Learn MACs as 'sticky' (saved in the config)? y/n", "y", choices=["y", "n"]),
                FixQuestion("aging", "Aging: minutes before a learned MAC is forgotten (0 = no aging)", "0",
                            min_value=0, max_value=1440),
            ],
        ),
    )


# ---------------------------------------------------------------- DHCP snooping


def check_dhcp_snooping(device: DeviceSnapshot, links: list) -> Iterator[Finding]:
    edge = edge_ports(device, links)
    if not edge:
        return
    cfg = device.l2security
    mgmt = management_vlan(device)
    uplinks = uplink_ports(device, links)
    edge_vlans = {i.access_vlan for i in edge if i.access_vlan and i.access_vlan != mgmt}
    snooped = parse_vlan_list(cfg.dhcp_snooping_vlans)

    problems = []
    if not cfg.dhcp_snooping:
        problems.append("DHCP snooping is not enabled")
    if edge_vlans - snooped:
        problems.append(f"edge VLAN(s) {format_vlan_list(edge_vlans - snooped)} are not snooped")
    untrusted = [p for p in uplinks if not device.interfaces[p].dhcp_trust]
    if untrusted and (cfg.dhcp_snooping or problems):
        problems.append(f"uplinks not trusted: {', '.join(map(short_interface, untrusted))}")
    unlimited = [i for i in edge if i.dhcp_rate is None]
    if unlimited:
        problems.append(f"no DHCP rate limit on {_ports(unlimited)}")
    if not problems:
        return

    followups = [FixQuestion("rate", "DHCP packets per second allowed per edge port", "15", min_value=1, max_value=2048)]
    if cfg.option82:
        followups.append(FixQuestion(
            "no_option82", "Stop the switch inserting DHCP option 82? Needed unless your DHCP server "
            "expects it (an IOS DHCP server drops such requests). y/n", "y", choices=["y", "n"]))
    yield Finding(
        "dhcp-snooping", "high" if not cfg.dhcp_snooping else "medium", f"{device.hostname} DHCP snooping",
        _sentence(problems) + ". Without DHCP snooping any device can run a rogue DHCP server "
        "and hand out itself as default gateway (man-in-the-middle).",
        "Trust the uplinks, rate-limit DHCP on edge ports, snoop the edge VLANs - and enable DHCP snooping "
        "LAST, so DHCP replies on the uplinks aren't dropped in between. If a DHCP server is connected "
        "directly to this switch, trust its port as well.",
        fix_input=FixInput(
            "dhcp-snooping", "VLANs to protect with DHCP snooping",
            format_vlan_list(edge_vlans | snooped),
            [FixTarget(device.host_ip, device.hostname, "", {"role": "device", "mgmt_vlan": str(mgmt or "")})]
            + _port_targets(device, untrusted, "trusted")
            + _port_targets(device, [i.name for i in edge], "edge"),
            followups=followups,
        ),
    )


# ---------------------------------------------------------------- Dynamic ARP Inspection


def check_dai(device: DeviceSnapshot, links: list) -> Iterator[Finding]:
    edge = edge_ports(device, links)
    if not edge:
        return
    cfg = device.l2security
    mgmt = management_vlan(device)
    edge_vlans = {i.access_vlan for i in edge if i.access_vlan and i.access_vlan != mgmt}
    inspected = parse_vlan_list(cfg.dai_vlans)
    uplinks = uplink_ports(device, links)
    untrusted = [p for p in uplinks if not device.interfaces[p].dai_trust]
    unlimited = [i for i in edge if i.dai_rate is None]
    full_validation = set(DAI_VALIDATION) <= set(cfg.dai_validate)

    problems = []
    if edge_vlans - inspected:
        problems.append(f"edge VLAN(s) {format_vlan_list(edge_vlans - inspected)} are not inspected")
    if not full_validation:
        problems.append("validation of src-mac, dst-mac and ip is not fully enabled")
    if untrusted and (inspected or problems):
        problems.append(f"uplinks not trusted: {', '.join(map(short_interface, untrusted))}")
    if unlimited:
        problems.append(f"no ARP rate limit on {_ports(unlimited)}")
    if not problems:
        return
    message = (_sentence(problems) + ". Without DAI anyone on the VLAN can send forged ARP "
               "replies and redirect other hosts' traffic through themselves (ARP spoofing).")
    location = f"{device.hostname} DAI"

    snooped = parse_vlan_list(cfg.dhcp_snooping_vlans) if cfg.dhcp_snooping else set()
    if not snooped:
        yield Finding(
            "dai-missing", "medium", location, message,
            "No automatic fix yet: DAI checks ARP against the DHCP snooping binding table. Enable DHCP "
            "snooping first, let the table fill (hosts renew their leases), then scan again - DAI "
            "can then be enabled automatically.",
        )
        return

    # Active hosts without a DHCP binding (static IP, or no renewal yet) would lose ARP under DAI.
    unbound = [i for i in edge if i.is_up and i.name not in device.dhcp_binding_ports]
    unbound_vlans = {i.access_vlan for i in unbound}
    safe_vlans = (edge_vlans & snooped) - unbound_vlans
    yield Finding(
        "dai-missing", "medium", location,
        message + (f" Active ports WITHOUT a DHCP binding (static IP?): {_ports(unbound)} - left out of "
                   "the suggested VLANs." if unbound else ""),
        "Trust the uplinks, rate-limit ARP on edge ports, validate src-mac/dst-mac/ip, then enable DAI "
        "on the chosen VLANs. Hosts with static IPs in those VLANs need an ARP ACL or they lose connectivity.",
        fix_input=FixInput(
            "dai", "VLANs to protect with DAI (must already be DHCP-snooped)",
            format_vlan_list(safe_vlans | (inspected & snooped)),
            [FixTarget(device.host_ip, device.hostname, "", {
                "role": "device", "mgmt_vlan": str(mgmt or ""),
                "snooped": format_vlan_list(snooped),
                "unbound": ",".join(f"{i.access_vlan}:{short_interface(i.name)}" for i in unbound),
            })]
            + _port_targets(device, untrusted, "trusted")
            + _port_targets(device, [i.name for i in edge], "edge"),
            followups=[FixQuestion("rate", "ARP packets per second allowed per edge port", "15",
                                   min_value=1, max_value=2048)],
        ),
    )


# ---------------------------------------------------------------- errdisable recovery


def check_errdisable_recovery(device: DeviceSnapshot, links: list) -> Iterator[Finding]:
    if not edge_ports(device, links):
        return
    missing = [c for c in RECOVERY_CAUSES if c not in device.l2security.errdisable_causes]
    if not missing:
        return
    interval = device.l2security.errdisable_interval
    yield Finding(
        "errdisable-recovery", "low", f"{device.hostname} errdisable recovery",
        f"No automatic errdisable recovery for: {', '.join(missing)}. A port shut down by port security, "
        "BPDU Guard or a DHCP/ARP rate limit stays down until someone runs shut/no shut on it.",
        "Let those ports come back by themselves after an interval (if the cause is still there, "
        "they're shut down again). Skip this if you prefer to inspect every err-disabled port by hand.",
        fix_input=FixInput(
            "errdisable-recovery", "Recovery interval in seconds (30-86400)", str(interval or 300),
            [FixTarget(device.host_ip, device.hostname, "", {"role": "device", "missing": ",".join(missing)})],
        ),
    )


DEVICE_CHECKS = [
    check_port_security, check_portfast, check_bpduguard,
    check_dhcp_snooping, check_dai, check_errdisable_recovery,
]
