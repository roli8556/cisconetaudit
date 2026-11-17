"""
Baseline scan: a static look at how devices are configured and what state they are in.
Nothing is changed and no traffic is generated - it only reads snapshots.

1. Links are found with CDP: "SW1 Et0/1 sees SW2 on its Et0/1". Only links where BOTH ends are
   in the project can be compared.
2. Link checks compare the two ends: MTU, speed/duplex, trunk/access mode, native VLAN,
   allowed VLANs, OSPF (area, timers, passive, version) and EtherChannel (group, mode).
3. Device checks compare the configuration with the live state, e.g. OSPF is enabled on an
   interface but no neighbor reached FULL, or a port-channel member isn't bundled.

Each check is a generator function: instead of building and returning a list, it "yield"s each
finding as it is found. The caller collects them with list(...) or extend(...). There's no direct
C++ equivalent - think of it as a function that can return several times and resume.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterator
from dataclasses import dataclass

from ..models import DeviceSnapshot, Finding, Fix, FixInput, FixTarget, InterfaceState, OspfInterface
from ..parsers.ios import config_interface_sections, format_vlan_list, parse_vlan_list, short_interface
from . import l2security, management

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

LACP_MODES = {"active", "passive"}
PAGP_MODES = {"desirable", "auto"}


# ---------------------------------------------------------------- links


@dataclass
class Endpoint:
    """One end of a link: a device + an interface on it."""

    device: DeviceSnapshot
    interface: str  # full name of the physical interface

    @property
    def state(self) -> InterfaceState | None:
        return self.device.interfaces.get(self.interface)

    @property
    def l2_name(self) -> str:
        """Where layer-2 settings live: on the Port-channel if this port is a member."""
        state = self.state
        if state and state.channel_group:
            return f"Port-channel{state.channel_group}"
        return self.interface

    @property
    def l2_state(self) -> InterfaceState | None:
        return self.device.interfaces.get(self.l2_name) or self.state

    @property
    def ospf(self) -> OspfInterface | None:
        """OSPF runs on the Port-channel for an L3 EtherChannel, otherwise on the interface."""
        return self.device.ospf_interfaces.get(self.interface) or self.device.ospf_interfaces.get(self.l2_name)

    def label(self, interface: str | None = None) -> str:
        return f"{self.device.hostname} {short_interface(interface or self.interface)}"

    def fix(self, *commands: str) -> Fix:
        # *commands collects any number of arguments into a tuple (like C++ variadic args)
        return Fix(self.device.host_ip, self.device.hostname, list(commands))

    def l2_target(self) -> FixTarget:
        """This end as the target of a fix-with-input for layer-2 settings. access_vlans lets the
        native-VLAN fix warn when the chosen VLAN is one that hosts are in."""
        access = sorted({i.access_vlan for i in self.device.interfaces.values()
                         if i.is_up and i.oper_mode == "static access" and i.access_vlan})
        return FixTarget(self.device.host_ip, self.device.hostname, self.l2_name,
                         {"access_vlans": ",".join(map(str, access))})


@dataclass
class Link:
    a: Endpoint
    b: Endpoint

    @property
    def location(self) -> str:
        return f"{self.a.label()} <-> {self.b.label()}"

    @property
    def l2_location(self) -> str:
        """Port-channel members share L2 settings, so report those once per port-channel."""
        return f"{self.a.label(self.a.l2_name)} <-> {self.b.label(self.b.l2_name)}"


def _base_hostname(name: str) -> str:
    return name.split(".")[0].lower()  # "SW2.lab.local" -> "sw2"


def find_links(snapshots: list[DeviceSnapshot]) -> list[Link]:
    """Pair up CDP neighbors where both ends are scanned devices. Each link is seen from both
    sides, so a set of already-seen links prevents adding it twice."""
    by_name = {_base_hostname(s.hostname): s for s in snapshots}  # dict comprehension
    by_ip = {s.host_ip: s for s in snapshots}
    links: list[Link] = []
    seen: set[frozenset] = set()

    for device in snapshots:
        for neighbor in device.cdp_neighbors:
            other = by_name.get(_base_hostname(neighbor.device_id)) or by_ip.get(neighbor.mgmt_ip)
            if other is None or other is device:
                continue
            # frozenset = immutable set, can be used as a set member / dict key. Order doesn't
            # matter, so A->B and B->A give the same key.
            key = frozenset({(device.host_ip, neighbor.local_interface), (other.host_ip, neighbor.remote_interface)})
            if key in seen:
                continue
            seen.add(key)
            ends = sorted(
                [Endpoint(device, neighbor.local_interface), Endpoint(other, neighbor.remote_interface)],
                key=lambda e: (e.device.hostname, e.interface),  # stable order -> stable finding keys
            )
            links.append(Link(*ends))
    return links


# ---------------------------------------------------------------- link checks


def check_mtu(link: Link) -> Iterator[Finding]:
    a, b = link.a.state, link.b.state
    if a and b and a.mtu and b.mtu and a.mtu != b.mtu:
        yield Finding(
            "mtu-mismatch", "medium", link.location,
            f"MTU differs: {a.mtu} vs {b.mtu}. Large frames are dropped on the smaller side, and "
            "OSPF adjacencies get stuck in EXSTART/EXCHANGE.",
            "No automatic fix: the right MTU is a design decision (and is often a system-wide setting).",
        )


def check_duplex(link: Link) -> Iterator[Finding]:
    a, b = link.a.state, link.b.state
    if not (a and b):
        return
    conf_a, conf_b = a.configured_duplex or "auto", b.configured_duplex or "auto"
    if a.is_up and b.is_up and {a.duplex, b.duplex} == {"full", "half"}:
        problem = f"running {a.duplex} vs {b.duplex} duplex"
    elif conf_a != conf_b:
        problem = f"configured duplex {conf_a} vs {conf_b}"
        if "auto" in (conf_a, conf_b):
            problem += " - the auto side can't negotiate with a hardcoded side and falls back to half duplex"
    else:
        return
    fixes = [e.fix(f"interface {e.interface}", "duplex auto") for e, s in ((link.a, a), (link.b, b))
             if s.configured_duplex and s.configured_duplex != "auto"]
    yield Finding(
        "duplex-mismatch", "high", link.location,
        f"Duplex mismatch: {problem}. Causes late collisions, CRC errors and very slow throughput.",
        "Set duplex to auto on the hardcoded end(s), so both ends negotiate.", fixes,
    )


def check_speed(link: Link) -> Iterator[Finding]:
    a, b = link.a.state, link.b.state
    if not (a and b):
        return
    conf_a, conf_b = a.configured_speed or "auto", b.configured_speed or "auto"
    if conf_a == conf_b:
        return
    both_fixed = "auto" not in (conf_a, conf_b)
    fixes = [e.fix(f"interface {e.interface}", "speed auto") for e, s in ((link.a, a), (link.b, b))
             if s.configured_speed and s.configured_speed != "auto"]
    yield Finding(
        "speed-mismatch", "high" if both_fixed else "low", link.location,
        f"Configured speed {conf_a} vs {conf_b}. "
        + ("Two different fixed speeds - the link can't come up." if both_fixed
           else "Usually works (the auto side detects the speed), but best practice is the same setting on both ends."),
        "Set speed to auto on the hardcoded end(s).", fixes,
    )


def _port_kind(state: InterfaceState) -> str:
    if state.admin_mode == "trunk" or state.oper_mode == "trunk":
        return "trunk"
    if "access" in state.admin_mode:
        return "access"
    return state.admin_mode  # "dynamic auto" / "dynamic desirable"


def check_switchport_mode(link: Link) -> Iterator[Finding]:
    a, b = link.a.l2_state, link.b.l2_state
    if not (a and b and a.switchport and b.switchport):
        return
    kind_a, kind_b = _port_kind(a), _port_kind(b)
    if {kind_a, kind_b} == {"trunk", "access"}:
        yield Finding(
            "trunk-access-mismatch", "high", link.l2_location,
            f"One end is a trunk, the other an access port ({kind_a} vs {kind_b}). VLANs leak "
            "between the access VLAN and the trunk's native VLAN, other VLANs don't pass.",
            "No automatic fix: decide whether this link should be a trunk or an access port.",
        )
    elif kind_a == kind_b == "dynamic auto":
        yield Finding(
            "trunk-access-mismatch", "medium", link.l2_location,
            "Both ends are 'dynamic auto': each waits for the other to start DTP, so no trunk forms.",
            "No automatic fix: set 'switchport mode trunk' (or access) explicitly on both ends.",
        )


def check_native_vlan(link: Link) -> Iterator[Finding]:
    a, b = link.a.l2_state, link.b.l2_state
    if not (a and b and a.is_trunk and b.is_trunk):
        return
    # The user picks the VLAN; both ends get it, so they always end up equal.
    targets = [link.a.l2_target(), link.b.l2_target()]
    if a.native_vlan == b.native_vlan == 1:
        yield Finding(
            "native-vlan-1", "medium", link.l2_location,
            "Both ends use native VLAN 1. Enables VLAN-hopping (double tagging) attacks; use an "
            "unused VLAN as native on all trunks (CIS Cisco IOS benchmark).",
            "Set the same unused native VLAN on both ends.",
            fix_input=FixInput("native-vlan", "Native VLAN for both ends (an unused VLAN)", "", targets),
        )
    elif a.native_vlan != b.native_vlan:
        # If exactly one end still uses VLAN 1, the other end's value is the likely intent.
        non_default = {a.native_vlan, b.native_vlan} - {1}
        default = str(non_default.pop()) if len(non_default) == 1 else ""
        yield Finding(
            "native-vlan-mismatch", "high", link.l2_location,
            f"Native VLAN differs: {a.native_vlan} vs {b.native_vlan}. Untagged traffic leaks between "
            "the two VLANs (a security issue) and STP may block the port.",
            "Set the same native VLAN on both ends.",
            fix_input=FixInput("native-vlan", "Native VLAN for both ends", default, targets),
        )


def check_allowed_vlans(link: Link) -> Iterator[Finding]:
    a, b = link.a.l2_state, link.b.l2_state
    if not (a and b and a.is_trunk and b.is_trunk):
        return
    vlans_a, vlans_b = parse_vlan_list(a.allowed_vlans), parse_vlan_list(b.allowed_vlans)
    if vlans_a == vlans_b:
        return
    # A VLAN only crosses the trunk if BOTH ends allow it - so the intersection (&) is exactly
    # what works today: the safe default. The union (|) is what was probably intended.
    common, union = format_vlan_list(vlans_a & vlans_b) or "none", format_vlan_list(vlans_a | vlans_b)
    only_a, only_b = format_vlan_list(vlans_a - vlans_b), format_vlan_list(vlans_b - vlans_a)
    yield Finding(
        "allowed-vlan-mismatch", "medium", link.l2_location,
        "Allowed VLANs differ. "
        + (f"Only on {link.a.label(link.a.l2_name)}: {only_a}. " if only_a else "")
        + (f"Only on {link.b.label(link.b.l2_name)}: {only_b}. " if only_b else "")
        + "Those VLANs can't cross this link.",
        f"Set the same allowed VLANs on both ends. Default {common} = what both ends carry today "
        f"(changes nothing that works). Both lists combined would be {union}.",
        fix_input=FixInput("allowed-vlans", "VLANs to allow on both ends", common,
                           [link.a.l2_target(), link.b.l2_target()]),
    )


def check_ospf(link: Link) -> Iterator[Finding]:
    a, b = link.a.ospf, link.b.ospf
    sa, sb = link.a.state, link.b.state
    versions_a = ({2} if a else set()) | ({3} if sa and sa.ospfv3 else set())  # | = set union
    versions_b = ({2} if b else set()) | ({3} if sb and sb.ospfv3 else set())

    if versions_a and versions_b and versions_a.isdisjoint(versions_b):
        yield Finding(
            "ospf-version-mismatch", "high", link.location,
            f"Different OSPF versions: OSPFv{min(versions_a)} vs OSPFv{min(versions_b)}. They never form an adjacency.",
            "No automatic fix: run the same OSPF version on both ends.",
        )
        return
    if bool(versions_a) != bool(versions_b):
        on = link.a if versions_a else link.b
        yield Finding(
            "ospf-one-side", "medium", link.location,
            f"OSPF runs only on {on.label()}. No adjacency over this link.",
            "No automatic fix: enable OSPF on the other end, or make this end passive.",
        )
        return
    if not (a and b):
        return  # only OSPFv3 on both - v3 details aren't collected yet

    if a.area != b.area:
        yield Finding(
            "ospf-area-mismatch", "high", link.location,
            f"OSPF area differs: {a.area} vs {b.area}. Hellos are ignored, no adjacency forms.",
            "No automatic fix: decide which area this link belongs to.",
        )
    if a.passive != b.passive:
        passive_end, passive = (link.a, a) if a.passive else (link.b, b)
        yield Finding(
            "ospf-passive-mismatch", "high", link.location,
            f"{passive_end.label()} is a passive OSPF interface, the other end isn't. No adjacency forms.",
            f"Make {passive_end.label()} non-passive (two routers on this link should peer).",
            [passive_end.fix(f"router ospf {passive.process_id}", f"no passive-interface {passive.name}")],
        )
    if (a.hello, a.dead) != (b.hello, b.dead) and None not in (a.hello, b.hello):
        yield Finding(
            "ospf-timer-mismatch", "high", link.location,
            f"OSPF timers differ: hello/dead {a.hello}/{a.dead} vs {b.hello}/{b.dead}. "
            "Hellos with other timers are ignored, no adjacency forms.",
            "Set the same timers on both ends: back to the defaults, or custom values.",
            fix_input=FixInput(
                "ospf-timers", "Timers for both ends: 'default', or hello/dead like 5/20", "default",
                [FixTarget(e.device.host_ip, e.device.hostname, o.name) for e, o in ((link.a, a), (link.b, b))],
            ),
        )


def _channel_family(mode: str) -> str:
    if mode in LACP_MODES:
        return "LACP"
    if mode in PAGP_MODES:
        return "PAgP"
    return mode  # "on"


def check_etherchannel_mode(link: Link) -> Iterator[Finding]:
    a, b = link.a.state, link.b.state
    if not (a and b) or not (a.channel_group or b.channel_group):
        return
    if bool(a.channel_group) != bool(b.channel_group):
        member = link.a if a.channel_group else link.b
        yield Finding(
            "etherchannel-one-side", "high", link.location,
            f"Only {member.label()} is in a port-channel (Po{member.state.channel_group}). The port is "
            "suspended or forms a loop risk.",
            "No automatic fix: add the other end to a port-channel, or remove this end from it.",
        )
        return
    mode_a, mode_b = a.channel_mode, b.channel_mode
    if not (mode_a and mode_b):
        return
    if _channel_family(mode_a) != _channel_family(mode_b):
        yield Finding(
            "etherchannel-mode-mismatch", "high", link.location,
            f"EtherChannel modes don't match: '{mode_a}' vs '{mode_b}' ({_channel_family(mode_a)} vs "
            f"{_channel_family(mode_b)}). The bundle won't form.",
            "No automatic fix: use the same protocol on both ends (LACP is the standard).",
        )
    elif mode_a == mode_b and mode_a in ("passive", "auto"):
        new_mode = "active" if mode_a == "passive" else "desirable"
        yield Finding(
            "etherchannel-mode-mismatch", "high", link.location,
            f"Both ends are '{mode_a}': each waits for the other to start negotiating, so the bundle never forms.",
            f"Set {link.a.label()} to mode {new_mode}.",
            [link.a.fix(f"interface {link.a.interface}", f"channel-group {a.channel_group} mode {new_mode}")],
        )


def _static_mode_commands(endpoint: Endpoint, oper_mode: str) -> list[str]:
    """Commands that pin a port to the mode it's operating in right now."""
    if oper_mode == "trunk":
        commands = []
        if endpoint.l2_state.trunk_encapsulation == "negotiate":
            # ISL-capable switches refuse "mode trunk" while the encapsulation is negotiated
            commands.append("switchport trunk encapsulation dot1q")
        return commands + ["switchport mode trunk"]
    return ["switchport mode access"]


def check_dtp(link: Link) -> Iterator[Finding]:
    """DTP (Dynamic Trunking Protocol) lets a port negotiate becoming a trunk. Between switches
    the mode should be configured, not negotiated: a negotiating port can be talked into a trunk
    by any device that speaks DTP ("switch spoofing" - access to every VLAN)."""
    a, b = link.a.l2_state, link.b.l2_state
    if not (a and b and a.switchport and b.switchport):
        return
    ends = (link.a, link.b)
    dynamic = [e for e in ends if e.l2_state.admin_mode.startswith("dynamic")]
    negotiating = [e for e in ends if e.l2_state.dtp]
    if not negotiating:
        return

    if dynamic:
        modes = ", ".join(f"{e.label(e.l2_name)} '{e.l2_state.admin_mode}'" for e in dynamic)
        oper = a.oper_mode if a.oper_mode == b.oper_mode and a.oper_mode in ("trunk", "static access") else ""
        if not oper:
            yield Finding(
                "dtp-dynamic", "medium", link.l2_location,
                f"DTP negotiates the mode on this link ({modes}), and the two ends don't agree on a mode "
                f"right now ({a.oper_mode} vs {b.oper_mode}).",
                "No automatic fix: decide trunk or access, then configure it with 'switchport nonegotiate' on both ends.",
            )
            return
        kind = "trunk" if oper == "trunk" else "access"
        # Two phases, so the link keeps working while the switches are changed one at a time:
        #   1) every end gets an explicit mode - still compatible with a dynamic peer
        #   2) only then DTP is switched off - both ends are static by now
        fixes = [Fix(e.device.host_ip, e.device.hostname,
                     [f"interface {e.l2_name}", *_static_mode_commands(e, oper)], phase=1) for e in ends]
        fixes += [Fix(e.device.host_ip, e.device.hostname,
                      [f"interface {e.l2_name}", "switchport nonegotiate"], phase=2) for e in ends]
        yield Finding(
            "dtp-dynamic", "medium", link.l2_location,
            f"The link mode is negotiated with DTP ({modes}). Negotiating ports can be talked into a "
            "trunk by a spoofing device, and a negotiation mismatch silently changes the link.",
            f"Configure both ends as static {kind} (the mode the link runs in now) with 'switchport "
            "nonegotiate'. Done in two steps, so the link stays up while the switches are changed.",
            fixes,
        )
    elif a.admin_mode == b.admin_mode == "trunk":  # other mixes are a trunk/access mismatch
        yield Finding(
            "dtp-on-trunk", "low", link.l2_location,
            "Static trunk, but DTP is still sent (" + ", ".join(e.label(e.l2_name) for e in negotiating)
            + "). Not needed between static trunks, and it advertises that the port can trunk.",
            "Add 'switchport nonegotiate' where DTP is still on (CIS Cisco IOS benchmark).",
            [e.fix(f"interface {e.l2_name}", "switchport nonegotiate") for e in negotiating],
        )


LINK_CHECKS = [
    check_mtu, check_duplex, check_speed, check_switchport_mode,
    check_native_vlan, check_allowed_vlans, check_dtp, check_ospf, check_etherchannel_mode,
]


def check_etherchannel_groups(links: list[Link]) -> Iterator[Finding]:
    """All member links of one port-channel must end in ONE port-channel on the other device.

    Group numbers are only locally significant (Po1 on SW1 may connect to Po2 on SW2 and work),
    so differing numbers are only a low-severity note; splitting a bundle is the real error.
    """
    # bundles[(SW1, 1, SW2)] = all (near, far) endpoint pairs of SW1 Po1's links towards SW2.
    # defaultdict(list) creates an empty list the first time a key is used - no "if key not in"
    bundles: dict[tuple, list[tuple[Endpoint, Endpoint]]] = defaultdict(list)
    for link in links:
        for near, far in ((link.a, link.b), (link.b, link.a)):
            if near.state and far.state and near.state.channel_group and far.state.channel_group:
                bundles[(near.device.hostname, near.state.channel_group, far.device.hostname)].append((near, far))

    def far_groups(pairs: list[tuple[Endpoint, Endpoint]]) -> set[int]:
        return {far.state.channel_group for _, far in pairs}

    # Device pairs with a split bundle: a "numbers differ but it works" note would be wrong there.
    split = {frozenset({host, other}) for (host, _, other), pairs in bundles.items() if len(far_groups(pairs)) > 1}
    reported: set[frozenset] = set()
    for (host, group, other_host), pairs in bundles.items():
        location = f"{host} Po{group} -> {other_host}"
        endpoints = [e for pair in pairs for e in pair]  # both ends of every member link
        others = far_groups(pairs)
        if len(others) > 1:
            groups = ", ".join(f"Po{g}" for g in sorted(others))
            yield Finding(
                "etherchannel-group-mismatch", "high", location,
                f"Members of {host} Po{group} connect to different port-channels on {other_host} ({groups}). "
                "The bundle is split - members get suspended.",
                "Move all members on both ends into one port-channel number of your choice "
                "(the port-channel's settings are copied, emptied port-channels are removed).",
                fix_input=FixInput("channel-group", "Port-channel number for this bundle (both ends)",
                                   str(group), channel_group_targets(endpoints)),
            )
        elif others != {group} and frozenset({host, other_host}) not in split:
            other_group = next(iter(others))
            pair = frozenset({(host, group), (other_host, other_group)})
            if pair not in reported:  # report each pair once, not from both sides
                reported.add(pair)
                yield Finding(
                    "etherchannel-group-mismatch", "low", location,
                    f"{host} Po{group} connects to {other_host} Po{other_group}. This works (group "
                    "numbers are local), but the same number on both ends makes troubleshooting easier.",
                    "Renumber so both ends use the same port-channel number. Renumbering briefly "
                    "interrupts traffic over this bundle.",
                    fix_input=FixInput("channel-group", "Port-channel number for this bundle (both ends)",
                                       str(min(group, other_group)), channel_group_targets(endpoints)),
                )


def channel_group_targets(endpoints: list[Endpoint]) -> list[FixTarget]:
    """Everything the port-channel renumber fix needs (see fix_inputs._build_channel_group):
    per device its used channel-group numbers, per involved port-channel its config and whether
    all of its members are being moved, and every member with its current group and mode."""
    targets: list[FixTarget] = []
    devices = {e.device.host_ip: e.device for e in endpoints}  # unique devices, in order
    for device in devices.values():
        mine = [e for e in endpoints if e.device is device]
        used = sorted({i.channel_group for i in device.interfaces.values() if i.channel_group})
        targets.append(FixTarget(device.host_ip, device.hostname, "", {
            "role": "device", "used_groups": ",".join(map(str, used)),
        }))
        sections = config_interface_sections(device.running_config)
        for group in sorted({e.state.channel_group for e in mine}):
            all_members = {i.name for i in device.interfaces.values()
                           if i.channel_group == group and not i.name.startswith("Port-channel")}
            moved = {e.interface for e in mine if e.state.channel_group == group}
            targets.append(FixTarget(device.host_ip, device.hostname, f"Port-channel{group}", {
                "role": "port-channel", "group": str(group),
                "config": "\n".join(sections.get(f"Port-channel{group}", [])),
                "all_moved": "yes" if all_members <= moved else "no",  # <= on sets = "is subset of"
            }))
        for e in mine:
            targets.append(FixTarget(device.host_ip, device.hostname, e.interface, {
                "role": "member", "group": str(e.state.channel_group), "mode": e.state.channel_mode or "on",
            }))
    return targets


# ---------------------------------------------------------------- device checks (config vs state)


def check_native_vlan_1(device: DeviceSnapshot, links: list[Link]) -> Iterator[Finding]:
    """Trunks on native VLAN 1 whose other end ISN'T scanned (compared links are handled by
    check_native_vlan, which can fix both ends at once)."""
    linked = {e.l2_name for link in links for e in (link.a, link.b) if e.device is device}
    for intf in device.interfaces.values():
        if intf.is_trunk and intf.native_vlan == 1 and not intf.channel_group and intf.name not in linked:
            yield Finding(
                "native-vlan-1", "medium", f"{device.hostname} {short_interface(intf.name)}",
                "Trunk uses native VLAN 1. Enables VLAN-hopping (double tagging) attacks; use an "
                "unused VLAN as native on all trunks (CIS Cisco IOS benchmark).",
                "No automatic fix: the other end isn't in this project - changing only this end would "
                "cause a native VLAN mismatch. Set the same unused VLAN on both ends.",
            )


def check_ospf_neighbor_states(device: DeviceSnapshot, links: list[Link]) -> Iterator[Finding]:
    for neighbor in device.ospf_neighbors:
        state = neighbor.state.split("/")[0].strip()  # "EXSTART/  -" -> "EXSTART"
        if state in ("FULL", "2WAY"):  # 2WAY is normal between two DROTHERs
            continue
        hint = {
            "EXSTART": "Stuck in database exchange - almost always an MTU mismatch.",
            "EXCHANGE": "Stuck in database exchange - almost always an MTU mismatch.",
            "INIT": "One-way: we hear the neighbor but it doesn't hear us (ACL, or mismatched hello settings).",
        }.get(state, "The adjacency isn't complete.")
        yield Finding(
            "ospf-neighbor-not-full", "high" if state in ("EXSTART", "EXCHANGE", "INIT") else "medium",
            f"{device.hostname} {short_interface(neighbor.interface)}",
            f"OSPF neighbor {neighbor.neighbor_id} ({neighbor.address}) is in state {neighbor.state}. {hint}",
            "No automatic fix: check the related link findings (MTU, timers, area).",
        )


def check_ospf_without_neighbor(device: DeviceSnapshot, links: list[Link]) -> Iterator[Finding]:
    """Config vs state: OSPF sends hellos out of an interface, but nobody answers."""
    with_neighbor = {n.interface for n in device.ospf_neighbors}  # set comprehension
    linked = {e.interface for link in links for e in (link.a, link.b) if e.device is device}
    cdp_seen = {n.local_interface for n in device.cdp_neighbors}

    for ospf in device.ospf_interfaces.values():
        intf = device.interfaces.get(ospf.name)
        if ospf.passive or ospf.network_type == "LOOPBACK" or ospf.name in with_neighbor:
            continue
        if not (intf and intf.is_up) or ospf.name in linked:
            continue  # down interfaces are expected to be quiet; scanned links are checked above
        location = f"{device.hostname} {short_interface(ospf.name)}"
        if ospf.name in cdp_seen:
            yield Finding(
                "ospf-no-adjacency", "medium", location,
                "OSPF is enabled and a device is connected (CDP), but no OSPF adjacency exists. "
                "That device isn't in this project, so the cause can't be checked from here.",
                "No automatic fix: compare area, timers and MTU with the connected device.",
            )
        else:
            yield Finding(
                "ospf-should-be-passive", "low", location,
                "OSPF sends hellos here but there is no OSPF neighbor and no network device behind it. "
                "Hellos towards hosts leak routing info and let anyone on the segment try to peer.",
                f"Make {short_interface(ospf.name)} a passive interface.",
                [Fix(device.host_ip, device.hostname, [f"router ospf {ospf.process_id}", f"passive-interface {ospf.name}"])],
            )


def check_config_vs_state(device: DeviceSnapshot, links: list[Link]) -> Iterator[Finding]:
    for intf in device.interfaces.values():
        if not intf.is_up:
            continue
        location = f"{device.hostname} {short_interface(intf.name)}"
        if intf.switchport and intf.admin_mode == "trunk" and intf.oper_mode not in ("trunk", ""):
            yield Finding(
                "trunk-not-trunking", "medium", location,
                f"Configured as trunk, but operational mode is '{intf.oper_mode}'.",
                "No automatic fix: check the other end of the link.",
            )
        flags = intf.channel_member_flags
        if intf.channel_group and flags and "P" not in flags and "H" not in flags:
            meaning = {"s": "suspended", "I": "stand-alone", "D": "down", "w": "waiting"}.get(flags[0], flags)
            yield Finding(
                "etherchannel-member-not-bundled", "high", location,
                f"Member of Po{intf.channel_group} but not bundled ({meaning}). Usually a mismatch with the "
                "other end (mode, speed, VLANs).",
                "No automatic fix: see the link findings for this port.",
            )


def check_dtp_edge_ports(device: DeviceSnapshot, links: list[Link]) -> Iterator[Finding]:
    """Ports in use, NOT on a compared link, that still negotiate with DTP (often the IOS
    default "dynamic auto"). Whoever is plugged in can negotiate a trunk."""
    linked = {e.l2_name for link in links for e in (link.a, link.b) if e.device is device}
    cdp = {n.local_interface: n.device_id for n in device.cdp_neighbors}
    for intf in device.interfaces.values():
        if not (intf.is_physical and intf.switchport and intf.is_up and intf.admin_mode.startswith("dynamic")):
            continue
        if intf.name in linked or intf.channel_group:
            continue
        location = f"{device.hostname} {short_interface(intf.name)}"
        neighbor = f" (CDP neighbor: {cdp[intf.name]})" if intf.name in cdp else ""
        message = (f"Port in '{intf.admin_mode}' mode{neighbor}: any device that speaks DTP can turn it "
                   "into a trunk and reach every VLAN (switch spoofing / VLAN hopping).")
        if intf.oper_mode == "static access":
            yield Finding(
                "dtp-edge-port", "high", location, message,
                f"Make it a static access port without DTP (it is an access port right now, VLAN {intf.access_vlan}).",
                [Fix(device.host_ip, device.hostname,
                     [f"interface {intf.name}", "switchport mode access", "switchport nonegotiate"])],
            )
        else:
            yield Finding(
                "dtp-edge-port", "high", location, message + f" It is a {intf.oper_mode} right now.",
                "No automatic fix: the other end isn't in this project - configure the mode explicitly "
                "on both ends, with 'switchport nonegotiate'.",
            )


def check_unused_ports(device: DeviceSnapshot, links: list[Link]) -> Iterator[Finding]:
    """Switchports that are down: shut them, make them static access without DTP, and park them
    in an unused VLAN - so plugging a cable in gives an attacker nothing (CIS Cisco IOS benchmark)."""
    unused = [
        intf for intf in device.interfaces.values()
        if intf.is_physical and intf.switchport and not intf.is_up
        and not intf.channel_group  # members are handled with their port-channel
        and not l2security.is_parked(intf)
    ]
    if not unused:
        return
    # VLANs in use on this switch: access VLANs of active ports, native VLANs of active trunks and
    # VLANs explicitly allowed on active trunks ("ALL" says nothing about what's really used).
    active = [i for i in device.interfaces.values() if i.is_up and i.switchport]
    in_use = sorted(
        {i.access_vlan for i in active if i.oper_mode == "static access" and i.access_vlan}
        | {i.native_vlan for i in active if i.is_trunk and i.native_vlan}
        | {v for i in active if i.is_trunk and i.allowed_vlans.upper() != "ALL" for v in parse_vlan_list(i.allowed_vlans)}
    )
    targets = [FixTarget(device.host_ip, device.hostname, "", {
        "role": "device",
        "vlans": ",".join(f"{vid}={name}" for vid, name in sorted(device.vlans.items())),
        "in_use": ",".join(map(str, in_use)),
    })] + [FixTarget(device.host_ip, device.hostname, i.name, {"role": "port"}) for i in unused]
    names = ", ".join(short_interface(i.name) for i in unused)
    # Suggest a VLAN that already looks like a parking VLAN - next() takes the first match, or "".
    default = next((str(vid) for vid, name in sorted(device.vlans.items())
                    if re.search(r"park|unused|black.?hole", name, re.I) and vid not in in_use), "")
    yield Finding(
        "unused-ports", "medium", f"{device.hostname} unused ports",
        f"{len(unused)} unused port(s) are not hardened: {names}. Anyone can plug in and get a "
        "working port (and possibly negotiate a trunk). Ports that are down only temporarily (a "
        "switched-off PC, an unplugged uplink) will stop working when fixed - check the list.",
        "Shut them down, make them static access ports with 'switchport nonegotiate', and put them "
        "in a parking VLAN that nothing else uses.",
        fix_input=FixInput("parking-vlan", f"Parking VLAN for the unused ports on {device.hostname}", default, targets),
    )


DEVICE_CHECKS = [
    check_native_vlan_1, check_ospf_neighbor_states, check_ospf_without_neighbor,
    check_config_vs_state, check_dtp_edge_ports, check_unused_ports,
]


# ---------------------------------------------------------------- the scan


class BaselineScan:
    name = "baseline"  # class attribute: shared by all instances, like a static member in C++

    def run(self, snapshots: list[DeviceSnapshot]) -> tuple[list[Finding], list[Link]]:
        links = find_links(snapshots)
        findings: list[Finding] = []
        for link in links:
            for check in LINK_CHECKS:  # functions in a list - called one by one
                findings.extend(check(link))
        findings.extend(check_etherchannel_groups(links))
        for device in snapshots:
            for check in DEVICE_CHECKS:
                findings.extend(check(device, links))
            for check in management.DEVICE_CHECKS:
                findings.extend(check(device, snapshots))
            for check in l2security.DEVICE_CHECKS:
                findings.extend(check(device, links))
        for check in management.NETWORK_CHECKS:
            findings.extend(check(snapshots))

        # Port-channel members report shared L2 settings with the same key - keep one of each.
        unique = {f.key: f for f in findings}
        return sorted(unique.values(), key=lambda f: (SEVERITY_ORDER[f.severity], f.location)), links
