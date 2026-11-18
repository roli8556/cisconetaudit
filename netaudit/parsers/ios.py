"""
Parsers for Cisco IOS / IOS-XE show commands and running-configs.

Where a good community parser exists we use ntc-templates (TextFSM templates that ship with
netmiko). "show ip ospf interface" has no full template, and the running-config is easier to
read directly, so those two are parsed here with regular expressions.

All functions take the raw text and return model objects, and none of them talk to a device -
so they can be tested with saved output (see tests/).
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Callable

from ntc_templates.parse import parse_output

from ..models import (
    CdpNeighbor,
    DeviceSnapshot,
    InterfaceState,
    L2SecurityConfig,
    ManagementConfig,
    NtpStatus,
    OspfInterface,
    OspfNeighbor,
)

# ---------------------------------------------------------------- interface names

# Order matters: the first name starting with the abbreviation wins ("Tw" -> TwoGigabitEthernet).
_FULL_NAMES = [
    "Ethernet", "FastEthernet", "GigabitEthernet", "TwoGigabitEthernet", "FiveGigabitEthernet",
    "TenGigabitEthernet", "TwentyFiveGigE", "FortyGigabitEthernet", "HundredGigE",
    "Port-channel", "Loopback", "Vlan", "Tunnel", "Serial",
]


def normalize_interface(name: str) -> str:
    """"Et0/1", "eth0/1", "Ethernet0/1" -> "Ethernet0/1". Different show commands abbreviate
    differently, so everything is converted to the full name before comparing."""
    match = re.fullmatch(r"([A-Za-z-]+)\s*([\d/.:]+)", name.strip())
    if not match:
        return name.strip()
    letters, number = match.group(1).lower(), match.group(2)
    for full in _FULL_NAMES:
        if full.lower().startswith(letters):
            return full + number
    return name.strip()


def short_interface(name: str) -> str:
    """"Ethernet0/1" -> "Et0/1", "Port-channel1" -> "Po1" (for display only)."""
    match = re.fullmatch(r"([A-Za-z-]+)([\d/.:]+)", name)
    return match.group(1)[:2] + match.group(2) if match else name


# ---------------------------------------------------------------- helpers


def _is_error(output: str) -> bool:
    """IOS answers unsupported/disabled features with "% ..." (e.g. "% CDP is not enabled")."""
    return output.lstrip().startswith("%")


def _ntc(command: str, output: str) -> list[dict]:
    """Run an ntc-template. Returns a list of dicts with lowercase keys, one per record."""
    if not output.strip() or _is_error(output):
        return []
    return parse_output(platform="cisco_ios", command=command, data=output)


def parse_vlan_list(text: str) -> set[int]:
    """"1,10-12,99" -> {1, 10, 11, 12, 99}; "ALL" -> 1..4094; "NONE"/"" -> empty set."""
    text = text.strip().upper()
    if text == "ALL":
        return set(range(1, 4095))
    vlans: set[int] = set()
    for part in text.replace(" ", "").split(","):
        if "-" in part:
            low, high = part.split("-")
            vlans.update(range(int(low), int(high) + 1))
        elif part.isdigit():
            vlans.add(int(part))
    return vlans


def format_vlan_list(vlans: set[int]) -> str:
    """{1, 10, 11, 12, 99} -> "1,10-12,99" (the reverse of parse_vlan_list)."""
    parts, ordered = [], sorted(vlans)
    i = 0
    while i < len(ordered):
        j = i
        while j + 1 < len(ordered) and ordered[j + 1] == ordered[j] + 1:
            j += 1
        parts.append(str(ordered[i]) if i == j else f"{ordered[i]}-{ordered[j]}")
        i = j + 1
    return ",".join(parts)


def _normalize_duplex(text: str) -> str:
    text = text.lower()
    for value in ("full", "half", "auto"):
        if value in text:
            return value
    return ""


def _normalize_speed(text: str) -> str:
    """"100Mb/s" -> "100mb/s", "1000Mb/s" -> "1000mb/s", "Auto-speed" -> "auto"."""
    text = text.lower().strip()
    if "auto" in text:
        return "auto"
    match = re.search(r"(\d+)\s*([mg]b/?s)", text)
    return f"{match.group(1)}{match.group(2)}" if match else text


def _ospf_area(text: str) -> int:
    """"0" -> 0, "0.0.0.1" -> 1. OSPF areas are 32-bit numbers, and IOS accepts both forms."""
    if "." in text:
        a, b, c, d = (int(x) for x in text.split("."))
        return (a << 24) | (b << 16) | (c << 8) | d  # << is bit shift, same as C++
    return int(text)


# ---------------------------------------------------------------- show commands


# ---------------------------------------------------------------- interfaces
#
# One InterfaceState per port is built from FOUR sources. parse_interfaces() creates the
# interfaces dict and passes it to the four parsers below; each one fills in its own fields on
# the SAME InterfaceState objects (they modify the dict in place and return nothing - Python
# passes references, like a std::map& in C++):
#
#     parse_show_interfaces   "show interfaces"             status, MTU, duplex, speed, media, ARP, IP
#     parse_switchport        "show interfaces switchport"  mode, VLANs, native tagging, DTP
#     parse_etherchannel      "show etherchannel summary"   channel group, protocol, member flags
#     parse_interface_config  the running-config            portfast, port-security, snooping...
#
# All of them normalize interface names to the full form, so "Et0/1" in one output and
# "Ethernet0/1" in another end up on the same InterfaceState.


def parse_interfaces(outputs: dict[str, str]) -> dict[str, InterfaceState]:
    """The core of the snapshot: {full interface name: InterfaceState}, one per port.

    If two parsers set the same field, the later one wins - so the running-config comes last.
    """
    interfaces: dict[str, InterfaceState] = {}
    parse_show_interfaces(interfaces, outputs.get("show interfaces", ""))
    parse_switchport(interfaces, outputs.get("show interfaces switchport", ""))
    parse_etherchannel(interfaces, outputs.get("show etherchannel summary", ""))
    parse_interface_config(interfaces, outputs.get("show running-config", ""))
    return interfaces


def _set_fields(interfaces: dict[str, InterfaceState], name: str, fields: dict[str, object]) -> None:
    """Set fields on one interface's InterfaceState, creating it the first time it is seen."""
    intf = interfaces.setdefault(name, InterfaceState(name=name))  # get, or insert new
    for field_name, value in fields.items():
        # setattr would silently ADD a new attribute for a misspelled name, and the real field
        # would stay empty - so check that the field exists first.
        if not hasattr(intf, field_name):
            raise AttributeError(f"InterfaceState has no field {field_name!r}")
        setattr(intf, field_name, value)  # same as intf.<field_name> = value


def _arp_types(output: str) -> dict[str, str]:
    """{interface: ARP type} from "show interfaces" - the ntc-template doesn't capture the
    "  ARP type: ARPA, ARP Timeout 04:00:00" line, so it's read by hand."""
    result: dict[str, str] = {}
    current = None  # the interface whose block we're in
    for line in output.splitlines():
        if header := re.match(r"(\S+) is .*line protocol is", line):  # "Ethernet0/1 is up, line protocol is up"
            current = normalize_interface(header.group(1))
        elif current and (arp := re.match(r"\s+ARP type: (\w+)", line)):
            result[current] = arp.group(1).lower()
    return result


def parse_show_interfaces(interfaces: dict[str, InterfaceState], output: str) -> None:
    """"show interfaces": status, protocol, MTU, duplex, speed, media type, ARP type and IP
    address of every interface."""
    arp_types = _arp_types(output)
    for row in _ntc("show interfaces", output):
        name = normalize_interface(row["interface"])
        _set_fields(interfaces, name, {
            "status": row["link_status"].strip().lower(),
            "protocol": row["protocol_status"].strip().lower().split()[0] if row["protocol_status"] else "",
            "mtu": int(row["mtu"]) if row["mtu"] else None,
            "duplex": _normalize_duplex(row["duplex"]),
            "speed": _normalize_speed(row["speed"]),
            "media_type": row["media_type"].strip().lower(),
            "arp_type": arp_types.get(name, ""),
            "ip_address": row["ip_address"],
        })


def _parse_key_value_blocks(output: str, first_key: str) -> list[dict[str, str]]:
    """Parse output made of "Key: Value" lines, with a new block starting at first_key.
    Indented lines continue the previous value (IOS wraps long VLAN lists that way)."""
    blocks: list[dict[str, str]] = []
    last_key = None
    for line in output.splitlines():
        if line.startswith((" ", "\t")) and last_key and blocks:
            blocks[-1][last_key] += line.strip()  # continuation of a wrapped value
            continue
        key, sep, value = line.partition(":")  # partition splits on the FIRST ":" only
        if not sep:
            last_key = None
            continue
        key = key.strip()
        if key == first_key:
            blocks.append({})
        if blocks:
            blocks[-1][key] = value.strip()
            last_key = key
    return blocks


def _leading_int(text: str) -> int | None:
    """"99 (VLAN0099)" -> 99, "1 (default)" -> 1, "" -> None."""
    match = re.match(r"\d+", text)  # re.match only matches at the START of the string
    return int(match.group()) if match else None


# What parse_switchport() reads from each port's block of "show interfaces switchport":
# (key as IOS prints it, InterfaceState field to set, function turning the raw text into the value).
# A missing key reads as "" - routed ports only print "Name" and "Switchport: Disabled".
# str.lower is passed as a function without calling it (no "()"): str.lower("ON") == "on".
_SWITCHPORT_FIELDS: list[tuple[str, str, Callable[[str], object]]] = [
    ("Switchport", "switchport", lambda v: v.lower() == "enabled"),
    ("Administrative Mode", "admin_mode", str.lower),  # what's configured: "dynamic auto"...
    ("Operational Mode", "oper_mode", str.lower),  # what the port does now: "trunk", "down"...
    ("Trunking Native Mode VLAN", "native_vlan", _leading_int),
    # "enabled"/"disabled"; None if this IOS doesn't print the line - unknown is not "disabled"
    ("Administrative Native VLAN tagging", "native_vlan_tagged", lambda v: v.lower() == "enabled" if v else None),
    ("Access Mode VLAN", "access_vlan", _leading_int),
    ("Trunking VLANs Enabled", "allowed_vlans", lambda v: v),  # kept as text: "ALL", "10,20,99"
    ("Negotiation of Trunking", "dtp", lambda v: v.lower() == "on"),
    ("Administrative Trunking Encapsulation", "trunk_encapsulation", str.lower),
]


def parse_switchport(interfaces: dict[str, InterfaceState], output: str) -> None:
    """"show interfaces switchport": the fields in _SWITCHPORT_FIELDS for every port.

    Parsed by hand instead of with ntc-templates: its template drops VLANs when a long
    "Trunking VLANs Enabled" list wraps onto the next line.
    """
    if _is_error(output):
        return
    for block in _parse_key_value_blocks(output, first_key="Name"):
        _set_fields(interfaces, normalize_interface(block["Name"]), {
            field_name: convert(block.get(key, "")) for key, field_name, convert in _SWITCHPORT_FIELDS
        })


_VLAN_LINE = re.compile(r"^(?P<id>\d+)\s+(?P<name>\S+)\s+(?:active|suspended|act/\S+)", re.M)


def parse_vlans(output: str) -> dict[int, str]:
    """"show vlan brief" -> {1: "default", 10: "USERS", ...}"""
    if _is_error(output):
        return {}
    return {int(m["id"]): m["name"] for m in _VLAN_LINE.finditer(output)}


# What parse_etherchannel() reads from each channel-group row (ntc-template keys). These are the
# same for every member port; the per-port status flags are added separately in the member loop.
_ETHERCHANNEL_FIELDS: list[tuple[str, str, Callable[[str], object]]] = [
    ("group", "channel_group", int),  # "1" -> 1
    ("bundle_protocol", "channel_protocol", str.strip),  # "LACP", "PAgP", "-" (= mode on)
]


def parse_etherchannel(interfaces: dict[str, InterfaceState], output: str) -> None:
    """"show etherchannel summary": which port-channel each member port belongs to
    (channel_group, channel_protocol, channel_member_flags). channel_mode comes from the config."""
    for row in _ntc("show etherchannel summary", output):
        # dict comprehension: {field name: converted value} for the whole channel group
        channel_values = {field_name: convert(row[key]) for key, field_name, convert in _ETHERCHANNEL_FIELDS}
        for member, flags in zip(row["member_interface"], row["member_interface_status"]):
            # zip() walks two lists side by side: (member1, flags1), (member2, flags2)...
            # {**a, "x": 1} = a copy of dict a plus one more key
            _set_fields(interfaces, normalize_interface(member), {
                **channel_values,
                "channel_member_flags": flags.strip(),  # per port: "P" bundled, "I" stand-alone...
            })


def parse_cdp_neighbors(output: str) -> list[CdpNeighbor]:
    return [
        CdpNeighbor(
            local_interface=normalize_interface(row["local_interface"]),
            device_id=row["neighbor_name"],
            remote_interface=normalize_interface(row["neighbor_interface"]),
            mgmt_ip=row["mgmt_address"],
            platform=row["platform"],
            capabilities=row["capabilities"],
        )
        for row in _ntc("show cdp neighbors detail", output)
    ]


def parse_ospf_neighbors(output: str) -> list[OspfNeighbor]:
    return [
        OspfNeighbor(
            neighbor_id=row["neighbor_id"],
            state=row["state"],
            address=row["ip_address"],
            interface=normalize_interface(row["interface"]),
        )
        for row in _ntc("show ip ospf neighbor", output)
    ]


# Lines we need from "show ip ospf interface". (?P<name>...) is a named group: match["name"]
_OSPF_HEADER = re.compile(r"^(?P<intf>\S+) is (?:up|down|administratively down), line protocol", re.M)
_OSPF_AREA = re.compile(r"Area (?P<area>[\d.]+)")
_OSPF_PROCESS = re.compile(r"Process ID (?P<pid>\d+),.*?Network Type (?P<type>\w+)")
_OSPF_TIMERS = re.compile(r"Hello (?P<hello>\d+), Dead (?P<dead>\d+)")


def parse_ospf_interfaces(output: str) -> dict[str, OspfInterface]:
    """Parse "show ip ospf interface" (the full version, not "brief").

    The output is one block per interface, each starting with "<name> is up, line protocol...".
    We cut the text into those blocks and pick the values out of each.
    """
    if _is_error(output):
        return {}
    result: dict[str, OspfInterface] = {}
    headers = list(_OSPF_HEADER.finditer(output))
    for i, header in enumerate(headers):
        end = headers[i + 1].start() if i + 1 < len(headers) else len(output)
        block = output[header.start():end]
        area, process, timers = _OSPF_AREA.search(block), _OSPF_PROCESS.search(block), _OSPF_TIMERS.search(block)
        if not (area and process):
            continue
        name = normalize_interface(header["intf"])
        result[name] = OspfInterface(
            name=name,
            process_id=int(process["pid"]),
            area=_ospf_area(area["area"]),
            network_type=process["type"],
            hello=int(timers["hello"]) if timers else None,
            dead=int(timers["dead"]) if timers else None,
            passive="Passive interface" in block,
        )
    return result


# ---------------------------------------------------------------- running-config


def config_sections(config: str, prefix: str) -> dict[str, list[str]]:
    """{"line vty 0 4": ["logging synchronous", ...], ...} for every section whose header starts
    with prefix. In IOS config, a section starts at a line without indentation and its settings
    are the indented lines below it."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in config.splitlines():
        if line.startswith(prefix):
            current = sections.setdefault(line.strip(), [])
        elif line.startswith(" ") and current is not None:
            current.append(line.strip())
        else:
            current = None  # any other top-level line ends the section
    return sections


def config_interface_sections(config: str) -> dict[str, list[str]]:
    """{"Ethernet0/1": ["switchport mode trunk", ...], ...} from the running-config."""
    return {normalize_interface(header.split(None, 1)[1]): lines
            for header, lines in config_sections(config, "interface ").items()}


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _global_lines(config: str) -> list[str]:
    """Top-level config lines (not indented)."""
    return [line.strip() for line in config.splitlines() if line and not line.startswith((" ", "!"))]


def parse_management_config(config: str) -> ManagementConfig:
    result = ManagementConfig()
    for line in _global_lines(config):
        if match := re.fullmatch(r"hostname (\S+)", line):
            result.hostname = match.group(1)
        elif match := re.fullmatch(r"(ip domain[ -]name) (\S+)", line):  # both syntaxes exist
            result.domain_command, result.domain_name = match.group(1), match.group(2)
        elif match := re.match(r"ntp server (?:vrf \S+ )?(\S+)", line):
            result.ntp_servers.append(match.group(1))
        elif match := re.match(r"logging host (?:ipv6 )?(\S+)", line):
            result.logging_hosts.append(match.group(1))
        elif (match := re.fullmatch(r"logging (\S+)", line)) and _is_ip(match.group(1)):
            # old syntax "logging 10.0.0.5" - only if it's an address, not "logging buffered"
            result.logging_hosts.append(match.group(1))
        elif line.startswith("ip ssh rsa keypair-name "):
            result.ssh_keypair_pinned = True
    for header, lines in config_sections(config, "line ").items():
        if header.startswith(("line con", "line vty")) and "logging synchronous" not in lines:
            result.lines_without_logging_sync.append(header)
    return result


def parse_l2security_config(config: str) -> L2SecurityConfig:
    result = L2SecurityConfig()
    for line in _global_lines(config):
        if re.fullmatch(r"spanning-tree portfast (edge )?default", line):
            result.portfast_default = True
        elif re.fullmatch(r"spanning-tree portfast (edge )?bpduguard default", line):
            result.bpduguard_default = True
        elif line == "ip dhcp snooping":
            result.dhcp_snooping = True
        elif match := re.fullmatch(r"ip dhcp snooping vlan (\S+)", line):
            result.dhcp_snooping_vlans = match.group(1)
        elif line == "no ip dhcp snooping information option":
            result.option82 = False
        elif match := re.fullmatch(r"ip arp inspection vlan (\S+)", line):
            result.dai_vlans = match.group(1)
        elif match := re.fullmatch(r"ip arp inspection validate (.+)", line):
            result.dai_validate = match.group(1).split()
        elif match := re.fullmatch(r"errdisable recovery cause (\S+)", line):
            result.errdisable_causes.append(match.group(1))
        elif match := re.fullmatch(r"errdisable recovery interval (\d+)", line):
            result.errdisable_interval = int(match.group(1))
    return result


# "aa:bb:cc:dd:ee:ff  10.10.10.5  86000  dhcp-snooping  10  Ethernet1/0" - last column = port
_BINDING = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\s+\S+\s+\d+\s+\S+\s+\d+\s+(\S+)", re.M)


def parse_dhcp_bindings(output: str) -> set[str]:
    """Ports that have at least one DHCP snooping binding."""
    return {normalize_interface(m.group(1)) for m in _BINDING.finditer(output)}


def parse_ntp_status(output: str) -> NtpStatus | None:
    """"Clock is synchronized, stratum 3, reference is 10.0.0.1" ... None if NTP isn't running
    ("%NTP is not enabled.")."""
    if _is_error(output) or "Clock is" not in output:
        return None
    stratum = re.search(r"stratum (\d+)", output)
    reference = re.search(r"reference is (\S+)", output)
    offset = re.search(r"clock offset is (-?[\d.]+) msec", output)
    return NtpStatus(
        synchronized="Clock is synchronized" in output,
        stratum=int(stratum.group(1)) if stratum else None,
        reference=reference.group(1) if reference else "",
        offset_ms=float(offset.group(1)) if offset else None,
    )


def parse_rsa_key_name(output: str) -> str:
    """The first key pair that isn't the temporary "...server" key. Note: this output starts with
    "% Key pair was generated at...", which is NOT an error - so no _is_error() check here."""
    names = re.findall(r"^Key name: (\S+)", output, re.M)
    return next((n for n in names if not n.endswith(".server")), "")


def interface_ips(output: str) -> set[str]:
    return {row["ip_address"] for row in _ntc("show interfaces", output) if row["ip_address"]}


# What parse_interface_config() looks for inside each "interface ..." section of the running-config.
# One entry per setting: (regex the WHOLE line must match, InterfaceState field to set, value).
# The value is a function of the regex match - "lambda m: m.group(1)" is a tiny unnamed
# function (like a C++ lambda) returning the first (...) group; "lambda m: True" ignores it.
# Every entry is checked against every line, so one line can set several fields
# (channel-group). To support a new setting: add a field to InterfaceState and an entry here.
_CONFIG_FIELDS: list[tuple[re.Pattern[str], str, Callable[[re.Match[str]], object]]] = [
    (re.compile(r"channel-group (\d+) mode \S+"), "channel_group", lambda m: int(m.group(1))),
    (re.compile(r"channel-group \d+ mode (\S+)"), "channel_mode", lambda m: m.group(1)),
    (re.compile(r"speed (\S+)"), "configured_speed", lambda m: m.group(1)),
    (re.compile(r"duplex (\S+)"), "configured_duplex", lambda m: m.group(1)),
    (re.compile(r"(?:ipv6 ospf \d+ area|ospfv3 \d+ (?:ipv4|ipv6) area).*"), "ospfv3", lambda m: True),
    (re.compile(r"spanning-tree portfast(?: edge)?"), "portfast", lambda m: "enable"),
    (re.compile(r"spanning-tree portfast disable"), "portfast", lambda m: "disable"),
    (re.compile(r"spanning-tree bpduguard (enable|disable)"), "bpduguard", lambda m: m.group(1)),
    # Only the bare line turns it ON - "switchport port-security maximum 2" etc. don't match
    (re.compile(r"switchport port-security"), "port_security", lambda m: True),
    (re.compile(r"ip dhcp snooping trust"), "dhcp_trust", lambda m: True),
    (re.compile(r"ip dhcp snooping limit rate (\d+)"), "dhcp_rate", lambda m: int(m.group(1))),
    (re.compile(r"ip arp inspection trust"), "dai_trust", lambda m: True),
    (re.compile(r"ip arp inspection limit rate (\d+).*"), "dai_rate", lambda m: int(m.group(1))),
]


def parse_interface_config(interfaces: dict[str, InterfaceState], config: str) -> None:
    """Settings that only the running-config shows, per interface section: the fields in
    _CONFIG_FIELDS (channel_mode, configured speed/duplex, ospfv3, portfast, bpduguard,
    port_security, DHCP snooping and DAI trust/rate)."""
    for name, lines in config_interface_sections(config).items():
        fields: dict[str, object] = {}
        for line in lines:
            for pattern, field_name, value in _CONFIG_FIELDS:
                # ":=" is the "walrus" operator: assign AND test in one go, like
                # "if (auto m = ...; m)" in C++17
                if match := pattern.fullmatch(line):
                    fields[field_name] = value(match)
        _set_fields(interfaces, name, fields)  # also with no matches: every section gets an InterfaceState


def build_snapshot(host_ip: str, hostname: str, outputs: dict[str, str]) -> DeviceSnapshot:
    """Combine the output of all show commands (keyed by command) into one DeviceSnapshot."""
    config = outputs.get("show running-config", "")  # used by several parsers below
    snapshot = DeviceSnapshot(
        host_ip=host_ip,
        hostname=hostname,
        running_config=config,
        interfaces=parse_interfaces(outputs),  # the core: one InterfaceState per port. Fill out the InterfaceState structure.
        cdp_neighbors=parse_cdp_neighbors(outputs.get("show cdp neighbors detail", "")),
        ospf_interfaces=parse_ospf_interfaces(outputs.get("show ip ospf interface", "")),
        ospf_neighbors=parse_ospf_neighbors(outputs.get("show ip ospf neighbor", "")),
        vlans=parse_vlans(outputs.get("show vlan brief", "")),
        management=parse_management_config(config),
        l2security=parse_l2security_config(config),
        dhcp_binding_ports=parse_dhcp_bindings(outputs.get("show ip dhcp snooping binding", "")),
        ntp=parse_ntp_status(outputs.get("show ntp status", "")),
        rsa_key_name=parse_rsa_key_name(outputs.get("show crypto key mypubkey rsa", "")),
        ip_addresses=interface_ips(outputs.get("show interfaces", "")) | {host_ip},
    )
    if _is_error(outputs.get("show cdp neighbors detail", "")):
        snapshot.notes.append("CDP is not enabled - links from this device can't be checked")
    return snapshot
