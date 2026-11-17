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

from ntc_templates.parse import parse_output

from ..models import (
    CdpNeighbor,
    DeviceSnapshot,
    InterfaceState,
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


def parse_show_interfaces(output: str) -> dict[str, InterfaceState]:
    interfaces: dict[str, InterfaceState] = {}
    for row in _ntc("show interfaces", output):
        name = normalize_interface(row["interface"])
        interfaces[name] = InterfaceState(
            name=name,
            status=row["link_status"].strip().lower(),
            protocol=row["protocol_status"].strip().lower().split()[0] if row["protocol_status"] else "",
            mtu=int(row["mtu"]) if row["mtu"] else None,
            duplex=_normalize_duplex(row["duplex"]),
            speed=_normalize_speed(row["speed"]),
        )
    return interfaces


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


def apply_switchport(interfaces: dict[str, InterfaceState], output: str) -> None:
    """Add "show interfaces switchport" data to the interfaces (modifies them in place).

    Parsed by hand instead of with ntc-templates: its template drops VLANs when a long
    "Trunking VLANs Enabled" list wraps onto the next line.
    """
    if _is_error(output):
        return
    for block in _parse_key_value_blocks(output, first_key="Name"):
        name = normalize_interface(block["Name"])
        intf = interfaces.setdefault(name, InterfaceState(name=name))  # get, or insert new
        intf.switchport = block.get("Switchport", "").lower() == "enabled"
        intf.admin_mode = block.get("Administrative Mode", "").lower()
        intf.oper_mode = block.get("Operational Mode", "").lower()
        native = re.match(r"\d+", block.get("Trunking Native Mode VLAN", ""))
        intf.native_vlan = int(native.group()) if native else None
        access = re.match(r"\d+", block.get("Access Mode VLAN", ""))
        intf.access_vlan = int(access.group()) if access else None
        intf.allowed_vlans = block.get("Trunking VLANs Enabled", "")
        intf.dtp = block.get("Negotiation of Trunking", "").lower() == "on"
        intf.trunk_encapsulation = block.get("Administrative Trunking Encapsulation", "").lower()


_VLAN_LINE = re.compile(r"^(?P<id>\d+)\s+(?P<name>\S+)\s+(?:active|suspended|act/\S+)", re.M)


def parse_vlans(output: str) -> dict[int, str]:
    """"show vlan brief" -> {1: "default", 10: "USERS", ...}"""
    if _is_error(output):
        return {}
    return {int(m["id"]): m["name"] for m in _VLAN_LINE.finditer(output)}


def apply_etherchannel(interfaces: dict[str, InterfaceState], output: str) -> None:
    """Add "show etherchannel summary" data: which port-channel each member belongs to."""
    for row in _ntc("show etherchannel summary", output):
        group = int(row["group"])
        protocol = row["bundle_protocol"].strip()
        for member, flags in zip(row["member_interface"], row["member_interface_status"]):
            # zip() walks two lists side by side: (member1, flags1), (member2, flags2)...
            name = normalize_interface(member)
            intf = interfaces.setdefault(name, InterfaceState(name=name))
            intf.channel_group = group
            intf.channel_protocol = protocol
            intf.channel_member_flags = flags.strip()


def parse_cdp_neighbors(output: str) -> list[CdpNeighbor]:
    return [
        CdpNeighbor(
            local_interface=normalize_interface(row["local_interface"]),
            device_id=row["neighbor_name"],
            remote_interface=normalize_interface(row["neighbor_interface"]),
            mgmt_ip=row["mgmt_address"],
            platform=row["platform"],
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


def apply_config(interfaces: dict[str, InterfaceState], config: str) -> None:
    """Add settings that only the running-config shows (modifies interfaces in place)."""
    for name, lines in config_interface_sections(config).items():
        intf = interfaces.setdefault(name, InterfaceState(name=name))
        for line in lines:
            if match := re.fullmatch(r"channel-group (\d+) mode (\S+)", line):
                # ":=" is the "walrus" operator: assign AND test in one go, like
                # "if (auto m = ...; m)" in C++17
                intf.channel_group = intf.channel_group or int(match.group(1))
                intf.channel_mode = match.group(2)
            elif match := re.fullmatch(r"speed (\S+)", line):
                intf.configured_speed = match.group(1)
            elif match := re.fullmatch(r"duplex (\S+)", line):
                intf.configured_duplex = match.group(1)
            elif re.match(r"(ipv6 ospf \d+ area|ospfv3 \d+ (ipv4|ipv6) area)", line):
                intf.ospfv3 = True


def build_snapshot(host_ip: str, hostname: str, outputs: dict[str, str]) -> DeviceSnapshot:
    """Combine the output of all show commands (keyed by command) into one DeviceSnapshot."""
    interfaces = parse_show_interfaces(outputs.get("show interfaces", ""))
    apply_switchport(interfaces, outputs.get("show interfaces switchport", ""))
    apply_etherchannel(interfaces, outputs.get("show etherchannel summary", ""))
    config = outputs.get("show running-config", "")
    apply_config(interfaces, config)

    snapshot = DeviceSnapshot(
        host_ip=host_ip,
        hostname=hostname,
        running_config=config,
        interfaces=interfaces,
        cdp_neighbors=parse_cdp_neighbors(outputs.get("show cdp neighbors detail", "")),
        ospf_interfaces=parse_ospf_interfaces(outputs.get("show ip ospf interface", "")),
        ospf_neighbors=parse_ospf_neighbors(outputs.get("show ip ospf neighbor", "")),
        vlans=parse_vlans(outputs.get("show vlan brief", "")),
        management=parse_management_config(config),
        ntp=parse_ntp_status(outputs.get("show ntp status", "")),
        rsa_key_name=parse_rsa_key_name(outputs.get("show crypto key mypubkey rsa", "")),
        ip_addresses=interface_ips(outputs.get("show interfaces", "")) | {host_ip},
    )
    if _is_error(outputs.get("show cdp neighbors detail", "")):
        snapshot.notes.append("CDP is not enabled - links from this device can't be checked")
    return snapshot
