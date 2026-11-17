"""
Fixes that need a value from the user: check the value, then build the commands.

Each kind of FixInput has two functions:
    _validate_<kind>(fix_input, value) -> error message, or None if the value is OK
    _build_<kind>(fix_input, value)    -> list of Fix (commands per device)

resolve() picks the right pair through a dict - a "dispatch table", the same idea as the menus
in main.py. Everything here is pure (no device access, no input()), so it's easy to test.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from collections import defaultdict

from ..models import Finding, Fix, FixInput, FixTarget
from ..parsers.ios import format_vlan_list, parse_vlan_list

# VLANs 1002-1005 are reserved for old FDDI/Token Ring; 1 is what we're moving away from.
RESERVED_VLANS = {1, 1002, 1003, 1004, 1005}


def _per_device(targets: list[FixTarget]) -> dict[str, list[FixTarget]]:
    """Group targets by device, keeping their order."""
    grouped: dict[str, list[FixTarget]] = defaultdict(list)
    for target in targets:
        grouped[target.host_ip].append(target)
    return grouped


def _fix(targets: list[FixTarget], commands: list[str]) -> Fix:
    return Fix(targets[0].host_ip, targets[0].hostname, commands)


# ---------------------------------------------------------------- native VLAN


def _validate_native_vlan(fix_input: FixInput, value: str) -> str | None:
    if not value.isdigit() or not 1 <= int(value) <= 4094:
        return "enter a VLAN number between 2 and 4094"
    if int(value) in RESERVED_VLANS:
        return f"VLAN {value} is reserved / the default - pick an unused VLAN"
    return None


def _warn_native_vlan(fix_input: FixInput, value: str) -> str | None:
    hosts = [t.hostname for t in fix_input.targets if value in t.params.get("access_vlans", "").split(",")]
    if hosts:
        return (f"VLAN {value} is the access VLAN of active ports on {', '.join(hosts)} - untagged traffic "
                "on this trunk would end up among those hosts. A dedicated, unused VLAN is safer")
    return None


def _build_native_vlan(fix_input: FixInput, value: str) -> list[Fix]:
    return [
        _fix([t], [f"interface {t.interface}", f"switchport trunk native vlan {value}"])
        for t in fix_input.targets
    ]


# ---------------------------------------------------------------- allowed VLANs

_VLAN_LIST = re.compile(r"\d+(-\d+)?(,\d+(-\d+)?)*")


def _validate_allowed_vlans(fix_input: FixInput, value: str) -> str | None:
    value = value.replace(" ", "").lower()
    if value in ("all", "none"):
        return None
    if not _VLAN_LIST.fullmatch(value):
        return "use a VLAN list like 10,20,30-35 (or 'all' / 'none')"
    for part in value.split(","):
        low, _, high = part.partition("-")
        if not 1 <= int(low) <= 4094 or (high and not int(low) <= int(high) <= 4094):
            return f"'{part}' is not a valid VLAN range (1-4094)"
    return None


def _warn_allowed_vlans(fix_input: FixInput, value: str) -> str | None:
    """The default is what crosses the trunk today - warn if the new list drops any of it."""
    value = value.replace(" ", "").lower()
    if value == "all":
        return None
    working = parse_vlan_list(fix_input.default) if fix_input.default != "none" else set()
    cut = working - (parse_vlan_list(value) if value != "none" else set())
    if cut:
        return (f"VLAN(s) {format_vlan_list(cut)} pass this trunk today and would be CUT OFF "
                "(check that none of them is your management VLAN)")
    return None


def _build_allowed_vlans(fix_input: FixInput, value: str) -> list[Fix]:
    value = value.replace(" ", "").lower()
    if value not in ("all", "none"):
        value = format_vlan_list(parse_vlan_list(value))  # normalize: "10,11,12" -> "10-12"
    return [
        _fix([t], [f"interface {t.interface}", f"switchport trunk allowed vlan {value}"])
        for t in fix_input.targets
    ]


# ---------------------------------------------------------------- OSPF timers


def _validate_ospf_timers(fix_input: FixInput, value: str) -> str | None:
    if value.lower() == "default":
        return None
    match = re.fullmatch(r"(\d+)\s*/\s*(\d+)", value)
    if not match:
        return "type 'default', or hello/dead in seconds like 5/20"
    hello, dead = int(match[1]), int(match[2])
    if not (1 <= hello <= 65535 and 1 <= dead <= 65535):
        return "timers must be between 1 and 65535 seconds"
    if dead <= hello:
        return "the dead interval must be longer than the hello interval (usually 4x)"
    return None


def _build_ospf_timers(fix_input: FixInput, value: str) -> list[Fix]:
    if value.lower() == "default":
        timer_commands = ["no ip ospf hello-interval", "no ip ospf dead-interval"]
    else:
        hello, dead = (int(x) for x in value.replace(" ", "").split("/"))
        timer_commands = [f"ip ospf hello-interval {hello}", f"ip ospf dead-interval {dead}"]
    return [_fix([t], [f"interface {t.interface}", *timer_commands]) for t in fix_input.targets]
    # *timer_commands "unpacks" the list into this one: [a, *[b, c]] == [a, b, c]


# ---------------------------------------------------------------- port-channel number
#
# Targets for a channel-group fix, per device (see baseline.channel_group_targets):
#   role=device        params: used_groups "1,2,5" (every channel-group on that device)
#   role=port-channel  params: group, config (the Po's config lines), all_moved "yes"/"no"
#   role=member        params: group, mode   (one member interface of the bundle)


def _validate_channel_group(fix_input: FixInput, value: str) -> str | None:
    if not value.isdigit() or not 1 <= int(value) <= 4096:
        return "enter a port-channel number"
    number = int(value)
    for host_ip, targets in _per_device(fix_input.targets).items():
        involved = {int(t.params["group"]) for t in targets if t.params["role"] == "member"}
        used = {int(g) for t in targets if t.params["role"] == "device" for g in t.params["used_groups"].split(",") if g}
        if number in used - involved:
            return f"Po{number} is already used for something else on {targets[0].hostname}"
    return None


def _build_channel_group(fix_input: FixInput, value: str) -> list[Fix]:
    """Move every member that isn't in Po<value> yet into it, on each device.

    Order matters on a real switch: first create the new port-channel with the old one's
    settings (trunk mode, VLANs...), then move the members, then delete port-channels that
    are now empty.
    """
    number = int(value)
    fixes = []
    for host_ip, targets in _per_device(fix_input.targets).items():
        members = [t for t in targets if t.params["role"] == "member" and int(t.params["group"]) != number]
        if not members:
            continue  # this device already uses the chosen number
        channels = [t for t in targets if t.params["role"] == "port-channel"]
        commands: list[str] = []
        if not any(int(c.params["group"]) == number for c in channels):
            template = channels[0].params["config"].splitlines() if channels else []
            commands += [f"interface Port-channel{number}", *template]
        for member in members:
            commands += [
                f"interface {member.interface}",
                "no channel-group",
                f"channel-group {number} mode {member.params['mode']}",
            ]
        for channel in channels:
            if int(channel.params["group"]) != number and channel.params["all_moved"] == "yes":
                commands.append(f"no interface Port-channel{channel.params['group']}")
        fixes.append(_fix(targets, commands))
    return fixes


# ---------------------------------------------------------------- parking VLAN for unused ports
#
# Targets (see baseline.check_unused_ports):
#   role=device  params: vlans "1=default,10=USERS" (existing VLANs), in_use "10,99" (on active ports)
#   role=port    one unused port


def _device_vlans(target: FixTarget) -> dict[int, str]:
    pairs = (item.split("=", 1) for item in target.params["vlans"].split(",") if item)
    return {int(vid): name for vid, name in pairs}


def _validate_parking_vlan(fix_input: FixInput, value: str) -> str | None:
    error = _validate_native_vlan(fix_input, value)  # same rules: 2-4094, not reserved
    if error:
        return error
    for target in fix_input.targets:
        if target.params["role"] == "device" and value in target.params["in_use"].split(","):
            return f"VLAN {value} is used by active ports on {target.hostname} - a parking VLAN must be unused"
    return None


def _warn_parking_vlan(fix_input: FixInput, value: str) -> str | None:
    for target in fix_input.targets:
        if target.params["role"] == "device":
            name = _device_vlans(target).get(int(value))
            if name and not re.search(r"park|unused|black.?hole", name, re.I):
                return f"VLAN {value} already exists on {target.hostname} as '{name}' - is it really unused"
    return None


def _build_parking_vlan(fix_input: FixInput, value: str) -> list[Fix]:
    fixes = []
    for host_ip, targets in _per_device(fix_input.targets).items():
        device = next(t for t in targets if t.params["role"] == "device")
        commands = []
        if int(value) not in _device_vlans(device):
            # Create it explicitly: otherwise IOS creates it itself and prints "% Access VLAN does
            # not exist. Creating vlan ...", which would look like an error and trigger a rollback.
            commands += [f"vlan {value}", "name PARKING"]
        for port in (t for t in targets if t.params["role"] == "port"):
            commands += [
                f"interface {port.interface}",
                "shutdown",
                "switchport mode access",
                f"switchport access vlan {value}",
                "switchport nonegotiate",
            ]
        fixes.append(_fix(targets, commands))
    return fixes


# ---------------------------------------------------------------- hostname / domain name
#
# Targets (see scans/management.py device_target): one per device, params:
#   rsa_key  name of the SSH key pair, e.g. "SW1.lab.local"
#   pinned   "yes" if "ip ssh rsa keypair-name" is already configured
#   + taken (hostname: other devices' names), current + command (domain name)


def pin_ssh_key(target: FixTarget) -> list[str]:
    """IOS uses the key pair named "<hostname>.<domain>" for SSH by default. Change either name
    and that key no longer matches - SSH can stop working (at once or after a reload), cutting
    off netaudit itself. Naming the current key explicitly keeps SSH on it."""
    if target.params.get("pinned") == "no" and target.params.get("rsa_key"):
        return [f"ip ssh rsa keypair-name {target.params['rsa_key']}"]
    return []


_HOST_LABEL = r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"  # one DNS label: letters, digits, "-"


def _validate_hostname(fix_input: FixInput, value: str) -> str | None:
    if not re.fullmatch(_HOST_LABEL, value) or not value[0].isalpha():
        return "use letters, digits and '-', starting with a letter (max 63 characters)"
    if value.lower() in ("router", "switch"):
        return "that's the IOS default - pick a name that identifies this device"
    taken = fix_input.targets[0].params.get("taken", "").lower().split(",")
    if value.lower() in taken:
        return f"another device in this project is already called {value}"
    return None


def _build_hostname(fix_input: FixInput, value: str) -> list[Fix]:
    target = fix_input.targets[0]
    return [_fix([target], [*pin_ssh_key(target), f"hostname {value}"])]


def _validate_domain_name(fix_input: FixInput, value: str) -> str | None:
    if len(value) > 253 or not re.fullmatch(rf"({_HOST_LABEL}\.)*{_HOST_LABEL}", value):
        return "use a domain like lab.local (letters, digits, '-' and dots)"
    return None


def _build_domain_name(fix_input: FixInput, value: str) -> list[Fix]:
    return [
        _fix([t], [*pin_ssh_key(t), f"{t.params['command']} {value}"])
        for t in fix_input.targets if t.params["current"] != value  # only devices that differ
    ]


# ---------------------------------------------------------------- NTP / syslog server


def _validate_server(fix_input: FixInput, value: str) -> str | None:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return "enter an IP address (a hostname would need working DNS on every device)"
    return None


def _build_ntp_server(fix_input: FixInput, value: str) -> list[Fix]:
    return [_fix([t], [f"ntp server {value}"]) for t in fix_input.targets]


def _build_syslog_server(fix_input: FixInput, value: str) -> list[Fix]:
    # "logging trap informational" = send severity 0-6 (everything except debug)
    return [_fix([t], [f"logging host {value}", "logging trap informational"]) for t in fix_input.targets]


# ---------------------------------------------------------------- dispatch

_HANDLERS = {
    "native-vlan": (_validate_native_vlan, _build_native_vlan),
    "allowed-vlans": (_validate_allowed_vlans, _build_allowed_vlans),
    "ospf-timers": (_validate_ospf_timers, _build_ospf_timers),
    "channel-group": (_validate_channel_group, _build_channel_group),
    "parking-vlan": (_validate_parking_vlan, _build_parking_vlan),
    "hostname": (_validate_hostname, _build_hostname),
    "domain-name": (_validate_domain_name, _build_domain_name),
    "ntp-server": (_validate_server, _build_ntp_server),
    "syslog-server": (_validate_server, _build_syslog_server),
}


def validate(fix_input: FixInput, value: str) -> str | None:
    validator, _ = _HANDLERS[fix_input.kind]
    return validator(fix_input, value.strip())


# Valid values that may still be a bad idea - the user is warned and asked to confirm.
_WARNINGS = {
    "native-vlan": _warn_native_vlan,
    "allowed-vlans": _warn_allowed_vlans,
    "parking-vlan": _warn_parking_vlan,
}


def warning(fix_input: FixInput, value: str) -> str | None:
    check = _WARNINGS.get(fix_input.kind)  # .get() returns None if this kind has no warning
    return check(fix_input, value.strip()) if check else None


def resolve(finding: Finding, value: str) -> Finding:
    """Return a copy of the finding with its fixes built from the user's value.

    dataclasses.replace() makes a copy with some fields changed - the original finding (which
    is also in the saved report) stays untouched.
    """
    assert finding.fix_input is not None
    _, builder = _HANDLERS[finding.fix_input.kind]
    fixes = builder(finding.fix_input, value.strip())
    return dataclasses.replace(finding, fixes=fixes, fix_input=None,
                               fix_description=f"{finding.fix_description} Chosen value: {value.strip()}")
