"""
Inventory: the list of devices (hosts) in a project.

Plaintext format, one device per line (this text only ever exists in memory - on disk it is
encrypted inside hosts.enc, see vault.py):

    ip username password [enable_password]

    192.168.100.11 admin S3cret
    192.168.100.12 admin S3cret En4bleSecret
    2001:db8::1    admin An0ther

Fields are separated by one or more spaces/tabs, so no field may contain a space.
The enable password is optional - leave it out if the account logs straight in at privilege 15.
Lines starting with # and empty lines are ignored.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Host:
    """One network device. frozen=True makes it immutable, like a const object in C++.

    repr=False keeps the passwords out of print(host) / log output / tracebacks.
    """

    ip: str
    username: str
    password: str = field(repr=False)
    # "str | None" = may be missing, like std::optional<std::string> in C++
    enable_password: str | None = field(default=None, repr=False)


class InventoryError(Exception):
    """Raised when the host list contains lines that can't be parsed."""


def _has_space(value: str) -> bool:
    return any(c.isspace() for c in value)


def validate_host(ip: str, username: str, password: str, enable_password: str | None = None) -> str | None:
    """Return an error message, or None if the fields are OK. Shared by the parser and the
    'add host' menu so both follow exactly the same rules."""
    try:
        ipaddress.ip_address(ip)  # accepts both IPv4 and IPv6
    except ValueError:
        return f"'{ip}' is not a valid IP address"
    if not username or not password:
        return "username and password can't be empty"
    if _has_space(username) or _has_space(password) or (enable_password and _has_space(enable_password)):
        return "username and passwords can't contain spaces"
    return None


def parse_hosts(text: str) -> list[Host]:
    """Parse the plaintext host list and return Host objects.

    Collects every problem before raising, so the user can fix them all in one go.
    Error messages never include the line itself - it contains passwords.
    """
    hosts: list[Host] = []
    errors: list[str] = []
    seen_ips: set[str] = set()

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()  # no argument = split on any run of spaces/tabs
        if len(parts) not in (3, 4):
            errors.append(f"line {line_no}: expected 'ip username password [enable_password]'")
            continue

        # parts[3] if it exists, else None. Python's ternary reads "A if cond else B".
        ip, username, password = parts[:3]
        enable_password = parts[3] if len(parts) == 4 else None

        error = validate_host(ip, username, password, enable_password)
        if error:
            errors.append(f"line {line_no}: {error}")
            continue
        if ip in seen_ips:
            errors.append(f"line {line_no}: duplicate host {ip}")
            continue

        seen_ips.add(ip)
        hosts.append(Host(ip, username, password, enable_password))

    if errors:
        raise InventoryError("Problems in host list:\n  " + "\n  ".join(errors))

    return hosts


def format_hosts(hosts: list[Host]) -> str:
    """The reverse of parse_hosts(): turn Host objects back into text for encryption."""
    lines = []
    for h in hosts:
        fields = [h.ip, h.username, h.password]
        if h.enable_password:
            fields.append(h.enable_password)
        lines.append(" ".join(fields) + "\n")
    return "".join(lines)
