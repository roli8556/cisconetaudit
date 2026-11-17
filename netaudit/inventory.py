"""
Inventory: the list of devices (hosts) in a project.

hosts.txt format, one device per line:
    name,ip,username

    SW1,192.168.100.11,admin
    SW2,192.168.100.12,admin

Lines starting with # and empty lines are ignored.
Passwords are deliberately NOT stored here (see README / threat model).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Host:
    """One network device. frozen=True makes it immutable, like a const object in C++."""

    name: str
    ip: str
    username: str


class InventoryError(Exception):
    """Raised when hosts.txt contains lines that can't be parsed."""


def load_hosts(path: Path) -> list[Host]:
    """Read hosts.txt and return a list of Host objects.

    Collects every problem in the file before raising, so the user can fix
    them all in one go instead of one error at a time.
    """
    hosts: list[Host] = []
    errors: list[str] = []
    seen_names: set[str] = set()

    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 3:
            errors.append(f"line {line_no}: expected 'name,ip,username', got '{line}'")
            continue

        name, ip, username = parts

        try:
            ipaddress.ip_address(ip)  # validates both IPv4 and IPv6
        except ValueError:
            errors.append(f"line {line_no}: '{ip}' is not a valid IP address")
            continue

        if not name or not username:
            errors.append(f"line {line_no}: name and username can't be empty")
            continue

        if name in seen_names:
            errors.append(f"line {line_no}: duplicate host name '{name}'")
            continue

        seen_names.add(name)
        hosts.append(Host(name=name, ip=ip, username=username))

    if errors:
        raise InventoryError("Problems in hosts.txt:\n  " + "\n  ".join(errors))

    return hosts
