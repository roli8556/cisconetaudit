"""
The common data model: what collectors produce and what the rest of netaudit consumes.

Collectors (SSH now, maybe Catalyst Center API later) all return these objects, so storage and
audit code never need to know how the data was fetched.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class RunningConfig:
    """A running-config as collected from one device."""

    host_ip: str
    hostname: str
    text: str
    collected_at: datetime = field(default_factory=datetime.now)
