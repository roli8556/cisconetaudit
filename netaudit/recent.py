"""
Recently used projects, so you can pick one from a list instead of typing its path.

Stored per Windows user in %APPDATA%\\netaudit\\recent_projects.json (~/.config/netaudit on
Linux/macOS). Only the folder path, the project name and when it was last opened are stored -
nothing secret: credentials stay inside each project's encrypted hosts.enc.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

MAX_ENTRIES = 10


@dataclass
class RecentProject:
    path: str  # stored as text - json can't store Path objects
    name: str
    last_opened: str  # ISO date/time, e.g. "2026-11-17T12:00:00"

    @property
    def exists(self) -> bool:
        return Path(self.path).is_dir()


def default_file() -> Path:
    """%APPDATA% on Windows; ~/.config elsewhere."""
    base = os.environ.get("APPDATA") or Path.home() / ".config"
    return Path(base) / "netaudit" / "recent_projects.json"


class RecentProjects:
    def __init__(self, file: Path) -> None:
        """file is a parameter (not hard-coded) so tests can use a temporary file."""
        self.file = file
        self.entries: list[RecentProject] = self._read()

    def _read(self) -> list[RecentProject]:
        try:
            data = json.loads(self.file.read_text(encoding="utf-8"))
            return [RecentProject(**item) for item in data]
        except (OSError, ValueError, TypeError):
            # Missing or damaged file: start with an empty list rather than refusing to start.
            # (json.JSONDecodeError is a subclass of ValueError, so it's covered.)
            return []

    def _write(self) -> None:
        self.file.parent.mkdir(parents=True, exist_ok=True)  # exist_ok: no error if it's there
        self.file.write_text(json.dumps([asdict(e) for e in self.entries], indent=2), encoding="utf-8")

    def remember(self, path: Path, name: str) -> None:
        """Put a project at the top of the list (moving it there if it's already listed)."""
        path_text = str(path.resolve())
        self.entries = [e for e in self.entries if os.path.normcase(e.path) != os.path.normcase(path_text)]
        # normcase: Windows paths are case-insensitive, so C:\\Lab and c:\\lab are the same folder
        self.entries.insert(0, RecentProject(path_text, name, datetime.now().isoformat(timespec="seconds")))
        del self.entries[MAX_ENTRIES:]  # keep only the newest MAX_ENTRIES
        self._write()

    def forget(self, entry: RecentProject) -> None:
        """Remove one entry. Missing folders are NOT removed automatically: a project on a USB
        stick or network share is only "missing" until it's connected again."""
        self.entries.remove(entry)
        self._write()
