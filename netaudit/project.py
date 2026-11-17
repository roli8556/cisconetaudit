"""
Project: a folder holding everything for one network you audit.

    projects/<name>/
        config.json     settings for this project (collection method etc.)
        hosts.txt       the devices to audit
        project.log     everything the tool has done in this project
        scans/          saved scan results
        configs/        saved device configurations
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .inventory import Host, load_hosts

CONFIG_FILE = "config.json"
HOSTS_FILE = "hosts.txt"
LOG_FILE = "project.log"
SUBFOLDERS = ("scans", "configs")
VALID_METHODS = ("ssh", "snmp")

HOSTS_TEMPLATE = """\
# One device per line: name,ip,username
# Passwords are NOT stored here - you'll be asked for them when connecting.
#
# Example:
# SW1,192.168.100.11,admin
"""


class ProjectError(Exception):
    """Raised when a project can't be created or loaded."""


@dataclass
class ProjectConfig:
    """The contents of config.json. A dataclass auto-generates __init__ etc."""

    name: str
    collection_method: str = "ssh"
    created: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    ssh_port: int = 22
    ssh_timeout: int = 10
    snmp_port: int = 161
    snmp_version: str = "3"

    def validate(self) -> None:
        if self.collection_method not in VALID_METHODS:
            raise ProjectError(
                f"collection_method must be one of {VALID_METHODS}, got '{self.collection_method}'"
            )

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=4), encoding="utf-8")

    @classmethod
    def from_file(cls, path: Path) -> "ProjectConfig":
        """Alternative constructor - like a static factory method in C++."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            config = cls(**data)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProjectError(f"config.json is invalid: {exc}") from exc
        config.validate()
        return config


class Project:
    """A loaded project. Create one with Project.create() or Project.load()."""

    def __init__(self, path: Path, config: ProjectConfig) -> None:
        self.path = path
        self.config = config
        self.hosts: list[Host] = []
        self.log = self._setup_logger()

    # ---------- the two ways to get a Project ----------

    @classmethod
    def create(cls, base_dir: Path, name: str, method: str = "ssh") -> "Project":
        """Create a new project folder with all required files."""
        path = base_dir / name
        if path.exists():
            raise ProjectError(f"A project already exists at {path}")

        config = ProjectConfig(name=name, collection_method=method)
        config.validate()

        path.mkdir(parents=True)
        for folder in SUBFOLDERS:
            (path / folder).mkdir()
        (path / HOSTS_FILE).write_text(HOSTS_TEMPLATE, encoding="utf-8")
        config.save(path / CONFIG_FILE)

        project = cls(path, config)
        project.log.info("Project created (method: %s)", method)
        return project

    @classmethod
    def load(cls, path: Path) -> "Project":
        """Load an existing project, checking that everything is in place."""
        missing = cls.check_structure(path)
        if missing:
            raise ProjectError(
                f"{path} is not a complete project. Missing: {', '.join(missing)}"
            )

        config = ProjectConfig.from_file(path / CONFIG_FILE)
        project = cls(path, config)
        project.hosts = load_hosts(path / HOSTS_FILE)
        project.log.info("Project loaded with %d host(s)", len(project.hosts))
        return project

    # ---------- helpers ----------

    @staticmethod
    def check_structure(path: Path) -> list[str]:
        """Return a list of required files/folders that are missing (empty = OK)."""
        if not path.is_dir():
            return [str(path)]
        required_files = [CONFIG_FILE, HOSTS_FILE]
        missing = [f for f in required_files if not (path / f).is_file()]
        missing += [d + "/" for d in SUBFOLDERS if not (path / d).is_dir()]
        return missing

    def _setup_logger(self) -> logging.Logger:
        """Each project gets its own logger writing to its own project.log."""
        logger = logging.getLogger(f"netaudit.{self.config.name}")
        logger.setLevel(logging.INFO)
        logger.handlers.clear()  # avoid duplicate lines if the project is reloaded
        handler = logging.FileHandler(self.path / LOG_FILE, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s"))
        logger.addHandler(handler)
        return logger

    def __repr__(self) -> str:
        return f"Project(name={self.config.name!r}, method={self.config.collection_method!r}, hosts={len(self.hosts)})"
