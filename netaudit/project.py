"""
Project: a folder holding everything for one network you audit.

    <any folder>/<name>/
        config.json     settings for this project (collection method etc.) - not secret
        hosts.enc       the devices to audit, with credentials - encrypted with the project password
        project.log     everything the tool has done in this project
        known_hosts     accepted SSH host keys (public keys - not secret)
        scans/          saved scan results
        configs/        saved device configurations (*.enc) - encrypted with the project password
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

from .inventory import Host, InventoryError, format_hosts, parse_hosts
from .models import RunningConfig
from .vault import Vault

CONFIG_FILE = "config.json"
HOSTS_FILE = "hosts.enc"
LOG_FILE = "project.log"
KNOWN_HOSTS_FILE = "known_hosts"  # created on first accepted SSH host key
SUBFOLDERS = ("scans", "configs")
VALID_METHODS = ("ssh", "snmp")
MIN_PASSWORD_LENGTH = 12


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

    def __init__(self, path: Path, config: ProjectConfig, vault: Vault) -> None:
        self.path = path
        self.config = config
        self.hosts: list[Host] = []
        self._vault = vault  # keeps the derived key so we can re-save without asking again
        self.log = self._setup_logger()

    # ---------- the two ways to get a Project ----------

    @classmethod
    def create(cls, base_dir: Path, name: str, password: str, method: str = "ssh") -> "Project":
        """Create a new project folder with all required files.

        password protects hosts.enc. It is never stored - forget it and the host list is gone.
        """
        path = base_dir / name
        if path.exists():
            raise ProjectError(f"A project already exists at {path}")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ProjectError(f"Project password must be at least {MIN_PASSWORD_LENGTH} characters")

        config = ProjectConfig(name=name, collection_method=method)
        config.validate()

        path.mkdir(parents=True)
        for folder in SUBFOLDERS:
            (path / folder).mkdir()
        config.save(path / CONFIG_FILE)

        project = cls(path, config, Vault.new(password))
        project.save_hosts()  # writes an empty, encrypted hosts.enc
        project.log.info("Project created (method: %s)", method)
        return project

    @classmethod
    def load(cls, path: Path, password: str) -> "Project":
        """Load an existing project, checking that everything is in place.

        Raises vault.WrongPasswordError if the password is wrong.
        """
        missing = cls.check_structure(path)
        if missing:
            raise ProjectError(
                f"{path} is not a complete project. Missing: {', '.join(missing)}"
            )

        config = ProjectConfig.from_file(path / CONFIG_FILE)
        vault, plaintext = Vault.unlock(path / HOSTS_FILE, password)
        project = cls(path, config, vault)
        project.hosts = parse_hosts(plaintext)
        project.log.info("Project loaded with %d host(s)", len(project.hosts))
        return project

    # ---------- managing hosts ----------

    def save_hosts(self) -> None:
        """Encrypt the current host list and write it to hosts.enc."""
        self._vault.write(self.path / HOSTS_FILE, format_hosts(self.hosts))

    def add_hosts(self, new_hosts: list[Host]) -> None:
        """Add hosts and save. All-or-nothing: if any IP already exists, nothing is added."""
        existing = {h.ip for h in self.hosts}  # set comprehension -> fast "in" lookups
        duplicates = [h.ip for h in new_hosts if h.ip in existing]
        if duplicates:
            raise InventoryError(f"Already in the project: {', '.join(duplicates)}")
        self.hosts.extend(new_hosts)
        self.save_hosts()
        for host in new_hosts:
            self.log.info("Host added: %s (user %s)", host.ip, host.username)  # never the password

    def remove_host(self, ip: str) -> None:
        remaining = [h for h in self.hosts if h.ip != ip]
        if len(remaining) == len(self.hosts):
            raise InventoryError(f"No host with IP {ip}")
        self.hosts = remaining
        self.save_hosts()
        self.log.info("Host removed: %s", ip)

    # ---------- device configs ----------

    def save_config(self, config: RunningConfig) -> Path:
        """Encrypt a running-config and store it as configs/<hostname>_<ip>_<timestamp>.enc.

        Encrypted because configs contain password hashes, SNMP communities, keys etc.
        The IP is part of the name because many devices share default hostnames ("Switch").
        Every fetch gets a new file, so old configs are kept for comparison.
        """
        stamp = config.collected_at.strftime("%Y-%m-%dT%H-%M-%S")  # no ":" - invalid on Windows
        # IPv6 has ":" too, and the hostname comes from the device - so whitelist the characters
        safe_ip = config.host_ip.replace(":", "-")
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", config.hostname) or "unknown"
        path = self.configs_dir / f"{safe_name}_{safe_ip}_{stamp}.enc"
        self._vault.write(path, config.text)
        self.log.info("Running-config saved: %s -> %s", config.host_ip, path.name)
        return path

    def list_configs(self) -> list[Path]:
        """All saved configs, sorted by name (= by hostname, then IP, then time)."""
        return sorted(self.configs_dir.glob("*.enc"))

    def read_config(self, path: Path) -> str:
        """Decrypt a saved config with the project key."""
        return self._vault.read(path)

    @property
    def configs_dir(self) -> Path:
        """@property makes this a method you use like an attribute: project.configs_dir
        (a read-only getter, without the () of a C++ getter)."""
        return self.path / "configs"

    @property
    def known_hosts_path(self) -> Path:
        return self.path / KNOWN_HOSTS_FILE

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
