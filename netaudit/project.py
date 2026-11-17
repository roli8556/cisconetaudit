"""
Project: a folder holding everything for one network you audit.

    <any folder>/<name>/
        config.json     settings for this project (SSH port/timeout, syslog server) - not secret
        hosts.enc       the devices to audit, with credentials - encrypted with the project password
        project.log.enc everything the tool has done in this project - encrypted line by line
        known_hosts     accepted SSH host keys (public keys - not secret)
        scans/          saved scan reports (*.enc) - encrypted JSON
        configs/        saved device configurations (*.enc) - encrypted with the project password
"""

from __future__ import annotations

import json
import logging
import logging.handlers  # the handlers (SysLogHandler...) are a separate module in the package
import os
import re
import socket
import sys
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from pathlib import Path

from .inventory import Host, InventoryError, format_hosts, parse_hosts
from .models import RunningConfig
from .scans.report import ScanReport
from .vault import Vault, VaultError

CONFIG_FILE = "config.json"
HOSTS_FILE = "hosts.enc"
LOG_FILE = "project.log.enc"  # one encrypted token per line, see EncryptedFileHandler
KNOWN_HOSTS_FILE = "known_hosts"  # created on first accepted SSH host key
SUBFOLDERS = ("scans", "configs")

# configs/<hostname>_<ip>_<timestamp>[_<n>].enc - see Project.save_config(). The hostname may
# contain "_", the IP never does (IPv6 colons become "-"), so the IP is the part before the time.
_CONFIG_NAME = re.compile(
    r"(?P<name>.+)_(?P<ip>[^_]+)_(?P<stamp>\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})(?:_(?P<n>\d+))?"
)


_NEW, _OLD = ".pwchange-new", ".pwchange-old"  # temporary suffixes while the password changes


def _staged(file: Path, suffix: str) -> Path:
    """hosts.enc -> hosts.enc.pwchange-new (same folder)."""
    return file.with_name(file.name + suffix)


def _unique_path(path: Path) -> Path:
    """path, or path with _2, _3... added if it already exists - two saves in the same second
    must never overwrite each other."""
    counter = 2
    candidate = path
    while candidate.exists():
        candidate = path.with_stem(f"{path.stem}_{counter}")
        counter += 1
    return candidate


class ProjectError(Exception):
    """Raised when a project can't be created or loaded."""


class EncryptedFileHandler(logging.Handler):
    """A logging handler that encrypts every log line separately before appending it.

    Logs can't be one big encrypted blob: they're appended to constantly, and re-encrypting the
    whole file per line would be slow and risky. One token per line means each line can be
    written (and later decrypted) on its own. What leaks: the number of lines and their rough
    length - not their content.

    Subclassing logging.Handler and overriding emit() is the standard way to send log records
    somewhere new - like overriding a virtual method in C++.
    """

    def __init__(self, path: Path, vault: Vault) -> None:
        super().__init__()  # call the base class constructor
        self.path = path
        self.vault = vault

    def emit(self, record: logging.LogRecord) -> None:
        try:
            token = self.vault.encrypt_line(self.format(record))
            with self.path.open("a", encoding="ascii") as file:  # "a" = append
                file.write(token + "\n")
        except Exception:
            self.handleError(record)  # logging must never crash the program


class QuietSysLogHandler(logging.handlers.SysLogHandler):
    """Python's SysLogHandler, but a failed send doesn't print a traceback into the menu.

    By default a broken handler prints "--- Logging error ---" plus a traceback to the console
    on EVERY log line - unusable when the syslog server is just down. Here the first error is
    remembered (shown in the settings menu) and the line is still in the encrypted local log.
    """

    def __init__(self, host: str, port: int, protocol: str, project_name: str) -> None:
        socktype = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        # The base class connects here for TCP - an unreachable server raises OSError right away.
        super().__init__(address=(host, port), facility=self.LOG_LOCAL0, socktype=socktype)
        self.last_error = ""
        # Python ends each message with a NUL byte by default (for very old daemons); modern
        # servers show it as "#000". Over TCP, servers split messages on newlines instead.
        self.append_nul = False
        end = "\n" if protocol == "tcp" else ""
        self.setFormatter(logging.Formatter(f"netaudit[{project_name}]: %(levelname)s %(message)s{end}"))

    def handleError(self, record: logging.LogRecord) -> None:
        # sys.exc_info() is "the exception being handled right now" - like std::current_exception
        self.last_error = str(sys.exc_info()[1])


@dataclass
class ProjectConfig:
    """The contents of config.json. A dataclass auto-generates __init__ etc."""

    name: str
    created: str = field(default_factory=lambda: datetime.now().isoformat(timespec="seconds"))
    ssh_port: int = 22
    ssh_timeout: int = 10
    syslog_host: str = ""  # "" = don't send the log to a syslog server
    syslog_port: int = 514
    syslog_protocol: str = "udp"  # "udp" or "tcp"

    def save(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), indent=4), encoding="utf-8")

    @classmethod
    def from_file(cls, path: Path) -> "ProjectConfig":
        """Alternative constructor - like a static factory method in C++.

        Settings this version doesn't know are ignored, so projects created by older versions
        (e.g. with "collection_method" / "snmp_port") still load.
        """
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            known = {f.name for f in fields(cls)}  # fields() lists a dataclass's fields
            return cls(**{key: value for key, value in data.items() if key in known})
        except (json.JSONDecodeError, TypeError, AttributeError) as exc:
            raise ProjectError(f"config.json is invalid: {exc}") from exc


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
    def create(cls, base_dir: Path, name: str, password: str) -> "Project":
        """Create a new project folder with all required files.

        password encrypts hosts.enc, the saved configs, scan reports and the log. It is never
        stored - forget it and all of that is unreadable.
        """
        path = base_dir / name
        if path.exists():
            raise ProjectError(f"A project already exists at {path}")

        config = ProjectConfig(name=name)

        path.mkdir(parents=True)
        for folder in SUBFOLDERS:
            (path / folder).mkdir()
        config.save(path / CONFIG_FILE)

        project = cls(path, config, Vault.new(password))
        project.save_hosts()  # writes an empty, encrypted hosts.enc
        project.log.info("Project created")
        return project

    @classmethod
    def load(cls, path: Path, password: str) -> "Project":
        """Load an existing project, checking that everything is in place.

        Raises vault.WrongPasswordError if the password is wrong.
        """
        cls.recover_password_change(path)  # must run first: it can restore hosts.enc
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
        path = _unique_path(self.configs_dir / f"{safe_name}_{safe_ip}_{stamp}.enc")
        self._vault.write(path, config.text)
        self.log.info("Running-config saved: %s -> %s", config.host_ip, path.name)
        return path

    def list_configs(self) -> list[Path]:
        """All saved configs, sorted by name (= by hostname, then IP, then time)."""
        return sorted(self.configs_dir.glob("*.enc"))

    def config_versions(self) -> dict[str, list[Path]]:
        """Saved configs per device: {ip: [oldest ... newest]}.

        Grouped by IP, not hostname: a renamed switch keeps its history. Files whose name
        doesn't follow the netaudit pattern are left out (and never deleted).
        """
        versions: dict[str, list[tuple[tuple, Path]]] = {}
        for path in self.configs_dir.glob("*.enc"):
            match = _CONFIG_NAME.fullmatch(path.stem)
            if match:
                # sort key: timestamp, then the _2/_3 counter for two saves in the same second
                order = (match["stamp"], int(match["n"] or 1))
                versions.setdefault(match["ip"], []).append((order, path))
        return {ip: [path for _, path in sorted(items)] for ip, items in sorted(versions.items())}

    def old_configs(self) -> list[Path]:
        """Every saved config except the newest one of each device."""
        return [path for paths in self.config_versions().values() for path in paths[:-1]]
        # paths[:-1] = all but the last element (a slice, like a sub-range in C++)

    def delete_configs(self, paths: list[Path]) -> None:
        for path in paths:
            path.unlink()  # unlink = delete a file
        self.log.info("Deleted %d old config(s): %s", len(paths), ", ".join(p.name for p in paths))

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

    def read_log(self) -> list[str]:
        """Decrypt project.log.enc line by line."""
        path = self.path / LOG_FILE
        if not path.is_file():
            return []
        lines = []
        for token in path.read_text(encoding="ascii").splitlines():
            try:
                lines.append(self._vault.decrypt_line(token))
            except VaultError:
                lines.append("[unreadable line - damaged, or written with another key]")
        return lines

    # ---------- scan reports ----------

    def save_scan(self, report: ScanReport) -> Path:
        """Store a scan report as encrypted JSON: scans/<type>_<timestamp>.enc"""
        stamp = report.started.strftime("%Y-%m-%dT%H-%M-%S")
        path = _unique_path(self.path / "scans" / f"{report.scan_type}_{stamp}.enc")
        self._vault.write(path, json.dumps(report.to_dict(), indent=2))
        self.log.info("Scan report saved: %s (%d findings)", path.name, len(report.findings))
        return path

    def list_scans(self) -> list[Path]:
        return sorted((self.path / "scans").glob("*.enc"))

    def read_scan(self, path: Path) -> ScanReport:
        return ScanReport.from_dict(json.loads(self._vault.read(path)))

    # ---------- changing the password ----------

    def check_password(self, password: str) -> bool:
        """Is this the project password? (Runs scrypt once - takes about half a second.)"""
        try:
            Vault.unlock(self.path / HOSTS_FILE, password)
            return True
        except VaultError:  # also catches WrongPasswordError, its subclass
            return False

    def change_password(self, current: str, new: str) -> int:
        """Re-encrypt every encrypted file with a key from the new password. Returns the number
        of files re-encrypted. Raises WrongPasswordError if current is wrong.

        Crash-safe in three phases (see recover_password_change for the other half):
          1. write every file re-encrypted as <file>.pwchange-new - originals untouched
          2. swap: <file> -> <file>.pwchange-old, <file>.pwchange-new -> <file>
          3. delete the .pwchange-old files
        """
        old_vault, _ = Vault.unlock(self.path / HOSTS_FILE, current)  # proves the current password
        new_vault = Vault.new(new)  # new random salt too
        log_file = self.path / LOG_FILE
        files = [self.path / HOSTS_FILE, *self.list_configs(), *self.list_scans()]

        # Phase 1: prepare. Any error -> remove what was prepared; nothing has changed.
        staged: list[Path] = []
        try:
            for file in files:
                new_vault.write(_staged(file, _NEW), old_vault.read(file))
                staged.append(file)
            if log_file.is_file():
                lines = []
                for token in log_file.read_text(encoding="ascii").splitlines():
                    try:
                        lines.append(new_vault.encrypt_line(old_vault.decrypt_line(token)))
                    except VaultError:
                        lines.append(token)  # already unreadable - keep it as it is
                _staged(log_file, _NEW).write_text("".join(line + "\n" for line in lines), encoding="ascii")
                staged.append(log_file)
        except Exception:
            for file in staged:
                _staged(file, _NEW).unlink(missing_ok=True)
            raise  # re-raise the same exception for the caller

        # Phase 2: swap (quick renames). Phase 3: clean up.
        for file in staged:
            os.replace(file, _staged(file, _OLD))
            os.replace(_staged(file, _NEW), file)
        for file in staged:
            _staged(file, _OLD).unlink()

        # From now on, everything (including new log lines) uses the new key.
        self._vault = new_vault
        self.log = self._setup_logger()
        self.log.info("Project password changed - %d file(s) re-encrypted", len(staged))
        return len(staged)

    @staticmethod
    def recover_password_change(path: Path) -> str:
        """Finish or undo a password change that was interrupted (crash, power cut).
        Returns a message for the user, or "" if there was nothing to recover.

        Leftover .pwchange-new files = the swap didn't finish -> roll back to the OLD password.
        Only .pwchange-old files left = the swap finished    -> keep the NEW password.
        """
        new_files = list(path.rglob(f"*{_NEW}"))  # rglob = search all subfolders too
        old_files = list(path.rglob(f"*{_OLD}"))
        if not new_files and not old_files:
            return ""
        if new_files:
            for old in old_files:
                os.replace(old, old.with_name(old.name.removesuffix(_OLD)))
            for new in new_files:
                new.unlink()
            return "An interrupted password change was undone - the OLD project password is still valid."
        for old in old_files:
            old.unlink()
        return "An interrupted password change was completed - the NEW project password is valid."

    # ---------- logging ----------

    def save_settings(self) -> None:
        """Write config.json and rebuild the logger, so e.g. a new syslog server is used at once."""
        self.config.save(self.path / CONFIG_FILE)
        self.log = self._setup_logger()

    @property
    def syslog_error(self) -> str:
        """Why syslog isn't working, or "" if it is (or isn't configured)."""
        if self._syslog_setup_error:
            return self._syslog_setup_error
        handler = next((h for h in self.log.handlers if isinstance(h, QuietSysLogHandler)), None)
        return handler.last_error if handler else ""

    def _setup_logger(self) -> logging.Logger:
        """Each project gets its own logger: always the encrypted log file, and a syslog server
        too if one is configured. One logger, several handlers - every line goes to all of them."""
        logger = logging.getLogger(f"netaudit.{self.config.name}")
        logger.setLevel(logging.INFO)
        for old in logger.handlers:  # if the project is reloaded, close the old handlers
            old.close()
        logger.handlers.clear()
        handler = EncryptedFileHandler(self.path / LOG_FILE, self._vault)
        handler.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-7s  %(message)s"))
        logger.addHandler(handler)
        logger.propagate = False  # don't also pass records to the root logger (e.g. the console)

        self._syslog_setup_error = ""
        if self.config.syslog_host:
            try:
                logger.addHandler(QuietSysLogHandler(
                    self.config.syslog_host, self.config.syslog_port, self.config.syslog_protocol, self.config.name))
            except OSError as exc:  # TCP: server unreachable; any protocol: name doesn't resolve
                self._syslog_setup_error = str(exc)
                logger.warning("Syslog server %s:%d/%s unreachable: %s - logging locally only",
                               self.config.syslog_host, self.config.syslog_port, self.config.syslog_protocol, exc)
        return logger

    def __repr__(self) -> str:
        return f"Project(name={self.config.name!r}, hosts={len(self.hosts)})"
