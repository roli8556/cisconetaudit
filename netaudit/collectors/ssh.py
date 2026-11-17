"""
SSH collector: logs in to Cisco IOS devices with netmiko, reads state and applies changes.

This is the ONLY module that imports netmiko. Everything else works with the plain model objects
it returns, so the collector can be swapped later (Catalyst Center API, saved files...) without
touching the scan logic.

Host keys are verified against the project's known_hosts before logging in (see hostkeys.py).
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from netmiko import ConnectHandler
from netmiko.exceptions import (
    ConfigInvalidException,
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
    ReadTimeout,
)
from paramiko.ssh_exception import BadHostKeyException, SSHException

from ..inventory import Host
from ..models import DeviceSnapshot, RunningConfig
from ..parsers.ios import build_snapshot
from .hostkeys import KeyStatus, KnownHosts, fingerprint

# show running-config on a big switch can take a while to scroll out
SHOW_TIMEOUT = 60

# Everything the baseline scan needs from one device. Unsupported commands (e.g. OSPF on a pure
# L2 switch) just answer "% ..." and are treated as empty by the parsers.
SNAPSHOT_COMMANDS = [
    "show running-config",
    "show interfaces",
    "show interfaces switchport",
    "show vlan brief",
    "show etherchannel summary",
    "show cdp neighbors detail",
    "show ip ospf interface",
    "show ip ospf neighbor",
    "show ntp status",
    "show crypto key mypubkey rsa",
]

# Changes are made with "configure terminal revert timer": if we can't confirm them within this
# many minutes (e.g. the change cut off our management access), IOS rolls them back by itself.
REVERT_MINUTES = 5

# IOS error messages start with "% " (e.g. "% Invalid input detected"). Syslog messages like
# "%LINK-3-UPDOWN" have no space, so they don't match.
IOS_ERROR = r"^% "

# Signature of the "ask the user" function: (ip, key_type, fingerprint) -> accept?
# Like std::function<bool(string, string, string)> in C++.
ConfirmKey = Callable[[str, str, str], bool]


class CollectorError(Exception):
    """Talking to one device failed. The message is safe to show and log."""


class SshCollector:
    def __init__(
        self,
        known_hosts: KnownHosts,
        confirm_new_key: ConfirmKey,
        port: int = 22,
        timeout: int = 10,
    ) -> None:
        """confirm_new_key is called when a device's host key isn't in known_hosts yet.
        The collector never does input()/print() itself - the caller decides how to ask
        (menu prompt now, maybe a GUI or "--accept-new-keys" flag later)."""
        self.known_hosts = known_hosts
        self.confirm_new_key = confirm_new_key
        self.port = port
        self.timeout = timeout

    # ---------- reading ----------

    def fetch_running_config(self, host: Host) -> RunningConfig:
        with self._session(host) as conn:
            hostname = conn.find_prompt().rstrip("#>")  # "SW1#" -> "SW1"
            text = conn.send_command("show running-config", read_timeout=SHOW_TIMEOUT)
        _check_running_config(text)
        return RunningConfig(host_ip=host.ip, hostname=hostname, text=text)

    def fetch_snapshot(self, host: Host) -> DeviceSnapshot:
        """Run all SNAPSHOT_COMMANDS in one session and parse them into a DeviceSnapshot."""
        with self._session(host) as conn:
            hostname = conn.find_prompt().rstrip("#>")
            # dict comprehension: {command: output} for every command in the list
            outputs = {cmd: conn.send_command(cmd, read_timeout=SHOW_TIMEOUT) for cmd in SNAPSHOT_COMMANDS}
        _check_running_config(outputs["show running-config"])
        return build_snapshot(host.ip, hostname, outputs)

    # ---------- changing ----------

    def apply_config(self, host: Host, commands: list[str], revert_minutes: int = REVERT_MINUTES) -> None:
        """Apply config commands safely:

        1. Enter config mode with a revert timer - IOS will undo everything by itself unless
           we confirm within revert_minutes.
        2. Send the commands. If IOS rejects one, roll back immediately.
        3. Open a NEW session and run "configure confirm". Succeeding proves we can still manage
           the device after the change. If we can't get back in, the timer rolls it back.
        """
        with self._session(host) as conn:
            try:
                conn.send_config_set(
                    commands,
                    config_mode_command=f"configure terminal revert timer {revert_minutes}",
                    error_pattern=IOS_ERROR,
                    read_timeout=SHOW_TIMEOUT,
                )
            except ValueError:  # netmiko couldn't get to a "(config)#" prompt
                raise CollectorError(
                    "can't start a config session with a revert timer. Rollback needs the IOS archive "
                    "feature: 'archive' + 'path flash:netaudit' (IOL: 'path unix:netaudit'). No changes made."
                ) from None
            except ConfigInvalidException as exc:
                if conn.check_config_mode():
                    conn.exit_config_mode()
                conn.send_command_timing("configure revert now")  # undo what was already applied
                rejected = str(exc).strip().splitlines()[-1] if str(exc).strip() else "unknown error"
                raise CollectorError(f"device rejected a command ({rejected}) - changes rolled back") from None

        try:
            with self._session(host) as conn:
                conn.send_command("configure confirm")
        except CollectorError as exc:
            raise CollectorError(
                f"changes applied, but reconnecting failed ({exc}). The device rolls back "
                f"automatically within {revert_minutes} minutes."
            ) from None

    def write_memory(self, host: Host) -> None:
        """Save running-config to startup-config (otherwise changes are lost on reload)."""
        with self._session(host) as conn:
            conn.save_config()

    # ---------- the shared session ----------

    @contextmanager
    def _session(self, host: Host) -> Iterator:
        """A logged-in netmiko session at privilege 15, used as: with self._session(host) as conn.

        @contextmanager turns this generator into something "with" can use: the code before
        "yield" runs on entering the block, the code after it on leaving - like a C++ RAII
        class with constructor + destructor, written as one function. Exceptions raised inside
        the caller's "with" block arrive at the yield, so they're translated here too.
        """
        self._verify_host_key(host)
        try:
            # ** unpacks the dict into keyword arguments: ConnectHandler(device_type=..., host=...)
            with ConnectHandler(**self._connection_params(host)) as conn:
                _ensure_privilege_15(conn, host)
                yield conn
        except NetmikoAuthenticationException:
            raise CollectorError("authentication failed (check username/password)") from None
        except NetmikoTimeoutException as exc:
            # netmiko wraps paramiko's BadHostKeyException in a "timeout" exception. The original
            # is kept in __context__ (Python records which exception was being handled).
            if isinstance(exc.__context__, BadHostKeyException):
                raise CollectorError("HOST KEY CHANGED during connect - refusing to log in") from None
            raise CollectorError("connection timed out (device down or SSH not enabled?)") from None
        except ReadTimeout:
            raise CollectorError("device stopped responding to a command") from None
        except (SSHException, OSError) as exc:
            raise CollectorError(f"SSH error: {exc}") from None

    def _connection_params(self, host: Host) -> dict:
        """Build the keyword arguments for netmiko's ConnectHandler."""
        params = {
            "device_type": "cisco_ios",  # selects netmiko's CiscoIosSSH driver class
            "host": host.ip,
            "username": host.username,
            "password": host.password,
            "port": self.port,
            "conn_timeout": self.timeout,  # TCP connect timeout
            "auth_timeout": self.timeout,
            # Strict host key checking against the project's known_hosts only:
            "ssh_strict": True,  # unknown/changed key -> refuse (netmiko default: accept anything)
            "system_host_keys": False,  # don't use ~/.ssh/known_hosts
            "alt_host_keys": True,
            "alt_key_file": str(self.known_hosts.path),
        }
        if host.enable_password:
            params["secret"] = host.enable_password  # netmiko calls it "secret"
        return params

    def _verify_host_key(self, host: Host) -> None:
        """Check the device's host key BEFORE sending any credentials."""
        try:
            status, key = self.known_hosts.check(host.ip, self.port, self.timeout)
        except (SSHException, OSError) as exc:  # OSError covers timeouts and refused connections
            raise CollectorError(f"can't reach SSH on {host.ip}:{self.port} ({exc})") from None

        if status is KeyStatus.CHANGED:
            raise CollectorError(
                f"HOST KEY CHANGED (now {key.get_name()} {fingerprint(key)}). Possible "
                "man-in-the-middle! If the device was replaced or its key regenerated, remove "
                f"its line from {self.known_hosts.path.name} and try again."
            )
        if status is KeyStatus.UNKNOWN:
            if not self.confirm_new_key(host.ip, key.get_name(), fingerprint(key)):
                raise CollectorError("host key not accepted - skipped")
            self.known_hosts.add(host.ip, self.port, key)


# ---------- module-level helpers (don't need an SshCollector instance) ----------


def _check_running_config(text: str) -> None:
    if "% " in text[:200] or not re.search(r"^end\s*$", text, re.MULTILINE):
        # IOS errors start with "% ...", and a complete config always ends with "end"
        raise CollectorError("output doesn't look like a complete running-config")


def _ensure_privilege_15(conn, host: Host) -> None:
    """At privilege < 15, IOS shows only PART of the running-config - auditing that would
    give false findings (and changes would fail), so refuse instead."""
    if not conn.check_enable_mode():  # prompt ends with ">" instead of "#"
        if not host.enable_password:
            raise CollectorError("not in privileged mode and no enable password is set")
        try:
            conn.enable()  # sends "enable" + the secret
        except ValueError:  # netmiko raises ValueError if the prompt never turns into "#"
            raise CollectorError("enable failed (wrong enable password?)") from None

    output = conn.send_command("show privilege")  # "Current privilege level is 15"
    match = re.search(r"privilege level is (\d+)", output)
    if not match or int(match.group(1)) != 15:
        raise CollectorError(f"need privilege level 15, got: {output.strip()}")
