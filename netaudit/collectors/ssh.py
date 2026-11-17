"""
SSH collector: logs in to a Cisco IOS device with netmiko and fetches data.

This is the ONLY module that imports netmiko. Everything else works with the plain
RunningConfig object it returns, so the collector can be swapped later (Catalyst Center API,
saved files...) without touching the audit logic.

Host keys are verified against the project's known_hosts before logging in (see hostkeys.py).
"""

from __future__ import annotations

import re
from collections.abc import Callable

from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
from paramiko.ssh_exception import BadHostKeyException, SSHException

from ..inventory import Host
from ..models import RunningConfig
from .hostkeys import KeyStatus, KnownHosts, fingerprint

# show running-config on a big switch can take a while to scroll out
SHOW_RUN_TIMEOUT = 60


class CollectorError(Exception):
    """Fetching data from one device failed. The message is safe to show and log."""


# Signature of the "ask the user" function: (ip, key_type, fingerprint) -> accept?
# Like std::function<bool(string, string, string)> in C++.
ConfirmKey = Callable[[str, str, str], bool]


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

    def fetch_running_config(self, host: Host) -> RunningConfig:
        """Connect, make sure we are at privilege 15, and return the running-config.

        Every failure is turned into a CollectorError, so the caller only has to catch one
        exception type and can carry on with the next host.
        """
        self._verify_host_key(host)
        try:
            # ** unpacks the dict into keyword arguments: ConnectHandler(device_type=..., host=...)
            # "with" = RAII: the SSH session is closed when the block ends, even on an exception.
            with ConnectHandler(**self._connection_params(host)) as conn:
                self._ensure_privilege_15(conn, host)
                hostname = conn.find_prompt().rstrip("#>")  # "SW1#" -> "SW1"
                text = conn.send_command("show running-config", read_timeout=SHOW_RUN_TIMEOUT)
        except NetmikoAuthenticationException:
            raise CollectorError("authentication failed (check username/password)") from None
        except NetmikoTimeoutException as exc:
            # netmiko wraps paramiko's BadHostKeyException in a "timeout" exception. The original
            # is kept in __context__ (Python records which exception was being handled).
            if isinstance(exc.__context__, BadHostKeyException):
                raise CollectorError("HOST KEY CHANGED during connect - refusing to log in") from None
            raise CollectorError("connection timed out (device down or SSH not enabled?)") from None
        except (SSHException, OSError) as exc:
            raise CollectorError(f"SSH error: {exc}") from None

        if "% " in text[:200] or not re.search(r"^end\s*$", text, re.MULTILINE):
            # IOS errors start with "% ...", and a complete config always ends with "end"
            raise CollectorError("output doesn't look like a complete running-config")

        return RunningConfig(host_ip=host.ip, hostname=hostname, text=text)

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
                f"its line from {self.known_hosts.path.name} and fetch again."
            )
        if status is KeyStatus.UNKNOWN:
            if not self.confirm_new_key(host.ip, key.get_name(), fingerprint(key)):
                raise CollectorError("host key not accepted - skipped")
            self.known_hosts.add(host.ip, self.port, key)

    @staticmethod
    def _ensure_privilege_15(conn, host: Host) -> None:
        """At privilege < 15, IOS shows only PART of the running-config - auditing that would
        give false findings, so refuse instead."""
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
