"""
SSH host key verification ("trust on first use", like OpenSSH's known_hosts).

Why: SSH encrypts the connection, but without checking the server's host key you don't know WHO
you are talking to. An attacker on the management network could pose as the switch and collect
the credentials we send. So:

  - The first time we see a device, the user is shown the key fingerprint and must accept it.
  - Accepted keys are stored in the project's known_hosts file.
  - Later connections must present the same key. If it changed, we refuse to connect.
    (Legit reasons: device replaced, or "crypto key generate rsa" was run again. Then remove the
    line from known_hosts and accept the new key.)

known_hosts is not encrypted: public keys aren't secret. It uses OpenSSH's file format.
"""

from __future__ import annotations

import base64
import hashlib
import socket
from enum import Enum
from pathlib import Path

import paramiko


class KeyStatus(Enum):
    """Result of comparing a device's key with known_hosts. Like a C++ enum class."""

    KNOWN = "known"
    UNKNOWN = "unknown"
    CHANGED = "changed"


def fingerprint(key: paramiko.PKey) -> str:
    """SHA256 fingerprint in the same format OpenSSH shows ("SHA256:abc...")."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def host_entry_name(ip: str, port: int) -> str:
    """How known_hosts names a host: "1.2.3.4", or "[1.2.3.4]:2222" for non-standard ports.
    Must match what paramiko looks up when netmiko connects."""
    return ip if port == 22 else f"[{ip}]:{port}"


class KnownHosts:
    """The project's known_hosts file."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._keys = paramiko.HostKeys()
        if path.is_file():
            self._keys.load(str(path))

    def check(self, ip: str, port: int, timeout: int) -> tuple[KeyStatus, paramiko.PKey]:
        """Connect (no login), get the device's host key and compare it with known_hosts."""
        name = host_entry_name(ip, port)
        known = self._keys.lookup(name)  # {key_type: key} or None

        # If we already have a key of some type, ask the device for that type first -
        # paramiko does the same when netmiko connects, so both see the same key.
        preferred = next(iter(known.keys())) if known else None
        key = self._fetch_key(ip, port, timeout, preferred)

        if not known:
            return KeyStatus.UNKNOWN, key
        if known.get(key.get_name()) == key:
            return KeyStatus.KNOWN, key
        return KeyStatus.CHANGED, key

    def add(self, ip: str, port: int, key: paramiko.PKey) -> None:
        self._keys.add(host_entry_name(ip, port), key.get_name(), key)
        self._keys.save(str(self.path))

    @staticmethod
    def _fetch_key(ip: str, port: int, timeout: int, preferred: str | None) -> paramiko.PKey:
        """Do just the SSH handshake (no authentication) and return the server's host key."""
        sock = socket.create_connection((ip, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        try:
            if preferred:
                options = transport.get_security_options()
                if preferred == "ssh-rsa":
                    # "ssh-rsa" names the KEY format, but the handshake negotiates a SIGNATURE
                    # algorithm. paramiko only offers the SHA-2 ones for RSA keys (same mapping
                    # as paramiko's own SSHClient does).
                    preferred = next(
                        (t for t in ("rsa-sha2-512", "rsa-sha2-256") if t in options.key_types),
                        None,
                    )
                if preferred in options.key_types:
                    options.key_types = [preferred] + [t for t in options.key_types if t != preferred]
            transport.start_client(timeout=timeout)
            return transport.get_remote_server_key()
        finally:
            transport.close()  # "finally" runs no matter what - also closes the socket
