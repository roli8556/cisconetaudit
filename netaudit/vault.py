"""
Vault: password-based encryption for project files that contain secrets (hosts.enc).

How a password becomes an encrypted file:

  1. Key derivation (scrypt)
     A password is not a key: it's short and guessable. scrypt stretches it into a 32-byte key
     and is deliberately slow and memory-hungry (~128 MB, a fraction of a second), so an attacker
     who steals the file can only try a few passwords per second instead of billions.
     A random "salt" is mixed in so the same password gives a different key in every project,
     which makes precomputed tables useless.

  2. Encryption (Fernet)
     Fernet = AES-128-CBC for secrecy + HMAC-SHA256 for integrity. The HMAC means a wrong
     password (or a tampered file) is detected and rejected instead of producing garbage.

The file on disk is JSON so it describes itself - salt and scrypt parameters are stored next to
the ciphertext. They are not secret; only the password is.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

FILE_FORMAT = "netaudit-vault"
FILE_VERSION = 1

# scrypt cost parameters (OWASP recommendation). Stored in each file, so they can be raised
# later without breaking old projects.
SCRYPT_N = 2**17  # CPU/memory cost
SCRYPT_R = 8      # block size
SCRYPT_P = 1      # parallelism
SALT_BYTES = 16


class VaultError(Exception):
    """The vault file is missing, damaged or in an unknown format."""


class WrongPasswordError(VaultError):
    """The password didn't decrypt the file (or the file was tampered with)."""


def _derive_key(password: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    raw_key = kdf.derive(password.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)  # Fernet wants the key base64-encoded


def _read_vault_file(path: Path) -> tuple[bytes, tuple[int, int, int], bytes]:
    """Parse a vault file into (salt, (n, r, p), encrypted token). Doesn't decrypt."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("format") != FILE_FORMAT or data.get("version") != FILE_VERSION:
            raise VaultError(f"{path.name} is not a netaudit vault file (or a newer version)")
        salt = base64.b64decode(data["salt"])
        params = (data["n"], data["r"], data["p"])
        token = data["data"].encode("ascii")
    except (OSError, json.JSONDecodeError, KeyError, ValueError, AttributeError) as exc:
        raise VaultError(f"Can't read {path.name}: {exc}") from exc
    return salt, params, token


class Vault:
    """Holds the derived key for one project, so files can be re-encrypted without
    asking for the password again. Get one with Vault.new() or Vault.unlock()."""

    def __init__(self, key: bytes, salt: bytes, n: int, r: int, p: int) -> None:
        self._fernet = Fernet(key)  # leading underscore = "private" by convention in Python
        self._salt = salt
        self._params = (n, r, p)

    @classmethod
    def new(cls, password: str) -> "Vault":
        """A fresh vault with a new random salt (used when creating a project)."""
        salt = os.urandom(SALT_BYTES)  # cryptographically secure random bytes
        key = _derive_key(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
        return cls(key, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)

    @classmethod
    def unlock(cls, path: Path, password: str) -> tuple["Vault", str]:
        """Derive the key from the password and decrypt path with it.
        Returns the vault (to read/write more files) and the decrypted text."""
        salt, (n, r, p), _ = _read_vault_file(path)
        vault = cls(_derive_key(password, salt, n, r, p), salt, n, r, p)
        return vault, vault.read(path)

    def read(self, path: Path) -> str:
        """Decrypt another file encrypted with this vault's key (no password needed - the
        slow scrypt step was already done in unlock())."""
        salt, params, token = _read_vault_file(path)
        if salt != self._salt or params != self._params:
            raise VaultError(f"{path.name} was encrypted by a different project")
        try:
            return self._fernet.decrypt(token).decode("utf-8")
        except InvalidToken:
            raise WrongPasswordError("Wrong project password (or the file has been modified)") from None

    def write(self, path: Path, plaintext: str) -> None:
        """Encrypt plaintext and save it to path.

        Written to a temporary file first and then swapped in with os.replace(), which is
        atomic: if the program crashes halfway, the old file is still intact. Losing the only
        copy of the inventory to a half-written file would be bad.
        """
        n, r, p = self._params
        data = {
            "format": FILE_FORMAT,
            "version": FILE_VERSION,
            "kdf": "scrypt",
            "n": n,
            "r": r,
            "p": p,
            "salt": base64.b64encode(self._salt).decode("ascii"),
            "data": self._fernet.encrypt(plaintext.encode("utf-8")).decode("ascii"),
        }
        tmp_path = path.with_name(path.name + ".tmp")
        tmp_path.write_text(json.dumps(data, indent=4), encoding="utf-8")
        os.replace(tmp_path, path)
