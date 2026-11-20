"""Encryption at rest and signing keys for TRACE AI.

Keys
----
All keys live in a key directory that is deliberately *outside* ``data/`` so a
copy of the data folder alone cannot be decrypted:

* ``TRACE_KEY_DIR`` (default ``~/.config/trace_ai``)
  - ``master.key``        32 random bytes; root secret for DB + evidence encryption
  - ``audit_signing.key`` Ed25519 private key that signs every audit-log entry

``TRACE_MASTER_KEY`` (base64 of 32 bytes) may be supplied instead of the key file,
for example from a secrets manager.  Back up the key directory separately from the
data: without it, encrypted evidence cannot be recovered.

Evidence file format (``.enc``)
-------------------------------
``TRACEENC1`` magic | 4-byte chunk size | 32-byte file salt, followed by chunks:
``12-byte nonce | AES-256-GCM(chunk) incl. 16-byte tag``.  Each chunk is
authenticated with AAD = header || chunk index || final-flag, so chunks cannot be
reordered, truncated, or appended without detection.  A per-file key is derived
with HKDF from the master key and the file salt.
"""

from __future__ import annotations

import base64
import hashlib
import os
import struct
from functools import lru_cache
from pathlib import Path
from typing import BinaryIO, Iterator

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_DIR = Path(os.environ.get("TRACE_KEY_DIR", Path.home() / ".config" / "trace_ai"))

MAGIC = b"TRACEENC1"
CHUNK_SIZE = 1024 * 1024
_HEADER = struct.Struct(">9sI32s")  # magic, chunk size, salt
_NONCE = 12
_TAG = 16


class DecryptionError(Exception):
    """Raised when encrypted evidence fails authentication."""


# --------------------------------------------------------------------------- #
# Keys
# --------------------------------------------------------------------------- #
def _key_dir() -> Path:
    path = Path(KEY_DIR)
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass
    return path


def _write_secret(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)


def master_key() -> bytes:
    env_value = os.environ.get("TRACE_MASTER_KEY")
    if env_value:
        key = base64.b64decode(env_value)
        if len(key) != 32:
            raise RuntimeError("TRACE_MASTER_KEY must be base64 of exactly 32 bytes.")
        return key
    path = _key_dir() / "master.key"
    if not path.exists():
        try:
            _write_secret(path, os.urandom(32))
        except FileExistsError:
            pass
    key = path.read_bytes()
    if len(key) != 32:
        raise RuntimeError(f"{path} is corrupt (expected 32 bytes).")
    return key


def _derive(purpose: bytes, salt: bytes | None = None) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=salt, info=b"trace-ai:" + purpose,
    ).derive(master_key())


def database_key_hex() -> str:
    """Raw 256-bit key for SQLCipher, as hex."""
    return _derive(b"sqlcipher-database").hex()


def key_fingerprint() -> str:
    return hashlib.sha256(_derive(b"fingerprint")).hexdigest()[:16]


# --------------------------------------------------------------------------- #
# Evidence file encryption
# --------------------------------------------------------------------------- #
def _aad(header: bytes, index: int, final: bool) -> bytes:
    return header + struct.pack(">QB", index, 1 if final else 0)


def encrypt_stream(source: BinaryIO, destination: Path) -> tuple[str, int]:
    """Encrypt ``source`` into ``destination``. Returns (plaintext sha256, size).

    Written to a temporary file first and atomically renamed, so a crash never
    leaves a half-written evidence file under its final name.
    """
    salt = os.urandom(32)
    header = _HEADER.pack(MAGIC, CHUNK_SIZE, salt)
    cipher = AESGCM(_derive(b"evidence-file", salt))
    digest = hashlib.sha256()
    total = 0
    temporary = destination.with_suffix(destination.suffix + ".part")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with open(temporary, "wb") as out:
        out.write(header)
        index = 0
        current = source.read(CHUNK_SIZE)
        while True:
            following = source.read(CHUNK_SIZE) if current else b""
            final = not following
            digest.update(current)
            total += len(current)
            nonce = os.urandom(_NONCE)
            out.write(nonce + cipher.encrypt(nonce, current, _aad(header, index, final)))
            if final:
                break
            current = following
            index += 1
        out.flush()
        os.fsync(out.fileno())
    os.replace(temporary, destination)
    return digest.hexdigest(), total


def encrypt_bytes(data: bytes, destination: Path) -> tuple[str, int]:
    import io
    return encrypt_stream(io.BytesIO(data), destination)


def is_encrypted_file(path: Path) -> bool:
    try:
        with open(path, "rb") as handle:
            return handle.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def decrypt_iter(path: Path) -> Iterator[bytes]:
    """Yield authenticated plaintext chunks. Raises DecryptionError on tampering."""
    with open(path, "rb") as handle:
        header = handle.read(_HEADER.size)
        if len(header) != _HEADER.size:
            raise DecryptionError("Encrypted file header is truncated.")
        magic, chunk_size, salt = _HEADER.unpack(header)
        if magic != MAGIC:
            raise DecryptionError("Not a TRACE AI encrypted evidence file.")
        cipher = AESGCM(_derive(b"evidence-file", salt))
        record = _NONCE + chunk_size + _TAG
        index = 0
        block = handle.read(record)
        while True:
            if len(block) < _NONCE + _TAG:
                raise DecryptionError("Encrypted file is truncated.")
            following = handle.read(record)
            final = not following
            nonce, body = block[:_NONCE], block[_NONCE:]
            try:
                yield cipher.decrypt(nonce, body, _aad(header, index, final))
            except InvalidTag as exc:
                raise DecryptionError(
                    f"Authentication failed at chunk {index}: the file was altered, "
                    "truncated, or encrypted with a different key."
                ) from exc
            if final:
                return
            block = following
            index += 1


def decrypt_to_bytes(path: Path) -> bytes:
    return b"".join(decrypt_iter(path))


def decrypt_to_file(path: Path, destination: Path) -> None:
    with open(destination, "wb") as out:
        for chunk in decrypt_iter(path):
            out.write(chunk)


def plaintext_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    for chunk in decrypt_iter(path):
        digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------- #
# Audit signing (Ed25519)
# --------------------------------------------------------------------------- #
@lru_cache(maxsize=4)
def _signing_key_cached(key_dir: str) -> Ed25519PrivateKey:
    path = Path(key_dir) / "audit_signing.key"
    if not path.exists():
        private = Ed25519PrivateKey.generate()
        raw = private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        try:
            _write_secret(path, raw)
        except FileExistsError:
            pass
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def signing_key() -> Ed25519PrivateKey:
    return _signing_key_cached(str(_key_dir()))


def public_key_pem() -> str:
    return signing_key().public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_key_id() -> str:
    raw = signing_key().public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(raw).hexdigest()[:16]


def sign(message: bytes) -> str:
    return base64.b64encode(signing_key().sign(message)).decode("ascii")


def verify_signature(message: bytes, signature_b64: str, public_pem: str | None = None) -> bool:
    try:
        if public_pem:
            public: Ed25519PublicKey = serialization.load_pem_public_key(public_pem.encode("ascii"))
        else:
            public = signing_key().public_key()
        public.verify(base64.b64decode(signature_b64), message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
