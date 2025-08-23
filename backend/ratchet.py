"""Simplified double ratchet implementation used for server-side encryption.

This module implements a lightweight symmetric key ratchet providing forward
secrecy for the layer of encryption applied by the server. Each conversation
pair obtains its own :class:`DoubleRatchet` instance keyed by the master
``AES_KEY``. The ratchet derives a new key for every message by combining the
previous root key with a random 32-byte header. Both parties update their root
key after processing a message so past keys are discarded.

The encrypted payload stored in the database consists of the random header
followed by the ciphertext. The associated nonce is stored separately. Clients
never interact with this ratchet directly; it protects the ciphertext sent from
the client to the server.

Concurrency
-----------
Requests processed by the web server may access ratchets simultaneously.  To
prevent race conditions, the global store used by :func:`get_ratchet` and the
per-conversation cache inside :class:`RatchetStore` employ threading locks.  A
single store instance is created lazily and reused for all requests, while each
conversation pair obtains exactly one :class:`DoubleRatchet` instance.

# 2025 update: Introduced synchronization around store creation and lookup to
# ensure thread-safe behaviour under parallel requests.
# 2025 update 2: Added configurable in-memory cache with LRU/TTL eviction to
# bound memory usage of per-conversation ratchets.  Entries are evicted when
# exceeding ``RATCHET_MAX_CACHE`` or after ``RATCHET_CACHE_TTL`` seconds.
# 2026 update: Added deterministic test vector generator to aid cross-client
#              compatibility testing.
"""

from __future__ import annotations

import os
from collections import OrderedDict
from dataclasses import dataclass
from hashlib import sha256
from threading import Lock
from time import time
from typing import Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


@dataclass
class DoubleRatchet:
    """Stateful ratchet that derives a new AES key for each message."""

    root_key: bytes

    def _derive_key(self, header: bytes) -> bytes:
        """Return a 32-byte AES key derived from ``root_key`` and ``header``."""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.root_key,
            info=header,
            backend=default_backend(),
        )
        return hkdf.derive(b"")

    def encrypt(self, plaintext: bytes) -> Tuple[bytes, bytes]:
        """Encrypt ``plaintext`` and rotate the root key.

        Returns a tuple of ``ciphertext`` (header + encrypted bytes) and ``nonce``.
        """
        header = os.urandom(32)
        nonce = os.urandom(12)
        key = self._derive_key(header)
        aes = AESGCM(key)
        ciphertext = aes.encrypt(nonce, plaintext, None)
        # The root key is only advanced when the peer decrypts so both sides
        # remain in sync until the ciphertext has been processed.
        return header + ciphertext, nonce

    def decrypt(self, data: bytes, nonce: bytes) -> bytes:
        """Decrypt ``data`` using the current root key and update it."""
        header, ciphertext = data[:32], data[32:]
        key = self._derive_key(header)
        aes = AESGCM(key)
        plaintext = aes.decrypt(nonce, ciphertext, None)
        # Advance the root key so subsequent messages use a fresh key.
        self.root_key = sha256(self.root_key + header).digest()
        return plaintext


class RatchetStore:
    """In-memory collection of ratchets keyed by sender and receiver.

    The store caches a :class:`DoubleRatchet` for every conversation pair.  To
    prevent unbounded memory growth the cache supports two eviction strategies:

    * **LRU** – when the number of entries exceeds ``RATCHET_MAX_CACHE`` the
      least recently used ratchet is discarded.
    * **TTL** – if ``RATCHET_CACHE_TTL`` is greater than zero, ratchets older
      than the configured number of seconds are removed on each lookup.

    Both settings are optional; defaults allow unlimited entries with no
    expiration.  A lock protects all cache operations so multiple threads may
    interact safely.
    """

    def __init__(self, master_key: bytes):
        """Create a new store with configurable eviction policies.

        Environment variables are consulted to configure cache behaviour:

        ``RATCHET_MAX_CACHE``
            Maximum number of active ratchets to retain. ``0`` means unlimited.
        ``RATCHET_CACHE_TTL``
            Time-to-live for each ratchet in seconds. ``0`` disables expiry.

        Invalid values raise :class:`ValueError` to fail fast during start-up.
        """

        # Master key from which per-conversation ratchets are derived.
        self.master_key = master_key

        # Parse configuration knobs from environment variables with validation.
        self.max_cache = self._read_env_int("RATCHET_MAX_CACHE", default=0)
        self.ttl = self._read_env_float("RATCHET_CACHE_TTL", default=0.0)

        # Ordered mapping of (sender, receiver) -> (DoubleRatchet, last access).
        # ``OrderedDict`` enables efficient LRU eviction by popping the oldest
        # item when the cache exceeds ``max_cache``.
        self._store: "OrderedDict[Tuple[str, str], Tuple[DoubleRatchet, float]]" = OrderedDict()

        # Lock guarding access to ``_store`` for thread-safe lookups.
        self._lock = Lock()

    @staticmethod
    def _read_env_int(name: str, default: int) -> int:
        """Return a non-negative integer from ``name`` or ``default``.

        Raises ``ValueError`` when the environment variable contains a negative
        or non-integer value. A value of ``0`` indicates "no limit".
        """

        value = os.getenv(name)
        if value is None:
            return default
        try:
            result = int(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be an integer") from exc
        if result < 0:
            raise ValueError(f"{name} must be >= 0")
        return result

    @staticmethod
    def _read_env_float(name: str, default: float) -> float:
        """Return a non-negative float from ``name`` or ``default``.

        Negative or non-numeric values raise ``ValueError``. ``0`` disables the
        associated feature (e.g. TTL).
        """

        value = os.getenv(name)
        if value is None:
            return default
        try:
            result = float(value)
        except ValueError as exc:
            raise ValueError(f"{name} must be a number") from exc
        if result < 0:
            raise ValueError(f"{name} must be >= 0")
        return result

    def _initial_root(self, a: str, b: str) -> bytes:
        """Derive a deterministic root key for the conversation."""
        info = f"{a}:{b}".encode()
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=info,
            backend=default_backend(),
        )
        return hkdf.derive(self.master_key)

    def _evict_expired(self, now: float) -> None:
        """Remove cached ratchets whose age exceeds ``ttl``.

        Iterates from the least recently used item forward, exiting early once a
        fresh entry is encountered. This keeps the check efficient even for
        larger caches.
        """

        if self.ttl <= 0:
            return
        while self._store:
            key, (_, ts) = next(iter(self._store.items()))
            if now - ts > self.ttl:
                # Discard oldest item and continue in case multiple expired.
                self._store.popitem(last=False)
            else:
                break

    def _enforce_size(self) -> None:
        """Ensure cache size stays within ``max_cache`` via LRU eviction."""

        if self.max_cache > 0 and len(self._store) > self.max_cache:
            # ``popitem(last=False)`` removes the least recently used entry.
            self._store.popitem(last=False)

    def get(self, sender: str, receiver: str) -> DoubleRatchet:
        """Return the ratchet used when ``sender`` sends to ``receiver``.

        All lookups are wrapped in a lock so that eviction and timestamp updates
        remain consistent across threads. The caller receives a
        :class:`DoubleRatchet` instance; expired entries are transparently
        recreated.
        """

        key = (sender, receiver)
        now = time()
        with self._lock:
            # Drop any entries that exceeded their TTL prior to servicing this
            # request. Eviction occurs outside of ``get`` calls as well because
            # new accesses may trigger clean-up of stale items.
            self._evict_expired(now)

            ratchet_entry = self._store.get(key)
            if ratchet_entry is None:
                ratchet = DoubleRatchet(self._initial_root(*key))
            else:
                ratchet = ratchet_entry[0]

            # Record the access time and maintain recency ordering for LRU.
            self._store[key] = (ratchet, now)
            self._store.move_to_end(key)

            # Bound memory usage after inserting the new/updated entry.
            self._enforce_size()

            return ratchet


# Global store used by resources. The AES_KEY constant is imported lazily to
# avoid circular imports during application startup.
_store: RatchetStore | None = None
# Lock guarding creation of the module-level store.  This ensures concurrent
# calls to :func:`get_ratchet` do not race to create separate instances.
_store_lock = Lock()


def get_ratchet(sender: str, receiver: str) -> DoubleRatchet:
    """Return the :class:`DoubleRatchet` for ``sender`` -> ``receiver``.

    The global store is created lazily and protected by ``_store_lock`` so that
    multiple concurrent requests do not instantiate separate stores.  Once
    initialised, lookups are delegated to :class:`RatchetStore`, which performs
    its own synchronization.
    """
    global _store
    if _store is None:
        # Double-checked locking: avoid taking the lock on the common fast path
        # but ensure only one store is created across threads.
        with _store_lock:
            if _store is None:
                from .resources import AES_KEY  # type: ignore

                _store = RatchetStore(AES_KEY)
    return _store.get(sender, receiver)


def generate_test_vector() -> dict:
    """Return a deterministic double ratchet test vector.

    The vector is used by the mobile clients to verify their implementations
    match the server.  Fixed inputs are chosen so the output is stable:

    * ``root_key`` – SHA-256 digest of ``b"deterministic root"``
    * ``header`` – bytes ``0x00`` through ``0x1f``
    * ``nonce`` – bytes ``0x00`` through ``0x0b``
    * ``plaintext`` – ASCII string ``"double ratchet test message"``

    The returned mapping encodes all binary values as hexadecimal strings.
    """

    plaintext = b"double ratchet test message"

    # Root key derived from a constant string for reproducibility.
    root_key = sha256(b"deterministic root").digest()

    # Deterministic header and nonce so the ciphertext remains stable.
    header = bytes(range(32))
    nonce = bytes(range(12))

    # Derive the AES key and encrypt the plaintext using AES-GCM.
    ratchet = DoubleRatchet(root_key)
    key = ratchet._derive_key(header)
    aes = AESGCM(key)
    ciphertext = aes.encrypt(nonce, plaintext, None)

    # Compute the updated root key as performed during decryption.
    updated_root = sha256(root_key + header).digest()

    return {
        "root_key": root_key.hex(),
        "ciphertext": (header + ciphertext).hex(),
        "nonce": nonce.hex(),
        "updated_root": updated_root.hex(),
    }


if __name__ == "__main__":
    # When executed directly this module writes the test vector to the
    # repository's ``tests/data`` directory. The file can then be consumed by
    # client implementations to verify cross-language compatibility.
    import json
    from pathlib import Path

    vector = generate_test_vector()

    # Locate the repository root relative to this file.
    root = Path(__file__).resolve().parents[1]
    out_path = root / "tests" / "data" / "ratchet_vectors.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(vector, fh, indent=2)
    print(f"wrote test vector to {out_path}")
