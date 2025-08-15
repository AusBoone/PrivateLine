"""Double ratchet unit tests.

These tests exercise the ratchet primitives in isolation and verify thread
safe behaviour of the shared store used by the API.  Concurrency tests simulate
multiple requests arriving in parallel to ensure that only one ratchet instance
is created per conversation.
"""

from concurrent.futures import ThreadPoolExecutor

from backend.ratchet import DoubleRatchet, RatchetStore, get_ratchet


def test_ratchet_rotation():
    """Keys should rotate after each encrypt/decrypt cycle."""
    dr = DoubleRatchet(b"0" * 32)
    first_key = dr.root_key
    ct, nonce = dr.encrypt(b"hello")
    # Encryption should not advance the key until a peer decrypts
    assert dr.root_key == first_key
    pt = dr.decrypt(ct, nonce)
    assert pt == b"hello"
    second_key = dr.root_key
    assert second_key != first_key
    ct2, nonce2 = dr.encrypt(b"bye")
    assert dr.root_key == second_key
    pt2 = dr.decrypt(ct2, nonce2)
    assert pt2 == b"bye"


def test_store_get_thread_safe():
    """RatchetStore.get should return a single instance under contention."""
    store = RatchetStore(b"0" * 32)

    def fetch() -> DoubleRatchet:
        # Fetch the ratchet for a fixed conversation from multiple threads.
        return store.get("alice", "bob")

    with ThreadPoolExecutor(max_workers=10) as pool:
        rats = list(pool.map(lambda _: fetch(), range(10)))

    first = rats[0]
    # All threads must observe the same ratchet object.
    assert all(r is first for r in rats)
    # Only a single entry should exist in the internal store.
    assert len(store._store) == 1


def test_global_get_ratchet_thread_safe():
    """get_ratchet should create one global store and ratchet concurrently."""

    def fetch() -> DoubleRatchet:
        # Access the global helper which internally initialises a shared store.
        return get_ratchet("alice", "bob")

    with ThreadPoolExecutor(max_workers=10) as pool:
        rats = list(pool.map(lambda _: fetch(), range(10)))

    first = rats[0]
    assert all(r is first for r in rats)
    # The module-level store should only contain a single ratchet entry.
    import backend.ratchet as ratchet_module

    assert ratchet_module._store is not None
    assert len(ratchet_module._store._store) == 1

