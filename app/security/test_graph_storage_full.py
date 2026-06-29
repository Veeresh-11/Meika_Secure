# app/security/test_graph_storage_full.py

import pytest
from unittest.mock import Mock

from app.security.graph.storage.base_store import TupleStoreBackend
from app.security.graph.storage.cache import TupleCache
from app.security.graph.storage.memory_store import MemoryTupleStore


# =====================================================
# base_store.py
# =====================================================

def test_base_store_add_not_implemented():
    backend = TupleStoreBackend()

    with pytest.raises(NotImplementedError):
        backend.add("a", "r", "b")


def test_base_store_has_not_implemented():
    backend = TupleStoreBackend()

    with pytest.raises(NotImplementedError):
        backend.has("a", "r", "b")


def test_base_store_find_subjects_not_implemented():
    backend = TupleStoreBackend()

    with pytest.raises(NotImplementedError):
        backend.find_subjects("r", "b")


def test_base_store_find_objects_not_implemented():
    backend = TupleStoreBackend()

    with pytest.raises(NotImplementedError):
        backend.find_objects("a", "r")


# =====================================================
# memory_store.py
# =====================================================

def test_memory_store_add_and_has():
    store = MemoryTupleStore()

    store.add("alice", "edit", "doc1")

    assert store.has("alice", "edit", "doc1") is True
    assert store.has("alice", "edit", "doc2") is False


def test_memory_store_find_objects():
    store = MemoryTupleStore()

    store.add("alice", "edit", "doc2")
    store.add("alice", "edit", "doc1")

    assert store.find_objects("alice", "edit") == [
        "doc1",
        "doc2",
    ]


def test_memory_store_find_subjects():
    store = MemoryTupleStore()

    store.add("alice", "edit", "doc1")
    store.add("bob", "edit", "doc1")

    assert store.find_subjects("edit", "doc1") == [
        "alice",
        "bob",
    ]


# =====================================================
# cache.py
# =====================================================

def test_cache_hit():
    backend = Mock()

    backend.has.return_value = True

    cache = TupleCache(backend, ttl_seconds=100)

    assert cache.has("a", "r", "b") is True
    assert cache.has("a", "r", "b") is True

    assert backend.has.call_count == 1


def test_cache_expired(monkeypatch):
    backend = Mock()
    backend.has.return_value = True

    cache = TupleCache(backend, ttl_seconds=1)

    values = iter([0, 2])

    monkeypatch.setattr(
        "app.security.graph.storage.cache.time.monotonic",
        lambda: next(values),
    )

    assert cache.has("a", "r", "b") is True
    assert cache.has("a", "r", "b") is True

    assert backend.has.call_count == 2


def test_cache_find_objects_passthrough():
    backend = Mock()

    backend.find_objects.return_value = ["doc1"]

    cache = TupleCache(backend)

    assert cache.find_objects("alice", "edit") == ["doc1"]

    backend.find_objects.assert_called_once_with(
        "alice",
        "edit",
    )


def test_cache_find_subjects_passthrough():
    backend = Mock()

    backend.find_subjects.return_value = ["alice"]

    cache = TupleCache(backend)

    assert cache.find_subjects("edit", "doc1") == ["alice"]

    backend.find_subjects.assert_called_once_with(
        "edit",
        "doc1",
    )


def test_cache_add_passthrough():
    backend = Mock()

    cache = TupleCache(backend)

    cache.add("alice", "edit", "doc1")

    backend.add.assert_called_once_with(
        "alice",
        "edit",
        "doc1",
    )