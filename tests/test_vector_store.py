"""Tests for the in-memory vector store (contract shared with pgvector)."""

from __future__ import annotations

from threatweave.vector.base import content_hash
from threatweave.vector.memory import InMemoryVectorStore


def test_search_orders_by_cosine_similarity() -> None:
    store = InMemoryVectorStore()
    store.upsert("a", [1.0, 0.0, 0.0])
    store.upsert("b", [0.9, 0.1, 0.0])
    store.upsert("c", [0.0, 1.0, 0.0])

    results = store.search([1.0, 0.0, 0.0], k=3, exclude="a")

    assert [n.id for n in results] == ["b", "c"]
    assert results[0].score > results[1].score


def test_search_excludes_and_limits_k() -> None:
    store = InMemoryVectorStore()
    for name in ("a", "b", "c"):
        store.upsert(name, [1.0, 0.0, 0.0])

    results = store.search([1.0, 0.0, 0.0], k=1, exclude="a")
    assert len(results) == 1
    assert results[0].id != "a"


def test_get_returns_vector_or_none() -> None:
    store = InMemoryVectorStore()
    store.upsert("a", [1.0, 2.0, 3.0])
    assert store.get("a") == [1.0, 2.0, 3.0]
    assert store.get("missing") is None


def test_upsert_replaces_existing_vector() -> None:
    store = InMemoryVectorStore()
    store.upsert("a", [1.0, 0.0, 0.0])
    store.upsert("a", [0.0, 1.0, 0.0])
    assert store.get("a") == [0.0, 1.0, 0.0]


def test_has_respects_content_hash_cache() -> None:
    store = InMemoryVectorStore()
    store.upsert("a", [1.0, 0.0], content_hash=content_hash("text"))

    assert store.has("a")  # exists, any hash
    assert store.has("a", content_hash=content_hash("text"))  # unchanged
    assert not store.has("a", content_hash=content_hash("different"))  # changed
    assert not store.has("missing")


def test_zero_vector_scores_zero() -> None:
    store = InMemoryVectorStore()
    store.upsert("zero", [0.0, 0.0, 0.0])
    store.upsert("unit", [1.0, 0.0, 0.0])

    scores = {n.id: n.score for n in store.search([1.0, 0.0, 0.0], k=5)}
    assert scores["zero"] == 0.0
    assert scores["unit"] > 0.9
