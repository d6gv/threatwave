"""Tests for similar() and the semantic augmentation of correlate()."""

from __future__ import annotations

from tests.conftest import FakeProvider
from threatweave.connectors.document import DocumentIntel
from threatweave.correlation.correlate import correlate
from threatweave.correlation.similar import similar
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_document
from threatweave.llm.base import ExtractionResult
from threatweave.models.graph import RelationType
from threatweave.models.ioc import IOC, IOCType
from threatweave.vector.memory import InMemoryVectorStore

# Report A and B are close in vector space; C is orthogonal. Crucially, the three
# reports share NO exact IOC, so any link between A and B is purely semantic.
_VECTORS = {"a": [1.0, 0.0, 0.0], "b": [0.95, 0.05, 0.0], "c": [0.0, 1.0, 0.0]}
_REPORTS = [
    ("Report A", "1.1.1.1", "a"),
    ("Report B", "2.2.2.2", "b"),
    ("Report C", "3.3.3.3", "c"),
]


def _seed() -> tuple[InMemoryGraphStore, InMemoryVectorStore]:
    store = InMemoryGraphStore()
    vectors = InMemoryVectorStore()
    provider = FakeProvider(embeddings=_VECTORS)
    for name, ip, text in _REPORTS:
        intel = DocumentIntel(
            report_name=name,
            source="s",
            text=text,
            iocs=[IOC(value=ip, type=IOCType.IPV4)],
            extraction=ExtractionResult(),
        )
        ingest_document(store, intel, provider=provider, vector_store=vectors)
    return store, vectors


def test_similar_ranks_neighbours() -> None:
    _, vectors = _seed()
    neighbours = similar(vectors, "campaign:Report A", k=5)
    assert [n.id for n in neighbours] == ["campaign:Report B", "campaign:Report C"]
    assert neighbours[0].score > neighbours[1].score


def test_similar_missing_entity_returns_empty() -> None:
    assert similar(InMemoryVectorStore(), "campaign:Nope") == []


def test_similar_applies_min_score() -> None:
    _, vectors = _seed()
    neighbours = similar(vectors, "campaign:Report A", k=5, min_score=0.5)
    assert [n.id for n in neighbours] == ["campaign:Report B"]  # C dropped


def test_correlate_adds_semantic_edges_without_shared_ioc() -> None:
    store, vectors = _seed()
    sub = correlate(store, "1.1.1.1", depth=1, vector_store=vectors, min_score=0.5)

    node_ids = {n.id for n in sub.nodes}
    assert "campaign:Report B" in node_ids  # surfaced purely by similarity

    semantic = [e for e in sub.edges if e.type is RelationType.SEMANTIC_SIMILARITY]
    assert len(semantic) == 1
    assert semantic[0].source == "campaign:Report A"
    assert semantic[0].target == "campaign:Report B"
    assert semantic[0].score > 0.5


def test_correlate_without_vector_store_has_no_semantic_edges() -> None:
    store, _ = _seed()
    sub = correlate(store, "1.1.1.1", depth=1)
    assert all(e.type is not RelationType.SEMANTIC_SIMILARITY for e in sub.edges)
