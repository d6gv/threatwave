"""Tests for inserting extracted document intelligence into the graph."""

from __future__ import annotations

from threatweave.connectors.document import DocumentIntel
from threatweave.graph.memory import InMemoryGraphStore
from threatweave.ingest import ingest_document
from threatweave.llm.base import TTP, ExtractionResult
from threatweave.models.graph import campaign_node_id
from threatweave.models.ioc import IOC, IOCType


def test_ingest_document_creates_nodes_and_edges(store: InMemoryGraphStore) -> None:
    intel = DocumentIntel(
        report_name="Report X",
        source="inline",
        iocs=[IOC(value="198.51.100.23", type=IOCType.IPV4)],
        extraction=ExtractionResult(
            ttps=[TTP(technique_id="T1566", name="Phishing")],
            actor="APT-Sample",
            target_sectors=["Finance", "Healthcare"],
        ),
    )

    campaign = ingest_document(store, intel)

    assert store.get_node("actor:APT-Sample").kind == "actor"
    assert store.get_node("ttp:T1566").kind == "ttp"
    assert store.get_node("sector:financial services") is not None
    assert store.get_node("sector:healthcare") is not None

    sub = store.neighborhood(campaign.id, depth=1)
    edge_types = {edge.type.value for edge in sub.edges}
    assert edge_types == {"attributed_to", "uses", "targets", "part_of"}


def test_ingest_document_normalizes_and_dedupes_sectors(
    store: InMemoryGraphStore,
) -> None:
    # "Finance", "financial" and "banking" all alias to one canonical sector.
    intel = DocumentIntel(
        report_name="R",
        source="s",
        extraction=ExtractionResult(target_sectors=["Finance", "financial", "banking"]),
    )
    ingest_document(store, intel)

    sub = store.neighborhood(campaign_node_id("R"), depth=1)
    sector_nodes = [node for node in sub.nodes if node.kind == "sector"]
    assert len(sector_nodes) == 1
    assert sector_nodes[0].label == "Financial Services"


def test_ingest_document_without_actor_or_ttps(store: InMemoryGraphStore) -> None:
    intel = DocumentIntel(
        report_name="Bare",
        source="s",
        iocs=[IOC(value="8.8.8.8", type=IOCType.IPV4)],
        extraction=ExtractionResult(),
    )
    campaign = ingest_document(store, intel)

    sub = store.neighborhood(campaign.id, depth=1)
    # Only the IOC links to the campaign; no actor/ttp/sector nodes created.
    assert {node.kind for node in sub.nodes} == {"campaign", "ioc"}
