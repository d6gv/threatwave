"""Glue between ingestion connectors and the graph store.

Turns ingested intelligence into graph nodes and edges. For both OTX pulses and
free-text documents, a Campaign node is the hub: indicators, TTPs, the actor and
the targeted sectors all link to it. This is the deterministic source of
correlation — entities sharing a campaign are connected, so querying one surfaces
the others.
"""

from __future__ import annotations

import logging
from typing import Any

from threatweave.connectors.document import DocumentIntel
from threatweave.connectors.otx import normalize_indicators
from threatweave.graph.base import GraphStore
from threatweave.models.graph import (
    Node,
    RelationType,
    campaign_node_id,
    sector_node_id,
    ttp_node_id,
)
from threatweave.models.ioc import Actor, Campaign
from threatweave.models.normalize import normalize_sector, sector_display

logger = logging.getLogger(__name__)


def ingest_otx_payload(
    store: GraphStore, payload: dict[str, Any], *, source: str = "alienvault-otx"
) -> int:
    """Ingest a raw OTX pulses payload into ``store``.

    Args:
        store: Destination graph store.
        payload: Parsed OTX pulses response.
        source: Provenance label stamped on ingested IOCs.

    Returns:
        The number of IOC nodes written (counting each indicator once per pulse).
    """
    written = 0
    for pulse in payload.get("results", []):
        campaign_name = pulse.get("name") or pulse.get("id")
        campaign_node = (
            store.upsert_campaign(Campaign(name=campaign_name)) if campaign_name else None
        )

        # Reuse the connector's normalization on this single pulse.
        for ioc in normalize_indicators({"results": [pulse]}, source=source):
            ioc_node = store.upsert_ioc(ioc)
            if campaign_node is not None:
                store.add_edge(ioc_node.id, campaign_node.id, RelationType.PART_OF)
            written += 1

    logger.info("ingested %d IOC nodes from OTX payload", written)
    return written


def ingest_document(store: GraphStore, intel: DocumentIntel) -> Node:
    """Ingest a document's extracted intelligence into ``store``.

    Creates a Campaign node for the report and links, all through it:
    IOCs (``PART_OF``), the actor (``ATTRIBUTED_TO``), TTPs (``USES``) and
    normalized target sectors (``TARGETS``). Returns the campaign node.
    """
    campaign = store.upsert_campaign(Campaign(name=intel.report_name))

    if intel.extraction.actor:
        actor = store.upsert_actor(Actor(name=intel.extraction.actor))
        store.add_edge(campaign.id, actor.id, RelationType.ATTRIBUTED_TO)

    for ttp in intel.extraction.ttps:
        ttp_node = store.upsert_node(
            Node(
                id=ttp_node_id(ttp.technique_id),
                kind="ttp",
                label=ttp.name or ttp.technique_id,
            )
        )
        store.add_edge(campaign.id, ttp_node.id, RelationType.USES)

    # Normalize sectors so different wordings collapse onto one node.
    seen_sectors: set[str] = set()
    for raw_sector in intel.extraction.target_sectors:
        canonical = normalize_sector(raw_sector)
        if not canonical or canonical in seen_sectors:
            continue
        seen_sectors.add(canonical)
        sector_node = store.upsert_node(
            Node(
                id=sector_node_id(canonical),
                kind="sector",
                label=sector_display(canonical),
            )
        )
        store.add_edge(campaign.id, sector_node.id, RelationType.TARGETS)

    for ioc in intel.iocs:
        ioc_node = store.upsert_ioc(ioc)
        store.add_edge(ioc_node.id, campaign.id, RelationType.PART_OF)

    logger.info(
        "ingested document %r: %d IOCs, %d TTPs, %d sectors, actor=%s",
        intel.report_name,
        len(intel.iocs),
        len(intel.extraction.ttps),
        len(seen_sectors),
        intel.extraction.actor or "-",
    )
    return campaign


# ``campaign_node_id`` is re-exported for callers that need the hub id.
__all__ = ["ingest_otx_payload", "ingest_document", "campaign_node_id"]
