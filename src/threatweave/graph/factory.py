"""Graph store construction from configuration.

Shared by the API and the CLI so both build the same backend the same way.
Seeding is intentionally *not* here — it is a demo concern handled by the API.
"""

from __future__ import annotations

from threatweave.config import Settings
from threatweave.graph.base import GraphStore
from threatweave.graph.memory import InMemoryGraphStore


def build_store(settings: Settings) -> GraphStore:
    """Return the graph store selected by ``settings.graph_backend``."""
    if settings.graph_backend == "memory":
        return InMemoryGraphStore()

    # Imported lazily so the memory backend needs no database driver at hand.
    from threatweave.graph.neo4j_store import Neo4jGraphStore

    return Neo4jGraphStore(
        uri=settings.neo4j.uri,
        user=settings.neo4j.user,
        password=settings.neo4j.password,
    )
