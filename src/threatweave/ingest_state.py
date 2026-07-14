"""Persistent, cross-process record of the last ingestion per source.

The scheduled ingestion (``threatweave ingest``) usually runs in a *different*
process from the API (a cron job, Windows Task Scheduler, a VPS timer), so the
run status cannot live in application memory. It is persisted to a small JSON
file — outside the repo by default (``data/`` is git-ignored) — which the CLI
writes and the API reads for ``GET /api/ingest/status``.

The file also backs the payload-hash dedup: a source records the hash of the last
payload it processed, so an unchanged re-pull is skipped instead of reprocessed.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# Default location: under the git-ignored ``data/`` tree, so real run state never
# lands in the repo. Overridable (see ``INGEST_STATE_PATH``).
DEFAULT_STATE_PATH = Path("data/ingest_state.json")


class SourceState(BaseModel):
    """The outcome of the most recent ingestion run for one source."""

    source: str
    status: str = "never"  # "ok" | "error" | "never"
    last_run: datetime | None = None
    new_iocs: int = 0
    total_iocs: int = 0
    error: str | None = None
    # Hash of the last processed payload; powers the "skip unchanged pull" dedup.
    payload_hash: str | None = None


class IngestStateData(BaseModel):
    """The full persisted document: one :class:`SourceState` per source."""

    sources: dict[str, SourceState] = Field(default_factory=dict)


def _now() -> datetime:
    return datetime.now(UTC)


class IngestState:
    """Load/update/persist the ingestion state file for all sources.

    Instances hold the path and a loaded copy of the data. :meth:`record` mutates
    that copy and writes it back atomically, so a concurrent API read never sees a
    half-written file.
    """

    def __init__(self, path: Path | str = DEFAULT_STATE_PATH) -> None:
        self._path = Path(path)
        self._data = self._read()

    def _read(self) -> IngestStateData:
        if not self._path.exists():
            return IngestStateData()
        try:
            return IngestStateData.model_validate_json(
                self._path.read_text(encoding="utf-8")
            )
        except (ValueError, OSError):
            # A corrupt or unreadable state file must not crash ingestion; start
            # fresh and let the next successful run overwrite it.
            logger.warning("ignoring unreadable ingest state at %s", self._path)
            return IngestStateData()

    def get(self, source: str) -> SourceState | None:
        """Return the recorded state for ``source``, or ``None`` if never run."""
        return self._data.sources.get(source)

    def payload_hash(self, source: str) -> str | None:
        """Return the last processed payload hash for ``source`` (dedup key)."""
        state = self._data.sources.get(source)
        return state.payload_hash if state else None

    def snapshot(self) -> IngestStateData:
        """Return the current in-memory state (used by the status endpoint)."""
        return self._data.model_copy(deep=True)

    def record(
        self,
        source: str,
        *,
        status: str,
        new_iocs: int = 0,
        total_iocs: int = 0,
        error: str | None = None,
        payload_hash: str | None = None,
    ) -> None:
        """Record the outcome of a run for ``source`` and persist immediately."""
        self._data.sources[source] = SourceState(
            source=source,
            status=status,
            last_run=_now(),
            new_iocs=new_iocs,
            total_iocs=total_iocs,
            error=error,
            payload_hash=payload_hash,
        )
        self._write()

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        payload = self._data.model_dump_json(indent=2)
        # Atomic replace: write a sibling temp file, then rename over the target,
        # so a reader never observes a partially written document.
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self._path)
