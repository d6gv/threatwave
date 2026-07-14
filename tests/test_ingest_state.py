"""Tests for the persistent per-source ingestion state."""

from __future__ import annotations

from pathlib import Path

from threatweave.ingest_state import IngestState


def test_unknown_source_has_no_state(tmp_path: Path) -> None:
    state = IngestState(tmp_path / "state.json")
    assert state.get("urlhaus") is None
    assert state.payload_hash("urlhaus") is None


def test_record_persists_and_reloads(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    IngestState(path).record(
        "urlhaus", status="ok", new_iocs=5, total_iocs=12, payload_hash="abc123"
    )

    # A fresh instance reads what the previous one wrote (cross-process contract).
    reloaded = IngestState(path)
    recorded = reloaded.get("urlhaus")
    assert recorded is not None
    assert recorded.status == "ok"
    assert recorded.new_iocs == 5
    assert recorded.total_iocs == 12
    assert recorded.last_run is not None
    assert reloaded.payload_hash("urlhaus") == "abc123"


def test_record_error_keeps_message(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    IngestState(path).record("feodo", status="error", error="connection refused")

    recorded = IngestState(path).get("feodo")
    assert recorded is not None
    assert recorded.status == "error"
    assert recorded.error == "connection refused"


def test_record_is_per_source(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    state = IngestState(path)
    state.record("urlhaus", status="ok", new_iocs=1)
    state.record("feodo", status="ok", new_iocs=2)

    snapshot = IngestState(path).snapshot()
    assert set(snapshot.sources) == {"urlhaus", "feodo"}
    assert snapshot.sources["feodo"].new_iocs == 2


def test_corrupt_state_file_starts_fresh(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    path.write_text("{not valid json", encoding="utf-8")

    state = IngestState(path)  # must not raise
    assert state.snapshot().sources == {}


def test_state_file_created_in_missing_directory(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "dir" / "state.json"
    IngestState(path).record("otx", status="ok")
    assert path.exists()
