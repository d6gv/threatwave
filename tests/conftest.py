"""Shared pytest fixtures."""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

from threatweave.graph.memory import InMemoryGraphStore
from threatweave.llm.base import TTP, ExtractionResult, LLMProvider

_SAMPLES = Path(__file__).resolve().parents[1] / "data" / "samples"


class FakeProvider(LLMProvider):
    """A stub LLM provider returning a fixed extraction, with call recording.

    Lets the whole ingestion pipeline be tested offline without any API calls.
    """

    def __init__(self, result: ExtractionResult | None = None) -> None:
        self.result = result or ExtractionResult()
        self.calls: list[str] = []

    def extract(self, text: str) -> ExtractionResult:
        self.calls.append(text)
        return self.result

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        raise NotImplementedError

    def narrate(self, subgraph: object) -> str:
        raise NotImplementedError


@pytest.fixture
def otx_payload() -> dict[str, Any]:
    """The synthetic OTX subscribed-pulses response used for offline tests."""
    return json.loads((_SAMPLES / "otx_subscribed.json").read_text(encoding="utf-8"))


@pytest.fixture
def sample_report() -> str:
    """The synthetic free-text threat report used for offline tests."""
    return (_SAMPLES / "threat_report.txt").read_text(encoding="utf-8")


@pytest.fixture
def store() -> InMemoryGraphStore:
    """A fresh in-memory graph store."""
    return InMemoryGraphStore()


@pytest.fixture
def fake_provider() -> FakeProvider:
    """A FakeProvider returning a representative extraction result."""
    return FakeProvider(
        ExtractionResult(
            ttps=[
                TTP(technique_id="T1566.001", name="Spearphishing Attachment"),
                TTP(technique_id="T1071.001", name="Web Protocols"),
            ],
            actor="APT-Sample",
            target_sectors=["Finance", "financial services"],
        )
    )
