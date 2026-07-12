"""Tests for the CLI: argument parsing and the ingest-doc command (mocked LLM)."""

from __future__ import annotations

import argparse

import pytest

from tests.conftest import FakeProvider
from threatweave.cli import build_parser, run_ingest_doc
from threatweave.graph.memory import InMemoryGraphStore


def test_parser_requires_a_source() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["ingest-doc"])


def test_parser_rejects_multiple_sources() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["ingest-doc", "--url", "u", "--text", "t"])


def test_run_ingest_doc_from_text_populates_graph(
    store: InMemoryGraphStore, fake_provider: FakeProvider
) -> None:
    args = argparse.Namespace(
        url=None, file=None, text="APT-Sample phishing 198.51.100.23 evil.example"
    )
    run_ingest_doc(args, store=store, provider=fake_provider)

    assert store.get_node("actor:APT-Sample") is not None
    assert store.get_node("ttp:T1566.001") is not None
    assert store.get_node("ioc:ipv4:198.51.100.23") is not None


def test_run_ingest_doc_from_file(
    tmp_path, store: InMemoryGraphStore, fake_provider: FakeProvider
) -> None:
    report = tmp_path / "report.txt"
    report.write_text("APT-Sample C2 at 8.8.8.8", encoding="utf-8")

    args = argparse.Namespace(url=None, file=str(report), text=None)
    run_ingest_doc(args, store=store, provider=fake_provider)

    assert store.get_node("ioc:ipv4:8.8.8.8") is not None
    assert store.get_node("actor:APT-Sample") is not None
