"""Tests for the document connector: HTML parsing and hybrid extraction."""

from __future__ import annotations

import httpx

from tests.conftest import FakeProvider
from threatweave.connectors.document import DocumentConnector, html_to_text


def test_html_to_text_strips_scripts_and_reads_title() -> None:
    html = (
        "<html><head><title>Threat Report</title>"
        "<style>.x{color:red}</style></head>"
        "<body><script>evil()</script><p>C2 at 198.51.100.23</p></body></html>"
    )
    title, text = html_to_text(html)

    assert title == "Threat Report"
    assert "evil()" not in text
    assert "color:red" not in text
    assert "198.51.100.23" in text


def test_from_text_runs_hybrid_extraction(fake_provider: FakeProvider) -> None:
    connector = DocumentConnector(fake_provider)
    intel = connector.from_text(
        "APT-Sample phishing. C2 198.51.100.23 and staging.malicious.example",
        source="inline",
    )

    ioc_values = {ioc.value for ioc in intel.iocs}
    assert "198.51.100.23" in ioc_values  # regex owns IOCs
    assert "staging.malicious.example" in ioc_values
    assert [t.technique_id for t in intel.extraction.ttps] == ["T1566.001", "T1071.001"]
    assert intel.extraction.actor == "APT-Sample"
    assert fake_provider.calls  # the LLM was invoked


def test_from_text_truncates_llm_input_but_not_regex(fake_provider: FakeProvider) -> None:
    connector = DocumentConnector(fake_provider, max_input_chars=10)
    text = "A" * 60 + " 8.8.8.8"

    intel = connector.from_text(text, source="inline")

    # Regex parsed the full text, so the IP is still found...
    assert any(ioc.value == "8.8.8.8" for ioc in intel.iocs)
    # ...but the LLM only saw the truncated prefix.
    assert len(fake_provider.calls[-1]) == 10


def test_from_url_parses_html(fake_provider: FakeProvider) -> None:
    html = "<title>Report Title</title><body><p>C2 staging.malicious.example</p></body>"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text=html, headers={"content-type": "text/html"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    connector = DocumentConnector(fake_provider, client=client)

    intel = connector.from_url("https://threat.test/report")

    assert intel.report_name == "Report Title"
    assert intel.source == "https://threat.test/report"
    assert any(ioc.value == "staging.malicious.example" for ioc in intel.iocs)


def test_from_text_on_sample_report(
    sample_report: str, fake_provider: FakeProvider
) -> None:
    connector = DocumentConnector(fake_provider)
    intel = connector.from_text(sample_report, name="Sample", source="sample")

    ioc_values = {ioc.value for ioc in intel.iocs}
    assert "198.51.100.23" in ioc_values
    assert "staging.malicious.example" in ioc_values
    assert "http://malicious.example/update/payload.bin" in ioc_values
    assert (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in ioc_values
    )
