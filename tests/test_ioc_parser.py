"""Tests for the deterministic regex IOC parser."""

from __future__ import annotations

from threatweave.models.ioc import IOCType
from threatweave.parsers.ioc_parser import parse_iocs, refang


def _values_of(text: str, ioc_type: IOCType) -> set[str]:
    return {ioc.value for ioc in parse_iocs(text) if ioc.type is ioc_type}


def test_extracts_valid_ipv4() -> None:
    values = _values_of("beacon to 192.168.1.10 and 8.8.8.8 observed", IOCType.IPV4)
    assert values == {"192.168.1.10", "8.8.8.8"}


def test_rejects_out_of_range_ipv4() -> None:
    # 999 is not a valid octet, so nothing should be extracted as an IP.
    assert _values_of("bogus 999.1.1.1 address", IOCType.IPV4) == set()


def test_classifies_hashes_by_length() -> None:
    md5 = "d41d8cd98f00b204e9800998ecf8427e"
    sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    text = f"iocs: {md5} {sha1} {sha256}"

    assert _values_of(text, IOCType.MD5) == {md5}
    assert _values_of(text, IOCType.SHA1) == {sha1}
    assert _values_of(text, IOCType.SHA256) == {sha256}


def test_hashes_are_lowercased() -> None:
    md5_upper = "D41D8CD98F00B204E9800998ECF8427E"
    assert _values_of(md5_upper, IOCType.MD5) == {md5_upper.lower()}


def test_extracts_domains_and_url() -> None:
    text = "download from http://evil.example.com/payload.bin then call home.bad.net"
    domains = _values_of(text, IOCType.DOMAIN)
    urls = _values_of(text, IOCType.URL)

    assert "evil.example.com" in domains
    assert "home.bad.net" in domains
    assert urls == {"http://evil.example.com/payload.bin"}


def test_file_extensions_are_not_domains() -> None:
    # "payload.exe" and "report.pdf" must not be misread as domains.
    domains = _values_of("dropped payload.exe and report.pdf", IOCType.DOMAIN)
    assert domains == set()


def test_refang_reverses_common_defanging() -> None:
    assert refang("hxxps://evil[.]com") == "https://evil.com"


def test_parses_defanged_indicators() -> None:
    text = "C2 at hxxp://malware[.]bad[.]com resolving to 10[.]0[.]0[.]5"
    domains = _values_of(text, IOCType.DOMAIN)
    ips = _values_of(text, IOCType.IPV4)
    urls = _values_of(text, IOCType.URL)

    assert "malware.bad.com" in domains
    assert "10.0.0.5" in ips
    assert urls == {"http://malware.bad.com"}


def test_deduplicates_and_sorts() -> None:
    text = "8.8.8.8 8.8.8.8 evil.com evil.com"
    results = parse_iocs(text)
    values = [(ioc.type.value, ioc.value) for ioc in results]

    # No duplicates, and output is sorted by (type, value).
    assert values == sorted(set(values))
    assert values.count(("ipv4", "8.8.8.8")) == 1


def test_source_is_attached() -> None:
    results = parse_iocs("8.8.8.8", source="unit-test")
    assert all(ioc.source == "unit-test" for ioc in results)
