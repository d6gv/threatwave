"""Deterministic extraction of obvious IOCs from free text using regex.

This module intentionally contains **no AI**. It recognises the unambiguous
indicator types (IPv4, MD5/SHA1/SHA256 hashes, domains and URLs) that can be
matched reliably with patterns. Fuzzy/contextual extraction (TTPs, actor names,
malware families from prose) is the job of the reserved ``LLMProvider.extract``
in a later phase.
"""

from __future__ import annotations

import re

from threatweave.models.ioc import IOC, IOCType

# --- Refanging -------------------------------------------------------------

# Threat reports routinely "defang" indicators so they are not clickable, e.g.
# ``hxxp://evil[.]com``. We reverse the most common transformations before
# matching so the patterns below stay simple.
_REFANG_SUBSTITUTIONS: tuple[tuple[str, str], ...] = (
    ("hxxps", "https"),
    ("hxxp", "http"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[:]", ":"),
    ("[//]", "//"),
)


def refang(text: str) -> str:
    """Return ``text`` with common IOC defanging reversed."""
    result = text
    for defanged, fanged in _REFANG_SUBSTITUTIONS:
        result = result.replace(defanged, fanged)
    return result


# --- Patterns --------------------------------------------------------------

# Hashes: hex strings of exact lengths, longest first so a SHA256 is not
# partially matched as an MD5. Word boundaries prevent matching inside longer
# alphanumeric tokens.
_HASH_PATTERNS: tuple[tuple[IOCType, re.Pattern[str]], ...] = (
    (IOCType.SHA256, re.compile(r"\b[a-fA-F0-9]{64}\b")),
    (IOCType.SHA1, re.compile(r"\b[a-fA-F0-9]{40}\b")),
    (IOCType.MD5, re.compile(r"\b[a-fA-F0-9]{32}\b")),
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

_URL_RE = re.compile(r"\bhttps?://[^\s<>\"'\]]+", re.IGNORECASE)

# Domain: one or more labels followed by an alphabetic TLD of length >= 2.
_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

# Common file extensions that look like a domain TLD but are not, so we do not
# flag ``report.pdf`` or ``payload.exe`` as domains.
_FILE_EXTENSIONS: frozenset[str] = frozenset(
    {
        "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jar",
        "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "rtf", "txt",
        "png", "jpg", "jpeg", "gif", "bmp", "svg", "ico",
        "zip", "rar", "7z", "gz", "tar", "iso", "bin",
        "html", "htm", "php", "asp", "aspx", "py", "sh", "dat", "log", "tmp",
    }
)

# Characters commonly trailing a URL in prose that are not part of it.
_URL_TRAILING = ".,;:)]}>\"'"


def _valid_ipv4(candidate: str) -> bool:
    """Return True if every octet of ``candidate`` is in the 0-255 range."""
    return all(octet.isdigit() and int(octet) <= 255 for octet in candidate.split("."))


def parse_iocs(text: str, *, source: str | None = None) -> list[IOC]:
    """Extract IOCs from ``text`` and return them deduplicated and sorted.

    The text is refanged first. Each indicator type is matched independently, so
    a URL and its host are both reported as distinct IOCs (their downstream
    relationship is established by the graph layer, not here). Results are
    deduplicated by ``(type, value)`` and sorted for deterministic output.

    Args:
        text: Free-form text to scan.
        source: Optional provenance label stored on every produced IOC.

    Returns:
        A deterministically ordered list of unique :class:`IOC` instances.
    """
    fanged = refang(text)

    # Deduplicate by (type, value); value is normalized per type below.
    found: dict[tuple[IOCType, str], IOC] = {}

    def add(ioc_type: IOCType, value: str) -> None:
        key = (ioc_type, value)
        if key not in found:
            found[key] = IOC(value=value, type=ioc_type, source=source)

    # Hashes are lowercased for a canonical form.
    for ioc_type, pattern in _HASH_PATTERNS:
        for match in pattern.findall(fanged):
            add(ioc_type, match.lower())

    for match in _IPV4_RE.findall(fanged):
        if _valid_ipv4(match):
            add(IOCType.IPV4, match)

    for raw in _URL_RE.findall(fanged):
        add(IOCType.URL, raw.rstrip(_URL_TRAILING))

    for match in _DOMAIN_RE.findall(fanged):
        tld = match.rsplit(".", 1)[-1].lower()
        if tld in _FILE_EXTENSIONS:
            continue
        add(IOCType.DOMAIN, match.lower())

    return sorted(found.values(), key=lambda ioc: (ioc.type.value, ioc.value))
