"""Core intelligence entities: indicators of compromise, actors and campaigns."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class IOCType(StrEnum):
    """Supported indicator-of-compromise types.

    Only observable types that can be extracted deterministically (regex/parsers,
    no AI) are represented here.
    """

    IPV4 = "ipv4"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    DOMAIN = "domain"
    URL = "url"


class IOC(BaseModel):
    """A single indicator of compromise.

    Instances are frozen so they are hashable and can act as stable identities
    when building graph nodes and deduplicating parser output.
    """

    model_config = ConfigDict(frozen=True)

    value: str
    type: IOCType
    source: str | None = None
    first_seen: datetime | None = None


class Actor(BaseModel):
    """A threat actor / adversary group."""

    name: str
    aliases: tuple[str, ...] = Field(default_factory=tuple)


class Campaign(BaseModel):
    """A named campaign or operation grouping related activity."""

    name: str
    actor: str | None = None
