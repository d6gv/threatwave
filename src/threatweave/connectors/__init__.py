"""Ingestion connectors: pull intelligence from external feeds and normalize it
into the internal :class:`~threatweave.models.ioc.IOC` model.
"""

from threatweave.connectors.base import Connector
from threatweave.connectors.document import DocumentConnector, DocumentIntel, html_to_text
from threatweave.connectors.otx import OTXConnector

__all__ = [
    "Connector",
    "OTXConnector",
    "DocumentConnector",
    "DocumentIntel",
    "html_to_text",
]
