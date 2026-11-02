"""Evidence store: the only way a fact enters the pipeline.

Each tool agent owns one store with its own prefix (ev-rec-, ev-enr-, ev-ti-),
so a citation shows which agent collected the fact. LLM agents never create
evidence; they only cite IDs from earlier stores.
"""
from __future__ import annotations

from core.envelope import Evidence, utc_now

PREFIXES = {"recon": "ev-rec-", "enrichment": "ev-enr-", "threat_intel": "ev-ti-"}


class EvidenceStore:
    def __init__(self, agent: str):
        self.prefix = PREFIXES[agent]
        self.items: list[Evidence] = []

    def add(self, type: str, subject: str, value: str, source: str) -> str:
        """Append one evidence item and return its new ID (numbered from 0001)."""
        evidence_id = f"{self.prefix}{len(self.items) + 1:04d}"
        self.items.append(
            Evidence(
                id=evidence_id,
                type=type,
                subject=subject,
                value=value,
                source=source,
                collected_at=utc_now(),
            )
        )
        return evidence_id
