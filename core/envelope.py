"""The agent output envelope (see skills/_shared/conventions.md, section 1).

Every agent returns exactly this structure, which is what makes the pipeline
chainable, testable and replayable.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

PIPELINE_VERSION = "0.1.0"

Status = Literal["ok", "degraded", "failed"]


def utc_now() -> str:
    """ISO 8601 UTC timestamp, e.g. 2026-11-08T10:00:02Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Evidence(BaseModel):
    id: str
    type: str
    subject: str
    value: str
    source: str
    collected_at: str


class StepError(BaseModel):
    step: str
    reason: str


class LLMUsage(BaseModel):
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    calls: int = 0

    def add(self, input_tokens: int, output_tokens: int) -> None:
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.calls += 1


class Envelope(BaseModel):
    agent: str
    version: str = PIPELINE_VERSION
    status: Status
    started_at: str
    finished_at: str
    input_ref: str
    output: dict[str, Any] = Field(default_factory=dict)
    evidence: list[Evidence] = Field(default_factory=list)
    errors: list[StepError] = Field(default_factory=list)
    llm_usage: Optional[LLMUsage] = None


def make_envelope(
    agent: str,
    input_ref: str,
    started_at: str,
    output: dict[str, Any],
    evidence: list[Evidence] | None = None,
    errors: list[StepError] | None = None,
    llm_usage: LLMUsage | None = None,
    status: Status | None = None,
) -> Envelope:
    """Build an envelope. If no status is given, any error means 'degraded'."""
    errors = errors or []
    if status is None:
        status = "degraded" if errors else "ok"
    return Envelope(
        agent=agent,
        status=status,
        started_at=started_at,
        finished_at=utc_now(),
        input_ref=input_ref,
        output=output,
        evidence=evidence or [],
        errors=errors,
        llm_usage=llm_usage,
    )
