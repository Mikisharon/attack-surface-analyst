"""Run recorder (FR-8): saves every agent envelope of one scan into one run file.

It is also the last line of the faithfulness check: before saving, it collects
every ID cited anywhere in the run and flags any that do not exist.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from core.envelope import PIPELINE_VERSION, Envelope, StepError
from core.llm import estimate_cost

ROOT = Path(__file__).resolve().parent.parent
RUNS_DIR = ROOT / "runs"

CITATION_RE = re.compile(r"\b(ev-(?:rec|enr|ti)-\d{4}|F-\d{4})\b")


def run_id_for(target: str, date: str) -> str:
    return f"{target.replace('.', '-')}-{date}"


def cited_ids(obj: Any) -> set[str]:
    """Every evidence/finding ID mentioned anywhere inside obj (lists, dicts, text)."""
    found: set[str] = set()
    if isinstance(obj, dict):
        for value in obj.values():
            found |= cited_ids(value)
    elif isinstance(obj, list):
        for value in obj:
            found |= cited_ids(value)
    elif isinstance(obj, str):
        found |= set(CITATION_RE.findall(obj))
    return found


def known_ids(steps: list[Envelope]) -> set[str]:
    ids = {ev.id for step in steps for ev in step.evidence}
    for step in steps:
        for finding in step.output.get("findings", []):
            ids.add(finding["id"])
    return ids


class Recorder:
    def __init__(self, target: str, runs_dir: Path = RUNS_DIR, label: str | None = None,
                 synthetic: bool = False):
        self.target = target
        self.runs_dir = Path(runs_dir)
        self.label = label
        self.synthetic = synthetic
        self.steps: list[Envelope] = []

    def add(self, envelope: Envelope) -> None:
        self.steps.append(envelope)

    def check_citations(self) -> int:
        """Flag (and degrade) any step that cites an ID that is not in the run."""
        valid = known_ids(self.steps)
        unknown_total = 0
        for step in self.steps:
            unknown = sorted(cited_ids(step.output) - valid)
            if unknown:
                unknown_total += len(unknown)
                step.errors.append(StepError(step="citation_check",
                                             reason=f"cites unknown IDs: {', '.join(unknown)}"))
                if step.status == "ok":
                    step.status = "degraded"
        return unknown_total

    def build(self) -> dict:
        unknown = self.check_citations()
        date = (self.steps[0].started_at[:10] if self.steps
                else datetime.utcnow().strftime("%Y-%m-%d"))
        by_agent = {s.agent: s for s in self.steps}
        hosts = by_agent.get("enrichment").output.get("hosts", []) if "enrichment" in by_agent else []
        counts = by_agent["prioritization"].output.get("counts", {}) if "prioritization" in by_agent else {}
        findings = by_agent["threat_intel"].output.get("findings", []) if "threat_intel" in by_agent else []
        cost = sum(estimate_cost(s.llm_usage.model, s.llm_usage.input_tokens, s.llm_usage.output_tokens)
                   for s in self.steps if s.llm_usage)
        models = sorted({s.llm_usage.model for s in self.steps if s.llm_usage})
        if any(s.status == "failed" for s in self.steps):
            status = "failed"
        elif any(s.status == "degraded" for s in self.steps):
            status = "degraded"
        else:
            status = "ok"
        return {
            "run_id": run_id_for(self.target, date),
            "target": self.target,
            "pipeline_version": PIPELINE_VERSION,
            "label": self.label,
            "synthetic": self.synthetic,
            "status": status,
            "steps": [s.model_dump() for s in self.steps],
            "summary": {
                "hosts": len(hosts),
                "live_hosts": sum(1 for h in hosts if h.get("live")),
                "findings": len(findings),
                "p1": counts.get("P1", 0),
                "p2": counts.get("P2", 0),
                "duration_s": _duration(self.steps),
                "cost_usd": round(cost, 4),
                "llm_models": models,
                "unknown_citations": unknown,
            },
        }

    def save(self) -> Path:
        run = self.build()
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        path = self.runs_dir / f"{run['run_id']}.json"
        path.write_text(json.dumps(run, indent=2) + "\n")
        update_index(self.runs_dir, run, path.name)
        return path


def _duration(steps: list[Envelope]) -> float:
    if not steps:
        return 0.0
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    start = datetime.strptime(steps[0].started_at, fmt)
    end = datetime.strptime(steps[-1].finished_at, fmt)
    return (end - start).total_seconds()


def update_index(runs_dir: Path, run: dict, filename: str) -> None:
    """runs/index.json lists available runs for the UI's target picker (newest first)."""
    index_path = runs_dir / "index.json"
    index = json.loads(index_path.read_text()) if index_path.exists() else {"runs": []}
    entries = [r for r in index["runs"] if r["run_id"] != run["run_id"]]
    entries.append({
        "run_id": run["run_id"],
        "target": run["target"],
        "date": run["run_id"][-10:],
        "file": filename,
        "label": run.get("label"),
        "synthetic": run.get("synthetic", False),
        "status": run["status"],
        "summary": run["summary"],
    })
    entries.sort(key=lambda r: (r["date"], r["run_id"]), reverse=True)
    index_path.write_text(json.dumps({"runs": entries}, indent=2) + "\n")
