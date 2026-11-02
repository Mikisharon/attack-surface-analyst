"""Prioritization agent (FR-6). Spec: skills/prioritization/SKILL.md.

Hybrid agent:
- Part A (code) computes a baseline P1-P4 from reference/scoring-rubric.md.
- Part B (LLM) reviews one host's findings at a time and may move each by at most one level.
- Part C (code) rejects anything that breaks the rules and falls back to the baseline.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from core.envelope import Envelope, LLMUsage, StepError, make_envelope, utc_now
from core.llm import BaseLLM, load_skill

AGENT = "prioritization"
LEVELS = ["P1", "P2", "P3", "P4"]
IMPORTANCE_ORDER = {"high": 0, "medium": 1, "low": 2, None: 3}
KIND_POINTS = {"sensitive_service_exposed": ("sensitive_service", 30),
               "non_production_exposed": ("non_production", 20),
               "default_page_exposed": ("default_page", 15),
               "unverified_version": ("unverified_version", 10),
               "no_https": ("no_https", 15),
               "missing_hsts": ("missing_hsts", 5)}
SUSPICIOUS_ADJUSTED_SHARE = 0.5


# ---------------------------------------------------------------- Part A: baseline

def baseline(finding: dict, importance: str | None) -> tuple[str, int, list[str]]:
    """Return (priority, points, rules_applied) from the scoring rubric."""
    rules, points = [], 0
    if finding.get("in_kev"):
        rules.append("kev_listed")
        points += 100
        if finding.get("kev_ransomware"):
            rules.append("kev_ransomware")
            points += 10
    if finding["kind"] == "known_vulnerability" and finding.get("cvss") is not None:
        cvss = finding["cvss"]
        rule, value = (("cvss_9_plus", 40) if cvss >= 9 else ("cvss_7_to_9", 30) if cvss >= 7
                       else ("cvss_4_to_7", 15) if cvss >= 4 else ("cvss_below_4", 5))
        rules.append(rule)
        points += value
    if finding["kind"] in KIND_POINTS:
        rule, value = KIND_POINTS[finding["kind"]]
        rules.append(rule)
        points += value
    imp = importance or "low"
    rules.append(f"importance_{imp}")
    points += {"high": 20, "medium": 10, "low": 0}[imp]

    if points >= 100 or finding.get("in_kev"):
        priority = "P1"
    elif points >= 45:
        priority = "P2"
    elif points >= 20:
        priority = "P3"
    else:
        priority = "P4"
    return priority, points, rules


def shift(priority: str, steps: int) -> str:
    return LEVELS[max(0, min(3, LEVELS.index(priority) + steps))]


# ---------------------------------------------------------------- Part B: review

class Decision(BaseModel):
    finding_id: str
    baseline: Literal["P1", "P2", "P3", "P4"]
    final: Literal["P1", "P2", "P3", "P4"]
    adjustment: Literal["up", "down", "none"]
    rationale: str
    evidence_ids: list[str]


class HostReview(BaseModel):
    decisions: list[Decision]


def heuristic_review(payload: dict) -> dict:
    """Offline stand-in for the LLM, using the 'reasons to move' list from SKILL.md."""
    host = payload["host"]
    name = host["name"].lower()
    forgotten = any(word in name for word in ("old", "legacy", "backup"))
    decisions = []
    for f in payload["findings"]:
        base, final, adj = f["baseline"], f["baseline"], "none"
        cite = f["evidence_ids"][0] if f["evidence_ids"] else f["id"]
        rationale = f"Baseline kept: the rubric score fits the evidence ({cite})."
        if forgotten and base != "P1" and f["kind"] != "missing_hsts":
            final, adj = shift(base, -1), "up"
            rationale = (f"Host name suggests a forgotten asset that is still live, so this is "
                         f"raised one level ({cite}).")
        elif host.get("role") == "cdn_or_redirect" and base != "P4" and not f.get("in_kev"):
            final, adj = shift(base, 1), "down"
            rationale = f"The host only redirects, which limits exposure ({cite})."
        decisions.append({"finding_id": f["id"], "baseline": base, "final": final,
                          "adjustment": adj, "rationale": rationale, "evidence_ids": [cite]})
    return {"decisions": decisions}


def check_decision(d: Decision, finding: dict, valid_ids: set[str]) -> list[str]:
    """Part C rules for one decision. Returns the reasons it must be rejected."""
    problems = []
    gap = LEVELS.index(d.final) - LEVELS.index(finding["baseline"])
    if d.baseline != finding["baseline"]:
        problems.append(f"{d.finding_id}: baseline is {finding['baseline']}, not {d.baseline}")
    if abs(gap) > 1:
        problems.append(f"{d.finding_id}: moved {abs(gap)} levels; at most one is allowed")
    if finding.get("in_kev") and d.final != "P1":
        problems.append(f"{d.finding_id}: KEV-listed findings must stay P1")
    expected = "none" if gap == 0 else "up" if gap < 0 else "down"
    if d.adjustment != expected:
        problems.append(f"{d.finding_id}: adjustment should be '{expected}'")
    if not d.evidence_ids or any(i not in valid_ids for i in d.evidence_ids):
        problems.append(f"{d.finding_id}: rationale must cite evidence IDs from the input")
    return problems


# ---------------------------------------------------------------- agent entry point

def run(enrichment: Envelope, threat_intel: Envelope, llm: BaseLLM,
        evidence_ids: set[str]) -> Envelope:
    started = utc_now()
    errors: list[StepError] = []
    hosts = {h["name"]: h for h in enrichment.output.get("hosts", [])}
    # Copy, so the Threat Intel envelope stays exactly as that agent recorded it.
    findings = [dict(f) for f in threat_intel.output.get("findings", [])]

    for f in findings:
        imp = hosts.get(f["host"], {}).get("importance")
        f_base, points, rules = baseline(f, imp)
        f.update({"baseline": f_base, "score": points, "rules_applied": rules})

    system = load_skill("prioritization")
    usage = LLMUsage(model=llm.model)
    results: dict[str, dict] = {}
    by_host: dict[str, list[dict]] = {}
    for f in findings:
        by_host.setdefault(f["host"], []).append(f)

    for host_name, host_findings in sorted(by_host.items()):
        host = hosts.get(host_name, {"name": host_name})
        valid_ids = evidence_ids | {f["id"] for f in host_findings}
        payload = {
            "host": {k: host.get(k) for k in ("name", "role", "importance", "reason", "title",
                                              "https", "status", "products")},
            "findings": [{k: f.get(k) for k in ("id", "kind", "product", "cve", "cvss", "in_kev",
                                                "summary", "evidence_ids", "baseline", "rules_applied")}
                         for f in host_findings],
        }
        wanted = {f["id"]: f for f in host_findings}

        def validate(review: HostReview) -> list[str]:
            got = [d.finding_id for d in review.decisions]
            problems = [] if sorted(got) == sorted(wanted) else [
                f"return exactly one decision per finding: {sorted(wanted)}"]
            for d in review.decisions:
                if d.finding_id in wanted:
                    problems += check_decision(d, wanted[d.finding_id], valid_ids)
            return problems

        answer = llm.ask_json(system=system,
                              task="Review the baseline priority of each finding on this host.",
                              payload=payload, schema=HostReview, fallback=heuristic_review,
                              validate=validate, effort="low")
        usage.add(answer.input_tokens, answer.output_tokens)
        decisions = {d.finding_id: d for d in (answer.data.decisions if answer.data else [])}
        for fid, f in wanted.items():
            d = decisions.get(fid)
            problems = check_decision(d, f, valid_ids) if d else ["no decision returned"]
            if problems:
                # Part C: invalid adjustment -> fall back to the rubric baseline.
                errors.append(StepError(step=f"review {fid}", reason="; ".join(problems) + "; baseline used"))
                results[fid] = {"final": f["baseline"], "adjustment": "none",
                                "rationale": f"Baseline kept: the LLM review was rejected by validation "
                                             f"({(f['evidence_ids'] or [fid])[0]}).",
                                "evidence_ids": f["evidence_ids"][:1], "fallback": True}
            else:
                results[fid] = {"final": d.final, "adjustment": d.adjustment,
                                "rationale": d.rationale, "evidence_ids": d.evidence_ids}

    prioritized = []
    for f in findings:
        r = results[f["id"]]
        prioritized.append({"finding_id": f["id"], "host": f["host"], "kind": f["kind"],
                            "baseline": f["baseline"], "score": f["score"], **r,
                            "rules_applied": f["rules_applied"]})
    prioritized.sort(key=lambda p: (LEVELS.index(p["final"]),
                                    IMPORTANCE_ORDER.get(hosts.get(p["host"], {}).get("importance"), 3),
                                    p["finding_id"]))
    moved = sum(1 for p in prioritized if p["adjustment"] != "none")
    share = round(moved / len(prioritized), 2) if prioritized else 0.0
    if share > SUSPICIOUS_ADJUSTED_SHARE:
        errors.append(StepError(step="adjustment share",
                                reason=f"LLM moved {share:.0%} of findings; the rubric or prompt may need work"))
    output = {"prioritized": prioritized,
              "counts": {lvl: sum(1 for p in prioritized if p["final"] == lvl) for lvl in LEVELS},
              "adjusted_share": share}
    return make_envelope(AGENT, "threat_intel", started, output, [], errors, llm_usage=usage)
