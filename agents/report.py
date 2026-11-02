"""Report agent (FR-7). Spec: skills/report/SKILL.md.

LLM-led: code builds the findings table straight from data (so it can never be
wrong about what was found) and validates the narrative; the LLM writes the
executive summary, recommendations and data limitations.
"""
from __future__ import annotations

import re

from pydantic import BaseModel

from core.envelope import Envelope, LLMUsage, StepError, make_envelope, utc_now
from core.llm import BaseLLM, load_skill
from core.recorder import CITATION_RE

AGENT = "report"
MAX_SUMMARY_WORDS = 150
KIND_LABELS = {
    "known_vulnerability": "Known vulnerability",
    "sensitive_service_exposed": "Sensitive service exposed",
    "non_production_exposed": "Non-production host exposed",
    "default_page_exposed": "Default page exposed",
    "no_https": "No HTTPS",
    "missing_hsts": "Missing HSTS header",
    "unverified_version": "Unverified software version",
}


class Recommendation(BaseModel):
    action: str
    finding_ids: list[str]


class Narrative(BaseModel):
    executive_summary: str
    recommendations: list[Recommendation]
    limitations: str


# ---------------------------------------------------------------- Part A: table

def findings_table(prioritized: list[dict], findings: dict[str, dict]) -> list[dict]:
    rows = []
    for p in prioritized:
        f = findings[p["finding_id"]]
        title = KIND_LABELS[f["kind"]]
        if f.get("cve"):
            title = f"{f['cve']} in {f['product']}" + (" (CISA KEV)" if f.get("in_kev") else "")
        details = f["summary"]
        if f.get("cvss") is not None:
            details = f"CVSS {f['cvss']} {f['severity']}. {details}"
        rows.append({"finding_id": p["finding_id"], "priority": p["final"], "host": p["host"],
                     "finding": title, "details": details,
                     "evidence_ids": sorted(set(f["evidence_ids"]) | set(p.get("evidence_ids", [])))})
    return rows


# ---------------------------------------------------------------- Part B: narrative

def heuristic_narrative(payload: dict) -> dict:
    """Offline stand-in for the LLM: a plain, template-based narrative from the same facts."""
    c, rows = payload["counts"], payload["findings"]
    urgent = [r for r in rows if r["priority"] in ("P1", "P2")]
    cite = f" [{rows[0]['finding_id']}]" if rows else ""
    summary = (f"We checked {payload['host_count']} hosts ({payload['live_count']} live) and "
               f"recorded {sum(c.values())} findings{cite}. ")
    if urgent:
        top = urgent[0]
        risk = ("software with a vulnerability that attackers are known to be exploiting"
                if top.get("in_kev") else "a service that should not be openly reachable"
                if top["kind"] in ("sensitive_service_exposed", "non_production_exposed")
                else "a serious weakness")
        summary += (f"{c['P1']} findings need action now and {c['P2']} more this sprint [{top['finding_id']}]. "
                    f"The most important risk is {risk} on {top['host']} [{top['finding_id']}].")
    else:
        summary += "No urgent issues were found: there are no P1 or P2 findings."
        if rows:
            summary += f" The remaining items are lower-priority hygiene fixes [{rows[0]['finding_id']}]."
    recs, seen_hosts = [], set()
    for r in rows:
        if len(recs) >= 5 or (r["priority"] not in ("P1", "P2") and len(recs) >= 3):
            break
        # One recommendation per host and fix: per product for CVEs, per kind otherwise.
        key = (r["host"], r["kind"], r.get("product") if r["kind"] == "known_vulnerability" else None)
        if key in seen_hosts:
            continue
        seen_hosts.add(key)
        if r["kind"] == "known_vulnerability":
            action = f"Upgrade {r['product']} on {r['host']} to a version without these known vulnerabilities"
        elif r["kind"] in ("sensitive_service_exposed", "non_production_exposed", "default_page_exposed"):
            action = f"Restrict internet access to {r['host']} (VPN, IP allowlist or decommission): {r['finding'].lower()}"
        elif r["kind"] == "no_https":
            action = f"Enable HTTPS on {r['host']} and redirect plain HTTP to it"
        elif r["kind"] == "missing_hsts":
            action = f"Add a Strict-Transport-Security header on {r['host']}"
        else:
            action = f"Confirm the exact software version on {r['host']} so it can be checked for CVEs"
        ids = [x["finding_id"] for x in rows if (x["host"], x["kind"],
               x.get("product") if x["kind"] == "known_vulnerability" else None) == key]
        recs.append({"action": f"{action} [{', '.join(ids)}].", "finding_ids": ids})
    if payload["degraded_steps"]:
        limitations = " ".join(
            f"The {s['agent'].replace('_', ' ')} step was degraded: {s['errors'][0]}." for s in payload["degraded_steps"])
    else:
        limitations = "All data sources responded."
    return {"executive_summary": summary, "recommendations": recs, "limitations": limitations}


def allowed_numbers(payload: dict) -> set[int]:
    c = payload["counts"]
    total = sum(c.values())
    return {payload["host_count"], payload["live_count"], total, c["P1"], c["P2"], c["P3"], c["P4"],
            c["P1"] + c["P2"], payload["kev_count"]}


def validate_narrative(n: Narrative, payload: dict, valid_ids: set[str]) -> list[str]:
    """Part C: counts, citations, length and the 'no CVE IDs in the summary' rule."""
    problems = []
    words = len(n.executive_summary.split())
    if words > MAX_SUMMARY_WORDS:
        problems.append(f"executive summary has {words} words; the maximum is {MAX_SUMMARY_WORDS}")
    if re.search(r"CVE-\d{4}-\d+", n.executive_summary):
        problems.append("the executive summary must not contain CVE IDs")
    # Every number in the summary must be one of the real counts. Citations and
    # priority labels (P1..P4) are removed first because they contain digits.
    text = CITATION_RE.sub("", n.executive_summary)
    text = re.sub(r"\bP[1-4]\b", "", text)
    numbers = {int(x) for x in re.findall(r"\b\d+\b", text)}
    wrong = sorted(numbers - allowed_numbers(payload))
    if wrong:
        c = payload["counts"]
        problems.append(f"numbers {wrong} do not match the data: hosts={payload['host_count']}, "
                        f"live={payload['live_count']}, P1={c['P1']}, P2={c['P2']}, P3={c['P3']}, P4={c['P4']}")
    all_text = " ".join([n.executive_summary, n.limitations] + [r.action for r in n.recommendations])
    cited = set(CITATION_RE.findall(all_text)) | {i for r in n.recommendations for i in r.finding_ids}
    unknown = sorted(cited - valid_ids)
    if unknown:
        problems.append(f"cites unknown IDs: {unknown}")
    if payload["findings"] and not CITATION_RE.search(n.executive_summary):
        problems.append("the executive summary must cite finding or evidence IDs in brackets, e.g. [F-0001]")
    if not 1 <= len(n.recommendations) <= 5 and payload["findings"]:
        problems.append("give between three and five recommendations")
    return problems


def render_markdown(target: str, date: str, payload: dict, narrative: dict, table: list[dict]) -> str:
    """Fill reference/report-template.md."""
    c = payload["counts"]
    recs = "\n".join(f"{i}. {r['action']}" for i, r in enumerate(narrative["recommendations"], 1)) or "None."
    rows = ["| Priority | Host | Finding | Details | Evidence |", "|---|---|---|---|---|"]
    for r in table:
        cells = [r["priority"], r["host"], r["finding"], r["details"], ", ".join(r["evidence_ids"])]
        rows.append("| " + " | ".join(str(x).replace("|", "\\|") for x in cells) + " |")
    return (
        f"# External Attack Surface Report: {target}\n\n"
        f"Scan date: {date} · Hosts discovered: {payload['host_count']} · Live hosts: {payload['live_count']}\n"
        f"P1: {c['P1']} · P2: {c['P2']} · P3: {c['P3']} · P4: {c['P4']}\n\n"
        f"## Executive summary\n\n{narrative['executive_summary']}\n\n"
        f"## Top recommendations\n\n{recs}\n\n"
        f"## Findings\n\n" + ("\n".join(rows) if table else "No findings.") + "\n\n"
        f"## Data limitations\n\n{narrative['limitations']}\n\n---\n\n"
        f"*Generated by Attack Surface Analyst from passive and minimal-touch data collected on {date}. "
        "Every finding links to the evidence it is based on. Scans are run only on authorized targets.*\n"
    )


# ---------------------------------------------------------------- agent entry point

def run(target: str, steps: list[Envelope], llm: BaseLLM) -> Envelope:
    started = utc_now()
    by_agent = {s.agent: s for s in steps}
    enrichment, ti, prio = by_agent["enrichment"], by_agent["threat_intel"], by_agent["prioritization"]
    findings = {f["id"]: f for f in ti.output.get("findings", [])}
    table = findings_table(prio.output.get("prioritized", []), findings)
    hosts = enrichment.output.get("hosts", [])
    valid_ids = {ev.id for s in steps for ev in s.evidence} | set(findings)

    payload = {
        "target": target,
        "host_count": len(hosts),
        "live_count": sum(1 for h in hosts if h.get("live")),
        "roles": sorted({h["role"] for h in hosts if h.get("role")}),
        "counts": prio.output.get("counts", {"P1": 0, "P2": 0, "P3": 0, "P4": 0}),
        "kev_count": sum(1 for f in findings.values() if f.get("in_kev")),
        "findings": [{**r, "kind": findings[r["finding_id"]]["kind"],
                      "product": findings[r["finding_id"]].get("product"),
                      "in_kev": findings[r["finding_id"]].get("in_kev")} for r in table],
        "degraded_steps": [{"agent": s.agent, "errors": [e.reason for e in s.errors]}
                           for s in steps if s.status == "degraded"],
    }
    usage = LLMUsage(model=llm.model)
    errors: list[StepError] = []
    answer = llm.ask_json(
        system=load_skill("report"),
        task=("Write the executive summary, top recommendations and data limitations for this "
              "external attack surface report. Cite IDs in brackets, e.g. [F-0001]."),
        payload=payload, schema=Narrative, fallback=heuristic_narrative,
        validate=lambda n: validate_narrative(n, payload, valid_ids), effort="medium")
    usage.add(answer.input_tokens, answer.output_tokens)
    if answer.errors or answer.data is None:
        # Never publish a narrative that failed validation: use the plain template instead.
        errors.append(StepError(step="narrative", reason="; ".join(answer.errors)
                                + "; replaced with the template narrative"))
        narrative = heuristic_narrative(payload)
    else:
        narrative = answer.data.model_dump()

    date = started[:10]
    output = {**narrative, "findings_table": table,
              "counts": payload["counts"], "host_count": payload["host_count"],
              "live_count": payload["live_count"],
              "markdown": render_markdown(target, date, payload, narrative, table)}
    return make_envelope(AGENT, "prioritization", started, output, [], errors, llm_usage=usage)
