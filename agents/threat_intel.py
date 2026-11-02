"""Threat Intel agent (FR-5). Spec: skills/threat-intel/SKILL.md.

Tool agent, no LLM: a model's memory of CVEs is incomplete and out of date, and
one wrong CVE destroys trust in the whole report. CVEs come only from NVD for an
exact CPE; "actively exploited" comes only from the CISA KEV catalog.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from core.envelope import Envelope, StepError, make_envelope, utc_now
from core.evidence import EvidenceStore
from core.net import BaseNet, SourceError
from core.scope import load_sources

AGENT = "threat_intel"
ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / ".cache"
KEV_FRESH_S = 24 * 3600
KEV_MAX_AGE_S = 7 * 24 * 3600
NVD_RETRIES = 3
TOP_CVES_PER_PRODUCT = 10

# reference/cpe-map.md as code: product -> list of (vendor, product). nginx has two vendors.
CPE_MAP = {
    "nginx": [("f5", "nginx"), ("nginx", "nginx")],
    "Apache HTTP Server": [("apache", "http_server")],
    "Microsoft IIS": [("microsoft", "internet_information_services")],
    "OpenSSL": [("openssl", "openssl")],
    "PHP": [("php", "php")],
    "Jenkins": [("jenkins", "jenkins")],
    "Grafana": [("grafana", "grafana")],
}

# Exposure rules from the SKILL.md table.
SENSITIVE_ROLES = {"admin_panel", "remote_access", "vpn_portal"}
KIND_ORDER = ["known_vulnerability", "sensitive_service_exposed", "non_production_exposed",
              "default_page_exposed", "no_https", "missing_hsts", "unverified_version"]


def cpe_names(product: str, version: str) -> list[str]:
    return [f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"
            for vendor, name in CPE_MAP.get(product, [])]


# ---------------------------------------------------------------- KEV catalog

def load_kev(net: BaseNet, cache_dir: Path | None) -> tuple[dict | None, str | None, str | None]:
    """Return ({cve_id: entry}, catalog_date, problem). None catalog means 'unknown'."""
    url = load_sources()["kev"]["url"]
    cache = cache_dir / "kev.json" if cache_dir else None
    age = time.time() - cache.stat().st_mtime if cache and cache.exists() else None
    if cache and age is not None and age < KEV_FRESH_S:
        return _index_kev(json.loads(cache.read_text())) + (None,)
    try:
        doc = net.get_json(url, timeout=60)
        if cache:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(doc))
        return _index_kev(doc) + (None,)
    except SourceError as exc:
        if cache and age is not None and age < KEV_MAX_AGE_S:
            catalog, date = _index_kev(json.loads(cache.read_text()))
            return catalog, date, f"KEV feed unavailable ({exc.reason}); used cached copy dated {date}"
        return None, None, f"KEV feed unavailable ({exc.reason}) and no recent cache; in_kev is unknown"


def _index_kev(doc: dict) -> tuple[dict, str | None]:
    catalog = {v["cveID"]: v for v in doc.get("vulnerabilities", [])}
    return catalog, (doc.get("dateReleased") or "")[:10] or None


# ---------------------------------------------------------------- NVD lookups

def nvd_lookup(net: BaseNet, cpe: str, cache_dir: Path | None) -> list[dict]:
    """All CVEs NVD lists for one CPE name, cached locally to respect the rate limit."""
    cache = None
    if cache_dir:
        cache = cache_dir / "nvd" / (hashlib.sha1(cpe.encode()).hexdigest() + ".json")
        if cache.exists() and time.time() - cache.stat().st_mtime < KEV_FRESH_S:
            return json.loads(cache.read_text())
    url = load_sources()["nvd"]["url"]
    api_key = os.environ.get("NVD_API_KEY")
    headers = {"apiKey": api_key} if api_key else None
    last: SourceError | None = None
    for attempt in range(NVD_RETRIES + 1):
        if attempt:
            net.sleep(30)  # NVD rate limit: wait, then retry
        try:
            data = net.get_json(url, params={"cpeName": cpe}, timeout=60, headers=headers)
            items = data.get("vulnerabilities", [])
            if cache:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text(json.dumps(items))
            # Without a key NVD allows few requests per rolling window: pace the next call.
            net.sleep(0.6 if api_key else 6)
            return items
        except SourceError as exc:
            last = exc
            if not exc.retryable:
                break
    raise last  # type: ignore[misc]


def parse_cve(item: dict) -> dict:
    cve = item.get("cve", item)
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    first_sentence = description.split(". ")[0].rstrip(".") + "." if description else ""
    score, severity = None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            score, severity = data.get("baseScore"), data.get("baseSeverity")
            break
    return {"cve": cve["id"], "cvss": score, "severity": severity,
            "summary": first_sentence, "published": (cve.get("published") or "")[:10]}


# ---------------------------------------------------------------- agent entry point

def run(enrichment: Envelope, net: BaseNet, cache_dir: Path | None = DEFAULT_CACHE) -> Envelope:
    started = utc_now()
    store = EvidenceStore(AGENT)
    errors: list[StepError] = []
    sources = load_sources()
    raw_findings: list[dict] = []
    all_cves: list[dict] = []

    kev, kev_date, kev_problem = load_kev(net, cache_dir)
    if kev_problem:
        errors.append(StepError(step="kev catalog", reason=kev_problem))

    nvd_down = False
    for host in enrichment.output.get("hosts", []):
        name, idx = host["name"], host.get("evidence_index", {})
        reachable = host.get("contacted") and host.get("status") is not None

        # --- Known vulnerabilities: exact versions only.
        for product in host.get("products", []):
            label = f"{product['product']} {product['version'] or ''}".strip()
            if product["version_confidence"] != "exact":
                if host.get("importance") == "high":
                    raw_findings.append({
                        "kind": "unverified_version", "host": name, "product": label,
                        "summary": f"{product['product']} detected without an exact version "
                                   "on a high-importance host; CVEs cannot be matched safely.",
                        "evidence_ids": [product["evidence_id"]]})
                continue
            cpes = cpe_names(product["product"], product["version"])
            if not cpes:
                errors.append(StepError(step=f"cve lookup {label}", reason="no CPE mapping"))
                continue
            if nvd_down:
                errors.append(StepError(step=f"cve lookup {label} on {name}", reason="NVD unavailable; not checked"))
                continue
            cves: dict[str, dict] = {}
            try:
                for cpe in cpes:
                    for item in nvd_lookup(net, cpe, cache_dir):
                        parsed = parse_cve(item)
                        cves.setdefault(parsed["cve"], parsed)  # merge vendors by CVE ID
            except SourceError as exc:
                nvd_down = True
                errors.append(StepError(step=f"cve lookup {label} on {name}",
                                        reason=f"NVD unavailable ({exc.reason}); CVE findings skipped"))
                continue
            for cve in cves.values():
                kev_entry = kev.get(cve["cve"]) if kev is not None else None
                cve["in_kev"] = None if kev is None else kev_entry is not None
                cve["kev_ransomware"] = bool(kev_entry and kev_entry.get("knownRansomwareCampaignUse") == "Known")
                cve.update({"host": name, "product": label})
                all_cves.append(dict(cve))
            # Cap: the 10 highest CVSS per product plus every KEV-listed CVE.
            ranked = sorted(cves.values(), key=lambda c: (-(c["cvss"] or 0), c["cve"]))
            keep = ranked[:TOP_CVES_PER_PRODUCT] + [c for c in ranked[TOP_CVES_PER_PRODUCT:] if c["in_kev"]]
            for cve in keep:
                ev_cve = store.add("cve_match", name,
                                   f"{cve['cve']} (CVSS {cve['cvss']} {cve['severity']}) listed by NVD for {label}",
                                   sources["nvd"]["cve_page"] + cve["cve"])
                ev_ids = [product["evidence_id"], ev_cve]
                if cve["in_kev"]:
                    kev_entry = kev[cve["cve"]]
                    ev_ids.append(store.add(
                        "kev_listing", name,
                        f"{cve['cve']} in CISA KEV since {kev_entry.get('dateAdded')}; "
                        f"ransomware use: {kev_entry.get('knownRansomwareCampaignUse', 'Unknown')}",
                        sources["kev"]["catalog_page"]))
                raw_findings.append({
                    "kind": "known_vulnerability", "host": name, "product": label,
                    "cve": cve["cve"], "cvss": cve["cvss"], "severity": cve["severity"],
                    "in_kev": cve["in_kev"], "kev_ransomware": cve["kev_ransomware"],
                    "summary": cve["summary"], "evidence_ids": ev_ids})

        if not reachable:
            continue
        # --- Exposure findings (rule-based).
        role = host.get("role")
        role_ev = host.get("classification_evidence") or idx.get("dns", [])[:1]
        if role in SENSITIVE_ROLES:
            raw_findings.append({"kind": "sensitive_service_exposed", "host": name,
                                 "summary": f"{role.replace('_', ' ').capitalize()} reachable from the internet.",
                                 "evidence_ids": role_ev})
        if role == "dev_or_staging":
            raw_findings.append({"kind": "non_production_exposed", "host": name,
                                 "summary": "Non-production (dev/staging) host reachable from the internet.",
                                 "evidence_ids": role_ev})
        if role == "parked_or_default":
            raw_findings.append({"kind": "default_page_exposed", "host": name,
                                 "summary": "Default server page exposed; often a forgotten, unpatched server.",
                                 "evidence_ids": role_ev})
        if host.get("https") is False:
            raw_findings.append({"kind": "no_https", "host": name,
                                 "summary": "HTTPS is not available; traffic is sent unencrypted.",
                                 "evidence_ids": [idx["https"]] if idx.get("https") else []})
        if host.get("https") and "Strict-Transport-Security" in host.get("missing_security_headers", []):
            raw_findings.append({"kind": "missing_hsts", "host": name,
                                 "summary": "Strict-Transport-Security header missing.",
                                 "evidence_ids": [idx["strict-transport-security"]]})

    # Stable IDs: by host, then kind, then CVE.
    raw_findings.sort(key=lambda f: (f["host"], KIND_ORDER.index(f["kind"]), f.get("cve", "")))
    findings = [{"id": f"F-{i:04d}", **f} for i, f in enumerate(raw_findings, start=1)]

    output = {"findings": findings, "kev_catalog_date": kev_date,
              "all_cves": sorted(all_cves, key=lambda c: (c["host"], c["cve"]))}
    return make_envelope(AGENT, "enrichment", started, output, store.items, errors)
