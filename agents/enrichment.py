"""Enrichment agent (FR-3, FR-4). Spec: skills/enrichment/SKILL.md.

Hybrid agent:
- Part A (code) resolves DNS, makes one polite HTTPS request per host, and turns
  headers and titles into evidence and detected products.
- Part B (LLM) classifies each live host's role and importance, citing only that
  host's evidence IDs.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Literal

from pydantic import BaseModel

from core.envelope import Envelope, LLMUsage, StepError, make_envelope, utc_now
from core.evidence import EvidenceStore
from core.llm import BaseLLM, load_skill
from core.net import BaseNet, PageResult, html_title
from core.scope import in_scope

AGENT = "enrichment"
MAX_PARALLEL_HOSTS = 5  # polite to the target, and within free-tier limits

ROLES = ["vpn_portal", "admin_panel", "remote_access", "email", "api", "auth", "dev_or_staging",
         "file_sharing", "marketing_site", "docs_or_support", "cdn_or_redirect",
         "parked_or_default", "unknown"]
Role = Literal["vpn_portal", "admin_panel", "remote_access", "email", "api", "auth",
               "dev_or_staging", "file_sharing", "marketing_site", "docs_or_support",
               "cdn_or_redirect", "parked_or_default", "unknown"]
Importance = Literal["high", "medium", "low"]
IMPORTANCE_RANK = {"low": 0, "medium": 1, "high": 2}

# reference/product-signatures.md as code: (source, regex, product, has_version_group)
SIGNATURES = [
    ("server", r"nginx/([\d.]+)", "nginx", True),
    ("server", r"Apache/([\d.]+)", "Apache HTTP Server", True),
    ("server", r"Microsoft-IIS/([\d.]+)", "Microsoft IIS", True),
    ("server", r"OpenSSL/([\d.]+[a-z]?)", "OpenSSL", True),
    ("x-powered-by", r"PHP/([\d.]+)", "PHP", True),
    ("x-powered-by", r"Express", "Express (Node.js)", False),
    ("x-powered-by", r"ASP\.NET", "ASP.NET", False),
    ("title", r"GlobalProtect Portal", "Palo Alto GlobalProtect", False),
    ("title", r"FortiGate", "Fortinet FortiGate", False),
    ("title", r"Grafana", "Grafana", False),
    ("title", r"Dashboard \[Jenkins\]", "Jenkins", False),
    ("x-jenkins", r"([\d.]+)", "Jenkins", True),
    ("title", r"Outlook", "Microsoft Exchange OWA", False),
]
# Products whose vendor version string is normally major.minor (e.g. Jenkins 2.441).
TWO_PART_VERSIONS = {"Jenkins"}

REPORTED_HEADERS = ["Server", "X-Powered-By", "Via", "X-Jenkins"]
SECURITY_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy"]


# ---------------------------------------------------------------- Part A: facts

def version_confidence(product: str, version: str | None) -> str:
    if not version:
        return "none"
    parts = [p for p in version.split(".") if p]
    needed = 2 if product in TWO_PART_VERSIONS else 3
    return "exact" if len(parts) >= needed else "partial"


def detect_products(sources: dict[str, tuple[str, str]]) -> list[dict]:
    """sources: {"server": (value, evidence_id), "title": (...), ...} -> product list."""
    found: dict[str, dict] = {}
    for source, pattern, product, has_version in SIGNATURES:
        if source not in sources:
            continue
        value, evidence_id = sources[source]
        match = re.search(pattern, value, re.IGNORECASE)
        if not match:
            continue
        version = match.group(1) if has_version else None
        entry = {"product": product, "version": version,
                 "version_confidence": version_confidence(product, version),
                 "evidence_id": evidence_id}
        # Keep the most specific detection when two signatures find the same product.
        rank = {"exact": 2, "partial": 1, "none": 0}
        if product not in found or rank[entry["version_confidence"]] > rank[found[product]["version_confidence"]]:
            found[product] = entry
    return sorted(found.values(), key=lambda p: p["product"])


def collect_raw(net: BaseNet, name: str, target: str) -> dict:
    """Network part for one host (runs in a thread pool). No evidence IDs yet."""
    raw: dict = {"name": name, "dns": {}, "page": None, "https": None, "https_error": None}
    for rtype in ("A", "AAAA", "CNAME"):
        raw["dns"][rtype] = net.resolve(name, rtype)
    if not any(raw["dns"].values()):
        return raw  # not live: skip the HTTP steps
    outside = [c for c in raw["dns"]["CNAME"] if not in_scope(c, target)]
    if outside:
        # PRD: hosts that resolve outside the target's domain are recorded, not contacted.
        raw["not_contacted"] = f"CNAME points outside {target} ({outside[0]})"
        return raw
    page = net.fetch_page(f"https://{name}/")
    raw["https"] = page.error is None
    if page.error:
        raw["https_error"] = page.error
        page = net.fetch_page(f"http://{name}/")  # one plain-HTTP attempt
    raw["page"] = page
    return raw


def build_profile(raw: dict, store: EvidenceStore) -> dict:
    """Turn raw network results into evidence items and a host profile (sequential, so IDs are stable)."""
    name = raw["name"]
    host = {"name": name, "live": False, "contacted": False, "ips": [], "cnames": [],
            "https": None, "status": None, "title": None, "products": [],
            "missing_security_headers": [], "evidence_ids": [], "evidence_index": {}}
    idx = host["evidence_index"]

    for rtype in ("A", "AAAA", "CNAME"):
        for record in raw["dns"].get(rtype, []):
            ev = store.add("dns", name, f"{rtype} {record}", f"dns:{name}/{rtype}")
            idx.setdefault("dns", []).append(ev)
            (host["cnames"] if rtype == "CNAME" else host["ips"]).append(record)
    host["live"] = bool(idx.get("dns"))
    if not host["live"]:
        host["note"] = "No DNS records: not live"
    if raw.get("not_contacted"):
        host["note"] = raw["not_contacted"]

    page: PageResult | None = raw.get("page")
    if page is not None:
        host["contacted"] = True
        host["https"] = raw["https"]
        if raw["https"] is False:
            idx["https"] = store.add("tls", name, f"HTTPS unavailable: {raw['https_error']}",
                                     f"https://{name}/")
        if page.error:
            host["fetch_error"] = page.error
            idx["fetch_error"] = store.add("http_status", name, f"No HTTP response: {page.error}",
                                           page.url)
        else:
            source = page.final_url or page.url
            host["status"] = page.status
            idx["status"] = store.add("http_status", name, f"HTTP {page.status}", source)
            headers = {k.lower(): v for k, v in page.headers.items()}
            product_sources: dict[str, tuple[str, str]] = {}
            for header in REPORTED_HEADERS:
                value = headers.get(header.lower())
                if value:
                    ev = store.add("http_header", name, f"{header}: {value}", source)
                    idx[header.lower()] = ev
                    product_sources[header.lower()] = (value, ev)
            if headers.get("location"):
                idx["location"] = store.add("http_header", name, f"Location: {headers['location']}", source)
            if page.redirect_blocked:
                host["redirect_blocked"] = page.redirect_blocked
            for header in SECURITY_HEADERS:
                if header.lower() in headers:
                    value = f"{header}: present"
                elif host["https"]:
                    value = f"{header}: missing"
                    host["missing_security_headers"].append(header)
                else:
                    continue  # security headers only mean something over HTTPS
                idx[header.lower()] = store.add("http_header", name, value, source)
            if headers.get("content-type"):
                idx["content-type"] = store.add("http_header", name,
                                                f"Content-Type: {headers['content-type']}", source)
            title = html_title(page.body)
            if title:
                host["title"] = title
                idx["title"] = store.add("html_title", name, title, source)
                product_sources["title"] = (title, idx["title"])
            host["products"] = detect_products(product_sources)

    host["evidence_ids"] = [ev for value in idx.values()
                            for ev in (value if isinstance(value, list) else [value])]
    return host


# ---------------------------------------------------------------- Part B: classify

class Classification(BaseModel):
    host: str
    role: Role
    importance: Importance
    reason: str
    evidence_ids: list[str]


TITLE_RULES = [  # (regex on page title, role, importance)
    (r"globalprotect|fortigate|fortinet|pulse secure|ivanti|anyconnect|citrix gateway", "vpn_portal", "high"),
    (r"jenkins|grafana|phpmyadmin|kibana|\badmin|dashboard", "admin_panel", "high"),
    (r"outlook|exchange|webmail", "email", "high"),
    (r"remote desktop|rd web|guacamole", "remote_access", "high"),
    (r"welcome to nginx|iis windows server|apache2 .*default page|^it works!?$", "parked_or_default", "medium"),
    (r"^index of /", "file_sharing", "medium"),
    (r"sign in|log ?in|single sign-on", "auth", "high"),
]
NAME_RULES = [  # (name label, role, importance) - a name alone caps importance at medium
    ({"vpn"}, "vpn_portal", "high"),
    ({"admin"}, "admin_panel", "high"),
    ({"mail", "owa", "webmail"}, "email", "high"),
    ({"sso", "login", "auth", "idp"}, "auth", "high"),
    ({"dev", "test", "staging", "uat", "qa"}, "dev_or_staging", "medium"),
    ({"api"}, "api", "medium"),
    ({"files", "share", "ftp", "nextcloud"}, "file_sharing", "medium"),
    ({"docs", "help", "support", "status"}, "docs_or_support", "low"),
    ({"cdn"}, "cdn_or_redirect", "low"),
]


def heuristic_classify(payload: dict) -> dict:
    """Offline stand-in for the LLM: keyword rules from reference/asset-roles.md.

    It reads the same evidence the LLM would get, and like the LLM it never
    follows instructions found inside a page title.
    """
    name = payload["host"]
    by_type: dict[str, list[dict]] = {}
    for e in payload["evidence"]:
        by_type.setdefault(e["type"], []).append(e)
    title_ev = (by_type.get("html_title") or [None])[0]
    dns_ev = (by_type.get("dns") or [None])[0]
    status_ev = next((e for e in by_type.get("http_status", []) if e["value"].startswith("HTTP ")), None)
    candidates: list[tuple[str, str, str, str]] = []  # role, importance, evidence id, why

    if title_ev:
        for pattern, role, importance in TITLE_RULES:
            if re.search(pattern, title_ev["value"], re.IGNORECASE):
                candidates.append((role, importance, title_ev["id"], f"page title '{title_ev['value'][:60]}'"))
                break
    labels = set(re.split(r"[.\-]", name.lower()))
    for words, role, importance in NAME_RULES:
        if labels & words and dns_ev:
            capped = "medium" if importance == "high" else importance
            candidates.append((role, capped, dns_ev["id"], f"host name contains '{sorted(labels & words)[0]}'"))
    if status_ev and re.match(r"HTTP 30[1278]", status_ev["value"]) and not title_ev:
        candidates.append(("cdn_or_redirect", "low", status_ev["id"], "the host only answers with a redirect"))
    content_type = next((e for e in by_type.get("http_header", []) if e["value"].lower().startswith("content-type: application/json")), None)
    if content_type and not title_ev:
        candidates.append(("api", "medium", content_type["id"], "it returns JSON with no HTML title"))
    if not candidates and title_ev and status_ev and status_ev["value"] == "HTTP 200":
        candidates.append(("marketing_site", "low", title_ev["id"], f"a public page titled '{title_ev['value'][:60]}'"))

    if not candidates:
        cite = (dns_ev or payload["evidence"][0])["id"]
        return {"host": name, "role": "unknown", "importance": "low",
                "reason": f"The evidence does not support a specific role ({cite}).", "evidence_ids": [cite]}

    # If two roles fit, choose the one with the higher importance.
    role, importance, ev_id, why = max(candidates, key=lambda c: IMPORTANCE_RANK[c[1]])
    reason = f"Classified as {role} because {why} ({ev_id})."
    others = [c for c in candidates if c[0] != role]
    if others:
        reason += f" Also fits {others[0][0]} ({others[0][2]})."
    cited = [ev_id] + [others[0][2]] if others else [ev_id]
    if labels & {"old", "legacy", "backup"} and dns_ev and importance != "high":
        importance = "high" if importance == "medium" else "medium"
        reason += f" Importance raised one level: the name suggests a forgotten asset ({dns_ev['id']})."
        cited.append(dns_ev["id"])
    return {"host": name, "role": role, "importance": importance, "reason": reason,
            "evidence_ids": sorted(set(cited))}


def classify(llm: BaseLLM, host: dict, store: EvidenceStore, system: str, usage: LLMUsage) -> tuple[dict, list[str]]:
    own = {e.id: e for e in store.items if e.id in host["evidence_ids"]}
    payload = {"host": host["name"],
               "evidence": [{"id": e.id, "type": e.type, "value": e.value} for e in own.values()]}

    def validate(answer: Classification) -> list[str]:
        errors = []
        if answer.host != host["name"]:
            errors.append(f"host must be '{host['name']}'")
        unknown = [i for i in answer.evidence_ids if i not in own]
        if not answer.evidence_ids or unknown:
            errors.append(f"evidence_ids must be non-empty and only use IDs given for this host; unknown: {unknown}")
        if not any(i in answer.reason for i in own):
            errors.append("reason must cite at least one evidence ID from the input")
        return errors

    answer = llm.ask_json(system=system, task="Classify this host's role and importance.",
                          payload=payload, schema=Classification, fallback=heuristic_classify,
                          validate=validate, effort="low")
    usage.add(answer.input_tokens, answer.output_tokens)
    if answer.errors or answer.data is None:
        return ({"role": "unknown", "importance": "low",
                 "reason": "LLM classification failed validation; role left unknown.",
                 "classification_evidence": []}, answer.errors)
    data = answer.data
    return ({"role": data.role, "importance": data.importance, "reason": data.reason,
             "classification_evidence": data.evidence_ids, "first_try_valid": answer.first_try_valid}, [])


# ---------------------------------------------------------------- agent entry point

def run(recon: Envelope, net: BaseNet, llm: BaseLLM) -> Envelope:
    started = utc_now()
    target = net.target
    store = EvidenceStore(AGENT)
    errors: list[StepError] = []
    names = [s["name"] for s in recon.output.get("subdomains", [])]

    with ThreadPoolExecutor(max_workers=MAX_PARALLEL_HOSTS) as pool:
        raws = list(pool.map(lambda n: collect_raw(net, n, target), names))
    hosts = [build_profile(raw, store) for raw in sorted(raws, key=lambda r: r["name"])]

    system = load_skill("enrichment")
    usage = LLMUsage(model=llm.model)
    llm_failed = False
    for host in hosts:
        if not host["live"]:
            host.update({"role": None, "importance": None, "reason": "Not live: not classified."})
            continue  # no LLM call for hosts with no DNS records
        result, problems = classify(llm, host, store, system, usage)
        host.update(result)
        if problems:
            llm_failed = True
            errors.append(StepError(step=f"classify {host['name']}", reason="; ".join(problems)))

    contactable = [h for h in hosts if h["contacted"]]
    unreachable = [h for h in contactable if h.get("fetch_error")]
    if contactable and len(unreachable) > len(contactable) / 2:
        errors.append(StepError(step="https fetch",
                                reason=f"{len(unreachable)} of {len(contactable)} hosts unreachable; "
                                       "this often means a network problem on the scanning side"))

    output = {"hosts": hosts,
              "live_count": sum(1 for h in hosts if h["live"]),
              "classified_count": sum(1 for h in hosts if h.get("role"))}
    status = "degraded" if errors or llm_failed else "ok"
    return make_envelope(AGENT, "recon", started, output, store.items, errors,
                         llm_usage=usage, status=status)
