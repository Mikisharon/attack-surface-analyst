"""Recon agent (FR-2). Spec: skills/recon/SKILL.md.

Tool agent, no LLM. Turns one domain into a clean, deduplicated list of
subdomains from certificate transparency logs (crt.sh). Passive only: it never
sends traffic to the target itself.
"""
from __future__ import annotations

from core.envelope import Envelope, StepError, make_envelope, utc_now
from core.evidence import EvidenceStore
from core.net import BaseNet, SourceError
from core.scope import in_scope, load_sources, normalize

AGENT = "recon"
RETRY_WAITS_S = (5, 15, 30)  # wait before retry 1, 2 and 3
CRTSH_TIMEOUT_S = 60


def fetch_crtsh(net: BaseNet, target: str) -> list[dict]:
    """Query crt.sh, retrying up to 3 times on timeouts and server errors."""
    url = load_sources()["crtsh"]["url"]
    last_error: SourceError | None = None
    for attempt in range(len(RETRY_WAITS_S) + 1):
        if attempt:
            net.sleep(RETRY_WAITS_S[attempt - 1])
        try:
            data = net.get_json(url, params={"q": f"%.{target}", "output": "json"},
                                timeout=CRTSH_TIMEOUT_S)
            if not isinstance(data, list):
                raise SourceError("unexpected response shape (expected a JSON list)")
            return data
        except SourceError as exc:
            last_error = exc
            if not exc.retryable:
                break
    raise last_error  # type: ignore[misc]


def run(target: str, net: BaseNet) -> Envelope:
    started = utc_now()
    target = normalize(target)
    errors: list[StepError] = []
    store = EvidenceStore(AGENT)

    try:
        entries = fetch_crtsh(net, target)
    except SourceError as exc:
        # Never fail the run because of crt.sh: the root domain alone is still useful.
        entries = []
        errors.append(StepError(step="crt.sh query",
                                reason=f"{exc.reason} (after retries); returning only the target"))

    names: dict[str, dict] = {}
    wildcards: set[str] = set()
    for entry in entries:
        for raw in str(entry.get("name_value", "")).split("\n"):
            name = normalize(raw)
            if not name:
                continue
            if name.startswith("*."):
                base = name[2:]
                if in_scope(base, target):
                    wildcards.add(base)
                continue
            if not in_scope(name, target):
                continue  # certificates sometimes list unrelated domains
            seen = names.setdefault(name, {"first_seen": None, "last_cert_expiry": None,
                                           "cert_id": entry.get("id")})
            not_before = str(entry.get("not_before", ""))[:10] or None
            not_after = str(entry.get("not_after", ""))[:10] or None
            if not_before and (seen["first_seen"] is None or not_before < seen["first_seen"]):
                seen["first_seen"] = not_before
                seen["cert_id"] = entry.get("id")  # cite the earliest certificate
            if not_after and (seen["last_cert_expiry"] is None or not_after > seen["last_cert_expiry"]):
                seen["last_cert_expiry"] = not_after

    # Always include the target itself, even if no certificate names it.
    names.setdefault(target, {"first_seen": None, "last_cert_expiry": None, "cert_id": None})

    subdomains = []
    for name in sorted(names):  # sorted, so reruns produce identical files
        info = names[name]
        if info["cert_id"] is not None:
            ev = store.add("ct_log", name,
                           f"Name appears in a certificate (first seen {info['first_seen']}, "
                           f"latest expiry {info['last_cert_expiry']})",
                           f"https://crt.sh/?id={info['cert_id']}")
        else:
            ev = store.add("ct_log", name, "Target domain (included by definition, not seen in CT logs)",
                           "config/targets.yaml")
        subdomains.append({"name": name, "first_seen": info["first_seen"],
                           "last_cert_expiry": info["last_cert_expiry"], "evidence_ids": [ev]})

    output = {"subdomains": subdomains, "wildcards": sorted(wildcards), "count": len(subdomains)}
    return make_envelope(AGENT, "target", started, output, store.items, errors)
