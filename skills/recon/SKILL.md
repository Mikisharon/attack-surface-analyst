---
name: recon
description: Discovers the subdomains of an authorized target domain from certificate transparency logs (crt.sh). Use as the first step of every Attack Surface Analyst run, or when asked which subdomains or hosts a domain has.
---

# Recon agent

**Kind:** Tool agent. No LLM in P0. This file is the specification and runbook for `agents/recon.py`.

**Job:** turn one domain into a clean, deduplicated list of subdomains, each with evidence of where it was found.

Follow the shared rules in `../_shared/conventions.md` (envelope, evidence, scope).

## Input

```json
{ "target": "scanme.nmap.org" }
```

The orchestrator has already checked the target against the allowlist.

## Workflow

1. Query `https://crt.sh/?q=%25.<target>&output=json` with a 60 s timeout.
2. For each certificate entry, split `name_value` on newlines. One certificate can cover several names.
3. Normalize each name: trim spaces, lowercase, remove a trailing dot.
4. Drop wildcard names (starting with `*.`). Record the wildcard's base domain separately in `output.wildcards`, because a wildcard certificate hints at hosts that will not appear by name.
5. Keep only names equal to the target or ending with `.<target>`. Certificates sometimes list unrelated domains. Those are out of scope.
6. Deduplicate. For each subdomain keep the **earliest** `not_before` date and the **latest** `not_after` date seen.
7. Create one evidence item per subdomain (type `ct_log`) with the crt.sh certificate ID as part of the `source` URL.
8. Always include the target itself in the list, even if no certificate names it.

## Output

```json
{
  "subdomains": [
    {
      "name": "portal.example.com",
      "first_seen": "2021-03-04",
      "last_cert_expiry": "2026-12-01",
      "evidence_ids": ["ev-rec-0003"]
    }
  ],
  "wildcards": ["example.com"],
  "count": 12
}
```

Sort `subdomains` alphabetically so reruns produce identical files.

## Failure handling

| Situation | What to do | Status |
|---|---|---|
| crt.sh timeout or HTTP 5xx | Retry up to 3 times, waiting 5 s, 15 s, 30 s | `ok` if a retry succeeds |
| Still failing after retries | Return only the target itself; record the reason in `errors` | `degraded` |
| Response is not valid JSON | Same as above. crt.sh sometimes returns an HTML error page | `degraded` |
| Zero certificates found | Return only the target; no error | `ok` |

Never fail the whole run because of crt.sh. A run with only the root domain is still useful for the later agents.

## Rules

- Passive only. Recon never sends traffic to the target. Why: discovery must be safe to run on any authorized target without touching its systems.
- Do not resolve DNS here. That is Enrichment's job, and mixing them makes failures harder to explain.
- Expired certificates still count. Old names often point to forgotten assets, which are exactly what attackers look for. Enrichment will find out if they are still live.

## P2 extension: adaptive recon

An LLM may propose likely names (for example, `staging-api` after seeing `staging`). A proposed name is added only if DNS confirms it resolves, and its evidence type is `dns_confirmed_guess`. The LLM proposes, the tool confirms.

## Test cases

- `scanme.nmap.org`: returns at least the target itself; status `ok` or `degraded`, never `failed`.
- Mocked crt.sh response containing `*.example.com`, `WWW.example.com.` and `other.com`: output is `www.example.com` plus the target, with `example.com` in `wildcards`.
- Mocked timeout three times: status `degraded`, one entry in `errors`.
