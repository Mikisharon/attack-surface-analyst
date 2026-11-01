---
name: threat-intel
description: Matches the products and versions found by Enrichment to known CVEs (NVD) and flags those actively exploited in the wild (CISA KEV catalog); also raises rule-based exposure findings. Use after Enrichment in an Attack Surface Analyst run, or when asked whether a product version has known or exploited vulnerabilities.
---

# Threat Intel agent

**Kind:** Tool agent. No LLM. This file is the specification and runbook for `agents/threat_intel.py`.

**Job:** turn host profiles into findings. Every finding must be exact and reproducible, which is why no LLM is used here: a model's memory of CVEs is incomplete and out of date, and a wrong CVE destroys trust in the whole report.

Follow the shared rules in `../_shared/conventions.md`.

## Input

The Enrichment envelope: `output.hosts`.

## Workflow

### 1. Load the CISA KEV catalog (once per run)

Download the KEV JSON feed from CISA (find the current feed URL on the CISA KEV catalog page and store it in `config/sources.yaml`). Keep a set of `cveID` values plus each entry's `dateAdded` and `knownRansomwareCampaignUse`. Cache the file for 24 hours in `.cache/`.

### 2. Known vulnerabilities (per detected product)

Only for products with `version_confidence: exact`:

1. Build the CPE name for the product and version (mapping table in `reference/cpe-map.md`).
2. Query the NVD CVE API 2.0 with that CPE name.
3. For each CVE returned, record: CVE ID, CVSS v3.x base score and severity, a one-line description (first sentence of the NVD description), published date.
4. Flag `in_kev: true` if the CVE ID is in the KEV set.
5. Create one evidence item per CVE match (type `cve_match`, source = the NVD CVE page URL) and one per KEV match (type `kev_listing`).

For `partial` or `none` version confidence, do **not** match CVEs. Instead raise an `unverified_version` finding (below). Why: matching on a product name alone produces dozens of false positives.

### 3. Exposure findings (rule-based)

| Rule | Finding kind |
|---|---|
| Host role is `admin_panel`, `remote_access` or `vpn_portal` and it is reachable from the internet | `sensitive_service_exposed` |
| Host role is `dev_or_staging` and it is reachable | `non_production_exposed` |
| Host role is `parked_or_default` | `default_page_exposed` |
| HTTPS not available (`https: false`) | `no_https` |
| `Strict-Transport-Security` missing on an HTTPS host | `missing_hsts` |
| Product detected with version confidence `partial` or `none` on a high-importance host | `unverified_version` |

Each exposure finding cites the Enrichment evidence IDs that triggered the rule.

## Output

```json
{
  "findings": [
    {
      "id": "F-0003",
      "kind": "known_vulnerability",
      "host": "portal.example.com",
      "product": "nginx 1.18.0",
      "cve": "CVE-0000-00000",
      "cvss": 7.5,
      "severity": "HIGH",
      "in_kev": false,
      "summary": "One-line description from NVD.",
      "evidence_ids": ["ev-enr-0011", "ev-ti-0004"]
    },
    {
      "id": "F-0004",
      "kind": "sensitive_service_exposed",
      "host": "portal.example.com",
      "summary": "VPN login portal reachable from the internet.",
      "evidence_ids": ["ev-enr-0012"]
    }
  ],
  "kev_catalog_date": "2026-11-07"
}
```

Finding IDs are `F-0001` upward in a stable order: by host name, then by kind, then by CVE ID.

## Failure handling

- NVD rate limit (HTTP 403 or 429): wait 30 s and retry up to 3 times. NVD allows few requests per rolling window without an API key, so also wait about 6 s between calls. An optional free key in `.env` (`NVD_API_KEY`) raises the limit.
- NVD unavailable after retries: keep exposure findings, skip CVE findings, mark `degraded` with the products that were not checked.
- KEV feed unavailable: use the cached copy if under 7 days old and record its date; otherwise set `in_kev` to `null` (unknown) and mark `degraded`. Never write `false` when you do not know.

## Rules

- Never invent or infer a CVE. A CVE appears only if NVD returned it for the exact CPE.
- Keep the full CVE list in the run file, but cap the findings to the 10 highest CVSS per product plus every KEV-listed CVE. Why: a report with 200 rows hides the 3 that matter.

## Test cases

- Synthetic host with an exact product version that has a KEV-listed CVE: produces a `known_vulnerability` finding with `in_kev: true`.
- Synthetic host with `Apache/2` only: produces `unverified_version`, no CVE findings.
- Synthetic host with role `vpn_portal`: produces `sensitive_service_exposed`.
