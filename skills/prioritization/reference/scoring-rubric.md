# Scoring rubric (baseline priority)

Code computes the baseline. Add up the points for every rule that applies, then map the total to a priority.

## Points

| Rule ID | Condition | Points |
|---|---|---|
| `kev_listed` | Finding is a CVE in the CISA KEV catalog | 100 (always P1) |
| `kev_ransomware` | KEV entry marks known ransomware use | +10 |
| `cvss_9_plus` | CVSS 9.0 or higher | 40 |
| `cvss_7_to_9` | CVSS 7.0 to 8.9 | 30 |
| `cvss_4_to_7` | CVSS 4.0 to 6.9 | 15 |
| `cvss_below_4` | CVSS below 4.0 | 5 |
| `sensitive_service` | Finding kind `sensitive_service_exposed` | 30 |
| `non_production` | Finding kind `non_production_exposed` | 20 |
| `default_page` | Finding kind `default_page_exposed` | 15 |
| `unverified_version` | Finding kind `unverified_version` | 10 |
| `no_https` | Finding kind `no_https` | 15 |
| `missing_hsts` | Finding kind `missing_hsts` | 5 |
| `importance_high` | Host importance high | +20 |
| `importance_medium` | Host importance medium | +10 |
| `importance_low` | Host importance low | +0 |

Only one `cvss_*` rule applies per finding.

## Priority mapping

| Total points | Priority | Meaning |
|---|---|---|
| 100 or more, or any KEV listing | P1 | Fix now (days) |
| 45 to 99 | P2 | Fix this sprint (weeks) |
| 20 to 44 | P3 | Plan the fix (this quarter) |
| below 20 | P4 | Track / accept |

## Worked examples

- KEV-listed CVE on any host: P1.
- CVSS 7.5 on a high-importance host: 30 + 20 = 50, so P2.
- Missing HSTS on a low-importance host: 5 + 0 = 5, so P4.
- VPN portal exposed (high importance): 30 + 20 = 50, so P2.

## Changing the rubric

The rubric is a product decision, not a technical detail. When you change a value, run the evals and record the change and its effect in `evals/results.md`.
