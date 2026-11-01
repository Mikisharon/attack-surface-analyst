# Product signatures

Code uses these patterns to detect products. Matching is case-insensitive. Extend this table as you meet new products; every change should come with a test case.

| Source | Pattern (regex) | Product | Version group |
|---|---|---|---|
| `Server` header | `nginx/([\d.]+)` | nginx | 1 |
| `Server` header | `Apache/([\d.]+)` | Apache HTTP Server | 1 |
| `Server` header | `Microsoft-IIS/([\d.]+)` | Microsoft IIS | 1 |
| `Server` header | `OpenSSL/([\d.]+[a-z]?)` | OpenSSL | 1 |
| `X-Powered-By` | `PHP/([\d.]+)` | PHP | 1 |
| `X-Powered-By` | `Express` | Express (Node.js) | none |
| `X-Powered-By` | `ASP\.NET` | ASP.NET | none |
| HTML title | `GlobalProtect Portal` | Palo Alto GlobalProtect | none |
| HTML title | `FortiGate` | Fortinet FortiGate | none |
| HTML title | `Grafana` | Grafana | none |
| HTML title | `Dashboard \[Jenkins\]` | Jenkins | none |
| `X-Jenkins` header | `([\d.]+)` | Jenkins | 1 |
| HTML title | `Outlook` | Microsoft Exchange OWA | none |

## Rules

- One header can contain several products (`Apache/2.4.49 (Unix) OpenSSL/1.1.1k`). Record each one.
- A version is `exact` only if it has at least major.minor.patch, or is the full string the vendor uses.
- If no pattern matches, record no product. Do not ask the LLM to guess a product. Why: a guessed product produces wrong CVE matches downstream.
