# Attack Surface Analyst

A multi-agent demo that turns a domain name into a prioritized, evidence-backed external attack surface report.

Five agents work in sequence: **Recon** finds subdomains, **Enrichment** profiles each host, **Threat Intel** matches software to known and actively exploited vulnerabilities, **Prioritization** decides what to fix first, and **Report** explains it to leadership and engineers. Code fetches the facts; the LLM reasons over them and never invents them.

> Status: specification complete, implementation in progress.

## Documentation

- [PRD & architecture](docs/PRD.md)
- [Agent skills](skills/): one `SKILL.md` per agent, plus [shared conventions](skills/_shared/conventions.md)

## Responsible use

Scans run only on targets listed in an allowlist: the author's own domain and sites that are intentionally public for security testing. Discovery is passive, and each discovered host receives at most one ordinary HTTPS request.
