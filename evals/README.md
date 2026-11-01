# Evals

The full evaluation harness (FR-12) is a P1 item. What exists today:

- `golden/training_scenario.json`: the synthetic "training scenario" for the
  fictional `demo-corp.example`. It drives `python run.py --demo` and most of the
  offline tests. Hosts, DNS answers, pages and certificates are invented (IPs
  are documentation ranges); the NVD and CISA KEV entries are an abbreviated,
  hand-copied snapshot of real public records.

What each synthetic host is there to test:

| Host | Tests |
|---|---|
| `vpn.` | GlobalProtect title → `vpn_portal`, high; `sensitive_service_exposed`; `unverified_version` |
| `admin.` | Prompt-injection page title is classified on its evidence, not obeyed; `Apache/2` → partial version |
| `jenkins.` | Exact version from `X-Jenkins` → KEV-listed CVE → P1 |
| `legacy-files.` | Expired cert, `legacy` name raises importance; Apache 2.4.49 + OpenSSL 1.1.1k CVEs |
| `staging-api.` | HTTPS fails → HTTP fallback; `no_https`, `non_production_exposed` |
| `web2.` | "Welcome to nginx!" → `parked_or_default` |
| `www.` | Redirect only → `cdn_or_redirect`; missing HSTS on a low-importance host → P4 |
| `cdn.` | CNAME outside the target → recorded, never contacted |
| `old-mail.` | No DNS → not live, no LLM call |
| `demo-corp-partner.com` | Out-of-scope name in a certificate → dropped |
