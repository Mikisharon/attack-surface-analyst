# Product to CPE mapping

CPE (Common Platform Enumeration) is the identifier NVD uses to say which product a CVE affects. Format:

`cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*`

| Detected product (from Enrichment) | CPE vendor | CPE product |
|---|---|---|
| nginx | `f5` (older CVEs may use `nginx`) | `nginx` |
| Apache HTTP Server | `apache` | `http_server` |
| Microsoft IIS | `microsoft` | `internet_information_services` |
| OpenSSL | `openssl` | `openssl` |
| PHP | `php` | `php` |
| Jenkins | `jenkins` | `jenkins` |
| Grafana | `grafana` | `grafana` |

## Rules

- Verify each new row by searching the product on the NVD website before adding it. Vendors and product names in CPE are not always obvious.
- When a product has two vendor names (nginx), query both and merge the results by CVE ID.
- A product not in this table gets no CVE lookup. Record it in `errors` as "no CPE mapping", so you know which rows to add next.
