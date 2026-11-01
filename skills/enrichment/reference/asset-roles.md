# Asset roles and importance

Classify every live host into exactly one role. Importance reflects how valuable the host is to an attacker and how much damage its compromise would cause.

| Role | Typical evidence | Default importance |
|---|---|---|
| `vpn_portal` | Titles or headers from GlobalProtect, Fortinet, Pulse/Ivanti, Cisco AnyConnect, Citrix Gateway | high |
| `admin_panel` | "Admin", "Login", "Dashboard" titles; management products (Jenkins, Grafana, phpMyAdmin, Kibana) | high |
| `remote_access` | RDP web, SSH web consoles, remote support tools | high |
| `email` | `mail`, `owa`, `webmail` names; Exchange / OWA titles | high |
| `api` | `api` in the name; JSON responses; no HTML title | medium |
| `auth` | `sso`, `login`, `auth`, `idp` names; identity provider titles | high |
| `dev_or_staging` | `dev`, `test`, `staging`, `uat`, `qa` in the name | medium |
| `file_sharing` | `files`, `share`, `ftp`, `nextcloud` | medium |
| `marketing_site` | Public website, CMS (WordPress, Webflow), product pages | low |
| `docs_or_support` | `docs`, `help`, `support`, `status` | low |
| `cdn_or_redirect` | Only redirects; CDN headers with no own content | low |
| `parked_or_default` | Default server pages ("Welcome to nginx", "IIS Windows Server") | medium |
| `unknown` | Evidence does not support any role | low |

## Importance definitions

- **high**: grants access to internal systems or sensitive data if compromised, or is a known favorite entry point for attackers.
- **medium**: could leak information or provide a foothold, but is not a direct path to sensitive systems.
- **low**: public content with little value beyond defacement.

## Adjustments

- A default or parked page is `medium`, not `low`. It often means a forgotten server that nobody patches.
- A name containing `old`, `legacy` or `backup` raises importance by one level, up to `high`, but only together with other evidence that the host is live.
