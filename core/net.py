"""Network access for the agents, with the scope rules built in.

Agents never call `requests` or DNS directly. They get a `Net` object, which:
- in live mode talks to the internet, but refuses any host that is neither a
  known public data source (crt.sh, NVD, CISA) nor inside the target domain;
- in demo/test mode (`FixtureNet`) answers from a recorded JSON file, so the
  whole pipeline runs offline and gives the same result every time.
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from core.scope import ScopeError, in_scope, load_sources

MAX_BODY_BYTES = 64 * 1024
MAX_REDIRECTS = 3
PAGE_TIMEOUT_S = 10


class SourceError(Exception):
    """A data source failed. `retryable` tells the caller whether to try again."""

    def __init__(self, reason: str, retryable: bool = True, status: int | None = None):
        super().__init__(reason)
        self.reason = reason
        self.retryable = retryable
        self.status = status


@dataclass
class PageResult:
    """What one fetch of https://<host>/ (or the http fallback) returned."""

    url: str
    final_url: str = ""
    status: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    error: str | None = None
    redirect_blocked: str | None = None  # a redirect we refused to follow


class BaseNet:
    target: str

    def get_json(self, url: str, params: dict | None = None, timeout: float = 60,
                 headers: dict | None = None) -> Any:
        raise NotImplementedError

    def fetch_page(self, url: str) -> PageResult:
        raise NotImplementedError

    def resolve(self, name: str, rtype: str) -> list[str]:
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


class LiveNet(BaseNet):
    def __init__(self, target: str):
        self.target = target
        sources = load_sources()
        self.user_agent = sources["user_agent"]
        # The only non-target hosts the pipeline may contact.
        self.source_hosts = {
            urlparse(sources[k]["url"]).hostname for k in ("crtsh", "nvd", "kev")
        }
        self.session = requests.Session()
        self.session.headers["User-Agent"] = self.user_agent

    def _check(self, url: str, allow_sources: bool) -> None:
        host = urlparse(url).hostname or ""
        if allow_sources and host in self.source_hosts:
            return
        if not in_scope(host, self.target):
            raise ScopeError(f"refusing to contact {host}: outside {self.target}")

    def get_json(self, url, params=None, timeout=60, headers=None):
        self._check(url, allow_sources=True)
        try:
            resp = self.session.get(url, params=params, timeout=timeout, headers=headers)
        except requests.Timeout:
            raise SourceError(f"timeout after {timeout}s")
        except requests.RequestException as exc:
            raise SourceError(f"connection error: {exc.__class__.__name__}")
        if resp.status_code in (403, 429) or resp.status_code >= 500:
            raise SourceError(f"HTTP {resp.status_code}", retryable=True, status=resp.status_code)
        if resp.status_code >= 400:
            raise SourceError(f"HTTP {resp.status_code}", retryable=False, status=resp.status_code)
        try:
            return resp.json()
        except ValueError:
            # crt.sh sometimes answers with an HTML error page.
            raise SourceError("response was not valid JSON")

    def fetch_page(self, url):
        result = PageResult(url=url)
        current = url
        try:
            for _ in range(MAX_REDIRECTS + 1):
                self._check(current, allow_sources=False)
                with self.session.get(current, timeout=PAGE_TIMEOUT_S,
                                      allow_redirects=False, stream=True) as resp:
                    result.final_url = current
                    result.status = resp.status_code
                    result.headers = dict(resp.headers)
                    body = b""
                    for chunk in resp.iter_content(8192):
                        body += chunk
                        if len(body) >= MAX_BODY_BYTES:
                            break
                    result.body = body[:MAX_BODY_BYTES].decode(resp.encoding or "utf-8", "replace")
                    location = resp.headers.get("Location")
                    if not (resp.is_redirect and location):
                        return result
                next_url = urljoin(current, location)
                # Only follow redirects that stay inside the target domain.
                if not in_scope(urlparse(next_url).hostname or "", self.target):
                    result.redirect_blocked = next_url
                    return result
                current = next_url
            return result  # redirect limit reached: keep the last response
        except ScopeError as exc:
            result.error = str(exc)
        except requests.Timeout:
            result.error = f"timeout after {PAGE_TIMEOUT_S}s"
        except requests.exceptions.SSLError:
            result.error = "TLS error"
        except requests.ConnectionError:
            result.error = "connection failed"
        except requests.RequestException as exc:
            result.error = exc.__class__.__name__
        return result

    def resolve(self, name, rtype):
        import dns.exception
        import dns.resolver

        try:
            answer = dns.resolver.resolve(name, rtype, lifetime=5)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        return [r.to_text().rstrip(".") for r in answer]


class FixtureNet(BaseNet):
    """Answers every request from a recorded scenario file. Never touches the network.

    Fixture layout (see evals/golden/training_scenario.json):
      crtsh: list of crt.sh entries, or {"error": "..."}
      dns:   {host: {"A": [...], "AAAA": [...], "CNAME": [...]}}
      http:  {url: {"status", "headers", "body"} or {"error": "..."}}
      nvd:   {cpe_name: [NVD "vulnerabilities" items]}
      kev:   the CISA KEV JSON document, or {"error": "..."}
    """

    def __init__(self, fixture: dict, target: str | None = None):
        self.fixture = fixture
        self.target = target or fixture["target"]
        self.calls: list[str] = []  # for tests: what was requested

    @classmethod
    def from_file(cls, path) -> "FixtureNet":
        with open(path) as f:
            return cls(json.load(f))

    def sleep(self, seconds):
        pass  # no real waiting in offline mode

    def _maybe_error(self, value):
        if isinstance(value, dict) and "error" in value:
            raise SourceError(value["error"], retryable=value.get("retryable", True))
        return value

    def get_json(self, url, params=None, timeout=60, headers=None):
        params = params or {}
        self.calls.append(url)
        host = urlparse(url).hostname
        if host == "crt.sh":
            return self._maybe_error(self.fixture.get("crtsh", []))
        if host == "services.nvd.nist.gov":
            nvd = self._maybe_error(self.fixture.get("nvd", {}))
            return {"vulnerabilities": nvd.get(params.get("cpeName", ""), [])}
        if host == "www.cisa.gov":
            return self._maybe_error(self.fixture.get("kev", {"vulnerabilities": []}))
        raise ScopeError(f"fixture has no source for {host}")

    def fetch_page(self, url):
        self.calls.append(url)
        host = urlparse(url).hostname or ""
        if not in_scope(host, self.target):
            return PageResult(url=url, error=f"refusing to contact {host}: outside {self.target}")
        entry = self.fixture.get("http", {}).get(url)
        if entry is None:
            return PageResult(url=url, error="connection failed")
        if "error" in entry:
            return PageResult(url=url, error=entry["error"])
        result = PageResult(url=url, final_url=entry.get("final_url", url),
                            status=entry["status"], headers=entry.get("headers", {}),
                            body=entry.get("body", "")[:MAX_BODY_BYTES])
        location = result.headers.get("Location")
        if location and 300 <= result.status < 400:
            next_url = urljoin(url, location)
            if not in_scope(urlparse(next_url).hostname or "", self.target):
                result.redirect_blocked = next_url
        return result

    def resolve(self, name, rtype):
        return list(self.fixture.get("dns", {}).get(name, {}).get(rtype, []))


def html_title(body: str) -> str | None:
    """Extract and clean the <title>, truncated to 200 characters."""
    import html

    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = " ".join(html.unescape(match.group(1)).split())
    return title[:200] or None
