from agents import recon
from core.net import FixtureNet, SourceError


class TimeoutNet(FixtureNet):
    def __init__(self, failures):
        super().__init__({"target": "example.com"})
        self.failures = failures
        self.attempts = 0
        self.waits = []

    def sleep(self, seconds):
        self.waits.append(seconds)

    def get_json(self, url, params=None, timeout=60, headers=None):
        self.attempts += 1
        if self.attempts <= self.failures:
            raise SourceError("timeout after 60s")
        return [{"id": 7, "name_value": "www.example.com", "not_before": "2024-01-01T00:00:00",
                 "not_after": "2025-01-01T00:00:00"}]


def test_normalizes_drops_wildcards_and_out_of_scope_names():
    net = FixtureNet({"target": "example.com", "crtsh": [
        {"id": 1, "name_value": "*.example.com\nWWW.example.com.\nother.com",
         "not_before": "2024-01-01T00:00:00", "not_after": "2025-01-01T00:00:00"}]})
    env = recon.run("example.com", net)
    assert env.status == "ok"
    assert [s["name"] for s in env.output["subdomains"]] == ["example.com", "www.example.com"]
    assert env.output["wildcards"] == ["example.com"]
    assert all(e.id.startswith("ev-rec-") for e in env.evidence)


def test_deduplicates_and_keeps_date_range(net):
    env = recon.run("demo-corp.example", net)
    vpn = next(s for s in env.output["subdomains"] if s["name"] == "vpn.demo-corp.example")
    assert vpn["first_seen"] == "2022-03-04" and vpn["last_cert_expiry"] == "2027-03-04"
    names = [s["name"] for s in env.output["subdomains"]]
    assert names == sorted(names) and len(names) == len(set(names))
    assert "jenkins.demo-corp.example" in names  # upper case + trailing dot normalized
    assert "demo-corp-partner.com" not in names


def test_timeout_every_attempt_is_degraded_not_failed():
    net = TimeoutNet(failures=99)
    env = recon.run("example.com", net)
    assert env.status == "degraded"
    assert len(env.errors) == 1
    assert [s["name"] for s in env.output["subdomains"]] == ["example.com"]
    assert net.waits == [5, 15, 30]


def test_timeout_three_times_then_success_is_ok():
    env = recon.run("example.com", TimeoutNet(failures=3))
    assert env.status == "ok"
    assert "www.example.com" in [s["name"] for s in env.output["subdomains"]]


def test_html_error_page_is_degraded():
    net = FixtureNet({"target": "example.com", "crtsh": {"error": "response was not valid JSON"}})
    env = recon.run("example.com", net)
    assert env.status == "degraded"


def test_zero_certificates_returns_target_without_error():
    env = recon.run("scanme.nmap.org", FixtureNet({"target": "scanme.nmap.org", "crtsh": []}))
    assert env.status == "ok" and env.output["count"] == 1 and not env.errors
