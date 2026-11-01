import pytest

from core.net import FixtureNet, LiveNet
from core.scope import ScopeError, check_target, in_scope
from run import main


def test_allowlisted_target_is_accepted():
    assert check_target("SCANME.nmap.org.").domain == "scanme.nmap.org"


def test_unknown_target_is_refused():
    with pytest.raises(ScopeError):
        check_target("example.org")


def test_cli_refuses_before_any_request(capsys):
    assert main(["not-allowed.com"]) == 2
    assert "Refused" in capsys.readouterr().out


def test_synthetic_target_needs_demo_flag(capsys):
    assert main(["demo-corp.example"]) == 2


@pytest.mark.parametrize("host,ok", [
    ("demo-corp.example", True), ("a.b.demo-corp.example", True),
    ("evildemo-corp.example", False), ("demo-corp.example.evil.com", False)])
def test_in_scope(host, ok):
    assert in_scope(host, "demo-corp.example") is ok


def test_live_net_refuses_out_of_scope_hosts():
    net = LiveNet("scanme.nmap.org")
    with pytest.raises(ScopeError):
        net._check("https://example.org/", allow_sources=True)
    net._check("https://crt.sh/", allow_sources=True)  # data sources are allowed
    with pytest.raises(ScopeError):
        net._check("https://crt.sh/", allow_sources=False)  # but never fetched as "pages"


def test_fixture_net_never_fetches_outside_target():
    net = FixtureNet({"target": "demo-corp.example"})
    assert "outside" in net.fetch_page("https://other.com/").error


class FakeResponse:
    def __init__(self, status, headers, body=b""):
        self.status_code, self.headers, self._body = status, headers, body
        self.encoding = "utf-8"
        self.is_redirect = status in (301, 302, 303, 307, 308)

    def iter_content(self, size):
        yield self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses, self.urls, self.headers = responses, [], {}

    def get(self, url, **kwargs):
        self.urls.append(url)
        return self.responses[url]


def test_live_fetch_follows_in_scope_redirect_but_not_out_of_scope():
    net = LiveNet("example.com")
    net.session = FakeSession({
        "https://a.example.com/": FakeResponse(301, {"Location": "https://b.example.com/"}),
        "https://b.example.com/": FakeResponse(302, {"Location": "https://evil.com/login"}),
    })
    page = net.fetch_page("https://a.example.com/")
    assert net.session.urls == ["https://a.example.com/", "https://b.example.com/"]
    assert page.redirect_blocked == "https://evil.com/login" and page.status == 302


def test_live_fetch_reads_at_most_64kb():
    net = LiveNet("example.com")
    net.session = FakeSession({"https://a.example.com/": FakeResponse(200, {}, b"x" * 200_000)})
    assert len(net.fetch_page("https://a.example.com/").body) == 64 * 1024


def test_live_net_sends_identifying_user_agent():
    assert LiveNet("example.com").session.headers["User-Agent"].startswith("AttackSurfaceAnalyst-demo")
