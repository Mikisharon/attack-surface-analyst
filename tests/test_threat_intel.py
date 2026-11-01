from agents import enrichment, recon, threat_intel
from core.envelope import make_envelope, utc_now
from core.llm import OfflineLLM
from core.net import FixtureNet


def ti_for(net):
    rec = recon.run(net.target, net)
    enr = enrichment.run(rec, net, OfflineLLM())
    return threat_intel.run(enr, net, cache_dir=None)


def synthetic_host(**overrides):
    base = {"name": "x.demo-corp.example", "live": True, "contacted": True, "https": True,
            "status": 200, "products": [], "missing_security_headers": [],
            "role": "marketing_site", "importance": "low",
            "evidence_index": {"dns": ["ev-enr-0001"]}, "evidence_ids": ["ev-enr-0001"]}
    base.update(overrides)
    return base


def run_hosts(hosts, fixture=None):
    env = make_envelope("enrichment", "recon", utc_now(), {"hosts": hosts})
    net = FixtureNet(fixture or {"target": "demo-corp.example", "kev": {"vulnerabilities": []}})
    return threat_intel.run(env, net, cache_dir=None)


def kinds(env, host=None):
    return [f["kind"] for f in env.output["findings"] if host is None or f["host"] == host]


def test_kev_listed_cve_is_flagged(net):
    env = ti_for(net)
    jenkins = [f for f in env.output["findings"] if f.get("cve") == "CVE-2024-23897"]
    assert len(jenkins) == 1 and jenkins[0]["in_kev"] is True and jenkins[0]["kev_ransomware"] is True
    types = {e.type for e in env.evidence}
    assert {"cve_match", "kev_listing"} <= types


def test_partial_version_gives_unverified_version_and_no_cves():
    env = run_hosts([synthetic_host(importance="high", role="admin_panel", products=[
        {"product": "Apache HTTP Server", "version": "2", "version_confidence": "partial",
         "evidence_id": "ev-enr-0001"}])])
    assert "unverified_version" in kinds(env)
    assert "known_vulnerability" not in kinds(env)


def test_vpn_portal_is_sensitive_service_exposed():
    env = run_hosts([synthetic_host(role="vpn_portal", importance="high",
                                    classification_evidence=["ev-enr-0001"])])
    assert kinds(env) == ["sensitive_service_exposed"]


def test_nginx_two_vendors_merged_by_cve_id(net):
    env = ti_for(net)
    apex = [f for f in env.output["findings"] if f["host"] == "demo-corp.example" and f.get("cve")]
    assert [f["cve"] for f in apex] == ["CVE-2021-23017"]


def test_finding_ids_are_stable_and_ordered(net):
    first = ti_for(net).output["findings"]
    second = ti_for(FixtureNet(net.fixture)).output["findings"]
    assert [f["id"] for f in first] == [f"F-{i:04d}" for i in range(1, len(first) + 1)]
    assert [(f["id"], f["host"], f["kind"]) for f in first] == [(f["id"], f["host"], f["kind"]) for f in second]


def test_kev_unavailable_means_unknown_not_false(scenario):
    scenario["kev"] = {"error": "HTTP 503"}
    env = ti_for(FixtureNet(scenario))
    assert env.status == "degraded"
    cves = [f for f in env.output["findings"] if f["kind"] == "known_vulnerability"]
    assert cves and all(f["in_kev"] is None for f in cves)


def test_nvd_unavailable_keeps_exposure_findings(scenario):
    scenario["nvd"] = {"error": "HTTP 503"}
    env = ti_for(FixtureNet(scenario))
    assert env.status == "degraded"
    assert "known_vulnerability" not in kinds(env)
    assert "sensitive_service_exposed" in kinds(env)


def test_missing_hsts_and_no_https(net):
    env = ti_for(net)
    assert "no_https" in kinds(env, "staging-api.demo-corp.example")
    assert "missing_hsts" in kinds(env, "www.demo-corp.example")
