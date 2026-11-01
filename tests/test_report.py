from agents import enrichment, prioritization, recon, report, threat_intel
from core.envelope import StepError
from core.llm import OfflineLLM
from core.net import FixtureNet
from tests.conftest import ScriptedLLM


def steps_for(net):
    rec = recon.run(net.target, net)
    enr = enrichment.run(rec, net, OfflineLLM())
    ti = threat_intel.run(enr, net, cache_dir=None)
    ids = {e.id for s in (rec, enr, ti) for e in s.evidence}
    pr = prioritization.run(enr, ti, OfflineLLM(), ids)
    return [rec, enr, ti, pr]


def test_no_p1_p2_says_no_urgent_issues():
    net = FixtureNet({"target": "example.com", "crtsh": [], "dns": {"example.com": {"A": ["203.0.113.1"]}},
                      "http": {"https://example.com/": {"status": 200, "headers": {
                          "Strict-Transport-Security": "max-age=1"}, "body": "<title>Example shop</title>"}}})
    env = report.run("example.com", steps_for(net), OfflineLLM())
    assert env.status == "ok"
    assert "No urgent issues" in env.output["executive_summary"]


def test_degraded_threat_intel_is_mentioned_in_limitations(net):
    steps = steps_for(net)
    steps[2].status = "degraded"
    steps[2].errors.append(StepError(step="kev catalog", reason="KEV feed unavailable"))
    env = report.run(net.target, steps, OfflineLLM())
    assert "threat intel" in env.output["limitations"].lower()


def test_planted_fake_count_is_caught(net):
    steps = steps_for(net)
    fake = {"executive_summary": "We found 5 critical issues [F-0004].",
            "recommendations": [{"action": "Patch Jenkins [F-0004].", "finding_ids": ["F-0004"]}],
            "limitations": "All data sources responded."}
    llm = ScriptedLLM([fake, fake])
    env = report.run(net.target, steps, llm)
    assert len(llm.prompts) == 2  # retried once with the correct numbers
    assert "numbers [5]" in llm.prompts[1][1]
    assert env.status == "degraded"
    assert "5 critical" not in env.output["executive_summary"]  # never published


def test_unknown_citation_and_cve_in_summary_are_rejected(net):
    steps = steps_for(net)
    bad = {"executive_summary": "CVE-2024-23897 is bad [F-9999].", "recommendations": [],
           "limitations": "All data sources responded."}
    good = report.heuristic_narrative  # second answer is valid
    llm = ScriptedLLM([bad, good])
    env = report.run(net.target, steps, llm)
    assert env.status == "ok"
    assert "unknown IDs" in llm.prompts[1][1] and "CVE IDs" in llm.prompts[1][1]


def test_findings_table_built_from_data(net):
    env = report.run(net.target, steps_for(net), OfflineLLM())
    table = env.output["findings_table"]
    assert table[0]["priority"] == "P1"
    assert "| Priority | Host |" in env.output["markdown"]
