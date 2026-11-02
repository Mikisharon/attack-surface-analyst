from agents import enrichment, prioritization, recon, threat_intel
from agents.prioritization import baseline
from core.llm import OfflineLLM
from tests.conftest import ScriptedLLM


def pipeline_until_ti(net):
    rec = recon.run(net.target, net)
    enr = enrichment.run(rec, net, OfflineLLM())
    ti = threat_intel.run(enr, net, cache_dir=None)
    ids = {e.id for s in (rec, enr, ti) for e in s.evidence}
    return enr, ti, ids


def test_rubric_worked_examples():
    assert baseline({"kind": "known_vulnerability", "in_kev": True, "cvss": 3.0}, "low")[0] == "P1"
    assert baseline({"kind": "known_vulnerability", "cvss": 7.5}, "high")[:2] == ("P2", 50)
    assert baseline({"kind": "missing_hsts"}, "low")[:2] == ("P4", 5)
    assert baseline({"kind": "sensitive_service_exposed"}, "high")[:2] == ("P2", 50)


def test_missing_hsts_on_marketing_site_ends_p4(net):
    enr, ti, ids = pipeline_until_ti(net)
    env = prioritization.run(enr, ti, OfflineLLM(), ids)
    www = [p for p in env.output["prioritized"]
           if p["host"] == "www.demo-corp.example" and p["kind"] == "missing_hsts"]
    assert www[0]["final"] == "P4"


def lower_everything(payload):
    """A misbehaving LLM: demotes every finding two levels."""
    decisions = []
    for f in payload["findings"]:
        final = {"P1": "P3", "P2": "P4", "P3": "P4", "P4": "P4"}[f["baseline"]]
        decisions.append({"finding_id": f["id"], "baseline": f["baseline"], "final": final,
                          "adjustment": "none" if final == f["baseline"] else "down",
                          "rationale": f"Lowered ({f['evidence_ids'][0]}).",
                          "evidence_ids": f["evidence_ids"][:1]})
    return {"decisions": decisions}


def test_kev_finding_stays_p1_even_if_llm_says_p2(net):
    enr, ti, ids = pipeline_until_ti(net)

    def kev_to_p2(payload):
        data = prioritization.heuristic_review(payload)
        for d, f in zip(data["decisions"], payload["findings"]):
            if f.get("in_kev"):
                d.update(final="P2", adjustment="down")
        return data
    env = prioritization.run(enr, ti, ScriptedLLM([kev_to_p2] * 40), ids)
    kev_ids = {f["id"] for f in ti.output["findings"] if f.get("in_kev")}
    assert kev_ids and all(p["final"] == "P1" for p in env.output["prioritized"] if p["finding_id"] in kev_ids)


def test_p4_to_p1_is_rejected_and_baseline_used(net):
    enr, ti, ids = pipeline_until_ti(net)

    def jump(payload):
        data = prioritization.heuristic_review(payload)
        for d in data["decisions"]:
            if d["baseline"] == "P4":
                d.update(final="P1", adjustment="up")
        return data
    env = prioritization.run(enr, ti, ScriptedLLM([jump] * 40), ids)
    p4 = [p for p in env.output["prioritized"] if p["baseline"] == "P4"]
    assert p4 and all(p["final"] == "P4" and p.get("fallback") for p in p4)
    assert env.status == "degraded"


def test_moving_more_than_half_is_flagged(net):
    enr, ti, ids = pipeline_until_ti(net)

    def demote_one_level(payload):
        data = prioritization.heuristic_review(payload)
        for d, f in zip(data["decisions"], payload["findings"]):
            if not f.get("in_kev") and f["baseline"] != "P4":
                d.update(final=prioritization.shift(f["baseline"], 1), adjustment="down")
        return data
    env = prioritization.run(enr, ti, ScriptedLLM([demote_one_level] * 40), ids)
    assert env.output["adjusted_share"] > 0.5
    assert any("adjustment share" == e.step for e in env.errors)


def test_threat_intel_envelope_is_not_modified(net):
    enr, ti, ids = pipeline_until_ti(net)
    before = ti.model_dump()
    prioritization.run(enr, ti, OfflineLLM(), ids)
    assert ti.model_dump() == before


def test_sorted_by_priority_then_importance(net):
    enr, ti, ids = pipeline_until_ti(net)
    env = prioritization.run(enr, ti, OfflineLLM(), ids)
    order = [p["final"] for p in env.output["prioritized"]]
    assert order == sorted(order)
