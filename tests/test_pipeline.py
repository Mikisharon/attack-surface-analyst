import json

from core.llm import OfflineLLM
from core.net import FixtureNet
from core.recorder import cited_ids, known_ids
from run import DEMO_FIXTURE, run_pipeline


def test_demo_run_end_to_end(tmp_path):
    path = run_pipeline("demo-corp.example", FixtureNet.from_file(DEMO_FIXTURE), OfflineLLM(),
                        runs_dir=tmp_path, synthetic=True)
    run = json.loads(path.read_text())
    assert [s["agent"] for s in run["steps"]] == ["recon", "enrichment", "threat_intel",
                                                  "prioritization", "report"]
    assert run["status"] == "ok"
    assert run["summary"]["unknown_citations"] == 0
    assert run["summary"]["p1"] >= 3
    index = json.loads((tmp_path / "index.json").read_text())
    assert index["runs"][0]["file"] == path.name


def test_recorder_flags_unknown_citations(tmp_path):
    from core.envelope import make_envelope, utc_now
    from core.recorder import Recorder
    rec = Recorder("demo-corp.example", runs_dir=tmp_path)
    rec.add(make_envelope("report", "prioritization", utc_now(),
                          {"executive_summary": "Bad claim [F-0042] (ev-enr-0099)."}))
    run = rec.build()
    assert run["summary"]["unknown_citations"] == 2
    assert run["steps"][0]["status"] == "degraded"


def test_reruns_are_identical_apart_from_timestamps(tmp_path):
    def strip(run):
        text = json.dumps(run["steps"])
        import re
        return re.sub(r'"(started_at|finished_at|collected_at)": "[^"]+"', "", text)
    a = run_pipeline("demo-corp.example", FixtureNet.from_file(DEMO_FIXTURE), OfflineLLM(), runs_dir=tmp_path / "a")
    b = run_pipeline("demo-corp.example", FixtureNet.from_file(DEMO_FIXTURE), OfflineLLM(), runs_dir=tmp_path / "b")
    assert strip(json.loads(a.read_text())) == strip(json.loads(b.read_text()))
