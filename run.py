"""CLI orchestrator: python run.py scanme.nmap.org

Runs the five agents in sequence and records every step in runs/<target>-<date>.json.

    python run.py --demo                 # offline training scenario, no network, no API key
    python run.py scanme.nmap.org        # live scan of an allowlisted target
    python run.py vulnweb.com --llm offline   # live data, heuristic stand-in instead of Claude
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from dotenv import load_dotenv

from agents import enrichment, prioritization, recon, report, threat_intel
from core.envelope import Envelope, StepError, make_envelope, utc_now
from core.llm import OFFLINE_MODEL, BaseLLM, make_llm
from core.net import BaseNet, FixtureNet, LiveNet
from core.recorder import RUNS_DIR, Recorder
from core.scope import ScopeError, check_target

ROOT = Path(__file__).resolve().parent
DEMO_FIXTURE = ROOT / "evals" / "golden" / "training_scenario.json"
DEMO_TARGET = "demo-corp.example"


def say(message: str) -> None:
    print(message, flush=True)


def run_pipeline(target: str, net: BaseNet, llm: BaseLLM, runs_dir: Path = RUNS_DIR,
                 cache_dir: Path | None = None, label: str | None = None,
                 synthetic: bool = False) -> Path:
    """Run recon -> enrichment -> threat intel -> prioritization -> report and save the run."""
    recorder = Recorder(target, runs_dir=runs_dir, label=label, synthetic=synthetic)

    def step(name: str, fn) -> Envelope | None:
        started = utc_now()
        try:
            env = fn()
        except Exception as exc:  # one agent crashing must still leave a recorded run
            env = make_envelope(name, "?", started, {}, errors=[StepError(step=name, reason=repr(exc))],
                                status="failed")
        recorder.add(env)
        extra = f", {env.llm_usage.calls} LLM calls" if env.llm_usage else ""
        say(f"  {env.agent:<15} {env.status:<9} {len(env.evidence):>3} evidence{extra}")
        for err in env.errors:
            say(f"      ! {err.step}: {err.reason}")
        return None if env.status == "failed" else env

    say(f"Scanning {target} (LLM: {llm.model})")
    rec = step("recon", lambda: recon.run(target, net))
    enr = rec and step("enrichment", lambda: enrichment.run(rec, net, llm))
    ti = enr and step("threat_intel", lambda: threat_intel.run(enr, net, cache_dir=cache_dir))
    evidence_ids = {e.id for s in recorder.steps for e in s.evidence}
    pr = ti and step("prioritization", lambda: prioritization.run(enr, ti, llm, evidence_ids))
    if pr:
        step("report", lambda: report.run(target, list(recorder.steps), llm))

    path = recorder.save()
    run = recorder.build()
    s = run["summary"]
    say(f"Run {run['status']}: {s['hosts']} hosts, {s['findings']} findings, P1={s['p1']}, "
        f"P2={s['p2']}, est. LLM cost ${s['cost_usd']:.4f}")
    say(f"Saved {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")
    return path


def main(argv: list[str] | None = None) -> int:
    load_dotenv(ROOT / ".env")
    parser = argparse.ArgumentParser(description="Attack Surface Analyst")
    parser.add_argument("target", nargs="?", help="an authorized domain from config/targets.yaml")
    parser.add_argument("--demo", action="store_true",
                        help="run the offline training scenario (no network, no API key needed)")
    parser.add_argument("--llm", choices=["auto", "claude", "offline"], default="auto",
                        help="auto = Claude if ANTHROPIC_API_KEY is set, else the offline heuristic")
    parser.add_argument("--runs-dir", type=Path, default=RUNS_DIR)
    args = parser.parse_args(argv)

    target_name = DEMO_TARGET if args.demo else args.target
    if not target_name:
        parser.error("give a target, or use --demo")
    try:
        target = check_target(target_name)  # FR-1: refuse before any request is made
    except ScopeError as exc:
        say(f"Refused: {exc}")
        return 2

    llm = make_llm(args.llm)
    if llm.model == OFFLINE_MODEL:
        say("Note: no Claude API key in use; LLM steps run with the offline heuristic stand-in.")

    if target.mode == "synthetic":
        if not args.demo:
            say(f"Refused: {target.domain} is a synthetic target; run it with --demo.")
            return 2
        net: BaseNet = FixtureNet.from_file(DEMO_FIXTURE)
        run_pipeline(target.domain, net, llm, runs_dir=args.runs_dir, cache_dir=None,
                     label="Training scenario (synthetic data)", synthetic=True)
    else:
        run_pipeline(target.domain, LiveNet(target.domain), llm, runs_dir=args.runs_dir,
                     cache_dir=ROOT / ".cache")
    say("Next: python scripts/publish.py  then  python -m http.server 8000 --directory site")
    return 0


if __name__ == "__main__":
    sys.exit(main())
