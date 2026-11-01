# Attack Surface Analyst

A multi-agent demo that turns a domain name into a prioritized, evidence-backed external attack surface report.

Five agents work in sequence: **Recon** finds subdomains, **Enrichment** profiles each host, **Threat Intel** matches software to known and actively exploited vulnerabilities, **Prioritization** decides what to fix first, and **Report** explains it to leadership and engineers. Code fetches the facts; the LLM reasons over them and never invents them.

> Status: P0 implemented (all five agents, run recorder, replay UI). P1 items (scheduled CI, eval harness, metrics panel) are next.

## Run the demo on your laptop

You need **Python 3.11 or newer** and **git**. Check with `python3 --version`.

```bash
# 1. Get the code
git clone https://github.com/Mikisharon/attack-surface-analyst.git
cd attack-surface-analyst

# 2. Create a virtual environment and install the dependencies
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 3. Run the offline demo (no internet scan, no API key needed)
python run.py --demo

# 4. Copy the recorded runs into the website and open it
python scripts/publish.py
python -m http.server 8000 --directory site
```

Then open <http://localhost:8000> and watch the five agents replay. Click any finding to see the evidence behind it. Stop the web server with `Ctrl+C`.

### What `--demo` does

It runs the full pipeline against **demo-corp.example**, a fictional company whose DNS answers, web pages and certificates come from `evals/golden/training_scenario.json`. Nothing is sent over the network. You should see:

```
Scanning demo-corp.example (LLM: offline-heuristic)
  recon           ok         10 evidence
  enrichment      ok         58 evidence, 9 LLM calls
  threat_intel    ok         10 evidence
  prioritization  ok          0 evidence, 8 LLM calls
  report          ok          0 evidence, 1 LLM calls
Run ok: 10 hosts, 19 findings, P1=4, P2=3, est. LLM cost $0.0000
```

### Use Claude for the LLM steps

Without an API key the three LLM steps use a small deterministic heuristic with the same inputs, output schema and validation, and the run is labelled "offline LLM stand-in" in the UI. To use Claude:

```bash
cp .env.example .env
# edit .env and set ANTHROPIC_API_KEY=sk-ant-...
python run.py --demo
```

The default model is `claude-opus-5-5`. Set `ASA_MODEL=claude-haiku-5-5` in `.env` for much cheaper runs (closer to the PRD's < $0.10 per target). Use `--llm offline` to force the heuristic, or `--llm claude` to require Claude.

### Scan a real, authorized target

```bash
python run.py scanme.nmap.org
python run.py vulnweb.com
```

Only domains listed in `config/targets.yaml` are accepted; anything else is refused before a single request is made. Recon is passive (certificate transparency via crt.sh), and each discovered host gets at most one HTTPS request. Threat Intel paces NVD requests (about 6 s apart without a key), so a live run takes a few minutes; add a free `NVD_API_KEY` to `.env` to speed it up.

### Run the tests

```bash
python -m pytest
```

All tests run offline with recorded or mocked network responses.

## How it fits together

```
run.py                 CLI orchestrator: allowlist check, then the five agents in order
agents/                recon.py, enrichment.py, threat_intel.py, prioritization.py, report.py
core/                  envelope.py (data contract), evidence.py, llm.py (Claude wrapper),
                       recorder.py (run files + citation check), scope.py, net.py (scoped network access)
config/                targets.yaml (allowlist), sources.yaml (data source URLs)
skills/                one SKILL.md per agent; LLM agents load theirs at runtime as instructions
evals/golden/          the synthetic training scenario
runs/                  recorded run files + index.json
site/                  replay UI (static HTML/CSS/JS); site/data/ holds published runs
scripts/publish.py     copies runs/ into site/data/
```

## Documentation

- [PRD & architecture](docs/PRD.md)
- [Agent skills](skills/): one `SKILL.md` per agent, plus [shared conventions](skills/_shared/conventions.md)

## Responsible use

Scans run only on targets listed in an allowlist: the author's own domain and sites that are intentionally public for security testing. Discovery is passive, and each discovered host receives at most one ordinary HTTPS request.
