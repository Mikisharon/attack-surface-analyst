// Replay UI (FR-9): pick a recorded run, watch the agents run in sequence,
// browse findings, open the evidence behind each one, read the report.
//
// Everything that came from a target (titles, headers) is inserted with
// textContent, never innerHTML: target content is untrusted data.
"use strict";

const AGENTS = [
  { id: "recon", name: "Recon", kind: "Tool", llm: false, does: "Finds subdomains in certificate transparency logs (crt.sh)." },
  { id: "enrichment", name: "Enrichment", kind: "Hybrid", llm: true, does: "Resolves DNS, fetches one page per host, detects software; the LLM classifies each host's role." },
  { id: "threat_intel", name: "Threat Intel", kind: "Tool", llm: false, does: "Matches exact versions to NVD CVEs and flags CISA KEV (actively exploited) entries." },
  { id: "prioritization", name: "Prioritization", kind: "Hybrid", llm: true, does: "Rubric baseline P1–P4; the LLM may move a finding by one level, with a cited reason." },
  { id: "report", name: "Report", kind: "LLM-led", llm: true, does: "Code builds the findings table; the LLM writes the summary, checked against the data." },
];
const CITATION_RE = /(ev-(?:rec|enr|ti)-\d{4}|F-\d{4})/g;

const state = { run: null, evidence: new Map(), findings: new Map(), timers: [], selected: null };
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value !== undefined && value !== null) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// Turn "text [F-0003] more" into text nodes plus clickable citation chips.
function cited(text) {
  const frag = document.createDocumentFragment();
  let last = 0;
  for (const match of String(text ?? "").matchAll(CITATION_RE)) {
    frag.append(document.createTextNode(text.slice(last, match.index)));
    frag.append(citeChip(match[0]));
    last = match.index + match[0].length;
  }
  frag.append(document.createTextNode(String(text ?? "").slice(last)));
  return frag;
}

function citeChip(id) {
  return el("button", { class: "cite", type: "button", title: `Open ${id}`, onclick: (e) => { e.stopPropagation(); openId(id); } }, id);
}

function prio(p) { return el("span", { class: `prio ${p}` }, p); }

// ------------------------------------------------------------------ loading

async function loadJSON(path) {
  const response = await fetch(path, { cache: "no-store" });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

async function init() {
  try {
    const index = await loadJSON("data/index.json");
    const picker = $("run-picker");
    for (const run of index.runs) {
      const label = `${run.target} · ${run.date}${run.synthetic ? " · training scenario" : ""}`;
      picker.append(el("option", { value: run.file }, label));
    }
    if (!index.runs.length) throw new Error("No runs in data/index.json yet.");
    const wanted = new URLSearchParams(location.search).get("run");
    if (wanted) picker.value = wanted;
    picker.addEventListener("change", () => selectRun(picker.value, true));
    $("replay").addEventListener("click", () => replay());
    $("skip").addEventListener("click", () => showAll());
    $("drawer-close").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeDrawer(); });
    document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));
    await selectRun(picker.value, true);
  } catch (err) {
    const box = $("load-error");
    box.hidden = false;
    box.textContent = `Could not load recorded runs (${err.message}). Run "python scripts/publish.py" and serve the site folder over HTTP, e.g. "python -m http.server 8000 --directory site".`;
  }
}

async function selectRun(file, autoplay) {
  const run = await loadJSON(`data/${file}`);
  state.run = run;
  state.evidence = new Map();
  state.findings = new Map();
  for (const step of run.steps) {
    for (const ev of step.evidence) state.evidence.set(ev.id, { ...ev, agent: step.agent });
    for (const f of step.output.findings || []) state.findings.set(f.id, f);
  }
  const prioStep = stepOf("prioritization");
  for (const p of prioStep?.output.prioritized || []) {
    const f = state.findings.get(p.finding_id);
    if (f) Object.assign(f, { priority: p });
  }
  history.replaceState(null, "", `?run=${encodeURIComponent(file)}`);
  renderBanners();
  if (autoplay) replay(); else showAll();
}

function stepOf(agent) { return state.run?.steps.find((s) => s.agent === agent); }

// ------------------------------------------------------------------ pipeline + replay

function renderBanners() {
  const box = $("banners");
  box.replaceChildren();
  const run = state.run;
  if (run.synthetic) {
    box.append(el("div", { class: "banner" }, el("strong", {}, "Training scenario. "),
      "A fictional company on the reserved .example domain. DNS, pages and certificates are synthetic; CVE and KEV entries are a snapshot of real public records."));
  }
  const models = run.summary.llm_models || [];
  if (models.includes("offline-heuristic")) {
    box.append(el("div", { class: "banner" }, el("strong", {}, "Offline LLM stand-in. "),
      "This run was recorded without a Claude API key: the LLM steps used a deterministic keyword heuristic with the same input, output schema and validation. Rerun with a key for model output."));
  }
  if (run.status !== "ok") {
    box.append(el("div", { class: "banner" }, el("strong", {}, `Run status: ${run.status}. `),
      "Some steps reported problems; see the step details and Data limitations."));
  }
}

function renderPipeline(visibleCount, runningIndex) {
  const list = $("pipeline");
  list.replaceChildren();
  AGENTS.forEach((agent, i) => {
    const step = stepOf(agent.id);
    let cls = "agent" + (agent.llm ? " llm" : "");
    let status = el("span", { class: "status waiting" }, "waiting");
    let meta = "";
    if (i === runningIndex) { cls += " running"; status = el("span", { class: "status waiting" }, "running…"); }
    else if (i < visibleCount && step) {
      status = el("span", { class: `status ${step.status}` }, step.status);
      const secs = Math.max(0, (Date.parse(step.finished_at) - Date.parse(step.started_at)) / 1000);
      const usage = step.llm_usage;
      meta = `${step.evidence.length} evidence · ${secs}s` + (usage ? ` · ${usage.calls} LLM calls · ` + (usage.model === "offline-heuristic" ? "offline heuristic" : `${usage.input_tokens + usage.output_tokens} tokens`) : "");
    } else if (i < visibleCount && !step) {
      status = el("span", { class: "status failed" }, "not run");
    } else cls += " pending";
    if (state.selected === agent.id) cls += " selected";
    list.append(el("li", {}, el("button", { class: cls, type: "button", onclick: () => selectStep(agent.id) },
      el("div", { class: "name" }, agent.name), el("div", { class: "kind" }, `${agent.kind}${agent.llm ? " · uses LLM" : ""}`),
      status, el("div", { class: "meta" }, meta))));
  });
}

function stopReplay() { state.timers.forEach(clearTimeout); state.timers = []; }

function replay() {
  stopReplay();
  $("results").hidden = true;
  $("step-detail").hidden = true;
  state.selected = null;
  const speed = Number($("speed").value) || 1;
  let delay = 0;
  renderPipeline(0, 0);
  AGENTS.forEach((agent, i) => {
    const step = stepOf(agent.id);
    // Pace by the recorded duration, clamped so fast offline runs are still watchable.
    const real = step ? (Date.parse(step.finished_at) - Date.parse(step.started_at)) : 0;
    delay += Math.min(3000, Math.max(900, real)) / speed;
    state.timers.push(setTimeout(() => {
      renderPipeline(i + 1, i + 1 < AGENTS.length ? i + 1 : -1);
      selectStep(agent.id);
      if (i === AGENTS.length - 1) showResults();
    }, delay));
  });
}

function showAll() {
  stopReplay();
  renderPipeline(AGENTS.length, -1);
  showResults();
}

function selectStep(agentId) {
  state.selected = agentId;
  document.querySelectorAll(".agent").forEach((b, i) => b.classList.toggle("selected", AGENTS[i].id === agentId));
  const agent = AGENTS.find((a) => a.id === agentId);
  const step = stepOf(agentId);
  const box = $("step-detail");
  box.hidden = false;
  box.replaceChildren(el("strong", {}, agent.name), " ", el("span", { class: "muted" }, agent.does));
  if (!step) { box.append(el("p", {}, "This step did not run.")); return; }
  const o = step.output;
  const facts = [];
  if (agentId === "recon") facts.push(`${o.count} subdomains`, `wildcards: ${(o.wildcards || []).join(", ") || "none"}`);
  if (agentId === "enrichment") facts.push(`${o.live_count} live hosts`, `${o.classified_count} classified`);
  if (agentId === "threat_intel") facts.push(`${(o.findings || []).length} findings`, `${(o.all_cves || []).length} CVEs matched`, `KEV catalog: ${o.kev_catalog_date ?? "unknown"}`);
  if (agentId === "prioritization") facts.push(Object.entries(o.counts || {}).map(([k, v]) => `${k}: ${v}`).join(" · "), `LLM adjusted ${Math.round((o.adjusted_share || 0) * 100)}%`);
  if (agentId === "report") facts.push(`${(o.findings_table || []).length} table rows`, `${(o.recommendations || []).length} recommendations`);
  if (step.llm_usage) facts.push(`model: ${step.llm_usage.model}`);
  box.append(el("ul", {}, facts.map((f) => el("li", {}, f))));
  if (step.errors.length) {
    box.append(el("div", {}, el("strong", {}, "Problems recorded:"),
      el("ul", {}, step.errors.map((e) => el("li", {}, `${e.step}: ${e.reason}`)))));
  }
}

// ------------------------------------------------------------------ results

function showResults() {
  $("results").hidden = false;
  const s = state.run.summary;
  const counts = stepOf("prioritization")?.output.counts || {};
  $("stats").replaceChildren(
    ...[["Hosts", s.hosts], ["Live", s.live_hosts], ["Findings", s.findings],
      ["P1", counts.P1 ?? 0], ["P2", counts.P2 ?? 0], ["Est. LLM cost", `$${(s.cost_usd || 0).toFixed(3)}`]]
      .map(([label, value]) => el("div", { class: "stat" }, el("b", {}, value), el("span", {}, label))));
  renderReport();
  renderFindings();
  renderHosts();
  renderEvidence();
  showTab("report");
}

function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  for (const tab of ["report", "findings", "hosts", "evidence"]) $(`tab-${tab}`).hidden = tab !== name;
}

function renderReport() {
  const box = $("tab-report");
  const r = stepOf("report")?.output;
  if (!r) { box.replaceChildren(el("p", {}, "The report step did not run.")); return; }
  const md = new Blob([r.markdown], { type: "text/markdown" });
  box.replaceChildren(
    el("h3", {}, "Executive summary"), el("p", {}, cited(r.executive_summary)),
    el("h3", {}, "Top recommendations"),
    el("ol", {}, (r.recommendations || []).map((rec) => el("li", {}, cited(rec.action)))),
    el("h3", {}, "Data limitations"), el("p", {}, cited(r.limitations)),
    el("p", {}, el("a", { href: URL.createObjectURL(md), download: `${state.run.run_id}-report.md` }, "Download the report as Markdown")),
  );
}

function renderFindings() {
  const rows = stepOf("prioritization")?.output.prioritized || [];
  const body = rows.map((p) => {
    const f = state.findings.get(p.finding_id) || {};
    const label = f.cve ? `${f.cve} · ${f.product}${f.in_kev ? " · KEV" : ""}` : f.kind?.replaceAll("_", " ");
    const moved = p.adjustment === "none" ? "" : ` (from ${p.baseline})`;
    return el("tr", { class: "clickable", onclick: () => openFinding(p.finding_id) },
      el("td", {}, prio(p.final), el("span", { class: "muted" }, moved)),
      el("td", { class: "mono" }, p.finding_id), el("td", {}, p.host), el("td", {}, label),
      el("td", {}, cited(p.rationale)));
  });
  $("tab-findings").replaceChildren(
    el("p", { class: "muted" }, "Click a finding to see the evidence behind it."),
    el("div", { class: "table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Priority", "ID", "Host", "Finding", "Prioritization rationale"].map((h) => el("th", {}, h)))),
      el("tbody", {}, body))));
}

function renderHosts() {
  const hosts = stepOf("enrichment")?.output.hosts || [];
  const body = hosts.map((h) => el("tr", {},
    el("td", {}, h.name),
    el("td", {}, h.live ? (h.contacted ? `${h.https ? "HTTPS" : "HTTP only"} ${h.status ?? ""}` : "live, not contacted") : "not live"),
    el("td", {}, h.role ? `${h.role} (${h.importance})` : "—"),
    el("td", { class: h.title ? "untrusted" : "" }, h.title || "—"),
    el("td", {}, (h.products || []).map((p) => `${p.product} ${p.version || ""} [${p.version_confidence}]`).join(", ") || "—"),
    el("td", {}, cited(h.note ? `${h.note}. ${h.reason || ""}` : h.reason || ""))));
  $("tab-hosts").replaceChildren(
    el("p", { class: "muted" }, "Page titles (marked with an amber edge) come from the target and are shown as untrusted data."),
    el("div", { class: "table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Host", "Reachability", "Role (importance)", "Page title", "Detected software", "Classification reason"].map((h) => el("th", {}, h)))),
      el("tbody", {}, body))));
}

function renderEvidence() {
  const box = $("tab-evidence");
  const input = el("input", { class: "filter", type: "search", placeholder: "Filter evidence (host, type, value)…", "aria-label": "Filter evidence" });
  const tbody = el("tbody");
  const all = [...state.evidence.values()];
  const draw = () => {
    const q = input.value.toLowerCase();
    tbody.replaceChildren(...all.filter((e) => !q || `${e.id} ${e.type} ${e.subject} ${e.value}`.toLowerCase().includes(q)).map((e) =>
      el("tr", { class: "clickable", onclick: () => openId(e.id) },
        el("td", { class: "mono" }, e.id), el("td", {}, e.type), el("td", {}, e.subject), el("td", { class: "untrusted" }, e.value))));
  };
  input.addEventListener("input", draw);
  draw();
  box.replaceChildren(input, el("div", { class: "table-wrap" }, el("table", {},
    el("thead", {}, el("tr", {}, ["ID", "Type", "Subject", "Value"].map((h) => el("th", {}, h)))), tbody)));
}

// ------------------------------------------------------------------ evidence drawer

function evidenceCard(id) {
  const ev = state.evidence.get(id);
  if (!ev) return el("div", { class: "ev-card" }, el("strong", {}, id), " — not found in this run.");
  const source = /^https?:\/\//.test(ev.source)
    ? el("a", { href: ev.source, target: "_blank", rel: "noopener noreferrer nofollow" }, ev.source) : ev.source;
  return el("div", { class: "ev-card" }, el("strong", { class: "mono" }, ev.id), " ", el("span", { class: "muted" }, ev.type),
    el("dl", {},
      el("dt", {}, "Subject"), el("dd", {}, ev.subject),
      el("dt", {}, "Value"), el("dd", { class: "untrusted" }, ev.value),
      el("dt", {}, "Source"), el("dd", {}, source),
      el("dt", {}, "Collected"), el("dd", {}, ev.collected_at),
      el("dt", {}, "Agent"), el("dd", {}, ev.agent)));
}

function openDrawer(title, ...content) {
  $("drawer-title").textContent = title;
  $("drawer-body").replaceChildren(...content);
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
}
function closeDrawer() { $("drawer").classList.remove("open"); $("drawer").setAttribute("aria-hidden", "true"); }

function openId(id) { id.startsWith("F-") ? openFinding(id) : openDrawer(id, evidenceCard(id)); }

function openFinding(id) {
  const f = state.findings.get(id);
  if (!f) { openDrawer(id, el("p", {}, "Finding not found in this run.")); return; }
  const p = f.priority || {};
  const ids = [...new Set([...(f.evidence_ids || []), ...(p.evidence_ids || [])])];
  openDrawer(`${id} · ${f.host}`,
    el("p", {}, p.final ? prio(p.final) : null, " ", el("strong", {}, f.cve ? `${f.cve} in ${f.product}` : f.kind.replaceAll("_", " "))),
    el("p", {}, f.cvss != null ? `CVSS ${f.cvss} ${f.severity}. ` : "", f.summary),
    f.in_kev ? el("p", {}, "Listed in the CISA Known Exploited Vulnerabilities catalog.") : null,
    p.final ? el("p", { class: "muted" }, `Baseline ${p.baseline} (score ${p.score}; rules: ${(p.rules_applied || []).join(", ")}) → final ${p.final}.`) : null,
    p.rationale ? el("p", {}, cited(p.rationale)) : null,
    el("h4", {}, "Evidence"), ...ids.map(evidenceCard));
}

init();
