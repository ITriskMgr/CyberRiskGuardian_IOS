/* CyberRiskGuardian Mobile — app logic.
 * (c) 2026 Marc-André Léger — CC BY-NC 4.0 */
(function () {
  "use strict";
  const VERSION = "1.0.2";
  const KEY = "crg.mobile.v1";
  const $ = id => document.getElementById(id);
  const PARAMS = CRG.PARAMS;

  /* ---------------------------------------------------------------- state */
  const DEFAULT_SCEN = () => {
    const s = JSON.parse(JSON.stringify(self.CRG_SAMPLE.SCEN[0]));
    s.id = ""; s._example = true; return s;
  };
  const defaults = () => ({
    settings: { appetite: 0.30, factor: 1000, currency: "CAD", shortcut: "CRG Assistant", lang: "en", callback: false },
    register: [],
    registerIsSample: false,
    draft: DEFAULT_SCEN(),
    cvssMetrics: CVSS4.parse(self.CRG_SAMPLE.SCEN[0].cvss),
    budget: { it: 100000000, years: [5050000, 5550000, 4870000], example: true },
    ai: { ctx: "", n: "5", q: "", pending: null, last: null },
    view: "calc"
  });
  let S = load();

  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) { const d = JSON.parse(raw); const base = defaults(); return Object.assign(base, d, { settings: Object.assign(base.settings, d.settings || {}), ai: Object.assign(base.ai, d.ai || {}) }); }
    } catch (e) { /* storage unavailable */ }
    const s = defaults();
    s.register = JSON.parse(JSON.stringify(self.CRG_SAMPLE.SCEN)).map(x => Object.assign(x, { origin: "example" }));
    s.registerIsSample = true;
    return s;
  }
  let saveTimer = null;
  function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => { try { localStorage.setItem(KEY, JSON.stringify(S)); } catch (e) { /* ignore */ } }, 150);
  }

  /* ---------------------------------------------------------------- formatting */
  const nf0 = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
  const fmt0 = x => (isFinite(x) ? nf0.format(x) : "–");
  const fmt2 = x => (isFinite(x) ? x.toFixed(2) : "–");
  const pct = (x, d = 1) => (x === null || !isFinite(x) ? "–" : (x * 100).toFixed(d) + "%");
  const money = x => {
    if (!isFinite(x)) return "–";
    try { return new Intl.NumberFormat(undefined, { style: "currency", currency: S.settings.currency || "CAD", maximumFractionDigits: 0 }).format(x); }
    catch (e) { return nf0.format(x) + " " + (S.settings.currency || ""); }
  };
  const parseNum = s => { if (s === null || s === undefined) return NaN; const t = String(s).replace(/[\s,$€£]/g, "").replace(/[^0-9.\-eE]/g, ""); return t === "" ? NaN : Number(t); };
  const clsKey = c => (c === "Above tolerance" ? "above" : c === "Below tolerance" ? "below" : c === "Approximately at tolerance" ? "at" : "none");
  const clsShort = c => (c === "Above tolerance" ? "Above" : c === "Below tolerance" ? "Below" : c === "Approximately at tolerance" ? "At tolerance" : "–");
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const v = (s, k) => Number(s.params[k] && typeof s.params[k] === "object" ? s.params[k].v : s.params[k]);

  let toastTimer;
  function toast(msg) { const t = $("toast"); t.textContent = msg; t.hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => (t.hidden = true), 2600); }

  /* ---------------------------------------------------------------- navigation */
  function show(view) {
    S.view = view; save();
    document.querySelectorAll(".view").forEach(el => (el.hidden = el.id !== "view-" + view));
    document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b.dataset.view === view));
    if (view === "reg") renderRegister();
    if (view === "ai") renderAICurrent();
    if (view === "budget") renderBudget();
    if (view === "cvss") renderCVSS();
    window.scrollTo(0, 0);
  }
  document.querySelectorAll(".tab").forEach(b => b.addEventListener("click", () => show(b.dataset.view)));

  /* ---------------------------------------------------------------- parameter rows */
  const PDEF = {
    PbA: ["Threat presence", "Pb(A)", "Probability the threat is present in the next 12 months", 0, 1],
    Pbx: ["Exploitation", "Pb(ψ,A)", "Probability the threat exploits the weakness", 0, 1],
    De: ["Expected damage", "δe", "Reasonably expected harm, normalized 0–1", 0, 1],
    Dm: ["Maximum damage", "δm", "Plausible worst-case harm, normalized 0–1", 0, 1],
    Mu: ["Criticality", "μ(E)", "Importance of the affected service to the mission", 0, 1],
    Th: ["Resilience", "θ", "Ability to prevent, detect, contain and recover. Higher is more resilient", 0.05, 1],
    red_p: ["Probability reduction", "P", "Expected effect of the treatment package on likelihood", 0, 1],
    red_i: ["Impact reduction", "Q", "Expected effect of the treatment package on impact", 0, 1]
  };
  function paramRow(key, get, set, opts = {}) {
    const [label, sym, hint, min, max] = PDEF[key] || opts.def;
    const wrap = document.createElement("div");
    wrap.className = "param";
    const id = (opts.prefix || "p-") + key;
    wrap.innerHTML = `<div><span class="p-label">${label}</span><span class="p-sym">${sym}</span></div>
      <input type="number" id="${id}-n" inputmode="decimal" min="${min}" max="${max}" step="0.01" aria-label="${label} value">
      <div class="p-hint">${hint}</div>
      <input type="range" id="${id}-r" min="${min}" max="${max}" step="0.05" aria-label="${label}">
      <div class="p-warn" hidden></div>`;
    const n = wrap.querySelector("input[type=number]"), r = wrap.querySelector("input[type=range]");
    const sync = () => { const x = get(); n.value = isFinite(x) ? +(+x).toFixed(2) : ""; r.value = isFinite(x) ? x : min; };
    n.addEventListener("input", () => { const x = parseNum(n.value); if (isFinite(x)) { set(Math.min(max, Math.max(min, x))); r.value = x; } });
    n.addEventListener("blur", sync);
    r.addEventListener("input", () => { const x = Number(r.value); set(x); n.value = +x.toFixed(2); });
    wrap._sync = sync; wrap._warn = msg => { const w = wrap.querySelector(".p-warn"); w.textContent = msg || ""; w.hidden = !msg; };
    sync();
    return wrap;
  }

  /* ---------------------------------------------------------------- calculator */
  const rows = {};
  function buildCalc() {
    const groups = { PbA: "g-likelihood", Pbx: "g-likelihood", De: "g-impact", Dm: "g-impact", Mu: "g-impact", Th: "g-res", red_p: "g-treat", red_i: "g-treat" };
    for (const k of Object.keys(groups)) {
      const isRed = k.startsWith("red_");
      rows[k] = paramRow(k,
        () => (isRed ? S.draft[k] : v(S.draft, k)),
        x => { if (isRed) S.draft[k] = x; else { if (typeof S.draft.params[k] !== "object") S.draft.params[k] = {}; S.draft.params[k].v = x; } markEdited(); recalc(); });
      $(groups[k]).appendChild(rows[k]);
    }
    $("f-name").addEventListener("input", e => { S.draft.name = e.target.value; markEdited(); recalc(); });
    $("f-statement").addEventListener("input", e => { S.draft.statement = e.target.value; markEdited(); save(); });
    $("f-cvss-manual").addEventListener("input", e => {
      const x = parseNum(e.target.value);
      if (e.target.value.trim() === "") delete S.draft.cvss_score; else if (isFinite(x) && x >= 0 && x <= 10) S.draft.cvss_score = x;
      markEdited(); recalc();
    });
    $("calc-edit-cvss").addEventListener("click", () => {
      if (S.draft.cvss) { try { S.cvssMetrics = CVSS4.parse(S.draft.cvss); } catch (e) { /* keep */ } }
      show("cvss");
    });
    $("btn-save").addEventListener("click", saveDraft);
    $("btn-new").addEventListener("click", newScenario);
    $("btn-del").addEventListener("click", () => { $("del-name").textContent = S.draft.id + " " + (S.draft.name || ""); $("del-confirm").hidden = false; });
    $("btn-del-no").addEventListener("click", () => ($("del-confirm").hidden = true));
    $("btn-del-yes").addEventListener("click", () => {
      S.register = S.register.filter(x => x.id !== S.draft.id);
      toast("Deleted " + S.draft.id);
      newScenario(); $("del-confirm").hidden = true;
    });
  }
  function markEdited() { if (S.draft._example) { S.draft._example = false; $("calc-example-note").hidden = true; } }

  function fillCalc() {
    const d = S.draft;
    $("f-name").value = d.name || "";
    $("f-statement").value = d.statement || "";
    $("f-cvss-manual").value = d.cvss_score ?? "";
    Object.values(rows).forEach(r => r._sync());
    $("calc-example-note").hidden = !d._example;
    $("del-wrap").hidden = !d.id || !S.register.some(x => x.id === d.id);
    $("del-confirm").hidden = true;
    recalc();
  }

  function draftCvss() {
    const d = S.draft;
    if (d.cvss_score !== undefined && d.cvss_score !== null && d.cvss_score !== "") return { score: Number(d.cvss_score), manual: true };
    if (d.cvss) { try { return { score: CVSS4.score(d.cvss), manual: false }; } catch (e) { return { error: e.message }; } }
    return { error: "No CVSS score yet" };
  }

  function recalc() {
    save();
    const d = S.draft, A = S.settings.appetite, F = S.settings.factor;
    // CVSS display
    const c = draftCvss();
    const chip = $("calc-cvss-chip");
    chip.className = "score-chip" + (isFinite(c.score) ? " sev-" + CVSS4.severity(c.score).toLowerCase() : "");
    chip.textContent = isFinite(c.score) ? c.score.toFixed(1) : "–";
    $("calc-cvss-vector").textContent = c.manual ? "Manual score" + (d.cvss ? " (vector kept: " + d.cvss + ")" : "") : (d.cvss || c.error || "–");
    // warnings
    rows.Dm._warn(v(d, "Dm") < v(d, "De") ? "Maximum damage is below expected damage. Check δm ≥ δe." : "");
    rows.Th._warn(v(d, "Th") <= 0 ? "Resilience must be above 0." : "");
    $("strip-id").textContent = (d.id ? d.id + " · " : "") + (d.name || "Unsaved scenario");
    $("res-ctx").textContent = "appetite " + A.toFixed(2) + " · factor " + fmt0(F);
    let r;
    try {
      if (c.error) throw new Error("Add a CVSS v4.0 vector or a manual score to calculate.");
      r = CRG.calc(Object.assign({}, d, { cvss_score: c.score }), A, F);
      $("calc-error").hidden = true;
    } catch (e) {
      $("calc-error").textContent = e.message; $("calc-error").hidden = false;
      $("strip-ratio").textContent = "–"; setPill($("strip-pill"), null); setPill($("r-pill"), null);
      $("r-ratio").textContent = "–"; $("r-kv").innerHTML = ""; $("r-sens").tBodies[0].innerHTML = ""; $("r-gauge").innerHTML = ""; $("r-driver").textContent = ""; $("r-robust").textContent = "";
      return null;
    }
    const cls = CRG.classify(r.ratio);
    $("strip-ratio").textContent = fmt2(r.ratio);
    setPill($("strip-pill"), cls); setPill($("r-pill"), cls);
    $("r-ratio").textContent = fmt2(r.ratio);
    $("r-kv").innerHTML = [
      ["Estimated risk", fmt0(r.est)], ["Tolerated risk", fmt0(r.tol)], ["Mitigated risk", fmt0(r.mit)], ["Residual risk", fmt0(r.res)],
      ["Before treatment", fmt2(r.pre_ratio) + ' <span class="sub">× tolerance</span>'], ["CVSS used", r.cvss.toFixed(1)]
    ].map(([a, b]) => `<dt>${a}</dt><dd>${b}</dd>`).join("");
    drawGauge($("r-gauge"), r.pre_ratio, r.ratio);
    const sv = CRG.sensitivity(Object.assign({}, d, { cvss_score: c.score }), 0.10, A, F);
    $("r-sens").tBodies[0].innerHTML = [["Lower case", sv.lower], ["Central case", sv.central], ["Higher case", sv.higher]]
      .map(([l, x]) => `<tr><td>${l}</td><td class="num">${fmt2(x.ratio)}</td><td class="num"><span class="pill ${clsKey(x.classification)}">${clsShort(x.classification)}</span></td></tr>`).join("");
    $("r-robust").textContent = sv.robust ? "The classification holds across the lower and higher cases." : "The classification changes between cases. Validate the most uncertain parameters before deciding.";
    const avgD = (v(d, "De") + v(d, "Dm")) / 2;
    $("r-driver").textContent = `Ratio = average damage ${fmt2(avgD)} × (1 − P×Q ${fmt2(d.red_p * d.red_i)}) ÷ appetite ${fmt2(A)}. Probabilities, CVSS, resilience and criticality scale the magnitude, not the ratio.`;
    return r;
  }
  function setPill(el, cls) {
    el.className = "pill" + (el.classList.contains("lg") || el.id === "r-pill" ? " lg" : "") + " " + clsKey(cls);
    el.textContent = cls ? clsShort(cls) : "Not calculated";
  }

  function drawGauge(svg, pre, res) {
    const W = 320, x0 = 8, x1 = 312, max = 2.5;
    const X = t => x0 + (Math.min(Math.max(t, 0), max) / max) * (x1 - x0);
    const ticks = [0, 0.9, 1.1, 2, 2.5];
    let h = `<rect x="${x0}" y="18" width="${x1 - x0}" height="8" rx="4" fill="var(--surface-2)"/>`;
    h += `<rect x="${X(0)}" y="18" width="${X(0.9) - X(0)}" height="8" rx="4" fill="var(--good)" opacity=".28"/>`;
    h += `<rect x="${X(0.9)}" y="14" width="${X(1.1) - X(0.9)}" height="16" rx="3" fill="var(--warn)" opacity=".35"/>`;
    h += `<rect x="${X(1.1)}" y="18" width="${X(max) - X(1.1)}" height="8" rx="4" fill="var(--bad)" opacity=".22"/>`;
    for (const t of ticks) h += `<text x="${X(t)}" y="48" text-anchor="${t === 0 ? "start" : t === max ? "end" : "middle"}">${t === max ? "2.5+" : t.toFixed(t % 1 ? 1 : 0)}</text>`;
    if (isFinite(pre)) {
      h += `<line x1="${X(pre)}" y1="22" x2="${X(res)}" y2="22" stroke="var(--ink)" stroke-width="1.5" stroke-dasharray="3 3" opacity=".6"/>`;
      h += `<circle cx="${X(pre)}" cy="22" r="6" fill="var(--surface)" stroke="var(--ink)" stroke-width="1.5"><title>Before treatment ${fmt2(pre)}</title></circle>`;
    }
    const key = clsKey(CRG.classify(res));
    const col = key === "above" ? "var(--bad)" : key === "at" ? "var(--warn)" : "var(--good)";
    h += `<circle cx="${X(res)}" cy="22" r="8" fill="${col}" stroke="var(--surface)" stroke-width="2"><title>Residual ${fmt2(res)}</title></circle>`;
    h += `<text x="${X(res)}" y="8" text-anchor="middle" style="fill:var(--ink);font-weight:600">${fmt2(res)}</text>`;
    svg.setAttribute("viewBox", `0 0 ${W} 56`);
    svg.innerHTML = h;
  }

  function nextId() {
    const used = new Set(S.register.map(x => x.id));
    let i = 1; while (used.has("S" + i)) i++; return "S" + i;
  }
  // The example register is never wiped silently: new scenarios are added next to it and example rows stay tagged.
  function clearSampleIfNeeded() { S.registerIsSample = false; }
  const allExamples = () => S.register.length > 0 && S.register.every(x => x.origin === "example");
  function saveDraft() {
    if (!recalc()) { toast("Complete the scenario before saving"); return; }
    const d = S.draft;
    if (!d.name || !d.name.trim()) { toast("Give the scenario a name first"); $("f-name").focus(); return; }
    const copy = JSON.parse(JSON.stringify(d)); delete copy._example;
    copy.updated = new Date().toISOString();
    const i = d.id ? S.register.findIndex(x => x.id === d.id) : -1;
    if (i >= 0) { if (copy.origin === "example") copy.origin = "manual"; S.register[i] = Object.assign(S.register[i], copy); toast("Updated " + d.id); }
    else {
      clearSampleIfNeeded();
      copy.id = nextId(); copy.origin = copy.origin === "example" ? "manual" : (copy.origin || "manual");
      S.register.push(copy); S.draft.id = copy.id; toast("Saved as " + copy.id);
    }
    S.draft._example = false;
    fillCalc(); save();
  }

  function newScenario() {
    S.draft = { id: "", name: "", statement: "", params: { PbA: { v: 0.5 }, Pbx: { v: 0.5 }, De: { v: 0.5 }, Dm: { v: 0.7 }, Th: { v: 0.5 }, Mu: { v: 0.5 } },
      cvss: S.draft.cvss || self.CRG_SAMPLE.SCEN[0].cvss, red_p: 0.5, red_i: 0.5, origin: "manual" };
    fillCalc(); show("calc"); $("f-name").focus();
  }
  function openScenario(id) {
    const s = S.register.find(x => x.id === id); if (!s) return;
    S.draft = JSON.parse(JSON.stringify(s));
    fillCalc(); show("calc");
  }

  /* ---------------------------------------------------------------- CVSS */
  const METRIC_DEF = [
    ["Exploitability", null],
    ["AV", "Attack Vector", { N: "Network", A: "Adjacent", L: "Local", P: "Physical" }],
    ["AC", "Attack Complexity", { L: "Low", H: "High" }],
    ["AT", "Attack Requirements", { N: "None", P: "Present" }],
    ["PR", "Privileges Required", { N: "None", L: "Low", H: "High" }],
    ["UI", "User Interaction", { N: "None", P: "Passive", A: "Active" }],
    ["Vulnerable system impact", null],
    ["VC", "Confidentiality", { H: "High", L: "Low", N: "None" }],
    ["VI", "Integrity", { H: "High", L: "Low", N: "None" }],
    ["VA", "Availability", { H: "High", L: "Low", N: "None" }],
    ["Subsequent system impact", null],
    ["SC", "Confidentiality", { H: "High", L: "Low", N: "None" }],
    ["SI", "Integrity", { H: "High", L: "Low", N: "None" }],
    ["SA", "Availability", { H: "High", L: "Low", N: "None" }]
  ];
  function buildCVSS() {
    const host = $("cv-metrics");
    let group = null;
    for (const def of METRIC_DEF) {
      if (def[1] === null) {
        const t = document.createElement("h2"); t.className = "group-title"; t.textContent = def[0]; host.appendChild(t);
        group = document.createElement("div"); group.className = "group"; host.appendChild(group); continue;
      }
      const [k, name, vals] = def;
      const m = document.createElement("div"); m.className = "metric";
      m.innerHTML = `<div class="metric-name"><span>${name}</span><span class="mono">${k}</span></div><div class="seg" role="group" aria-label="${name}">` +
        Object.entries(vals).map(([code, lab]) => `<button type="button" data-m="${k}" data-v="${code}">${lab}</button>`).join("") + "</div>";
      group.appendChild(m);
    }
    host.addEventListener("click", e => {
      const b = e.target.closest("button[data-m]"); if (!b) return;
      S.cvssMetrics[b.dataset.m] = b.dataset.v; save(); renderCVSS();
    });
    $("cv-paste").addEventListener("input", e => {
      const t = e.target.value.trim(); if (!t) { $("cv-error").hidden = true; return; }
      try { S.cvssMetrics = CVSS4.parse(t); $("cv-error").hidden = true; save(); renderCVSS(); }
      catch (err) { $("cv-error").textContent = err.message; $("cv-error").hidden = false; }
    });
    $("cv-copy").addEventListener("click", () => copyText(CVSS4.build(S.cvssMetrics), "Vector copied"));
    $("cv-apply").addEventListener("click", () => {
      S.draft.cvss = CVSS4.build(S.cvssMetrics); delete S.draft.cvss_score; markEdited();
      fillCalc(); show("calc"); toast("CVSS " + CVSS4.score(S.draft.cvss).toFixed(1) + " applied");
    });
  }
  function renderCVSS() {
    const m = S.cvssMetrics, vec = CVSS4.build(m), sc = CVSS4.score(m), sev = CVSS4.severity(sc);
    $("cv-vector").textContent = vec;
    $("cv-strip-score").textContent = sc.toFixed(1);
    const p = $("cv-strip-sev"); p.className = "pill sev-" + sev.toLowerCase(); p.textContent = sev;
    document.querySelectorAll("#cv-metrics button[data-m]").forEach(b => b.setAttribute("aria-pressed", String(m[b.dataset.m] === b.dataset.v)));
  }

  /* ---------------------------------------------------------------- register */
  function computeAll() {
    const A = S.settings.appetite, F = S.settings.factor;
    return S.register.map(s => {
      try { const r = CRG.calc(s, A, F); return { s, r, cls: CRG.classify(r.ratio) }; }
      catch (e) { return { s, err: e.message }; }
    });
  }
  function renderRegister() {
    const all = computeAll(), ok = all.filter(x => x.r);
    const n = { above: 0, at: 0, below: 0 };
    ok.forEach(x => n[clsKey(x.cls)]++);
    const est = ok.reduce((a, x) => a + x.r.est, 0), res = ok.reduce((a, x) => a + x.r.res, 0);
    $("reg-example-note").hidden = !allExamples();
    $("reg-strip").innerHTML = S.register.length
      ? `<span class="strip-ratio">${S.register.length}</span><span class="strip-id">scenarios · appetite ${S.settings.appetite.toFixed(2)}</span>`
      : `<span class="strip-id">No scenarios yet</span>`;
    $("reg-tiles").innerHTML = S.register.length ? `
      <div class="tile above"><div class="t-n">${n.above}</div><div class="t-l">Above tolerance</div></div>
      <div class="tile at"><div class="t-n">${n.at}</div><div class="t-l">At tolerance</div></div>
      <div class="tile below"><div class="t-n">${n.below}</div><div class="t-l">Below tolerance</div></div>
      <div class="tile wide"><div><div class="t-l">Total estimated</div><div class="t-n">${fmt0(est)}</div></div>
        <div><div class="t-l">Total residual</div><div class="t-n">${fmt0(res)}</div></div>
        <div><div class="t-l">Reduction</div><div class="t-n">${est ? Math.round((1 - res / est) * 100) + "%" : "–"}</div></div></div>` : "";
    const tot = ok.length || 1;
    $("reg-dist").innerHTML = ok.length ? ["above", "at", "below"].map(k => `<span class="${k}" style="width:${(n[k] / tot) * 100}%"></span>`).join("") : "";
    $("reg-dist").hidden = !ok.length;
    const sorted = all.slice().sort((a, b) => (b.r ? b.r.ratio : -1) - (a.r ? a.r.ratio : -1));
    $("reg-list").innerHTML = sorted.map(x => {
      const k = x.r ? clsKey(x.cls) : "none";
      const tag = x.s.origin === "ai" ? '<span class="tag">✦ AI draft</span>' : x.s.origin === "example" ? '<span class="tag ex">Example</span>' : "";
      return `<button class="item ${k}" data-id="${esc(x.s.id)}"><span class="i-stripe"></span>
        <span class="i-name">${esc(x.s.id)} · ${esc(x.s.name || "Untitled")}${tag}</span>
        <span class="i-ratio">${x.r ? fmt2(x.r.ratio) : "–"}<small>${x.r ? clsShort(x.cls) : "incomplete"}</small></span>
        <span class="i-meta">${x.r ? "Residual " + fmt0(x.r.res) + " · CVSS " + x.r.cvss.toFixed(1) : esc(x.err)}</span></button>`;
    }).join("");
    $("reg-list").hidden = !S.register.length;
    $("reg-empty").hidden = !!S.register.length;
    $("reg-count").textContent = S.register.length;
    $("reg-clear").hidden = !S.register.length;
  }
  function buildRegister() {
    $("reg-list").addEventListener("click", e => { const b = e.target.closest(".item"); if (b) openScenario(b.dataset.id); });
    $("reg-new").addEventListener("click", newScenario);
    $("reg-sample").addEventListener("click", () => {
      S.register = JSON.parse(JSON.stringify(self.CRG_SAMPLE.SCEN)).map(x => Object.assign(x, { origin: "example" }));
      S.registerIsSample = true; S.settings.appetite = self.CRG_SAMPLE.APPETITE; S.settings.factor = self.CRG_SAMPLE.FACTOR;
      save(); renderRegister(); toast("Loaded 30 MediBec example scenarios");
    });
    $("reg-clear").addEventListener("click", () => ($("reg-clear-confirm").hidden = false));
    $("reg-clear-no").addEventListener("click", () => ($("reg-clear-confirm").hidden = true));
    $("reg-clear-yes").addEventListener("click", () => { S.register = []; S.registerIsSample = false; $("reg-clear-confirm").hidden = true; save(); renderRegister(); toast("Register cleared"); });
    $("reg-export-json").addEventListener("click", () => {
      const out = { _comment: "CyberRiskGuardian data model exported from CyberRiskGuardian Mobile " + VERSION + ". Values are analyst estimates unless validated.",
        APPETITE: S.settings.appetite, FACTOR: S.settings.factor, CURRENCY: S.settings.currency, PERIOD: "next 12 months",
        SCEN: S.register.map(s => { const c = JSON.parse(JSON.stringify(s)); delete c._example; return c; }) };
      download("crg-register-" + new Date().toISOString().slice(0, 10) + ".json", JSON.stringify(out, null, 1), "application/json");
    });
    $("reg-export-csv").addEventListener("click", () => {
      const head = ["id", "name", "PbA", "Pbx", "De", "Dm", "Th", "Mu", "cvss", "cvss_vector", "red_p", "red_i", "estimated", "tolerated", "residual", "ratio", "classification", "origin"];
      const q = x => { const t = String(x ?? ""); return /[",\n]/.test(t) ? '"' + t.replace(/"/g, '""') + '"' : t; };
      const lines = [head.join(",")].concat(computeAll().map(({ s, r, cls }) => [s.id, s.name, ...PARAMS.map(k => v(s, k)), r ? r.cvss : "", s.cvss || "", s.red_p, s.red_i,
        r ? r.est.toFixed(2) : "", r ? r.tol.toFixed(2) : "", r ? r.res.toFixed(2) : "", r ? r.ratio.toFixed(4) : "", cls || "", s.origin || ""].map(q).join(",")));
      download("crg-register-" + new Date().toISOString().slice(0, 10) + ".csv", lines.join("\n"), "text/csv");
    });
    $("reg-import").addEventListener("change", async e => {
      const f = e.target.files[0]; if (!f) return;
      try {
        const d = JSON.parse(await f.text());
        const list = Array.isArray(d) ? d : d.SCEN;
        if (!Array.isArray(list) || !list.length) throw new Error("No SCEN array found");
        const okList = list.filter(s => s && s.params && PARAMS.every(k => isFinite(v(s, k))));
        if (!okList.length) throw new Error("No scenario has the six parameters");
        clearSampleIfNeeded();
        const used = new Set(S.register.map(x => x.id));
        okList.forEach(s => { s.red_p = Number(s.red_p ?? 0); s.red_i = Number(s.red_i ?? 0); if (!s.id || used.has(s.id)) s.id = nextIdFrom(used); used.add(s.id); s.origin = s.origin || "import"; S.register.push(s); });
        if (!Array.isArray(d)) { if (isFinite(d.APPETITE)) S.settings.appetite = Number(d.APPETITE); if (isFinite(d.FACTOR)) S.settings.factor = Number(d.FACTOR); if (d.CURRENCY) S.settings.currency = d.CURRENCY; }
        save(); renderRegister(); toast("Imported " + okList.length + " scenario" + (okList.length > 1 ? "s" : ""));
      } catch (err) { toast("Import failed: " + err.message); }
      e.target.value = "";
    });
  }
  function nextIdFrom(used) { let i = 1; while (used.has("S" + i)) i++; return "S" + i; }

  async function download(name, text, type) {
    const blob = new Blob([text], { type });
    try {
      const file = new File([blob], name, { type });
      if (navigator.canShare && navigator.canShare({ files: [file] })) { await navigator.share({ files: [file], title: name }); return; }
    } catch (e) { if (e && e.name === "AbortError") return; }
    const a = document.createElement("a"); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click(); setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1500);
  }
  async function copyText(t, msg) {
    try { await navigator.clipboard.writeText(t); toast(msg || "Copied"); }
    catch (e) { toast("Copy failed. Select the text and copy it manually."); }
  }

  /* ---------------------------------------------------------------- budget */
  function appetiteRow(prefix, get, set) {
    return paramRow("appetite", get, set, { prefix, def: ["Risk appetite", "", "0.30 risk averse · 0.50 neutral · 0.70 risk seeking", 0.05, 0.95] });
  }
  let bdApp;
  function buildBudget() {
    bdApp = appetiteRow("bd-", () => S.settings.appetite, x => { S.settings.appetite = x; save(); renderBudget(false); });
    $("bd-appetite-row").appendChild(bdApp);
    const it = $("bd-it");
    it.addEventListener("input", () => { S.budget.it = parseNum(it.value); S.budget.example = false; renderBudget(false); save(); });
    it.addEventListener("blur", () => { if (isFinite(S.budget.it)) it.value = fmt0(S.budget.it); });
    [1, 2, 3].forEach(i => {
      const el = $("bd-y" + i);
      el.addEventListener("input", () => { S.budget.years[i - 1] = parseNum(el.value); S.budget.example = false; renderBudget(false); save(); });
      el.addEventListener("blur", () => { const x = S.budget.years[i - 1]; if (isFinite(x)) el.value = fmt0(x); });
    });
  }
  function renderBudget(fill = true) {
    const B = S.budget, A = S.settings.appetite, it = B.it;
    if (fill) {
      $("bd-it").value = isFinite(it) ? fmt0(it) : "";
      [1, 2, 3].forEach(i => ($("bd-y" + i).value = isFinite(B.years[i - 1]) ? fmt0(B.years[i - 1]) : ""));
      bdApp._sync();
    }
    const t = CRG.budgetTarget(A), band = CRG.BUDGET_BAND;
    $("bd-target-amt").textContent = isFinite(it) ? money(t * it) : "–";
    $("bd-target-pct").textContent = pct(t) + " of the IT budget for appetite " + A.toFixed(2) + (B.example ? " · example figures" : "");
    $("bd-strip-pct").textContent = pct(t);
    const pos = A <= 0.30 ? "Risk averse" : A < 0.45 ? "Cautious" : A <= 0.55 ? "Risk neutral" : A < 0.70 ? "Open" : "Risk seeking";
    const sp = $("bd-strip-pos"); sp.className = "pill none"; sp.textContent = pos;
    $("bd-kv").innerHTML = isFinite(it) ? [["Floor 4% (risk seeking)", money(band.min * it)], ["Median 7.8% (neutral)", money(band.median * it)], ["Ceiling 12% (risk averse)", money(band.max * it)]]
      .map(([a, b]) => `<dt>${a}</dt><dd>${b}</dd>`).join("") : "";
    const yrs = B.years.map((s, i) => ({ i: i + 1, s, p: isFinite(s) && isFinite(it) && it > 0 ? s / it : null })).filter(y => y.p !== null);
    drawBand($("bd-band"), t, yrs);
    $("bd-years").tBodies[0].innerHTML = yrs.length ? yrs.map(y => {
      const st = CRG.bandStatus(y.p), ia = CRG.impliedAppetite(y.p);
      const k = st === "Within band" ? "below" : "above";
      return `<tr><td>Y${y.i}</td><td class="num">${money(y.s)}</td><td class="num">${pct(y.p)}</td><td class="num">${ia === null ? "–" : ia.toFixed(2)}<br><span class="pill ${k}">${st === "Within band" ? "Within band" : st.startsWith("Below") ? "Below floor" : "Above ceiling"}</span></td></tr>`;
    }).join("") : `<tr><td colspan="4" class="muted">Enter planned spend to check it against the band.</td></tr>`;
  }
  function drawBand(svg, target, yrs) {
    const x0 = 10, x1 = 310, lo = 0, hi = 0.14;
    const X = p => x0 + (Math.min(Math.max(p, lo), hi) - lo) / (hi - lo) * (x1 - x0);
    let h = `<rect x="${x0}" y="26" width="${x1 - x0}" height="10" rx="5" fill="var(--surface-2)"/>`;
    h += `<rect x="${X(0.04)}" y="26" width="${X(0.12) - X(0.04)}" height="10" rx="3" fill="var(--accent)" opacity=".25"/>`;
    for (const [p, l] of [[0.04, "4%"], [0.078, "7.8%"], [0.12, "12%"]]) h += `<line x1="${X(p)}" x2="${X(p)}" y1="22" y2="40" stroke="var(--muted)" stroke-width="1"/><text x="${X(p)}" y="54" text-anchor="middle">${l}</text>`;
    h += `<text x="${X(0.04)}" y="68" text-anchor="middle">seeking</text><text x="${X(0.078)}" y="68" text-anchor="middle">neutral</text><text x="${X(0.12)}" y="68" text-anchor="middle">averse</text>`;
    // Year markers: labels stagger upward when points sit close together so they never overlap.
    const placed = [];
    yrs.slice().sort((a, b) => a.p - b.p).forEach(y => {
      const x = X(y.p); let row = 0;
      while (placed.some(q => q.row === row && Math.abs(q.x - x) < 18)) row++;
      placed.push({ x, row });
      h += `<circle cx="${x}" cy="31" r="5" fill="var(--surface)" stroke="var(--ink)" stroke-width="1.5"/><text x="${x}" y="${18 - row * 10}" text-anchor="middle">Y${y.i}</text>`;
    });
    h += `<path d="M${X(target) - 7} 12 L${X(target) + 7} 12 L${X(target)} 24 Z" fill="var(--accent)"/>`;
    h += `<text x="${X(target)}" y="8" text-anchor="middle" style="fill:var(--accent);font-weight:600">target</text>`;
    svg.innerHTML = h;
  }

  /* ---------------------------------------------------------------- settings */
  let setApp;
  function buildSettings() {
    const dlg = $("settings");
    document.querySelectorAll("[data-open-settings]").forEach(b => b.addEventListener("click", () => {
      setApp._sync(); $("set-factor").value = S.settings.factor; $("set-currency").value = S.settings.currency;
      $("set-shortcut").value = S.settings.shortcut; $("set-lang").value = S.settings.lang; $("set-callback").checked = !!S.settings.callback;
      if (dlg.showModal) dlg.showModal(); else dlg.setAttribute("open", "");
    }));
    setApp = appetiteRow("set-", () => S.settings.appetite, x => { S.settings.appetite = x; save(); });
    $("set-appetite-row").appendChild(setApp);
    $("set-factor").addEventListener("input", e => { const x = parseNum(e.target.value); if (x > 0) { S.settings.factor = x; save(); } });
    $("set-currency").addEventListener("input", e => { S.settings.currency = e.target.value.toUpperCase().slice(0, 4); save(); });
    $("set-shortcut").addEventListener("input", e => { S.settings.shortcut = e.target.value; save(); syncShortcutName(); });
    $("set-lang").addEventListener("change", e => { S.settings.lang = e.target.value; save(); });
    $("set-callback").addEventListener("change", e => { S.settings.callback = e.target.checked; save(); });
    dlg.addEventListener("close", () => { fillCalc(); if (S.view === "reg") renderRegister(); if (S.view === "budget") renderBudget(); });
    $("app-version").textContent = VERSION;
  }
  function syncShortcutName() { document.querySelectorAll(".sc-name").forEach(el => (el.textContent = S.settings.shortcut || "CRG Assistant")); }

  /* ---------------------------------------------------------------- Apple Intelligence via Shortcuts */
  const GUARD = "You support a cybersecurity risk analyst using the CyberRiskGuardian method. Be factual and concise. " +
    "Do not invent facts about the organization; label assumptions. Your output is decision support: an analytical hypothesis that people must validate. ";
  const langLine = () => (S.settings.lang === "fr" ? " Respond in French (Canadian usage)." : " Respond in English.");
  function scenSummary(d) {
    const c = draftCvss(); let r = null;
    try { r = CRG.calc(Object.assign({}, d, { cvss_score: c.score }), S.settings.appetite, S.settings.factor); } catch (e) { /* incomplete */ }
    const p = k => fmt2(v(d, k));
    return `Scenario: ${d.name || "(unnamed)"}\nCausal chain: ${d.statement || "(not described)"}\n` +
      `Parameters (0-1): threat presence Pb(A)=${p("PbA")}, exploitation Pb(psi,A)=${p("Pbx")}, expected damage=${p("De")}, maximum damage=${p("Dm")}, resilience theta=${p("Th")}, criticality mu=${p("Mu")}. ` +
      `CVSS v4.0 = ${isFinite(c.score) ? c.score.toFixed(1) : "n/a"}. Treatment package: probability reduction P=${fmt2(d.red_p)}, impact reduction Q=${fmt2(d.red_i)}. Risk appetite=${fmt2(S.settings.appetite)}.` +
      (r ? `\nResults: estimated risk ${fmt0(r.est)}, tolerated ${fmt0(r.tol)}, residual ${fmt0(r.res)}; residual/tolerated ratio ${fmt2(r.ratio)} (${CRG.classify(r.ratio)}; bands: below 0.90, approximately at 0.90-1.10, above 1.10); before treatment ${fmt2(r.pre_ratio)}.` : "");
  }
  function buildPrompt(task) {
    const d = S.draft;
    switch (task) {
      case "test": return "Reply with exactly: CRG OK";
      case "scenarios": {
        const n = Number($("ai-n").value) || 5, ctx = $("ai-ctx").value.trim();
        return GUARD + `Organization context: ${ctx}\n\nPropose ${n} distinct, non-overlapping cybersecurity risk scenarios for the next 12 months. ` +
          "Each must be a complete causal chain: threat source, exploited weakness, affected asset or process, cybersecurity event, organizational consequence. Avoid generic labels such as just 'ransomware'. " +
          "Return ONLY a JSON array, no other text. Each item: {\"name\": short title, \"statement\": one-sentence causal chain, \"threat_source\": text, \"vulnerability\": text, \"asset\": text, \"consequence\": text, " +
          "\"PbA\": number 0-1 probability the threat is present, \"Pbx\": number 0-1 probability of exploitation, \"De\": number 0-1 expected damage, \"Dm\": number 0-1 maximum damage (not below De), " +
          "\"Th\": number 0.05-1 organizational resilience (higher is more resilient), \"Mu\": number 0-1 criticality of the affected service, \"rationale\": one sentence}." +
          (S.settings.lang === "fr" ? " Write the text fields in French; keep the JSON keys in English." : "");
      }
      case "explain": return GUARD + "Explain this risk result to senior management in 120 to 180 words: what the scenario is, what drives the ratio, whether residual risk is within appetite, and what decision is needed. Use only the numbers given; do not compute new ones.\n\n" + scenSummary(d) + langLine();
      case "treat": return GUARD + "Propose 5 to 7 realistic treatment measures for this scenario, covering governance, prevention, detection, response and recovery where relevant. For each: measure, what it reduces (probability or impact) and an indicative strength (low/medium/high), accountable owner role, horizon (0-90 days, 3-6 months, 6-12 months or 12-24 months). Flag measures that would also reduce other common risks. Plain text list.\n\n" + scenSummary(d) + langLine();
      case "kri": return GUARD + "Propose 3 to 5 measurable key risk indicators for this scenario. For each: name, measurement method, data source, owner role, reporting frequency, target, warning threshold, critical threshold. Plain text list.\n\n" + scenSummary(d) + langLine();
      case "ask": return GUARD + "The CRG model: Estimated = PbA x Pbx x CVSS x ((De+Dm)/2) x Mu / theta x Factor; Tolerated uses Appetite in place of the average damage; Residual = Estimated x (1 - P x Q); ratio Residual/Tolerated, bands below 0.90, 0.90-1.10, above 1.10.\n\nQuestion: " + $("ai-q").value.trim() + langLine();
    }
  }
  const TASK_LABEL = { test: "Shortcut test", scenarios: "Generated scenarios", explain: "Explanation for management", treat: "Suggested treatment measures", kri: "Proposed key risk indicators", ask: "Answer" };

  function runAI(task) {
    if (task === "scenarios" && !$("ai-ctx").value.trim()) { show("ai"); toast("Describe the organization first"); $("ai-ctx").focus(); return; }
    if (task === "ask" && !$("ai-q").value.trim()) { show("ai"); toast("Type a question first"); $("ai-q").focus(); return; }
    if ((task === "explain" || task === "treat" || task === "kri") && !S.draft.name) { toast("Name the scenario on the Risk tab first"); return; }
    const prompt = buildPrompt(task);
    S.ai.pending = { task, scen: S.draft.id || "", at: Date.now() }; save();
    const name = encodeURIComponent(S.settings.shortcut || "CRG Assistant");
    let url;
    if (S.settings.callback && !isStandalone()) {
      const back = location.origin + location.pathname + "?ai=1";
      url = `shortcuts://x-callback-url/run-shortcut?name=${name}&input=text&text=${encodeURIComponent(prompt)}` +
        `&x-success=${encodeURIComponent(back)}&x-cancel=${encodeURIComponent(back + "&cancel=1")}&x-error=${encodeURIComponent(back + "&err=1")}`;
    } else {
      url = `shortcuts://run-shortcut?name=${name}&input=text&text=${encodeURIComponent(prompt)}`;
    }
    show("ai"); renderPending();
    location.href = url;
  }
  const isStandalone = () => window.navigator.standalone === true || matchMedia("(display-mode: standalone)").matches;

  function renderPending() {
    const p = S.ai.pending;
    $("ai-pending").hidden = !p;
    if (p) $("ai-pending-text").innerHTML = `Running <b>${esc(TASK_LABEL[p.task])}</b> in the <b>${esc(S.settings.shortcut)}</b> Shortcut. When it finishes, come back here and tap <b>Paste result</b>. Nothing happened? Check the Setup steps below.`;
  }
  function buildAI() {
    document.querySelectorAll("[data-ai-task]").forEach(b => b.addEventListener("click", () => runAI(b.dataset.aiTask)));
    $("ai-ctx").value = S.ai.ctx || ""; $("ai-n").value = S.ai.n || "5"; $("ai-q").value = S.ai.q || "";
    $("ai-ctx").addEventListener("input", e => { S.ai.ctx = e.target.value; save(); });
    $("ai-n").addEventListener("change", e => { S.ai.n = e.target.value; save(); });
    $("ai-q").addEventListener("input", e => { S.ai.q = e.target.value; save(); });
    $("ai-paste").addEventListener("click", async () => {
      try {
        const t = await navigator.clipboard.readText();
        if (!t || !t.trim()) throw new Error("empty");
        handleResult(t);
      } catch (e) { toast("Couldn't read the clipboard. Paste into the box below instead."); $("ai-manual").focus(); }
    });
    $("ai-manual-go").addEventListener("click", () => { const t = $("ai-manual").value; if (t.trim()) { handleResult(t); $("ai-manual").value = ""; } });
    $("ai-cancel").addEventListener("click", () => { S.ai.pending = null; save(); renderPending(); });
    $("ai-output").addEventListener("click", e => {
      const add = e.target.closest("[data-add]"); if (add) addAIScenario(Number(add.dataset.add), add);
      const cp = e.target.closest("[data-copy-out]"); if (cp) copyText(S.ai.last ? S.ai.last.text : "", "Copied");
      const note = e.target.closest("[data-attach]"); if (note) attachToScenario();
      const cl = e.target.closest("[data-close-out]"); if (cl) { S.ai.last = null; save(); renderAIOutput(); }
    });
    document.addEventListener("visibilitychange", () => { if (!document.hidden && S.ai.pending) { show("ai"); renderPending(); } });
    renderPending(); renderAIOutput();
  }
  function handleResult(text) {
    const p = S.ai.pending || { task: "ask" };
    S.ai.pending = null;
    let items = null;
    if (p.task === "scenarios") items = parseScenarios(text);
    S.ai.last = { task: p.task, text: text.trim(), items, scen: p.scen, at: Date.now() };
    save(); renderPending(); renderAIOutput(); show("ai");
    if (p.task === "test") toast(/CRG OK/i.test(text) ? "Shortcut works" : "The Shortcut answered, but not as expected. Check the setup.");
  }
  function parseScenarios(text) {
    let t = text.replace(/```(?:json)?/gi, "").trim();
    const a = t.indexOf("["), b = t.lastIndexOf("]");
    if (a < 0 || b <= a) return null;
    try {
      const arr = JSON.parse(t.slice(a, b + 1));
      if (!Array.isArray(arr)) return null;
      const cl = (x, lo = 0, hi = 1, dflt = 0.5) => { const n = Number(x); return isFinite(n) ? Math.min(hi, Math.max(lo, n)) : dflt; };
      return arr.filter(o => o && (o.name || o.statement)).map(o => {
        const De = cl(o.De), Dm = Math.max(De, cl(o.Dm, 0, 1, De));
        return { name: String(o.name || "Untitled").slice(0, 140), statement: String(o.statement || ""), threat_source: o.threat_source || "", vulnerability: o.vulnerability || "",
          asset: o.asset || "", consequence: o.consequence || "", rationale: o.rationale || "",
          PbA: cl(o.PbA), Pbx: cl(o.Pbx), De, Dm, Th: cl(o.Th, 0.05, 1), Mu: cl(o.Mu), added: false };
      });
    } catch (e) { return null; }
  }
  function renderAIOutput() {
    const L = S.ai.last, host = $("ai-output");
    if (!L) { host.innerHTML = ""; return; }
    let body;
    if (L.task === "scenarios" && L.items && L.items.length) {
      body = L.items.map((o, i) => `<div class="scen-card"><h4>${esc(o.name)}</h4><p>${esc(o.statement)}</p>
        <div class="scen-params">Pb(A) ${fmt2(o.PbA)} · Pb(ψ,A) ${fmt2(o.Pbx)} · δe ${fmt2(o.De)} · δm ${fmt2(o.Dm)} · θ ${fmt2(o.Th)} · μ ${fmt2(o.Mu)}</div>
        ${o.rationale ? `<p class="small muted">${esc(o.rationale)}</p>` : ""}
        <button class="btn sm ${o.added ? "" : "primary"}" data-add="${i}" ${o.added ? "disabled" : ""}>${o.added ? "Added to register" : "Add to register as draft"}</button></div>`).join("") +
        `<p class="small muted">Drafts use the CVSS vector of the current scenario as a placeholder. Score each draft's own weakness on the CVSS tab and set the treatment package before relying on the result.</p>`;
    } else {
      body = `<div class="ai-text">${esc(L.text)}</div>` + (L.task === "scenarios" ? `<p class="small muted">The answer wasn't in the expected JSON format, so it is shown as text. Try again, or switch the Shortcut to Private Cloud Compute.</p>` : "");
    }
    host.innerHTML = `<div class="card ai-out"><div class="eyebrow"><span class="spark">✦</span> ${esc(TASK_LABEL[L.task] || "Result")}${L.scen ? " · " + esc(L.scen) : ""}</div>
      <span class="ai-badge">Analyst estimate — validation required</span>${body}
      <div class="actions tight"><button class="btn sm" data-copy-out>Copy</button>${(L.task === "explain" || L.task === "treat" || L.task === "kri") && L.scen ? '<button class="btn sm" data-attach>Add to scenario notes</button>' : ""}<button class="btn sm" data-close-out>Dismiss</button></div></div>`;
  }
  function addAIScenario(i, btn) {
    const o = S.ai.last.items[i]; if (!o || o.added) return;
    clearSampleIfNeeded();
    const s = { id: nextId(), name: o.name, statement: o.statement, threat_source: o.threat_source, vulns: o.vulnerability ? [o.vulnerability] : [], assets: o.asset,
      consequences: o.consequence ? { Summary: o.consequence } : undefined,
      params: Object.fromEntries(PARAMS.map(k => [k, { v: o[k], rat: o.rationale, conf: "Low", ev: "AI draft — validation required" }])),
      cvss: S.draft.cvss || self.CRG_SAMPLE.SCEN[0].cvss, red_p: 0, red_i: 0, origin: "ai", updated: new Date().toISOString() };
    S.register.push(s); o.added = true; save(); renderAIOutput(); toast("Added " + s.id + " as an AI draft");
  }
  function attachToScenario() {
    const L = S.ai.last, s = S.register.find(x => x.id === L.scen);
    if (!s) { toast("Save the scenario first"); return; }
    const key = { explain: "management_note", treat: "treatment_ideas", kri: "kri_ideas" }[L.task];
    s[key] = L.text + "\n[AI draft — validation required]";
    if (S.draft.id === s.id) S.draft[key] = s[key];
    save(); toast("Added to " + s.id);
  }
  function renderAICurrent() {
    const d = S.draft;
    $("ai-cur-name").textContent = (d.id ? d.id + " · " : "") + (d.name || "No scenario on the Risk tab");
    let meta = "Unsaved";
    try { const c = draftCvss(); const r = CRG.calc(Object.assign({}, d, { cvss_score: c.score }), S.settings.appetite, S.settings.factor); meta = "Ratio " + fmt2(r.ratio) + " · " + CRG.classify(r.ratio); } catch (e) { meta = "Incomplete"; }
    $("ai-cur-meta").textContent = meta;
  }
  function checkCallback() {
    const q = new URLSearchParams(location.search);
    if (!q.has("ai")) return;
    const result = q.get("result");
    history.replaceState(null, "", location.pathname);
    if (q.has("cancel")) { S.ai.pending = null; save(); toast("Cancelled"); return; }
    if (q.has("err")) { toast("Shortcut error: " + (q.get("errorMessage") || "unknown")); return; }
    if (result) handleResult(result);
  }

  /* ---------------------------------------------------------------- boot */
  buildCalc(); buildCVSS(); buildRegister(); buildBudget(); buildSettings(); buildAI(); syncShortcutName();
  fillCalc();
  checkCallback();
  show(S.ai.pending ? "ai" : (S.view || "calc"));

  if ("serviceWorker" in navigator && location.protocol.startsWith("http")) {
    window.addEventListener("load", () => navigator.serviceWorker.register("sw.js").catch(() => {}));
  }
})();
