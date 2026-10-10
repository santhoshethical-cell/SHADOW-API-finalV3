"use strict";
const $ = (s) => document.querySelector(s);
const show = (el) => el.removeAttribute("hidden");
const hide = (el) => el.setAttribute("hidden", "");
const SEV = ["Critical", "High", "Medium", "Low", "Info"];
const SEV_COLOR = { Critical:"#fb5a76", High:"#ff9d4d", Medium:"#ffcf5c", Low:"#4cc6ff", Info:"#6b7f92" };
let state = { level: null, scanId: null, charts: {} };

async function api(path, opts = {}) {
  const res = await fetch(path, { credentials: "same-origin",
    headers: { "Content-Type": "application/json" }, ...opts });
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (e) {}
    const err = new Error(detail); err.status = res.status; throw err;
  }
  return res;
}

/* ---------- auth guard: this page requires a signed-in, ready user ---------- */
(async () => {
  try {
    const me = await (await api("/api/me")).json();
    if (me.must_change_password) return location.replace("/set-password");
    $("#who").textContent = me.username;
  } catch (e) { location.replace("/login"); }
})();

$("#logout").addEventListener("click", async () => {
  try { await api("/api/logout", { method: "POST" }); } catch (e) {}
  location.replace("/login");
});

/* ---------- scan setup ---------- */
$("#levels").addEventListener("click", (e) => {
  const btn = e.target.closest(".level"); if (!btn) return;
  state.level = btn.dataset.level;
  document.querySelectorAll(".level").forEach((b) => b.classList.toggle("active", b === btn));
  const needsAuthz = state.level !== "basic";
  $("#authz").toggleAttribute("hidden", !needsAuthz);
  refreshStartButton();
});
$("#authz-check").addEventListener("change", refreshStartButton);
$("#target-url").addEventListener("input", refreshStartButton);

let scanConfirmed = false;   // set once the pre-scan SPA/API check has run

function refreshStartButton() {
  const hasUrl = $("#target-url").value.trim().length > 3;
  const authzOk = state.level === "basic" || $("#authz-check").checked;
  $("#start-scan").disabled = !(state.level && hasUrl && authzOk);
  // any change to the target/level invalidates a previous pre-check
  scanConfirmed = false;
  $("#precheck-box").hidden = true;
  if (!$("#start-scan").disabled) $("#start-scan").textContent = "Start scan";
}

$("#start-scan").addEventListener("click", startScan);
$("#new-scan").addEventListener("click", () => location.reload());

/* Step 1: confirm the target is a SPA / API app before scanning. */
async function startScan() {
  hide($("#setup-error"));
  const btn = $("#start-scan"), box = $("#precheck-box");
  if (scanConfirmed) return doStartScan();

  btn.disabled = true; btn.textContent = "Checking target…"; box.hidden = true;
  try {
    const pc = await (await api("/api/precheck", { method: "POST",
      body: JSON.stringify({ target_url: $("#target-url").value.trim() }) })).json();
    box.hidden = false;
    box.className = "precheck " + (pc.recommended ? "ok" : "warn");
    box.innerHTML = `<strong>${pc.recommended ? "✓" : "⚠"}</strong> ${esc(pc.verdict)}`;
    scanConfirmed = true;
    btn.disabled = false;
    if (pc.recommended) { btn.textContent = "Start scan"; return doStartScan(); }
    btn.textContent = "Scan anyway";   // not a great fit — require a 2nd click
  } catch (err) {
    box.hidden = false; box.className = "precheck warn";
    box.innerHTML = `<strong>⚠</strong> ${esc(err.message)}`;
    scanConfirmed = true; btn.disabled = false; btn.textContent = "Scan anyway";
  }
}

/* Step 2: actually start the scan. */
async function doStartScan() {
  hide($("#setup-error"));
  const payload = { target_url: $("#target-url").value.trim(), level: state.level,
    authorized_confirmed: $("#authz-check").checked,
    options: (window.collectAdvancedOptions ? window.collectAdvancedOptions() : {}) };
  try {
    const r = await (await api("/api/scan", { method: "POST", body: JSON.stringify(payload) })).json();
    state.scanId = r.scan_id;
    hide($("#panel-setup")); hide($("#panel-history")); show($("#panel-progress"));
    $("#progress-target").textContent = r.target_url;
    streamProgress(r.scan_id);
  } catch (err) { $("#setup-error").textContent = err.message; show($("#setup-error")); }
}

/* ---------- real-time progress (SSE) ---------- */
function streamProgress(scanId) {
  const es = new EventSource(`/api/scan/${scanId}/stream`);
  const con = $("#console");
  es.onmessage = (ev) => {
    const d = JSON.parse(ev.data);
    if (d.phase) markPhase(d.phase);
    if (d.message) appendLine(con, d.message, d);
    if (d.type === "done") { es.close(); setStatus("completed"); loadReport(scanId); }
    if (d.type === "error") { es.close(); setStatus("failed"); appendLine(con, "Scan failed: " + d.message, { level: "warning" }); }
  };
  es.onerror = () => { /* SSE auto-reconnects; ignore transient drops */ };
}
function appendLine(con, text, d) {
  const line = document.createElement("span");
  line.className = "ln" + (d && d.phase ? " ph" : "") + (d && (d.level === "warning" || d.level === "error") ? " warn" : "");
  line.textContent = text;
  con.appendChild(line); con.scrollTop = con.scrollHeight;
}
function markPhase(n) {
  document.querySelectorAll(".phase").forEach((p) => {
    const pn = +p.dataset.phase;
    p.classList.toggle("active", pn === n);
    if (pn < n) { p.classList.add("done"); p.classList.remove("active"); }
  });
}
function setStatus(s) {
  const el = $("#progress-status"); el.textContent = s; el.className = "pill " + s;
  if (s === "completed") document.querySelectorAll(".phase").forEach((p) => { p.classList.add("done"); p.classList.remove("active"); });
}

/* ---------- report ---------- */
document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((x) => x.classList.toggle("active", x === t));
  const tab = t.dataset.tab;
  $("#tab-summary").toggleAttribute("hidden", tab !== "summary");
  $("#tab-technical").toggleAttribute("hidden", tab !== "technical");
}));

/* Tier 1: authoritative reference links for each finding */
function cweUrl(cwe) {
  const m = /CWE-(\d+)/i.exec(cwe || "");
  return m ? `https://cwe.mitre.org/data/definitions/${m[1]}.html` : null;
}
function owaspUrl(v) {
  const ref = (v.references || []).find((x) => { const u = safeUrl(x); return u && new URL(u).hostname.endsWith("owasp.org"); });
  return ref || "https://owasp.org/API-Security/editions/2023/en/0x11-t10/";
}

async function loadReport(scanId) {
  show($("#panel-report"));
  $("#export-pdf").href = `/api/scan/${scanId}/export.pdf`;
  $("#export-csv").href = `/api/scan/${scanId}/export.csv`;
  $("#export-json").href = `/api/scan/${scanId}/export.json`;
  state.scanId = scanId;
  if (window.Enrichment) window.Enrichment.start(scanId);
  const summary = await (await api(`/api/scan/${scanId}/summary`)).json();
  renderSummary(summary);
  const tech = await (await api(`/api/scan/${scanId}/technical`)).json();
  renderTechnical(tech);
}

/* Reopen a saved report from history (reads stored results; no rescan). */
window.openReport = function (scanId) {
  hide($("#panel-setup")); hide($("#panel-history")); hide($("#panel-progress"));
  loadReport(scanId).catch((err) => {
    show($("#panel-setup")); show($("#panel-history"));
    $("#setup-error").textContent = "Could not open report: " + err.message; show($("#setup-error"));
  });
};

const STATUS_LABEL = { confirmed: "Confirmed", potential: "Potential", unknown: "Unknown", dismissed: "Dismissed" };

function renderSummary(s) {
  $("#headline").textContent = s.headline;
  $("#gauge-score").textContent = s.risk_score.toFixed(1);
  $("#gauge-level").textContent = s.risk_level;
  const st = s.stats;
  $("#stat-row").innerHTML = [
    ["Discovered", st.endpoints_discovered], ["Shadow", st.shadow_unmanaged],
    ["Documented", st.documented],
    ["Confirmed", st.confirmed_findings ?? "—"], ["Potential", st.potential_findings ?? "—"],
  ].map(([k, v]) => `<div class="stat"><b>${esc(v)}</b><small>${esc(k)}</small></div>`).join("");

  drawGauge(s.charts.risk_gauge);
  drawInventory(s.charts.inventory || {});
  drawSeverity(s.charts.severity, s.charts.severity_by_status);
  drawOwasp(s.charts.owasp_category);

  // Shadow / unmanaged API list (the key discovery finding even with 0 vulns)
  const shadow = s.shadow_endpoints || [];
  const sec = $("#shadow-section");
  if (shadow.length) {
    sec.hidden = false;
    $("#shadow-count").textContent = shadow.length;
    $("#shadow-list").innerHTML = shadow.map((e) =>
      `<div class="shadow-item"><span class="method">${esc(e.method)}</span>
       <span class="mono">${esc(e.url)}</span></div>`).join("");
  } else {
    sec.hidden = true;
  }

  const active = s.findings.filter((f) => f.evidence_category !== "dismissed");
  $("#findings").innerHTML = active.length ? active.map((f) => {
    const cls = sevClass(f.severity), cat = f.evidence_category || "unknown";
    return `<div class="finding ${cls} cat-${esc(cat)}">
      <div class="finding-head"><strong>${esc(f.title)}</strong>
        <span class="badges"><span class="status-badge ${esc(cat)}" title="${esc(f.evidence_basis || "")}">${esc(STATUS_LABEL[cat] || cat)}</span>
        <span class="sev-badge ${cls}">${esc(f.severity)}</span></span></div>
      <p>${esc(f.plain_meaning || "")}</p>
      <p class="todo"><strong>What to do:</strong> ${esc(f.what_to_do || "")}</p>
      <p class="muted small">Scanner status: ${esc(f.status || "—")} · confidence ${esc(f.confidence ?? "—")} · ${esc(f.evidence_basis || "")}</p>
    </div>`;
  }).join("") : `<div class="finding info"><p>No security findings were reported by the scanner.</p></div>`;
  const dismissed = s.findings.length - active.length;
  const ck = s.checks || {};
  const incomplete = (ck.inconclusive || 0) + (ck.skipped || 0) + (ck.failed || 0);
  const notes = [];
  if (incomplete) notes.push(`${incomplete} security check(s) did not complete (inconclusive ${ck.inconclusive || 0}, skipped ${ck.skipped || 0}, failed ${ck.failed || 0}) — absence of findings there is not evidence of safety.`);
  if (dismissed) notes.push(`${dismissed} result(s) dismissed by the scanner as false positives are hidden.`);
  const cn = $("#checks-note");
  cn.hidden = !notes.length; cn.textContent = notes.join(" ");
}

function renderTechnical(t) {
  const eps = (t.endpoints && (t.endpoints.all || [])) || [];
  const rows = eps.slice(0, 400).map((e) => `<tr>
    <td class="mono">${esc(e.method || "")}</td>
    <td class="mono">${esc((e.url || "").replace(/^https?:\/\/[^/]+/, ""))}</td>
    <td>${esc(e.documentation_status || "")}</td></tr>`).join("");
  const vulns = (t.vulnerabilities || []).map((v) => `<div class="vuln">
    <div class="finding-head"><strong>${esc(v.title || v.owasp_name || "")}</strong>
      <span class="sev-badge ${sevClass(v.severity)}">${esc(v.severity||"")}</span></div>
    <div class="kv"><span>OWASP: <a href="${esc(safeUrl(owaspUrl(v)) || "#")}" target="_blank" rel="noopener"><b>${esc(v.owasp_category||"")}</b></a></span>
      <span>Scanner status: <b>${esc(v.status||"")}</b></span>
      <span>Evidence: <span class="status-badge ${esc((v.evidence||{}).evidence_category||"unknown")}">${esc(STATUS_LABEL[(v.evidence||{}).evidence_category] || "Unknown")}</span></span>
      <span>Confidence: <b>${v.confidence ?? ""}</b></span>
      <span>Risk: <b>${v.risk_score ?? ""}</b></span>
      <span>CWE: ${cweUrl(v.cwe_id) ? `<a href="${cweUrl(v.cwe_id)}" target="_blank" rel="noopener"><b>${esc(v.cwe_id)}</b></a>` : `<b>${esc(v.cwe_id||"—")}</b>`}</span></div>
    <p class="muted">${esc(v.description || "")}</p>
    ${v.poc_evidence ? `<p class="muted"><strong>Evidence:</strong> ${esc(v.poc_evidence)}</p>` : ""}
    ${v.poc_request ? `<pre>${esc(String(v.poc_request).slice(0,1200))}</pre>` : ""}
  </div>`).join("");
  $("#tech-content").innerHTML = `
    <div class="tech-section"><h3 class="section-h">Scanner findings — all statuses (${(t.vulnerabilities||[]).length})</h3>
      <p class="muted section-note">${(() => { const c = {}; (t.vulnerabilities||[]).forEach((v) => { const k = (v.evidence||{}).evidence_category || "unknown"; c[k] = (c[k]||0) + 1; });
        return ["confirmed","potential","unknown","dismissed"].filter((k) => c[k]).map((k) => `${c[k]} ${esc(STATUS_LABEL[k].toLowerCase())}`).join(" · "); })()}.
        Scanner status and confidence are shown unchanged; “Evidence” is the evidence-based category used in counts.</p>
      ${vulns || '<p class="muted">None.</p>'}</div>
    <div class="tech-section"><h3 class="section-h">Discovered operations (${eps.length})</h3>
      <table class="tech-table"><thead><tr><th>Method</th><th>Path</th><th>Status</th></tr></thead>
      <tbody>${rows}</tbody></table></div>`;
}

/* ---------- charts ---------- */
function destroy(k) { if (state.charts[k]) { state.charts[k].destroy(); delete state.charts[k]; } }
const INV_COLOR = { "Documented":"#4cc6ff", "Shadow / unmanaged":"#f472b6", "Unknown":"#6b7f92" };
function drawInventory(inv) {
  destroy("inv");
  const labels = Object.keys(inv); const data = Object.values(inv);
  if (!data.length) { labels.push("None"); data.push(1); }
  state.charts.inv = new Chart($("#chart-inventory"), {
    type: "doughnut",
    data: { labels, datasets: [{ data, backgroundColor: labels.map((l) => INV_COLOR[l] || "#2a3a49"), borderColor: "#0b1119", borderWidth: 2 }] },
    options: { plugins: { legend: { labels: { color: "#9fb3c2", boxWidth: 12 }, position: "bottom" } }, cutout: "62%" },
  });
}
function drawSeverity(sev, byStatus) {
  destroy("sev");
  const conf = (byStatus && byStatus.confirmed) || null, pot = (byStatus && byStatus.potential) || null;
  if (!conf && !pot) {   // older summary shape
    const labels = SEV.filter((s) => sev[s]); const data = labels.map((s) => sev[s]);
    if (!data.length) { labels.push("None"); data.push(1); }
    state.charts.sev = new Chart($("#chart-severity"), { type: "doughnut",
      data: { labels, datasets: [{ data, backgroundColor: labels.map((l) => SEV_COLOR[l] || "#2a3a49"), borderColor: "#0b1119", borderWidth: 2 }] },
      options: { plugins: { legend: { labels: { color: "#9fb3c2", boxWidth: 12 }, position: "bottom" } }, cutout: "62%" } });
    return;
  }
  const labels = SEV.filter((k) => (conf && conf[k]) || (pot && pot[k]));
  state.charts.sev = new Chart($("#chart-severity"), {
    type: "bar",
    data: { labels: labels.length ? labels : ["None"], datasets: [
      { label: "Confirmed", data: labels.map((k) => (conf && conf[k]) || 0), backgroundColor: "#fb5a76", borderRadius: 4 },
      { label: "Potential", data: labels.map((k) => (pot && pot[k]) || 0), backgroundColor: "#ffcf5c", borderRadius: 4 }] },
    options: { plugins: { legend: { labels: { color: "#9fb3c2", boxWidth: 12 }, position: "bottom" } },
      scales: { x: { stacked: true, ticks: { color: "#9fb3c2" }, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, ticks: { color: "#9fb3c2", precision: 0 }, grid: { color: "#152230" } } } },
  });
}
function drawOwasp(cat) {
  destroy("owasp");
  const labels = Object.keys(cat); const data = Object.values(cat);
  state.charts.owasp = new Chart($("#chart-owasp"), {
    type: "bar",
    data: { labels: labels.length ? labels : ["None"], datasets: [{ data: data.length ? data : [0],
      backgroundColor: "#34e0c4", borderRadius: 5 }] },
    options: { plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: "#9fb3c2" }, grid: { display: false } },
        y: { ticks: { color: "#9fb3c2", precision: 0 }, grid: { color: "#152230" }, beginAtZero: true } } },
  });
}
function drawGauge(g) {
  destroy("gauge");
  const score = Math.max(0, Math.min(10, g.score || 0));
  const color = score >= 9 ? SEV_COLOR.Critical : score >= 7 ? SEV_COLOR.High : score >= 4 ? SEV_COLOR.Medium : score > 0 ? SEV_COLOR.Low : SEV_COLOR.Info;
  state.charts.gauge = new Chart($("#gauge"), {
    type: "doughnut",
    data: { datasets: [{ data: [score, 10 - score], backgroundColor: [color, "#182634"], borderWidth: 0 }] },
    options: { rotation: -90, circumference: 180, cutout: "78%", plugins: { legend: { display: false }, tooltip: { enabled: false } } },
  });
}

function sevClass(s) {
  s = (s || "").toLowerCase();
  return s === "critical" ? "crit" : s === "high" ? "high"
    : s === "medium" ? "medium" : s === "low" ? "low" : "info";
}

/* Only plain http(s) links are ever rendered as hrefs. */
function safeUrl(u) {
  try {
    const url = new URL(String(u || ""));
    return (url.protocol === "https:" || url.protocol === "http:") && !url.username && !url.password
      ? url.href : null;
  } catch (e) { return null; }
}

function esc(s) { return String(s ?? "").replace(/[&<>"]/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;" }[c])); }
