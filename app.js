const $ = (id) => document.getElementById(id);
const fileInput = $("files");
const fileText = $("fileText");
const dropzone = $("dropzone");
let selectedFiles = [];

fileInput.addEventListener("change", () => {
  selectedFiles = [...fileInput.files];
  fileText.textContent = selectedFiles.length
    ? `${selectedFiles.length} file(s) selected`
    : "or click to choose files";
});

["dragenter","dragover"].forEach(evt => {
  dropzone.addEventListener(evt, e => {
    e.preventDefault();
    dropzone.style.borderColor = "#7ee2ad";
  });
});
["dragleave","drop"].forEach(evt => {
  dropzone.addEventListener(evt, e => {
    e.preventDefault();
    dropzone.style.borderColor = "";
  });
});
dropzone.addEventListener("drop", e => {
  selectedFiles = [...e.dataTransfer.files];
  fileText.textContent = selectedFiles.length
    ? `${selectedFiles.length} file(s) selected`
    : "or click to choose files";
});

$("demoBtn").addEventListener("click", async () => {
  setStatus("● DEMO LOADED");
  const demo = new Blob([JSON.stringify([
    {"timestamp":"2026-10-02T10:02:00Z","event":"suspicious_login","user":"user_4821","ip":"185.44.12.9","resource":"auth","status":"success"},
    {"timestamp":"2026-10-02T10:04:00Z","event":"unusual_api_request","user":"user_4821","ip":"185.44.12.9","resource":"/api/customers/search","status":"success"},
    {"timestamp":"2026-10-02T10:05:00Z","event":"database_access","user":"user_4821","ip":"185.44.12.9","resource":"customer_db","status":"success"},
    {"timestamp":"2026-10-02T10:06:00Z","event":"large_data_export","user":"user_4821","ip":"185.44.12.9","resource":"customer_db","status":"success","bytes":8200000000}
  ], null, 2)], {type:"application/json"});
  const demoFile = new File([demo], "demo_incident.json", {type:"application/json"});
  selectedFiles = [demoFile];
  fileText.textContent = "demo_incident.json";
});

$("investigateBtn").addEventListener("click", async () => {
  if (!selectedFiles.length) {
    alert("Upload a log file or load the demo first.");
    return;
  }

  setStatus("◌ INVESTIGATING...");
  $("investigateBtn").disabled = true;

  try {
    const form = new FormData();
    selectedFiles.forEach(f => form.append("files", f));

    const res = await fetch("/api/investigate", {method:"POST", body:form});
    const data = await res.json();

    if (!res.ok) throw new Error(data.error || "Investigation failed.");

    render(data);
    setStatus("● INVESTIGATION COMPLETE");
    window.scrollTo({top: $("results").offsetTop - 20, behavior:"smooth"});
  } catch (err) {
    setStatus("● ERROR");
    alert(err.message);
  } finally {
    $("investigateBtn").disabled = false;
  }
});

function setStatus(text) {
  $("status").textContent = text;
}

function escapeHtml(s) {
  return String(s ?? "")
    .replaceAll("&","&amp;")
    .replaceAll("<","&lt;")
    .replaceAll(">","&gt;")
    .replaceAll('"',"&quot;")
    .replaceAll("'","&#039;");
}

function render(data) {
  const r = data.report;
  $("results").classList.remove("hidden");

  $("eventsAnalyzed").textContent = data.stats.events_analyzed;
  $("anomalies").textContent = data.stats.anomalies;
  $("correlated").textContent = data.stats.correlated_events;
  $("confidence").textContent = `${r.confidence}%`;

  $("incidentTitle").textContent = r.incident;
  $("initialEvent").textContent = r.initial_event;
  $("account").textContent = r.compromised_account;
  $("resource").textContent = r.affected_resource;
  $("severityText").textContent = r.severity;
  $("severityBadge").textContent = r.severity;

  const timeline = $("timeline");
  timeline.innerHTML = data.timeline.map(e => `
    <div class="event">
      <div class="event-time">${escapeHtml(e.time)}</div>
      <div class="dot"></div>
      <div>
        <div class="event-title">${escapeHtml(e.event)}</div>
        <div class="event-sub">${escapeHtml(e.user)} • ${escapeHtml(e.resource)} • ${escapeHtml(e.ip)}</div>
      </div>
    </div>
  `).join("");

  $("evidenceList").innerHTML = (r.evidence || []).map(e => `
    <div class="evidence-item">
      <div><span class="evidence-time">${escapeHtml(e.time)}</span> &nbsp; <b>${escapeHtml(e.event)}</b></div>
      <div class="evidence-reason">${escapeHtml(e.reason)}</div>
    </div>
  `).join("") || `<div class="muted">No evidence items returned.</div>`;

  renderGraph(r.graph);
  $("actions").innerHTML = (r.recommended_actions || []).map(a =>
    `<div class="action">${escapeHtml(a)}</div>`
  ).join("");

  if (r.ai_error) {
    $("actions").insertAdjacentHTML("afterbegin",
      `<div class="action" style="grid-column:1/-1;border-color:#6a5530;color:#ffd36b">${escapeHtml(r.ai_error)}</div>`
    );
  }
}

function renderGraph(graph) {
  const root = $("graph");
  const nodes = graph?.nodes || [];
  if (!nodes.length) {
    root.innerHTML = `<div class="muted">No graphable entities found.</div>`;
    return;
  }

  const interesting = nodes.filter(n => ["ip","user","resource","event"].includes(n.kind)).slice(0, 8);
  root.innerHTML = interesting.map((n, i) => {
    const node = `<div class="node"><small>${escapeHtml(n.kind.toUpperCase())}</small><b>${escapeHtml(n.value)}</b></div>`;
    return i < interesting.length - 1 ? node + `<div class="arrow">→</div>` : node;
  }).join("");
}
