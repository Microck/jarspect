/* ============================================================
   Jarspect - Frontend Logic
   Handles: drag-drop upload, scan orchestration, result rendering
   ============================================================ */

const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const statusBar = document.getElementById("status-bar");
const resultsEl = document.getElementById("results");
const riskLineEl = document.getElementById("risk-line");
const scanIdEl = document.getElementById("scan-id");
const summaryEl = document.getElementById("summary");
const explanationEl = document.getElementById("explanation");
const indicatorsEl = document.getElementById("indicators");
const submitButton = document.getElementById("run-scan");
const btnText = submitButton.querySelector(".btn-text");
const btnSpinner = submitButton.querySelector(".btn-spinner");
const dropZone = document.getElementById("drop-zone");
const fileInput = document.getElementById("mod-file");
const fileNameEl = document.getElementById("file-name");
const verdictEl = document.querySelector(".results-verdict");

/* --- Status management --- */
function setStatus(message, state = "ok") {
  statusEl.textContent = message;
  statusBar.dataset.state = state;
}

/* --- Button loading state --- */
function setLoading(loading) {
  submitButton.disabled = loading;
  btnText.textContent = loading ? "Scanning..." : "Upload & Scan";
  btnSpinner.hidden = !loading;
}

/* --- Helpers --- */
function numberOrUndefined(value) {
  if (value === "") return undefined;
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function buildAuthorPayload() {
  const authorId = document.getElementById("author-id").value.trim();
  if (!authorId) return undefined;

  const payload = { author_id: authorId };
  const modId = document.getElementById("mod-id").value.trim();
  if (modId) payload.mod_id = modId;

  const accountAge = numberOrUndefined(document.getElementById("account-age").value);
  const priorMods = numberOrUndefined(document.getElementById("prior-mods").value);
  const reportCount = numberOrUndefined(document.getElementById("report-count").value);

  if (accountAge !== undefined) payload.account_age_days = accountAge;
  if (priorMods !== undefined) payload.prior_mod_count = priorMods;
  if (reportCount !== undefined) payload.report_count = reportCount;

  return payload;
}

/* --- Drag and drop --- */
dropZone.addEventListener("click", () => fileInput.click());

fileInput.addEventListener("change", () => {
  const file = fileInput.files?.[0];
  if (file) {
    fileNameEl.textContent = file.name;
    fileNameEl.classList.add("has-file");
  } else {
    fileNameEl.textContent = "No file selected";
    fileNameEl.classList.remove("has-file");
  }
});

dropZone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropZone.classList.add("drag-over");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("drag-over");
});

dropZone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropZone.classList.remove("drag-over");
  const file = e.dataTransfer.files?.[0];
  if (file && file.name.endsWith(".jar")) {
    // Transfer the dropped file to the hidden input
    const dt = new DataTransfer();
    dt.items.add(file);
    fileInput.files = dt.files;
    fileNameEl.textContent = file.name;
    fileNameEl.classList.add("has-file");
  } else {
    setStatus("Only .jar files are accepted.", "error");
  }
});

/* --- API calls --- */
async function uploadJar(file) {
  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch("/upload", {
    method: "POST",
    body: formData,
  });

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({}));
    throw new Error(errorPayload.detail || "Upload failed");
  }

  return response.json();
}

async function runScan(uploadId, authorPayload) {
  const requestBody = { upload_id: uploadId };
  if (authorPayload) requestBody.author = authorPayload;

  const response = await fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestBody),
  });

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({}));
    throw new Error(errorPayload.detail || "Scan failed");
  }

  return response.json();
}

/* --- Severity helpers --- */
function normalizeSeverity(sev) {
  if (!sev) return "info";
  const s = sev.toLowerCase();
  if (s.includes("critical")) return "critical";
  if (s.includes("high")) return "high";
  if (s.includes("medium") || s.includes("moderate")) return "medium";
  if (s.includes("low")) return "low";
  return "info";
}

/* --- Render results --- */
function renderResult(scanResponse) {
  const result = scanResponse.result || {};
  const verdict = result.verdict || {};
  const indicators = verdict.indicators || [];

  const tier = verdict.risk_tier || "UNKNOWN";
  const score = verdict.risk_score ?? "?";

  riskLineEl.textContent = `${tier} risk \u00B7 ${score}/100`;
  scanIdEl.textContent = scanResponse.scan_id || "n/a";
  summaryEl.textContent = verdict.summary || "No verdict summary returned.";
  explanationEl.textContent = verdict.explanation || "No explanation returned.";

  // Set tier for color theming
  if (verdictEl) verdictEl.dataset.tier = tier;

  // Render indicators
  indicatorsEl.innerHTML = "";

  if (indicators.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty-state";
    empty.textContent = "No indicators returned. The mod appears clean.";
    indicatorsEl.appendChild(empty);
  } else {
    indicators.forEach((indicator, index) => {
      const li = document.createElement("li");
      li.style.animationDelay = `${index * 60}ms`;

      const sev = normalizeSeverity(indicator.severity);

      const rationaleHtml = indicator.rationale
        ? `<p class="indicator-rationale">${escapeHtml(indicator.rationale)}</p>`
        : "";

      li.innerHTML = `
        <div class="indicator-head">
          <span class="indicator-id">${escapeHtml(indicator.id || "")}</span>
          <span class="indicator-source">${escapeHtml(indicator.source || "")}</span>
          <span class="severity-badge" data-sev="${sev}">${escapeHtml(indicator.severity || "")}</span>
        </div>
        <p class="indicator-title">${escapeHtml(indicator.title || "")}</p>
        <p class="indicator-evidence">${escapeHtml(indicator.evidence || "")}</p>
        ${rationaleHtml}
      `;
      indicatorsEl.appendChild(li);
    });
  }

  resultsEl.hidden = false;
  // Smooth scroll to results
  resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* --- HTML escaping --- */
function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

/* --- Form submission --- */
form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const selectedFile = fileInput.files?.[0];
  if (!selectedFile) {
    setStatus("Choose a .jar file before running scan.", "error");
    return;
  }

  setLoading(true);
  resultsEl.hidden = true;
  setStatus("Uploading file\u2026", "scanning");

  try {
    const uploadPayload = await uploadJar(selectedFile);
    setStatus(`Uploaded ${uploadPayload.filename}. Running full scan\u2026`, "scanning");

    const authorPayload = buildAuthorPayload();
    const scanPayload = await runScan(uploadPayload.upload_id, authorPayload);

    renderResult(scanPayload);
    setStatus("Scan complete.", "done");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected error";
    setStatus(message, "error");
  } finally {
    setLoading(false);
  }
});
