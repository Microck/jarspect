const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const riskLineEl = document.getElementById("risk-line");
const scanIdEl = document.getElementById("scan-id");
const summaryEl = document.getElementById("summary");
const explanationEl = document.getElementById("explanation");
const indicatorsEl = document.getElementById("indicators");
const submitButton = document.getElementById("run-scan");

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.dataset.state = isError ? "error" : "ok";
}

function numberOrUndefined(value) {
  if (value === "") {
    return undefined;
  }
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : undefined;
}

function buildAuthorPayload() {
  const authorId = document.getElementById("author-id").value.trim();
  if (!authorId) {
    return undefined;
  }

  const payload = { author_id: authorId };
  const modId = document.getElementById("mod-id").value.trim();
  if (modId) {
    payload.mod_id = modId;
  }

  const accountAge = numberOrUndefined(document.getElementById("account-age").value);
  const priorMods = numberOrUndefined(document.getElementById("prior-mods").value);
  const reportCount = numberOrUndefined(document.getElementById("report-count").value);

  if (accountAge !== undefined) {
    payload.account_age_days = accountAge;
  }
  if (priorMods !== undefined) {
    payload.prior_mod_count = priorMods;
  }
  if (reportCount !== undefined) {
    payload.report_count = reportCount;
  }

  return payload;
}

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
  if (authorPayload) {
    requestBody.author = authorPayload;
  }

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

function renderResult(scanResponse) {
  const result = scanResponse.result || {};
  const verdict = result.verdict || {};
  const indicators = verdict.indicators || [];

  riskLineEl.textContent = `${verdict.risk_tier || "UNKNOWN"} risk (${verdict.risk_score ?? "?"}/100)`;
  scanIdEl.textContent = `scan_id: ${scanResponse.scan_id || "n/a"}`;
  summaryEl.textContent = verdict.summary || "No verdict summary returned.";
  explanationEl.textContent = verdict.explanation || "No explanation returned.";

  indicatorsEl.innerHTML = "";
  for (const indicator of indicators) {
    const li = document.createElement("li");
    li.innerHTML = `
      <p><strong>${indicator.id}</strong> · ${indicator.source} · ${indicator.severity}</p>
      <p>${indicator.title}</p>
      <p class="mono">${indicator.evidence}</p>
    `;
    indicatorsEl.appendChild(li);
  }

  if (indicators.length === 0) {
    const li = document.createElement("li");
    li.textContent = "No indicators returned.";
    indicatorsEl.appendChild(li);
  }

  resultsEl.hidden = false;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const fileInput = document.getElementById("mod-file");
  const selectedFile = fileInput.files?.[0];
  if (!selectedFile) {
    setStatus("Choose a .jar file before running scan.", true);
    return;
  }

  submitButton.disabled = true;
  setStatus("Uploading file...");

  try {
    const uploadPayload = await uploadJar(selectedFile);
    setStatus(`Uploaded ${uploadPayload.filename}. Running full scan...`);

    const authorPayload = buildAuthorPayload();
    const scanPayload = await runScan(uploadPayload.upload_id, authorPayload);

    renderResult(scanPayload);
    setStatus("Scan complete.");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected error";
    setStatus(message, true);
  } finally {
    submitButton.disabled = false;
  }
});
