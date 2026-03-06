const $ = (selector) => document.querySelector(selector);

const form = $("#scan-form");
const statusEl = $("#status");
const resultsEl = $("#results");
const scanIdEl = $("#scan-id");
const fileCountEl = $("#file-count");
const classCountEl = $("#class-count");
const explanationEl = $("#explanation");
const indicatorsEl = $("#indicators");
const filtersEl = $("#indicator-filters");
const submitBtn = $("#run-scan");
const btnText = $("#btn-text");
const btnLoader = $("#btn-loader");
const dropZone = $("#drop-zone");
const fileInput = $("#mod-file");
const fileNameEl = $("#file-name");
const fileBadgeName = $("#file-badge-name");
const pipelineStepsEl = $("#pipeline-steps");
const copyScanIdBtn = $("#copy-scan-id");
const copyExplanationBtn = $("#copy-explanation");
const verdictMethodBadge = $("#verdict-method-badge");
const verdictBanner = $("#verdict-banner");
const verdictLabel = $("#verdict-label");
const verdictMethod = $("#verdict-method");
const confidenceValue = $("#confidence-value");
const riskScoreValue = $("#risk-score-value");
const capabilitiesBlock = $("#capabilities-block");
const capabilitiesList = $("#capabilities-list");
const artifactsBlock = $("#artifacts-block");
const artifactsGrid = $("#artifacts-grid");

let activeFilter = "all";
let currentEvidence = [];

function escapeHtml(value) {
  const node = document.createElement("div");
  node.textContent = value;
  return node.innerHTML;
}

function normalizeVerdict(raw) {
  const normalized = String(raw || "").trim().toUpperCase();
  if (normalized === "CLEAN") return "CLEAN";
  if (normalized === "SUSPICIOUS") return "SUSPICIOUS";
  if (normalized === "MALICIOUS") return "MALICIOUS";
  return "UNKNOWN";
}

function normalizeSeverity(raw) {
  const normalized = String(raw || "").trim().toLowerCase();
  if (normalized.includes("critical") || normalized.includes("malicious")) return "critical";
  if (normalized.includes("high")) return "high";
  if (normalized.includes("med") || normalized.includes("medium")) return "medium";
  if (normalized.includes("low")) return "low";
  return "info";
}

function setStatus(message, state) {
  statusEl.textContent = message;
  statusEl.dataset.state = state || "";
}

function setLoading(on) {
  submitBtn.disabled = on;
  submitBtn.dataset.scanning = on ? "true" : "false";
  btnText.textContent = on ? "Scanning" : "Run scan";
  btnLoader.hidden = !on;
}

/* ========== Pipeline step rendering ========== */
const PIPELINE_STEPS = [
  { id: "upload", label: "Upload", detail: "Sending .jar to server" },
  { id: "threat-intel", label: "Threat intelligence", detail: "MalwareBazaar hash lookup" },
  { id: "bytecode", label: "Bytecode analysis", detail: "Archive traversal, class parsing, YARA, detectors" },
  { id: "ai-verdict", label: "AI verdict", detail: "Azure OpenAI analysis" },
];

const STEP_ICONS = {
  pending: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="10" opacity="0.3"/></svg>`,
  running: `<span class="typing-dots"><span class="dot"></span><span class="dot"></span><span class="dot"></span></span>`,
  done: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
  skip: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><line x1="5" y1="12" x2="19" y2="12"/></svg>`,
};

function showPipelineSteps() {
  pipelineStepsEl.hidden = false;
  pipelineStepsEl.innerHTML = "";
  PIPELINE_STEPS.forEach((step, i) => {
    const el = document.createElement("div");
    el.className = "pipeline-step";
    el.dataset.state = "pending";
    el.id = `step-${step.id}`;
    el.style.animationDelay = `${i * 60}ms`;
    el.innerHTML =
      `<span class="pipeline-step-icon pipeline-step-icon--pending">${STEP_ICONS.pending}</span>` +
      `<div class="pipeline-step-body">` +
      `<span class="pipeline-step-label">${escapeHtml(step.label)}</span>` +
      `<span class="pipeline-step-detail">${escapeHtml(step.detail)}</span>` +
      `</div>`;
    pipelineStepsEl.appendChild(el);
  });
}

function updatePipelineStep(stepId, state, detail) {
  const el = document.getElementById(`step-${stepId}`);
  if (!el) return;
  el.dataset.state = state;
  const iconEl = el.querySelector(".pipeline-step-icon");
  iconEl.className = `pipeline-step-icon pipeline-step-icon--${state}`;
  iconEl.innerHTML = STEP_ICONS[state] || STEP_ICONS.pending;
  if (detail) {
    el.querySelector(".pipeline-step-detail").textContent = detail;
  }
}

function hidePipelineSteps() {
  pipelineStepsEl.hidden = true;
}

/* ========== Copy to clipboard ========== */
function copyToClipboard(text, btn) {
  navigator.clipboard.writeText(text).then(() => {
    btn.dataset.copied = "true";
    const origHtml = btn.innerHTML;
    btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
    setTimeout(() => {
      btn.dataset.copied = "false";
      btn.innerHTML = origHtml;
    }, 1500);
  }).catch(() => {});
}

copyScanIdBtn.addEventListener("click", () => {
  const text = scanIdEl.textContent;
  if (text && text !== "--") copyToClipboard(text, copyScanIdBtn);
});

copyExplanationBtn.addEventListener("click", (e) => {
  e.preventDefault();
  const text = explanationEl.textContent;
  if (text) copyToClipboard(text, copyExplanationBtn);
});

function updateScanButtonState() {
  const hasFile = fileInput.files && fileInput.files.length > 0;
  submitBtn.disabled = !hasFile;
}

async function uploadJar(file) {
  const payload = new FormData();
  payload.append("file", file);

  const response = await fetch("/upload", { method: "POST", body: payload });
  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({}));
    throw new Error(errorPayload.detail || "Upload failed");
  }

  return response.json();
}

async function runScan(uploadId) {
  const response = await fetch("/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ upload_id: uploadId }),
  });

  if (!response.ok) {
    const errorPayload = await response.json().catch(() => ({}));
    throw new Error(errorPayload.detail || "Scan failed");
  }

  return response.json();
}

function capabilitySeverity(capabilityName) {
  if (["credential_theft", "persistence", "execution"].includes(capabilityName)) {
    return "high";
  }
  if (["native_loading", "deserialization", "dynamic_loading"].includes(capabilityName)) {
    return "medium";
  }
  if (["network", "filesystem"].includes(capabilityName)) {
    return "low";
  }
  return "info";
}

function buildEvidenceItems(response) {
  const items = [];
  const verdict = response.verdict || {};
  const capabilityAssessment = verdict.capabilities_assessment || {};

  if (response.malwarebazaar) {
    const family = response.malwarebazaar.family || "Unknown family";
    const tags = Array.isArray(response.malwarebazaar.tags)
      ? response.malwarebazaar.tags.join(", ")
      : "";

    items.push({
      id: "MB-HASH-MATCH",
      source: "malwarebazaar",
      category: "threat_intel",
      severity: "critical",
      title: "Known malware hash match",
      evidence: tags ? `${family} (${tags})` : family,
      file_path: null,
      rationale: "Hash matched MalwareBazaar threat intelligence feed.",
    });
  }

  const capabilities = response.capabilities || {};
  Object.keys(capabilities).forEach((name) => {
    const signal = capabilities[name] || {};
    if (!signal.present) return;

    const evidence = Array.isArray(signal.evidence) && signal.evidence.length > 0
      ? signal.evidence.join(" | ")
      : "Capability present.";

    items.push({
      id: `CAP-${name.toUpperCase()}`,
      source: "capability",
      category: "capability",
      severity: capabilitySeverity(name),
      title: name.replace(/_/g, " "),
      evidence,
      file_path: null,
      rationale: capabilityAssessment[name] || "Detected from static bytecode capability extraction.",
    });
  });

  const yaraHits = Array.isArray(response.yara_hits) ? response.yara_hits : [];
  yaraHits.forEach((hit) => {
    items.push({
      id: hit.id || "YARA-HIT",
      source: "yara",
      category: "yara",
      severity: hit.severity || "med",
      title: "YARA signature hit",
      evidence: hit.evidence || "YARA rule match",
      file_path: hit.file_path || null,
      rationale: "Matched static signature rule.",
    });
  });

  return items;
}

function renderIndicatorFilters(items) {
  const countsByCategory = {};
  items.forEach((item) => {
    const category = item.category || "other";
    countsByCategory[category] = (countsByCategory[category] || 0) + 1;
  });

  filtersEl.innerHTML = "";
  const allButton = document.createElement("button");
  allButton.className = "filter-btn";
  allButton.type = "button";
  allButton.dataset.cat = "all";
  allButton.textContent = `All (${items.length})`;
  allButton.classList.toggle("active", activeFilter === "all");
  filtersEl.appendChild(allButton);

  Object.keys(countsByCategory)
    .sort()
    .forEach((category) => {
      const button = document.createElement("button");
      button.className = "filter-btn";
      button.type = "button";
      button.dataset.cat = category;
      const catLabel = category.replace(/_/g, " ");
      button.textContent = `${catLabel.charAt(0).toUpperCase() + catLabel.slice(1)} (${countsByCategory[category]})`;
      button.classList.toggle("active", activeFilter === category);
      filtersEl.appendChild(button);
    });
}

function renderIndicators() {
  indicatorsEl.innerHTML = "";
  const filtered = activeFilter === "all"
    ? currentEvidence
    : currentEvidence.filter((item) => item.category === activeFilter);

  if (filtered.length === 0) {
    const emptyNode = document.createElement("li");
    emptyNode.className = "empty-state";
    emptyNode.textContent = currentEvidence.length === 0
      ? "No suspicious indicators detected."
      : "No indicators in this category.";
    indicatorsEl.appendChild(emptyNode);
    return;
  }

  filtered.forEach((item) => {
    const severity = normalizeSeverity(item.severity);
    const fileHtml = item.file_path
      ? `<p class="indicator-file">${escapeHtml(item.file_path)}</p>`
      : "";
    const rationaleHtml = item.rationale
      ? `<p class="indicator-rationale">${escapeHtml(item.rationale)}</p>`
      : "";

    const node = document.createElement("li");
    node.innerHTML =
      `<div class="indicator-head">` +
      `<span class="indicator-id">${escapeHtml(item.id || "")}</span>` +
      `<span class="indicator-source">${escapeHtml(item.source || "")}</span>` +
      `<span class="severity-badge" data-sev="${severity}">${severity.toUpperCase()}</span>` +
      `</div>` +
      `<p class="indicator-title">${escapeHtml(item.title || "")}</p>` +
      `<p class="indicator-evidence">${escapeHtml(item.evidence || "")}</p>` +
      fileHtml +
      rationaleHtml;
    indicatorsEl.appendChild(node);
  });
}

function renderResult(response) {
  const verdict = response.verdict || {};
  const intake = response.intake || {};
  const normalizedVerdict = normalizeVerdict(verdict.result);

  verdictBanner.dataset.tier = normalizedVerdict;
  verdictLabel.textContent = normalizedVerdict;

  const methodText = verdict.method
    ? verdict.method.replace(/_/g, " ")
    : "unknown";
  verdictMethod.textContent = methodText;
  verdictMethodBadge.textContent = methodText;

  const confidence = Number.isFinite(verdict.confidence)
    ? Math.round(verdict.confidence * 100)
    : null;
  confidenceValue.textContent = confidence == null ? "--" : `${confidence}%`;

  const riskScore = Number.isFinite(verdict.risk_score) ? verdict.risk_score : null;
  riskScoreValue.textContent = riskScore == null ? "--" : String(riskScore);

  explanationEl.textContent = verdict.explanation || "No explanation returned.";

  scanIdEl.textContent = response.scan_id || "--";
  fileCountEl.textContent = intake.file_count == null ? "--" : String(intake.file_count);
  classCountEl.textContent = intake.class_file_count == null ? "--" : String(intake.class_file_count);

  renderCapabilitiesAssessment(verdict.capabilities_assessment);
  renderExtractedArtifacts(response.profile);

  currentEvidence = buildEvidenceItems(response);
  if (activeFilter !== "all" && !currentEvidence.some((item) => item.category === activeFilter)) {
    activeFilter = "all";
  }
  renderIndicatorFilters(currentEvidence);
  renderIndicators();

  resultsEl.hidden = false;
  setTimeout(() => {
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }, 50);
}

function renderCapabilitiesAssessment(assessment) {
  if (!assessment || Object.keys(assessment).length === 0) {
    capabilitiesBlock.hidden = true;
    return;
  }

  capabilitiesBlock.hidden = false;
  capabilitiesList.innerHTML = "";

  Object.entries(assessment).forEach(([capability, rationale]) => {
    const node = document.createElement("div");
    node.className = "capability-item";
    node.innerHTML =
      `<span class="capability-name">${escapeHtml(capability.replace(/_/g, " "))}</span>` +
      `<p class="capability-rationale">${escapeHtml(rationale)}</p>`;
    capabilitiesList.appendChild(node);
  });
}

function renderExtractedArtifacts(profile) {
  if (!profile) {
    artifactsBlock.hidden = true;
    return;
  }

  const sections = [];
  const caps = profile.capabilities || {};

  const allUrls = new Set();
  const allCommands = new Set();
  const allFilePaths = new Set();

  Object.values(caps).forEach((signal) => {
    if (!signal || !Array.isArray(signal.evidence)) return;
    signal.evidence.forEach((ev) => {
      if (/^https?:\/\//.test(ev)) allUrls.add(ev);
    });
  });

  if (Array.isArray(profile.reconstructed_strings)) {
    profile.reconstructed_strings.forEach((s) => {
      if (/^https?:\/\//.test(s)) allUrls.add(s);
    });
  }

  if (allUrls.size > 0) {
    sections.push({ title: "URLs", items: [...allUrls] });
  }
  if (allCommands.size > 0) {
    sections.push({ title: "Commands", items: [...allCommands] });
  }
  if (allFilePaths.size > 0) {
    sections.push({ title: "File paths", items: [...allFilePaths] });
  }

  if (Array.isArray(profile.suspicious_manifest_entries) && profile.suspicious_manifest_entries.length > 0) {
    sections.push({ title: "Suspicious manifest", items: profile.suspicious_manifest_entries });
  }

  if (Array.isArray(profile.reconstructed_strings) && profile.reconstructed_strings.length > 0) {
    const nonUrl = profile.reconstructed_strings.filter((s) => !/^https?:\/\//.test(s));
    if (nonUrl.length > 0) {
      sections.push({ title: "Hidden strings", items: nonUrl });
    }
  }

  if (sections.length === 0) {
    artifactsBlock.hidden = true;
    return;
  }

  artifactsBlock.hidden = false;
  artifactsGrid.innerHTML = "";

  sections.forEach((section) => {
    const node = document.createElement("div");
    node.className = "artifact-group";
    const itemsHtml = section.items
      .map((item) => `<li class="artifact-value mono">${escapeHtml(item)}</li>`)
      .join("");
    node.innerHTML =
      `<span class="artifact-label">${escapeHtml(section.title)}</span>` +
      `<ul class="artifact-list">${itemsHtml}</ul>`;
    artifactsGrid.appendChild(node);
  });
}

filtersEl.addEventListener("click", (event) => {
  const button = event.target.closest(".filter-btn");
  if (!button) return;
  activeFilter = button.dataset.cat || "all";
  renderIndicatorFilters(currentEvidence);
  renderIndicators();
});

dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
  const file = fileInput.files && fileInput.files[0];
  if (file) {
    fileNameEl.textContent = file.name;
    fileBadgeName.textContent = formatFileSize(file.size);
    dropZone.classList.add("has-file");
  } else {
    fileNameEl.textContent = "Choose .jar file or drag here";
    fileBadgeName.textContent = "";
    dropZone.classList.remove("has-file");
  }

  updateScanButtonState();
});

function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

dropZone.addEventListener("dragover", (event) => {
  event.preventDefault();
  dropZone.classList.add("drag-over");
});

dropZone.addEventListener("dragleave", () => {
  dropZone.classList.remove("drag-over");
});

dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  dropZone.classList.remove("drag-over");

  const file = event.dataTransfer.files && event.dataTransfer.files[0];
  if (!file || !file.name.toLowerCase().endsWith(".jar")) {
    setStatus("Only .jar files are accepted.", "error");
    return;
  }

  const transfer = new DataTransfer();
  transfer.items.add(file);
  fileInput.files = transfer.files;
  fileNameEl.textContent = file.name;
  fileBadgeName.textContent = formatFileSize(file.size);
  dropZone.classList.add("has-file");
  updateScanButtonState();
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const file = fileInput.files && fileInput.files[0];
  if (!file) {
    setStatus("Select a .jar file first.", "error");
    return;
  }

  setLoading(true);
  resultsEl.hidden = true;
  showPipelineSteps();

  try {
    // Step 1: Upload
    updatePipelineStep("upload", "running");
    setStatus("", "scanning");
    const upload = await uploadJar(file);
    updatePipelineStep("upload", "done", `upload_id: ${upload.upload_id.slice(0, 12)}…`);

    // Steps 2-4: Scan (server runs all 3 layers)
    updatePipelineStep("threat-intel", "running");
    updatePipelineStep("bytecode", "pending");
    updatePipelineStep("ai-verdict", "pending");

    const result = await runScan(upload.upload_id);

    // Stagger pipeline step transitions so the user sees each one resolve
    const delay = (ms) => new Promise((r) => setTimeout(r, ms));
    const method = (result.verdict && result.verdict.method) || "";

    if (method === "malwarebazaar_hash") {
      updatePipelineStep("threat-intel", "done", "Hash match found — MALICIOUS");
      await delay(350);
      updatePipelineStep("bytecode", "skip", "Short-circuited by hash match");
      await delay(250);
      updatePipelineStep("ai-verdict", "skip", "Short-circuited by hash match");
    } else {
      updatePipelineStep("threat-intel", "done", "No hash match");
      await delay(400);
      updatePipelineStep("bytecode", "running");
      await delay(500);
      updatePipelineStep("bytecode", "done", `${result.intake?.file_count || "?"} files, ${result.intake?.class_file_count || "?"} classes`);
      await delay(400);
      if (method.includes("ai_verdict")) {
        updatePipelineStep("ai-verdict", "running");
        await delay(500);
        updatePipelineStep("ai-verdict", "done", `Verdict: ${result.verdict?.result || "?"}`);
      } else if (method === "heuristic_fallback") {
        updatePipelineStep("ai-verdict", "skip", "AI unavailable — heuristic used");
      } else {
        updatePipelineStep("ai-verdict", "done");
      }
    }

    await delay(300);
    renderResult(result);
    setStatus("Scan complete.", "done");

    // Hide pipeline after a beat so the user sees the completed state
    setTimeout(() => hidePipelineSteps(), 1500);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unexpected error";
    setStatus(message, "error");
    hidePipelineSteps();
  } finally {
    setLoading(false);
  }
});


