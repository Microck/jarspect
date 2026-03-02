use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{DefaultBodyLimit, Multipart, Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::fs;
use tower_http::services::ServeDir;
use tracing::info;
use uuid::Uuid;
use yara_x::Compiler;

mod analysis;
mod behavior;
mod detectors;
mod scoring;
pub use analysis::ArchiveEntry;

#[derive(Clone)]
struct AppState {
    uploads_dir: PathBuf,
    scans_dir: PathBuf,
    web_dir: PathBuf,
    signatures: Arc<Vec<SignatureDefinition>>,
    yara_rulepacks: Arc<Vec<analysis::YaraRulepack>>,
    upload_max_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct ScanRequest {
    upload_id: String,
    author: Option<AuthorMetadata>,
}

#[derive(Debug, Deserialize)]
struct AuthorMetadata {
    author_id: String,
    mod_id: Option<String>,
    account_age_days: Option<u32>,
    prior_mod_count: Option<u32>,
    report_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScanRunResponse {
    scan_id: String,
    result: ScanResult,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ScanResult {
    intake: IntakeResult,
    #[serde(rename = "static")]
    static_findings: StaticFindings,
    behavior: BehaviorPrediction,
    reputation: Option<ReputationResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    bytecode_evidence: Option<analysis::BytecodeEvidence>,
    verdict: Verdict,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IntakeResult {
    upload_id: String,
    storage_path: String,
    file_count: usize,
    class_file_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct StaticFindings {
    matches: Vec<Indicator>,
    counts_by_category: HashMap<String, usize>,
    counts_by_severity: HashMap<String, usize>,
    matched_pattern_ids: Vec<String>,
    matched_signature_ids: Vec<String>,
    analyzed_files: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct BehaviorPrediction {
    predicted_network_urls: Vec<String>,
    #[serde(default)]
    predicted_commands: Vec<String>,
    predicted_file_writes: Vec<String>,
    predicted_persistence: Vec<String>,
    #[serde(default)]
    predictions: Vec<behavior::PredictedBehavior>,
    confidence: f64,
    indicators: Vec<Indicator>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ReputationResult {
    author_id: String,
    author_score: f64,
    account_age_days: u32,
    prior_mod_count: u32,
    report_count: u32,
    indicators: Vec<Indicator>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Verdict {
    risk_tier: String,
    risk_score: u8,
    summary: String,
    explanation: String,
    indicators: Vec<Indicator>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Indicator {
    source: String,
    id: String,
    title: String,
    category: String,
    severity: String,
    file_path: Option<String>,
    evidence: String,
    rationale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence_locations: Option<Vec<analysis::Location>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extracted_urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extracted_commands: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    extracted_file_paths: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
struct SignatureDefinition {
    id: String,
    kind: String,
    value: String,
    severity: String,
    description: String,
}

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let payload = Json(serde_json::json!({ "detail": self.message }));
        (self.status, payload).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::internal(error.to_string())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "jarspect=info,tower_http=info".into()),
        )
        .init();

    let cwd = std::env::current_dir()?;
    let uploads_dir = cwd.join(".local-data/uploads");
    let scans_dir = cwd.join(".local-data/scans");
    let web_dir = cwd.join("web");

    fs::create_dir_all(&uploads_dir).await?;
    fs::create_dir_all(&scans_dir).await?;

    let active_rulepacks = parse_active_rulepacks()?;
    let signatures = Arc::new(load_signatures(cwd.as_path(), &active_rulepacks)?);
    let yara_rulepacks = Arc::new(load_yara_rulepacks(cwd.as_path(), &active_rulepacks)?);
    let rulepack_names = active_rulepacks
        .iter()
        .map(|pack| pack.as_str())
        .collect::<Vec<_>>();
    info!(rulepacks = ?rulepack_names, "loaded signature and YARA rulepacks");

    let state = AppState {
        uploads_dir,
        scans_dir,
        web_dir: web_dir.clone(),
        signatures,
        yara_rulepacks,
        upload_max_bytes: 50 * 1024 * 1024,
    };

    let bind_addr =
        std::env::var("JARSPECT_BIND").unwrap_or_else(|_| "127.0.0.1:18000".to_string());

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/upload", post(upload))
        .route("/scan", post(scan))
        .route("/scans/{scan_id}", get(get_scan))
        .nest_service("/static", ServeDir::new(web_dir))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("jarspect listening on http://{bind_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let index_path = state.web_dir.join("index.html");
    let content = fs::read_to_string(&index_path)
        .await
        .map_err(|_| AppError::not_found("Missing web/index.html"))?;
    Ok(Html(content))
}

async fn health() -> Json<Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "jarspect",
        "version": "0.1.0"
    }))
}

async fn upload(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let mut filename = None;
    let mut bytes = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(format!("Invalid multipart payload: {e}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        filename = field.file_name().map(ToString::to_string);
        let data = field
            .bytes()
            .await
            .map_err(|e| AppError::bad_request(format!("Failed to read upload: {e}")))?;
        if data.len() > state.upload_max_bytes {
            return Err(AppError::bad_request("Uploaded file exceeds max size"));
        }
        bytes = Some(data.to_vec());
        break;
    }

    let filename = filename.ok_or_else(|| AppError::bad_request("Missing upload file"))?;
    if !filename.to_lowercase().ends_with(".jar") {
        return Err(AppError::bad_request("Only .jar files are supported"));
    }
    let content = bytes.ok_or_else(|| AppError::bad_request("Missing upload file bytes"))?;

    let upload_id = Uuid::new_v4().simple().to_string();
    let output_path = state.uploads_dir.join(format!("{upload_id}.jar"));
    fs::write(&output_path, &content)
        .await
        .map_err(|e| AppError::internal(format!("Failed to persist upload: {e}")))?;

    Ok(Json(serde_json::json!({
        "upload_id": upload_id,
        "filename": filename,
        "size_bytes": content.len(),
        "storage_url": output_path.to_string_lossy(),
    })))
}

async fn scan(
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanRunResponse>, AppError> {
    validate_artifact_id(&request.upload_id)?;
    let upload_path = state.uploads_dir.join(format!("{}.jar", request.upload_id));
    if !upload_path.exists() {
        return Err(AppError::not_found("Upload not found"));
    }

    let bytes = fs::read(&upload_path)
        .await
        .map_err(|e| AppError::internal(format!("Failed to read upload: {e}")))?;
    let root_label = format!("{}.jar", request.upload_id);
    let entries = analysis::read_archive_entries_recursive(root_label.as_str(), &bytes)?;

    let intake = IntakeResult {
        upload_id: request.upload_id.clone(),
        storage_path: upload_path.to_string_lossy().into_owned(),
        file_count: entries.len(),
        class_file_count: entries
            .iter()
            .filter(|entry| entry.path.ends_with(".class"))
            .count(),
    };

    let bytecode_evidence = Some(analysis::extract_bytecode_evidence(&entries));
    let static_findings = run_static_analysis(
        &entries,
        bytecode_evidence.as_ref(),
        &state.signatures,
        &state.yara_rulepacks,
    )?;
    let derived_behavior = behavior::derive_behavior(&static_findings.matches);
    let behavior = BehaviorPrediction {
        predicted_network_urls: derived_behavior.predicted_network_urls,
        predicted_commands: derived_behavior.predicted_commands,
        predicted_file_writes: derived_behavior.predicted_file_writes,
        predicted_persistence: derived_behavior.predicted_persistence,
        predictions: derived_behavior.predictions,
        confidence: derived_behavior.confidence,
        indicators: vec![],
    };
    let reputation = request.author.as_ref().map(score_author);
    let verdict = build_verdict(&static_findings.matches, reputation.as_ref());

    let result = ScanResult {
        intake,
        static_findings,
        behavior,
        reputation,
        bytecode_evidence,
        verdict,
    };

    let scan_id = Uuid::new_v4().simple().to_string();
    let scan_payload = ScanRunResponse {
        scan_id: scan_id.clone(),
        result,
    };

    let path = state.scans_dir.join(format!("{scan_id}.json"));
    let payload_bytes = serde_json::to_vec_pretty(&scan_payload)
        .map_err(|e| AppError::internal(format!("Failed to serialize scan result: {e}")))?;
    fs::write(path, payload_bytes)
        .await
        .map_err(|e| AppError::internal(format!("Failed to persist scan result: {e}")))?;

    Ok(Json(scan_payload))
}

async fn get_scan(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<String>,
) -> Result<Json<ScanRunResponse>, AppError> {
    validate_artifact_id(&scan_id)?;
    let path = state.scans_dir.join(format!("{scan_id}.json"));
    if !path.exists() {
        return Err(AppError::not_found("Scan not found"));
    }
    let data = fs::read_to_string(path)
        .await
        .map_err(|e| AppError::internal(format!("Failed to read scan result: {e}")))?;
    let payload: ScanRunResponse = serde_json::from_str(&data)
        .map_err(|e| AppError::internal(format!("Corrupted scan payload: {e}")))?;
    Ok(Json(payload))
}

fn run_static_analysis(
    entries: &[ArchiveEntry],
    bytecode_evidence: Option<&analysis::BytecodeEvidence>,
    signatures: &[SignatureDefinition],
    yara_rulepacks: &[analysis::YaraRulepack],
) -> Result<StaticFindings> {
    let mut matches = Vec::new();
    let mut matched_pattern_ids = Vec::new();
    let mut matched_signature_ids = Vec::new();

    let metadata_findings: Vec<analysis::MetadataFinding> = analysis::analyze_metadata(entries);
    for finding in metadata_findings {
        matches.push(Indicator {
            source: "metadata".to_string(),
            id: finding.id,
            title: finding.title,
            category: "metadata".to_string(),
            severity: finding.severity,
            file_path: Some(finding.file_path),
            evidence: finding.evidence,
            rationale: finding.rationale,
            evidence_locations: None,
            extracted_urls: None,
            extracted_commands: None,
            extracted_file_paths: None,
        });
    }

    let patterns = [
        (
            "EXEC-RUNTIME",
            "Runtime process execution",
            "execution",
            "high",
            Regex::new(r"Runtime\.getRuntime\(\)\.exec").unwrap(),
            "Detected process execution primitive commonly used in malware droppers.",
        ),
        (
            "NET-URL",
            "Outbound URL pattern",
            "network",
            "low",
            Regex::new(r"https?://[A-Za-z0-9._/-]+\.[A-Za-z]{2,}").unwrap(),
            "Found hardcoded network URL in archive payload.",
        ),
        (
            "OBF-BASE64",
            "Long base64 blob",
            "obfuscation",
            "med",
            Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}").unwrap(),
            "Found long base64-like payload that can hide staged commands.",
        ),
        (
            "REFLECTIVE-LOAD",
            "Reflection usage",
            "obfuscation",
            "med",
            Regex::new(r"Class\.forName").unwrap(),
            "Found reflective class loading token.",
        ),
    ];

    for entry in entries {
        let entry_text = entry.text.as_deref().unwrap_or("");

        for (id, title, category, severity, regex, rationale) in &patterns {
            if let Some(found) = regex.find(entry_text) {
                matched_pattern_ids.push((*id).to_string());
                matches.push(Indicator {
                    source: "pattern".to_string(),
                    id: (*id).to_string(),
                    title: (*title).to_string(),
                    category: (*category).to_string(),
                    severity: (*severity).to_string(),
                    file_path: Some(entry.path.clone()),
                    evidence: snippet(entry_text, found.start(), found.end()),
                    rationale: (*rationale).to_string(),
                    evidence_locations: None,
                    extracted_urls: None,
                    extracted_commands: None,
                    extracted_file_paths: None,
                });
            }
        }

        for signature in signatures {
            let hit = match signature.kind.as_str() {
                "token" => entry_text
                    .find(&signature.value)
                    .map(|offset| (offset, offset + signature.value.len())),
                "regex" => Regex::new(&signature.value)
                    .ok()
                    .and_then(|re| re.find(entry_text).map(|m| (m.start(), m.end()))),
                _ => None,
            };

            if let Some((start, end)) = hit {
                matched_signature_ids.push(signature.id.clone());
                matches.push(Indicator {
                    source: "signature".to_string(),
                    id: signature.id.clone(),
                    title: "Known suspicious signature".to_string(),
                    category: "signature".to_string(),
                    severity: signature.severity.clone(),
                    file_path: Some(entry.path.clone()),
                    evidence: snippet(entry_text, start, end),
                    rationale: signature.description.clone(),
                    evidence_locations: None,
                    extracted_urls: None,
                    extracted_commands: None,
                    extracted_file_paths: None,
                });
            }
        }
    }

    for (entry_path, finding) in analysis::scan_yara_rulepacks(entries, yara_rulepacks)? {
        let yara_id = format!(
            "YARA-{}-{}",
            finding.pack.indicator_prefix(),
            finding.rule_identifier.to_ascii_uppercase()
        );
        matched_signature_ids.push(yara_id.clone());
        matches.push(Indicator {
            source: "yara".to_string(),
            id: yara_id,
            title: "YARA-X rule match".to_string(),
            category: "signature".to_string(),
            severity: finding.severity,
            file_path: Some(entry_path),
            evidence: finding.evidence,
            rationale: format!(
                "Rule-based malware signature detected by YARA-X {} rulepack.",
                finding.pack.as_str()
            ),
            evidence_locations: None,
            extracted_urls: None,
            extracted_commands: None,
            extracted_file_paths: None,
        });
    }

    if let Some(bytecode_evidence) = bytecode_evidence {
        for finding in detectors::run_capability_detectors(bytecode_evidence, entries) {
            let evidence = detector_evidence_summary(&finding);
            let file_path = finding
                .evidence_locations
                .first()
                .map(|location| location.entry_path.clone());

            matches.push(Indicator {
                source: "detector".to_string(),
                id: finding.id,
                title: finding.title,
                category: finding.category,
                severity: finding.severity,
                file_path,
                evidence,
                rationale: finding.rationale,
                evidence_locations: Some(finding.evidence_locations),
                extracted_urls: to_optional_vec(finding.extracted_urls),
                extracted_commands: to_optional_vec(finding.extracted_commands),
                extracted_file_paths: to_optional_vec(finding.extracted_file_paths),
            });
        }
    }

    matched_pattern_ids.sort();
    matched_pattern_ids.dedup();
    matched_signature_ids.sort();
    matched_signature_ids.dedup();

    let mut counts_by_category: HashMap<String, usize> = HashMap::new();
    let mut counts_by_severity: HashMap<String, usize> = HashMap::new();
    for indicator in &matches {
        *counts_by_category
            .entry(indicator.category.clone())
            .or_insert(0) += 1;
        *counts_by_severity
            .entry(indicator.severity.clone())
            .or_insert(0) += 1;
    }

    Ok(StaticFindings {
        matches,
        counts_by_category,
        counts_by_severity,
        matched_pattern_ids,
        matched_signature_ids,
        analyzed_files: entries.len(),
    })
}

fn score_author(author: &AuthorMetadata) -> ReputationResult {
    let age = author.account_age_days.unwrap_or(14);
    let prior_mods = author.prior_mod_count.unwrap_or(1);
    let reports = author.report_count.unwrap_or(0);
    let mod_id = author
        .mod_id
        .clone()
        .unwrap_or_else(|| "unknown-mod".to_string());

    let age_component = (age as f64 / 365.0).min(1.0) * 0.4;
    let output_component = (prior_mods as f64 / 20.0).min(1.0) * 0.3;
    let report_penalty = (reports as f64 / 10.0).min(1.0) * 0.5;
    let score = (age_component + output_component - report_penalty).clamp(0.0, 1.0);

    let mut indicators = Vec::new();
    if score < 0.35 {
        indicators.push(Indicator {
            source: "reputation".to_string(),
            id: "REP-AUTHOR-TRUST".to_string(),
            title: "Author trust score".to_string(),
            category: "reputation".to_string(),
            severity: "critical".to_string(),
            file_path: None,
            evidence: format!(
                "author_score={score:.3}; account_age_days={age}; prior_mod_count={prior_mods}; report_count={reports}; mod_id={mod_id}"
            ),
            rationale: "Low-author-history profile with report activity increases risk.".to_string(),
            evidence_locations: None,
            extracted_urls: None,
            extracted_commands: None,
            extracted_file_paths: None,
        });
    }

    ReputationResult {
        author_id: author.author_id.clone(),
        author_score: score,
        account_age_days: age,
        prior_mod_count: prior_mods,
        report_count: reports,
        indicators,
    }
}

fn build_verdict(static_indicators: &[Indicator], reputation: Option<&ReputationResult>) -> Verdict {
    let scored = scoring::score_static_indicators(static_indicators, reputation);

    let mut verdict_indicators = static_indicators.to_vec();
    if let Some(rep) = reputation {
        verdict_indicators.extend_from_slice(&rep.indicators);
    }

    let reputation_fragment = if reputation.is_some() {
        " and reputation"
    } else {
        ""
    };
    let summary = format!(
        "Jarspect assessed this mod as {} risk ({}/100) from static capability{} evidence.",
        scored.risk_tier, scored.risk_score, reputation_fragment
    );

    Verdict {
        risk_tier: scored.risk_tier,
        risk_score: scored.risk_score as u8,
        summary,
        explanation: scored.explanation.join("\n"),
        indicators: verdict_indicators,
    }
}

fn snippet(text: &str, start: usize, end: usize) -> String {
    let left = start.saturating_sub(80);
    let right = (end + 80).min(text.len());
    text[left..right].trim().to_string()
}

fn to_optional_vec(values: Vec<String>) -> Option<Vec<String>> {
    if values.is_empty() {
        None
    } else {
        Some(values)
    }
}

fn detector_evidence_summary(finding: &detectors::DetectorFinding) -> String {
    let mut details = vec![format!("callsites={}", finding.evidence_locations.len())];
    if !finding.extracted_urls.is_empty() {
        details.push(format!("urls={}", finding.extracted_urls.len()));
    }
    if !finding.extracted_commands.is_empty() {
        details.push(format!("commands={}", finding.extracted_commands.len()));
    }
    if !finding.extracted_file_paths.is_empty() {
        details.push(format!("paths={}", finding.extracted_file_paths.len()));
    }

    format!("{} [{}]", finding.id, details.join(", "))
}

fn parse_active_rulepacks() -> Result<Vec<analysis::RulepackKind>> {
    let raw_value = std::env::var("JARSPECT_RULEPACKS").unwrap_or_else(|_| "demo".to_string());
    let mut packs = Vec::new();

    for token in raw_value.split(',') {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }

        if let Some(pack) = analysis::RulepackKind::from_token(normalized.as_str()) {
            if !packs.contains(&pack) {
                packs.push(pack);
            }
        } else {
            anyhow::bail!(
                "Invalid JARSPECT_RULEPACKS value '{normalized}'. Expected demo, prod, or demo,prod"
            )
        }
    }

    if packs.is_empty() {
        anyhow::bail!("JARSPECT_RULEPACKS must include at least one pack: demo or prod")
    }

    Ok(packs)
}

fn signatures_path_for_pack(cwd: &Path, pack: &str) -> PathBuf {
    cwd.join("data/signatures")
        .join(pack)
        .join("signatures.json")
}

fn yara_path_for_pack(cwd: &Path, pack: &str) -> PathBuf {
    cwd.join("data/signatures").join(pack).join("rules.yar")
}

fn load_signatures(
    cwd: &Path,
    packs: &[analysis::RulepackKind],
) -> Result<Vec<SignatureDefinition>> {
    let mut signatures = Vec::new();

    for pack in packs {
        let path = signatures_path_for_pack(cwd, pack.as_str());
        let payload = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read signature corpus: {}", path.display()))?;
        let mut parsed: Vec<SignatureDefinition> = serde_json::from_str(&payload)
            .with_context(|| format!("Invalid signature JSON: {}", path.display()))?;
        signatures.append(&mut parsed);
    }

    Ok(signatures)
}

fn load_yara_rulepacks(
    cwd: &Path,
    packs: &[analysis::RulepackKind],
) -> Result<Vec<analysis::YaraRulepack>> {
    let mut loaded_rulepacks = Vec::new();

    for pack in packs {
        let path = yara_path_for_pack(cwd, pack.as_str());
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read YARA rules: {}", path.display()))?;
        let mut compiler = Compiler::new();
        compiler
            .add_source(source.as_str())
            .with_context(|| format!("Failed compiling YARA rules from {}", path.display()))?;
        loaded_rulepacks.push(analysis::YaraRulepack {
            kind: *pack,
            rules: compiler.build(),
        });
    }

    Ok(loaded_rulepacks)
}

fn validate_artifact_id(value: &str) -> Result<(), AppError> {
    if value.len() != 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(AppError::bad_request(
            "Invalid identifier format (expected 32 hex chars)",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn base_scan_result_json() -> serde_json::Value {
        json!({
            "intake": {
                "upload_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "storage_path": ".local-data/uploads/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.jar",
                "file_count": 2,
                "class_file_count": 1
            },
            "static": {
                "matches": [],
                "counts_by_category": {},
                "counts_by_severity": {},
                "matched_pattern_ids": [],
                "matched_signature_ids": [],
                "analyzed_files": 2
            },
            "behavior": {
                "predicted_network_urls": [],
                "predicted_commands": [],
                "predicted_file_writes": [],
                "predicted_persistence": [],
                "predictions": [],
                "confidence": 0.42,
                "indicators": []
            },
            "reputation": null,
            "verdict": {
                "risk_tier": "LOW",
                "risk_score": 7,
                "summary": "safe-ish",
                "explanation": "explanation",
                "indicators": []
            }
        })
    }

    #[test]
    fn scan_run_response_deserializes_with_bytecode_evidence() {
        let mut payload = json!({
            "scan_id": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "result": base_scan_result_json()
        });

        payload["result"]["bytecode_evidence"] = json!({
            "items": [
                {
                    "kind": "cp_utf8",
                    "value": "java/lang/String",
                    "location": {
                        "entry_path": "com/example/Agent.class",
                        "class_name": "com/example/Agent",
                        "method": {
                            "name": "run",
                            "descriptor": "()V"
                        },
                        "pc": null
                    }
                }
            ]
        });

        let serialized = serde_json::to_string(&payload).expect("failed to serialize test payload");
        let parsed = serde_json::from_str::<ScanRunResponse>(&serialized)
            .expect("expected payload with bytecode_evidence to deserialize");

        let evidence = parsed
            .result
            .bytecode_evidence
            .expect("expected bytecode_evidence to be present");
        assert_eq!(evidence.items.len(), 1);

        let analysis::BytecodeEvidenceItem::CpUtf8 { location, .. } = &evidence.items[0] else {
            panic!("expected cp_utf8 variant")
        };
        let method = location.method.as_ref().expect("expected method metadata");
        assert_eq!(method.name, "run");
        assert_eq!(method.descriptor, "()V");
    }

    #[test]
    fn scan_run_response_deserializes_without_bytecode_evidence() {
        let payload = json!({
            "scan_id": "cccccccccccccccccccccccccccccccc",
            "result": base_scan_result_json()
        });

        let serialized = serde_json::to_string(&payload).expect("failed to serialize test payload");
        let parsed = serde_json::from_str::<ScanRunResponse>(&serialized)
            .expect("expected payload without bytecode_evidence to deserialize");

        assert!(parsed.result.bytecode_evidence.is_none());
    }

    #[test]
    fn verdict_ignores_behavior_prediction_outputs() {
        let static_indicators = vec![Indicator {
            source: "detector".to_string(),
            id: "DETC-02.NETWORK_IO".to_string(),
            title: "Network primitive".to_string(),
            category: "capability".to_string(),
            severity: "high".to_string(),
            file_path: Some("DemoMod.class".to_string()),
            evidence: "URLConnection.connect".to_string(),
            rationale: "Outbound networking primitive detected.".to_string(),
            evidence_locations: None,
            extracted_urls: Some(vec!["https://example.com/c2".to_string()]),
            extracted_commands: None,
            extracted_file_paths: None,
        }];

        let empty_behavior = BehaviorPrediction {
            predicted_network_urls: vec![],
            predicted_commands: vec![],
            predicted_file_writes: vec![],
            predicted_persistence: vec![],
            predictions: vec![],
            confidence: 0.0,
            indicators: vec![],
        };
        let populated_behavior = BehaviorPrediction {
            predicted_network_urls: vec!["https://evil.example/c2".to_string()],
            predicted_commands: vec!["powershell -enc AAAA".to_string()],
            predicted_file_writes: vec!["mods/cache.bin".to_string()],
            predicted_persistence: vec!["schtasks".to_string()],
            predictions: vec![behavior::PredictedBehavior {
                kind: "network_url".to_string(),
                value: "https://evil.example/c2".to_string(),
                confidence: 0.9,
                supporting_indicator_ids: vec!["DETC-02.NETWORK_IO".to_string()],
                rationale: "Derived from extracted indicator fields; supporting indicators: DETC-02.NETWORK_IO."
                    .to_string(),
            }],
            confidence: 0.9,
            indicators: vec![],
        };

        assert_ne!(
            empty_behavior.predicted_network_urls,
            populated_behavior.predicted_network_urls
        );

        let score_for_context = |behavior_prediction: &BehaviorPrediction| {
            let _ = behavior_prediction;
            build_verdict(&static_indicators, None).risk_score
        };

        assert_eq!(
            score_for_context(&empty_behavior),
            score_for_context(&populated_behavior)
        );
    }
}
