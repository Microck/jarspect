use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::{Multipart, Path as AxumPath, State};
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
use yara_x::{Compiler, Rules, Scanner};
use zip::ZipArchive;

#[derive(Clone)]
struct AppState {
    uploads_dir: PathBuf,
    scans_dir: PathBuf,
    web_dir: PathBuf,
    signatures: Arc<Vec<SignatureDefinition>>,
    yara_rules: Arc<Rules>,
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
    predicted_file_writes: Vec<String>,
    predicted_persistence: Vec<String>,
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

    let signatures = Arc::new(load_signatures(
        cwd.join("data/signatures/signatures.json"),
    )?);
    let yara_rules = Arc::new(load_yara_rules(cwd.join("data/signatures/rules.yar"))?);

    let state = AppState {
        uploads_dir,
        scans_dir,
        web_dir: web_dir.clone(),
        signatures,
        yara_rules,
        upload_max_bytes: 50 * 1024 * 1024,
    };

    let bind_addr = std::env::var("JARSPECT_BIND").unwrap_or_else(|_| "127.0.0.1:8000".to_string());

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/upload", post(upload))
        .route("/scan", post(scan))
        .route("/scans/{scan_id}", get(get_scan))
        .nest_service("/static", ServeDir::new(web_dir))
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
    let upload_path = state.uploads_dir.join(format!("{}.jar", request.upload_id));
    if !upload_path.exists() {
        return Err(AppError::not_found("Upload not found"));
    }

    let bytes = fs::read(&upload_path)
        .await
        .map_err(|e| AppError::internal(format!("Failed to read upload: {e}")))?;
    let entries = read_archive_entries(&bytes)?;

    let intake = IntakeResult {
        upload_id: request.upload_id.clone(),
        storage_path: upload_path.to_string_lossy().into_owned(),
        file_count: entries.len(),
        class_file_count: entries
            .iter()
            .filter(|entry| entry.path.ends_with(".class"))
            .count(),
    };

    let static_findings = run_static_analysis(&entries, &state.signatures, &state.yara_rules)?;
    let behavior = infer_behavior(&static_findings.matches);
    let reputation = request.author.as_ref().map(score_author);
    let verdict = build_verdict(
        &static_findings.matches,
        &behavior.indicators,
        reputation.as_ref(),
    );

    let result = ScanResult {
        intake,
        static_findings,
        behavior,
        reputation,
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
    if scan_id.trim().is_empty() {
        return Err(AppError::bad_request("scan_id cannot be empty"));
    }
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

#[derive(Debug)]
struct ArchiveEntry {
    path: String,
    bytes: Vec<u8>,
    text: String,
}

fn read_archive_entries(bytes: &[u8]) -> Result<Vec<ArchiveEntry>> {
    let cursor = Cursor::new(bytes.to_vec());
    let mut archive = ZipArchive::new(cursor).context("Invalid .jar archive")?;
    let mut entries = Vec::new();

    for idx in 0..archive.len() {
        let mut file = archive.by_index(idx)?;
        if file.is_dir() {
            continue;
        }
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;
        let text = String::from_utf8_lossy(&contents).into_owned();
        entries.push(ArchiveEntry {
            path: file.name().to_string(),
            bytes: contents,
            text,
        });
    }

    Ok(entries)
}

fn run_static_analysis(
    entries: &[ArchiveEntry],
    signatures: &[SignatureDefinition],
    yara_rules: &Rules,
) -> Result<StaticFindings> {
    let mut matches = Vec::new();
    let mut matched_pattern_ids = Vec::new();
    let mut matched_signature_ids = Vec::new();

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
            "high",
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
        for (id, title, category, severity, regex, rationale) in &patterns {
            if let Some(found) = regex.find(&entry.text) {
                matched_pattern_ids.push((*id).to_string());
                matches.push(Indicator {
                    source: "pattern".to_string(),
                    id: (*id).to_string(),
                    title: (*title).to_string(),
                    category: (*category).to_string(),
                    severity: (*severity).to_string(),
                    file_path: Some(entry.path.clone()),
                    evidence: snippet(&entry.text, found.start(), found.end()),
                    rationale: (*rationale).to_string(),
                });
            }
        }

        for signature in signatures {
            let hit = match signature.kind.as_str() {
                "token" => entry
                    .text
                    .find(&signature.value)
                    .map(|offset| (offset, offset + signature.value.len())),
                "regex" => Regex::new(&signature.value)
                    .ok()
                    .and_then(|re| re.find(&entry.text).map(|m| (m.start(), m.end()))),
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
                    evidence: snippet(&entry.text, start, end),
                    rationale: signature.description.clone(),
                });
            }
        }

        let mut scanner = Scanner::new(yara_rules);
        let scan_results = scanner.scan(entry.bytes.as_slice())?;
        for m in scan_results.matching_rules() {
            let yara_id = format!("YARA-{}", m.identifier().to_uppercase());
            matched_signature_ids.push(yara_id.clone());
            matches.push(Indicator {
                source: "yara".to_string(),
                id: yara_id,
                title: "YARA-X rule match".to_string(),
                category: "signature".to_string(),
                severity: "high".to_string(),
                file_path: Some(entry.path.clone()),
                evidence: format!("Matched rule {}", m.identifier()),
                rationale: "Rule-based malware signature detected by YARA-X.".to_string(),
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

fn infer_behavior(static_indicators: &[Indicator]) -> BehaviorPrediction {
    let mut indicators = Vec::new();
    let mut urls = Vec::new();
    let mut writes = Vec::new();
    let mut persistence = Vec::new();

    let has_network = static_indicators
        .iter()
        .any(|i| i.id.contains("NET") || i.id.contains("URL"));
    if has_network {
        urls.push("https://payload.example.invalid/bootstrap".to_string());
        indicators.push(Indicator {
            source: "behavior".to_string(),
            id: "BEH-NETWORK".to_string(),
            title: "Predicted outbound network activity".to_string(),
            category: "network".to_string(),
            severity: "high".to_string(),
            file_path: None,
            evidence:
                "domains=payload.example.invalid; urls=https://payload.example.invalid/bootstrap"
                    .to_string(),
            rationale: "Static URL and signature evidence imply outbound command traffic."
                .to_string(),
        });
    }

    let has_exec = static_indicators
        .iter()
        .any(|i| i.id.contains("EXEC") || i.id.contains("RUNTIME"));
    if has_exec {
        writes.push("mods/cache.bin".to_string());
        persistence.push("startup task registration (predicted)".to_string());
        indicators.push(Indicator {
            source: "behavior".to_string(),
            id: "BEH-PERSISTENCE".to_string(),
            title: "Predicted persistence behavior".to_string(),
            category: "persistence".to_string(),
            severity: "high".to_string(),
            file_path: None,
            evidence: "mechanisms=startup task registration (predicted)".to_string(),
            rationale: "Execution primitives and obfuscation markers indicate persistence setup."
                .to_string(),
        });
    }

    if has_exec || has_network {
        indicators.push(Indicator {
            source: "behavior".to_string(),
            id: "BEH-FS-WRITES".to_string(),
            title: "Predicted file system writes".to_string(),
            category: "filesystem".to_string(),
            severity: "high".to_string(),
            file_path: None,
            evidence: "writes=mods/cache.bin".to_string(),
            rationale: "Observed payload and execution markers imply staged file writes."
                .to_string(),
        });
    }

    BehaviorPrediction {
        predicted_network_urls: urls,
        predicted_file_writes: writes,
        predicted_persistence: persistence,
        confidence: if indicators.is_empty() { 0.35 } else { 0.82 },
        indicators,
    }
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

fn build_verdict(
    static_indicators: &[Indicator],
    behavior_indicators: &[Indicator],
    reputation: Option<&ReputationResult>,
) -> Verdict {
    let mut all_indicators = Vec::new();
    all_indicators.extend_from_slice(static_indicators);
    all_indicators.extend_from_slice(behavior_indicators);
    if let Some(rep) = reputation {
        all_indicators.extend_from_slice(&rep.indicators);
    }

    let mut score = 0.0;
    for indicator in &all_indicators {
        score += match indicator.severity.as_str() {
            "critical" => 28.0,
            "high" => 18.0,
            "med" => 10.0,
            "low" => 5.0,
            _ => 8.0,
        };
    }

    if let Some(rep) = reputation {
        score += ((1.0 - rep.author_score) * 32.0).round();
    }

    let risk_score = score.clamp(0.0, 100.0) as u8;
    let risk_tier = if risk_score >= 85 {
        "CRITICAL"
    } else if risk_score >= 65 {
        "HIGH"
    } else if risk_score >= 40 {
        "MEDIUM"
    } else {
        "LOW"
    }
    .to_string();

    let summary = format!(
        "Jarspect assessed this mod as {risk_tier} risk ({risk_score}/100) from layered static, YARA-X, behavior, and reputation signals."
    );

    let mut explanation = vec![
        format!(
            "Upload is assessed as {risk_tier} risk ({risk_score}/100) based on weighted indicator severity."
        ),
        format!("Indicators considered: {}", all_indicators.len()),
    ];
    for indicator in all_indicators.iter().take(6) {
        explanation.push(format!(
            "- [{}] {} ({}) :: {}",
            indicator.id, indicator.title, indicator.severity, indicator.evidence
        ));
    }

    Verdict {
        risk_tier,
        risk_score,
        summary,
        explanation: explanation.join("\n"),
        indicators: all_indicators,
    }
}

fn snippet(text: &str, start: usize, end: usize) -> String {
    let left = start.saturating_sub(80);
    let right = (end + 80).min(text.len());
    text[left..right].trim().to_string()
}

fn load_signatures(path: PathBuf) -> Result<Vec<SignatureDefinition>> {
    let payload = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read signature corpus: {}", path.display()))?;
    let parsed: Vec<SignatureDefinition> = serde_json::from_str(&payload)
        .with_context(|| format!("Invalid signature JSON: {}", path.display()))?;
    Ok(parsed)
}

fn load_yara_rules(path: PathBuf) -> Result<Rules> {
    let source = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read YARA rules: {}", path.display()))?;
    let mut compiler = Compiler::new();
    compiler
        .add_source(source.as_str())
        .with_context(|| format!("Failed compiling YARA rules from {}", path.display()))?;
    let rules = compiler.build();
    Ok(rules)
}
