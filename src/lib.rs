use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};
use yara_x::Compiler;

pub mod analysis;
pub mod detectors;
pub mod malwarebazaar;
pub mod profile;
pub mod scan;
pub mod verdict;

pub use analysis::ArchiveEntry;

#[derive(Clone)]
pub struct AppState {
    pub uploads_dir: PathBuf,
    pub scans_dir: PathBuf,
    pub web_dir: PathBuf,
    pub signatures: Arc<Vec<SignatureDefinition>>,
    pub yara_rulepacks: Arc<Vec<analysis::YaraRulepack>>,
    pub upload_max_bytes: usize,
    pub malwarebazaar_api_key: Option<String>,
    pub ai_config: Option<verdict::AiConfig>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ScanRequest {
    pub upload_id: String,
    #[serde(default)]
    pub author: Option<AuthorMetadata>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthorMetadata {
    pub author_id: String,
    pub mod_id: Option<String>,
    pub account_age_days: Option<u32>,
    pub prior_mod_count: Option<u32>,
    pub report_count: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ScanRunResponse {
    pub scan_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub verdict: Verdict,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub malwarebazaar: Option<malwarebazaar::MalwareBazaarResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_findings: Option<StaticFindings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<BTreeMap<String, profile::CapabilitySignal>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub yara_hits: Option<Vec<profile::YaraHit>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<profile::ModMetadata>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<profile::CapabilityProfile>,
    pub intake: IntakeResult,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct IntakeResult {
    pub upload_id: String,
    pub storage_path: String,
    pub file_count: usize,
    pub class_file_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Verdict {
    pub result: String,
    pub confidence: f64,
    pub risk_score: u8,
    pub method: String,
    pub explanation: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities_assessment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StaticFindings {
    pub matches: Vec<Indicator>,
    pub counts_by_category: HashMap<String, usize>,
    pub counts_by_severity: HashMap<String, usize>,
    pub matched_pattern_ids: Vec<String>,
    pub matched_signature_ids: Vec<String>,
    pub analyzed_files: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Indicator {
    pub source: String,
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub file_path: Option<String>,
    pub evidence: String,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_locations: Option<Vec<analysis::Location>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_urls: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_commands: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extracted_file_paths: Option<Vec<String>>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SignatureDefinition {
    id: String,
    kind: String,
    value: String,
    severity: String,
    description: String,
}

pub async fn run_scan(
    state: &AppState,
    request: ScanRequest,
    scan_id_override: Option<&str>,
) -> Result<ScanRunResponse> {
    scan::run_scan(state, request, scan_id_override).await
}

pub fn run_static_analysis(
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
            Regex::new(r"Runtime\.getRuntime\(\)\.exec").expect("valid regex"),
            "Detected process execution primitive commonly used in malware droppers.",
        ),
        (
            "NET-URL",
            "Outbound URL pattern",
            "network",
            "low",
            Regex::new(r"https?://[A-Za-z0-9._/-]+\.[A-Za-z]{2,}").expect("valid regex"),
            "Found hardcoded network URL in archive payload.",
        ),
        (
            "NET-DISCORD-WEBHOOK",
            "Discord webhook endpoint",
            "network",
            "high",
            Regex::new(
                r"(?i)https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
            )
            .expect("valid regex"),
            "Found a Discord webhook URL. Embedded webhooks are commonly used for exfiltration.",
        ),
        (
            "NET-PASTEBIN-RAW",
            "Pastebin raw endpoint",
            "network",
            "med",
            Regex::new(r"(?i)https?://(?:www\.)?pastebin\.com/(?:raw/|raw\.php\?i=)[A-Za-z0-9]+").expect("valid regex"),
            "Found a Pastebin raw URL, often used for staged payload delivery.",
        ),
        (
            "NET-RAW-GITHUB",
            "Raw GitHub content endpoint",
            "network",
            "med",
            Regex::new(r#"(?i)https?://raw\.githubusercontent\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/[^\s\"'<>]+"#)
                .expect("valid regex"),
            "Found a raw.githubusercontent.com URL, commonly used for staged payload hosting.",
        ),
        (
            "OBF-BASE64",
            "Long base64 blob",
            "obfuscation",
            "med",
            Regex::new(r"[A-Za-z0-9+/]{100,}={0,2}").expect("valid regex"),
            "Found long base64-like payload that can hide staged commands.",
        ),
        (
            "REFLECTIVE-LOAD",
            "Reflection usage",
            "obfuscation",
            "med",
            Regex::new(r"Class\.forName").expect("valid regex"),
            "Found reflective class loading token.",
        ),
    ];

    for entry in entries {
        let entry_text = entry.text.as_deref().unwrap_or("");

        for (id, title, category, severity, regex, rationale) in &patterns {
            if let Some(found) = regex.find(entry_text) {
                matched_pattern_ids.push((*id).to_string());

                let evidence = snippet(entry_text, found.start(), found.end());
                let extracted_urls = match *id {
                    "NET-DISCORD-WEBHOOK" | "NET-PASTEBIN-RAW" | "NET-RAW-GITHUB" => {
                        detectors::spec::extract_urls(std::iter::once(evidence.as_str()))
                    }
                    _ => Vec::new(),
                };
                matches.push(Indicator {
                    source: "pattern".to_string(),
                    id: (*id).to_string(),
                    title: (*title).to_string(),
                    category: (*category).to_string(),
                    severity: (*severity).to_string(),
                    file_path: Some(entry.path.clone()),
                    evidence,
                    rationale: (*rationale).to_string(),
                    evidence_locations: None,
                    extracted_urls: to_optional_vec(extracted_urls),
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

fn snippet(text: &str, start: usize, end: usize) -> String {
    let mut left = start.saturating_sub(80).min(text.len());
    while left > 0 && !text.is_char_boundary(left) {
        left -= 1;
    }

    let mut right = end.saturating_add(80).min(text.len());
    while right < text.len() && !text.is_char_boundary(right) {
        right += 1;
    }

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

pub fn parse_active_rulepacks() -> Result<Vec<analysis::RulepackKind>> {
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

pub fn load_signatures(
    cwd: &Path,
    packs: &[analysis::RulepackKind],
) -> Result<Vec<SignatureDefinition>> {
    let mut signatures = Vec::new();

    for pack in packs {
        let path = signatures_path_for_pack(cwd, pack.as_str());
        debug!(path = %path.display(), pack = %pack.as_str(), "loading signature corpus");
        let payload = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read signature corpus: {}", path.display()))?;
        let mut parsed: Vec<SignatureDefinition> = serde_json::from_str(&payload)
            .with_context(|| format!("Invalid signature JSON: {}", path.display()))?;
        let count = parsed.len();
        signatures.append(&mut parsed);
        info!(pack = %pack.as_str(), count, "loaded signature corpus");
    }

    info!(total_signatures = signatures.len(), "signature loading complete");
    Ok(signatures)
}

pub fn load_yara_rules(
    cwd: &Path,
    packs: &[analysis::RulepackKind],
) -> Result<Vec<analysis::YaraRulepack>> {
    let mut loaded_rulepacks = Vec::new();

    for pack in packs {
        let path = yara_path_for_pack(cwd, pack.as_str());
        debug!(path = %path.display(), pack = %pack.as_str(), "loading YARA rules");
        let source = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read YARA rules: {}", path.display()))?;
        let mut compiler = Compiler::new();
        compiler
            .add_source(source.as_str())
            .with_context(|| format!("Failed compiling YARA rules from {}", path.display()))?;
        let rules = compiler.build();
        let rule_count = rules.iter().count();
        loaded_rulepacks.push(analysis::YaraRulepack {
            kind: *pack,
            rules,
        });
        info!(pack = %pack.as_str(), rule_count, "compiled YARA rules");
    }

    info!(
        total_rulepacks = loaded_rulepacks.len(),
        "YARA rule loading complete"
    );
    Ok(loaded_rulepacks)
}

pub fn validate_artifact_id(value: &str) -> Result<()> {
    if value.len() != 32 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!("Invalid identifier format (expected 32 hex chars)")
    }

    Ok(())
}
