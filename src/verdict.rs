use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::time::sleep;
use url::Url;

use crate::StaticFindings;
use crate::profile::CapabilityProfile;

#[derive(Debug, Clone)]
pub struct AiConfig {
    pub endpoint: String,
    pub api_key: String,
    pub deployment: Option<String>,
    pub api_version: String,
    pub model: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiVerdict {
    pub result: String,
    pub confidence: f64,
    pub risk_score: u8,
    pub explanation: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub capabilities_assessment: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct AiVerdictResponse {
    verdict: Option<String>,
    confidence: Option<f64>,
    risk_score: Option<u8>,
    explanation: Option<String>,
    #[serde(default)]
    capabilities_assessment: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
struct AiProfileSummary {
    mod_metadata: AiModMetadata,
    jar_size_bytes: usize,
    class_count: usize,
    capabilities: BTreeMap<String, AiCapabilitySignal>,
    yara_hits: Vec<AiYaraHit>,
    suspicious_manifest_entries: Vec<String>,
    suspicious_strings: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extracted_urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extracted_domains: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extracted_commands: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    extracted_file_paths: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    matched_patterns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    matched_signatures: Vec<String>,
    low_signal_indicator_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    low_signal_indicators: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AiModMetadata {
    loader: Option<String>,
    mod_id: Option<String>,
    name: Option<String>,
    version: Option<String>,
    authors: Vec<String>,
    entrypoints: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AiCapabilitySignal {
    present: bool,
    evidence: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AiYaraHit {
    id: String,
    severity: String,
    file_path: Option<String>,
    evidence: String,
}

fn build_ai_profile_summary(profile: &CapabilityProfile, static_findings: &StaticFindings) -> AiProfileSummary {
    let extracted = collect_extracted_artifacts(static_findings);

    let matched_patterns = collect_match_ids(static_findings, "pattern", 12);
    let matched_signatures = collect_match_ids(static_findings, "signature", 12);

    let mod_metadata = AiModMetadata {
        loader: profile.mod_metadata.loader.clone(),
        mod_id: profile.mod_metadata.mod_id.clone(),
        name: profile.mod_metadata.name.clone(),
        version: profile.mod_metadata.version.clone(),
        authors: limit_and_truncate(&profile.mod_metadata.authors, 5, 120),
        entrypoints: limit_and_truncate(&profile.mod_metadata.entrypoints, 5, 140),
    };

    let capabilities = profile
        .capabilities
        .iter()
        .map(|(key, signal)| {
            (
                key.clone(),
                AiCapabilitySignal {
                    present: signal.present,
                    evidence: limit_and_truncate(&signal.evidence, 2, 180),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();

    let yara_hits = profile
        .yara_hits
        .iter()
        .take(5)
        .map(|hit| AiYaraHit {
            id: hit.id.clone(),
            severity: hit.severity.clone(),
            file_path: hit.file_path.clone(),
            evidence: truncate_string(hit.evidence.as_str(), 180),
        })
        .collect::<Vec<_>>();

    let suspicious_manifest_entries =
        limit_and_truncate(&profile.suspicious_manifest_entries, 5, 180);
    let suspicious_strings = collect_suspicious_strings(&profile.reconstructed_strings, 10);
    let low_signal_indicators = limit_and_truncate(&profile.low_signal_indicators, 10, 220);

    AiProfileSummary {
        mod_metadata,
        jar_size_bytes: profile.jar_size_bytes,
        class_count: profile.class_count,
        capabilities,
        yara_hits,
        suspicious_manifest_entries,
        suspicious_strings,
        extracted_urls: extracted.urls,
        extracted_domains: extracted.domains,
        extracted_commands: extracted.commands,
        extracted_file_paths: extracted.file_paths,
        matched_patterns,
        matched_signatures,
        low_signal_indicator_count: profile.low_signal_indicators.len(),
        low_signal_indicators,
    }
}

fn collect_match_ids(static_findings: &StaticFindings, source: &str, limit: usize) -> Vec<String> {
    let mut ids = static_findings
        .matches
        .iter()
        .filter(|indicator| indicator.source == source)
        .filter(|indicator| is_medium_or_higher(indicator.severity.as_str()))
        .map(|indicator| indicator.id.clone())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids.truncate(limit);
    ids
}

fn is_medium_or_higher(severity: &str) -> bool {
    matches!(
        severity.trim().to_ascii_lowercase().as_str(),
        "med" | "medium" | "high" | "critical"
    )
}

#[derive(Debug, Default)]
struct ExtractedArtifacts {
    urls: Vec<String>,
    domains: Vec<String>,
    commands: Vec<String>,
    file_paths: Vec<String>,
}

fn collect_extracted_artifacts(static_findings: &StaticFindings) -> ExtractedArtifacts {
    let mut urls = BTreeSet::new();
    let mut domains = BTreeSet::new();
    let mut commands = BTreeSet::new();
    let mut file_paths = BTreeSet::new();

    for indicator in &static_findings.matches {
        if let Some(items) = indicator.extracted_urls.as_ref() {
            for raw in items {
                urls.insert(truncate_string(raw.as_str(), 220));
                if let Ok(parsed) = Url::parse(raw.as_str()) {
                    if let Some(host) = parsed.host_str() {
                        domains.insert(host.trim().to_ascii_lowercase());
                    }
                }
            }
        }

        if let Some(items) = indicator.extracted_commands.as_ref() {
            for raw in items {
                commands.insert(truncate_string(raw.as_str(), 180));
            }
        }

        if let Some(items) = indicator.extracted_file_paths.as_ref() {
            for raw in items {
                file_paths.insert(truncate_string(raw.as_str(), 180));
            }
        }
    }

    ExtractedArtifacts {
        urls: urls.into_iter().take(10).collect(),
        domains: domains.into_iter().take(10).collect(),
        commands: commands.into_iter().take(10).collect(),
        file_paths: file_paths.into_iter().take(10).collect(),
    }
}

fn limit_and_truncate(items: &[String], max_items: usize, max_len: usize) -> Vec<String> {
    items
        .iter()
        .take(max_items)
        .map(|value| truncate_string(value.as_str(), max_len))
        .collect::<Vec<_>>()
}

fn truncate_string(value: &str, max_len: usize) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= max_len {
        return trimmed.to_string();
    }

    let mut end = max_len.min(trimmed.len());
    while end > 0 && !trimmed.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }

    let mut out = trimmed[..end].to_string();
    out.push_str("...");
    out
}

fn collect_suspicious_strings(strings: &[String], limit: usize) -> Vec<String> {
    let mut collected = Vec::new();
    for value in strings {
        if !is_suspicious_string(value.as_str()) {
            continue;
        }

        collected.push(truncate_string(value.as_str(), 220));
        if collected.len() >= limit {
            break;
        }
    }

    collected
}

fn is_suspicious_string(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    if lower.contains("discord") && lower.contains("webhook") {
        return true;
    }
    if lower.contains("http://") || lower.contains("https://") {
        return true;
    }
    if lower.contains(".onion") {
        return true;
    }
    if lower.contains("pastebin") || lower.contains("raw.githubusercontent") {
        return true;
    }
    if lower.contains("token") && (lower.contains("discord") || lower.contains("session")) {
        return true;
    }
    false
}

fn retry_after_from_payload(payload: &Value) -> Option<u64> {
    let message = payload
        .get("error")
        .and_then(|value| value.get("message"))
        .and_then(Value::as_str)?;
    retry_after_from_message(message)
}

fn retry_after_from_message(message: &str) -> Option<u64> {
    let lower = message.to_ascii_lowercase();
    let marker = "retry after";
    let idx = lower.find(marker)?;
    let tail = lower[idx + marker.len()..].trim_start();

    let mut digits = String::new();
    for ch in tail.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }

        if !digits.is_empty() {
            break;
        }
    }

    if digits.is_empty() {
        return None;
    }

    digits.parse::<u64>().ok()
}

pub async fn ai_verdict(
    profile: &CapabilityProfile,
    static_findings: &StaticFindings,
    config: &AiConfig,
) -> Result<AiVerdict> {
    let client = Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .context("failed to build AI HTTP client")?;

    let system_prompt = concat!(
        "You are a senior malware analyst specializing in Minecraft Java mods (.jar files). ",
        "Your primary mission is to CATCH MALWARE. Missing real malware is worse than a false positive, ",
        "but do not label popular/legitimate mods as malware based on generic primitives alone. ",
        "Classify the provided capability profile into exactly one of CLEAN, SUSPICIOUS, MALICIOUS.\n\n",
        "MALICIOUS indicators (any ONE of these is sufficient for MALICIOUS):\n",
        "- Credential theft capability (reading browser cookies, Discord tokens, session files, crypto wallets)\n",
        "- Network exfiltration combined with filesystem access or credential access\n",
        "- Process/command execution combined with extracted_commands showing real command lines (powershell/cmd/wget/curl), suspicious domains/URLs, credential theft, persistence, or stealthy obfuscation\n",
        "- Persistence mechanisms (scheduled tasks, startup entries, registry modification)\n",
        "- Native code loading (JNI/DLL loading) combined with network, credential, or persistence capabilities\n",
        "- Obfuscation patterns (e.g. long base64 blobs / string encryption) combined with staged loader behavior (Base64 decode, dynamic loading, or suspicious network evidence)\n",
        "- Reconstructed strings containing Discord webhook URLs, suspicious C2-like URLs, or clear exfiltration targets\n",
        "- Any YARA rule hit with severity high or critical\n\n",
        "LEGITIMATE mod patterns that are NOT inherently malicious:\n",
        "- Runtime.exec used for GPU/hardware probing (common in rendering mods like Sodium/Iris)\n",
        "- ProcessBuilder/Runtime.exec used to invoke ffmpeg/encoders for replay/video mods\n",
        "- Class.forName / reflection for dependency injection or mod compatibility layers\n",
        "- Dynamic class loading for mod plugin systems\n",
        "- Network access limited to version checking, mod update APIs, or analytics\n",
        "- Filesystem access for config files, caches, or resource packs\n\n",
        "Important interpretation rules:\n",
        "- Unsafe deserialization findings are vulnerability-risk signals, not malware by themselves. Do NOT label SUSPICIOUS solely because deserialization is present.\n",
        "- Local/private URLs/domains (localhost, 127.0.0.1, 10.x.x.x, 192.168.x.x, 172.16-31.x.x) are low-signal and common in testing/integration code.\n",
        "- Do NOT infer specific shell usage (PowerShell/cmd) from class names or error strings. Only treat execution as command-driven when extracted_commands contains a plausible command line.\n\n",
        "CLEAN: Only standard mod capabilities, recognized loader metadata, no threatening capability combinations.\n",
        "If mod_metadata.loader is missing/unknown AND mod_id/name are missing, default to SUSPICIOUS unless you can clearly justify why it's a legitimate mod/library artifact.\n",
        "SUSPICIOUS: Use only when evidence is genuinely ambiguous AND you can cite specific concrete evidence items.\n",
        "MALICIOUS: Clear malicious capability combinations or known malware indicators.\n\n",
        "Key principle: A SINGLE capability in isolation (like execution OR network OR native loading alone) is often legitimate in mods. ",
        "MALICIOUS requires COMBINATIONS of concerning capabilities or clear malware-specific indicators.\n\n",
        "Explanation requirements:\n",
        "- Always cite the concrete evidence you relied on (mention at least one capability evidence line containing a class path).\n",
        "- If networking/execution/filesystem are present, use extracted_urls / extracted_domains / extracted_commands / extracted_file_paths to justify why it is benign vs suspicious vs malicious.\n",
        "- Consider matched_patterns / matched_signatures: OBF-BASE64 is a LOW-SIGNAL heuristic and is common in benign mods/libraries; treat it as meaningful only when paired with Base64 decode, dynamic loading, missing mod metadata, or suspicious URLs/domains.\n",
        "- Consider low_signal_indicators: malware often computes URLs at runtime, so networking primitives without literal URLs can still matter when combined with obfuscation, dynamic loading, or missing mod metadata.\n",
        "- If you output SUSPICIOUS, state what additional evidence would upgrade to MALICIOUS or downgrade to CLEAN.\n\n",
        "Output requirements:\n",
        "- Return strict JSON (no markdown, no extra keys) with keys: verdict, confidence (0..1), risk_score (0..100), explanation, capabilities_assessment.\n",
        "- explanation MUST be a single short sentence (<= 300 characters).\n",
        "- capabilities_assessment MUST be an object mapping each of these 8 keys to a short STRING rationale (<= 120 characters each): ",
        "network, dynamic_loading, execution, credential_theft, persistence, native_loading, filesystem, deserialization.\n",
        "- Do NOT nest objects inside capabilities_assessment. Do NOT include booleans there."
    );
    let summary = build_ai_profile_summary(profile, static_findings);
    let user_prompt = format!(
        "Analyze this capability profile and return JSON only.\n\n{}",
        serde_json::to_string(&summary).context("failed to serialize capability profile")?
    );

    let messages = json!([
        { "role": "system", "content": system_prompt },
        { "role": "user", "content": user_prompt }
    ]);

    let (url, headers, body) = build_request(config, messages);

    const MAX_TRANSIENT_ATTEMPTS: usize = 5;
    const MAX_PARSE_ATTEMPTS: usize = 5;
    const MAX_RATE_LIMIT_WAIT: Duration = Duration::from_secs(15 * 60);

    let started = Instant::now();
    let mut transient_attempts = 0usize;
    let mut parse_attempts = 0usize;
    let mut api_calls = 0usize;

    loop {
        api_calls = api_calls.saturating_add(1);

        let mut request = client.post(url.as_str()).json(&body);
        for (key, value) in &headers {
            request = request.header(*key, value);
        }

        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => {
                transient_attempts = transient_attempts.saturating_add(1);
                if transient_attempts <= MAX_TRANSIENT_ATTEMPTS {
                    let backoff = Duration::from_secs(2_u64.saturating_mul(transient_attempts as u64));
                    tracing::warn!(
                        api_calls,
                        transient_attempts,
                        backoff_secs = backoff.as_secs(),
                        error = %error,
                        "AI request failed; retrying"
                    );
                    sleep(backoff).await;
                    continue;
                }

                return Err(error).context("AI request failed");
            }
        };

        let status = response.status();
        let retry_after_header = response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok())
            .and_then(|raw| raw.trim().parse::<u64>().ok());

        let payload: Value = match response.json().await {
            Ok(payload) => payload,
            Err(error) => {
                transient_attempts = transient_attempts.saturating_add(1);
                if transient_attempts <= MAX_TRANSIENT_ATTEMPTS {
                    let backoff = Duration::from_secs(2_u64.saturating_mul(transient_attempts as u64));
                    tracing::warn!(
                        api_calls,
                        transient_attempts,
                        backoff_secs = backoff.as_secs(),
                        error = %error,
                        "Failed to decode AI response payload; retrying"
                    );
                    sleep(backoff).await;
                    continue;
                }

                return Err(error).context("failed to decode AI response payload");
            }
        };

        if status.as_u16() == 429 {
            let retry_after = retry_after_header.or_else(|| retry_after_from_payload(&payload));
            let wait_secs = retry_after.unwrap_or(60).saturating_add(1);
            let wait = Duration::from_secs(wait_secs);
            if started.elapsed().saturating_add(wait) > MAX_RATE_LIMIT_WAIT {
                tracing::warn!(
                    api_calls,
                    waited_secs = started.elapsed().as_secs(),
                    wait_secs,
                    body = %payload,
                    "AI rate limited for too long; aborting"
                );
                anyhow::bail!("AI rate limited for too long (429)"
                );
            }

            tracing::warn!(api_calls, wait_secs, body = %payload, "AI rate limited (429); waiting then retrying");
            sleep(wait).await;
            continue;
        }

        if !status.is_success() {
            tracing::warn!(status = %status, body = %payload, "AI API returned non-200 status");
            anyhow::bail!("AI API returned status {status}: {payload}");
        }

        let Some(content) = extract_message_content(&payload) else {
            parse_attempts = parse_attempts.saturating_add(1);
            if parse_attempts <= MAX_PARSE_ATTEMPTS {
                tracing::warn!(api_calls, parse_attempts, body = %payload, "AI response missing message content; retrying");
                sleep(Duration::from_secs(1)).await;
                continue;
            }

            tracing::warn!(body = %payload, "AI response missing message content");
            anyhow::bail!("missing AI message content");
        };

        let parsed = match parse_verdict_content(content) {
            Ok(parsed) => parsed,
            Err(error) => {
                parse_attempts = parse_attempts.saturating_add(1);
                if parse_attempts <= MAX_PARSE_ATTEMPTS {
                    tracing::warn!(api_calls, parse_attempts, error = %error, body = %payload, "AI verdict response invalid; retrying");
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }

                return Err(error).context("AI response content was not valid JSON verdict payload");
            }
        };

        return Ok(AiVerdict {
            result: normalize_verdict(parsed.verdict.as_deref()),
            confidence: parsed.confidence.unwrap_or(0.0).clamp(0.0, 1.0),
            risk_score: parsed.risk_score.unwrap_or(50).min(100),
            explanation: parsed
                .explanation
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| "AI analysis returned no explanation.".to_string()),
            capabilities_assessment: parsed.capabilities_assessment,
        });
    }
}

pub fn fallback_verdict(explanation: impl Into<String>) -> AiVerdict {
    AiVerdict {
        result: "UNKNOWN".to_string(),
        confidence: 0.0,
        risk_score: 50,
        explanation: explanation.into(),
        capabilities_assessment: BTreeMap::new(),
    }
}

pub fn heuristic_verdict(
    static_findings: &StaticFindings,
    profile: &CapabilityProfile,
    reason: &str,
) -> AiVerdict {
    let mut weighted_score = 0_u32;
    let mut high_or_critical = 0_u32;
    let mut has_execution = false;
    let mut has_network = false;
    let mut has_credential = false;
    let mut has_persistence = false;
    let mut has_native = false;
    let mut has_yara_high = false;

    for indicator in &static_findings.matches {
        let severity = indicator.severity.trim().to_ascii_lowercase();

        // Many pattern matches are intentionally broad (e.g. long base64 blobs) and are useful as
        // context for AI, but should not on their own flip the heuristic fallback into SUSPICIOUS.
        // Keep high-signal patterns and high/critical severities.
        if indicator.source == "pattern"
            && !matches!(severity.as_str(), "high" | "critical")
            && !matches!(
                indicator.id.as_str(),
                "NET-DISCORD-WEBHOOK" | "EXEC-RUNTIME"
            )
        {
            continue;
        }

        let weight = indicator_weight(indicator, severity.as_str());

        if matches!(
            indicator.source.as_str(),
            "detector" | "yara" | "signature" | "pattern"
        ) {
            weighted_score = weighted_score.saturating_add(weight);
            if matches!(severity.as_str(), "high" | "critical") {
                high_or_critical = high_or_critical.saturating_add(1);
            }
        }

        if indicator.source == "yara" && matches!(severity.as_str(), "high" | "critical") {
            has_yara_high = true;
        }

        if indicator.source != "detector" {
            continue;
        }

        if indicator.id.starts_with("DETC-01") && is_medium_or_higher(severity.as_str()) {
            has_execution = true;
        }
        if indicator.id.starts_with("DETC-02") && is_medium_or_higher(severity.as_str()) {
            has_network = true;
        }
        if indicator.id.starts_with("DETC-07") && is_medium_or_higher(severity.as_str()) {
            has_native = true;
        }
        if indicator.id.starts_with("DETC-05") && is_medium_or_higher(severity.as_str()) {
            has_persistence = true;
        }
        if indicator.id.starts_with("DETC-08") && is_medium_or_higher(severity.as_str()) {
            has_credential = true;
        }
    }

    let malware_combo = (has_credential && (has_network || has_execution))
        || (has_persistence && has_execution)
        || (has_yara_high && (has_execution || has_credential || has_persistence));

    let (result, confidence, risk_score) = if malware_combo
        || (high_or_critical >= 2 && weighted_score >= 6)
        || weighted_score >= 10
    {
        (
            "MALICIOUS".to_string(),
            0.86,
            (80_u32 + weighted_score.saturating_mul(2)).min(100) as u8,
        )
    } else if weighted_score >= 1
        || high_or_critical >= 1
        || (has_execution && has_network)
        || (has_native && has_network)
    {
        (
            "SUSPICIOUS".to_string(),
            0.65,
            (25_u32 + weighted_score.saturating_mul(12)).min(79) as u8,
        )
    } else {
        (
            "CLEAN".to_string(),
            0.64,
            (weighted_score.saturating_mul(4)).min(20) as u8,
        )
    };

    let mut capabilities_assessment = std::collections::BTreeMap::new();
    for (capability, signal) in &profile.capabilities {
        if signal.present {
            capabilities_assessment.insert(
                capability.clone(),
                format!(
                    "present with {} medium/high evidence item(s)",
                    signal.evidence.len()
                ),
            );
        }
    }

    let explanation = format!(
        "{} Heuristic fallback evaluated detector/signature severity (score={}, high_or_critical={}) and capability correlation.",
        reason, weighted_score, high_or_critical
    );

    AiVerdict {
        result,
        confidence,
        risk_score,
        explanation,
        capabilities_assessment,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, HashMap};

    use super::heuristic_verdict;
    use crate::{Indicator, StaticFindings};
    use crate::profile::{CapabilityProfile, ModMetadata};

    fn empty_profile() -> CapabilityProfile {
        CapabilityProfile {
            mod_metadata: ModMetadata::default(),
            capabilities: BTreeMap::new(),
            yara_hits: Vec::new(),
            low_signal_indicators: Vec::new(),
            reconstructed_strings: Vec::new(),
            suspicious_manifest_entries: Vec::new(),
            class_count: 0,
            jar_size_bytes: 0,
        }
    }

    fn findings_with(indicator: Indicator) -> StaticFindings {
        StaticFindings {
            matches: vec![indicator],
            counts_by_category: HashMap::new(),
            counts_by_severity: HashMap::new(),
            matched_pattern_ids: Vec::new(),
            matched_signature_ids: Vec::new(),
            analyzed_files: 1,
        }
    }

    #[test]
    fn network_primitive_medium_is_not_enough_to_be_suspicious() {
        let findings = findings_with(Indicator {
            source: "detector".to_string(),
            id: "DETC-02.NETWORK_PRIMITIVE".to_string(),
            title: "Outbound networking primitive detected".to_string(),
            category: "capability".to_string(),
            severity: "med".to_string(),
            file_path: Some("Example.class".to_string()),
            evidence: "java/net/URL.openConnection".to_string(),
            rationale: "broad".to_string(),
            evidence_locations: None,
            extracted_urls: Some(vec!["https://example.invalid".to_string()]),
            extracted_commands: None,
            extracted_file_paths: None,
        });

        let verdict = heuristic_verdict(&findings, &empty_profile(), "no-ai");
        assert_eq!(verdict.result, "CLEAN");
    }

    #[test]
    fn pattern_only_medium_is_not_enough_to_be_suspicious() {
        let findings = findings_with(Indicator {
            source: "pattern".to_string(),
            id: "OBF-BASE64".to_string(),
            title: "Long base64 blob".to_string(),
            category: "obfuscation".to_string(),
            severity: "med".to_string(),
            file_path: Some("Example.class".to_string()),
            evidence: "AAAA...".to_string(),
            rationale: "Broad indicator".to_string(),
            evidence_locations: None,
            extracted_urls: None,
            extracted_commands: None,
            extracted_file_paths: None,
        });

        let verdict = heuristic_verdict(&findings, &empty_profile(), "no-ai");
        assert_eq!(verdict.result, "CLEAN");
    }

    #[test]
    fn high_signal_pattern_still_makes_it_suspicious() {
        let findings = findings_with(Indicator {
            source: "pattern".to_string(),
            id: "NET-DISCORD-WEBHOOK".to_string(),
            title: "Discord webhook endpoint".to_string(),
            category: "network".to_string(),
            severity: "high".to_string(),
            file_path: Some("Example.class".to_string()),
            evidence: "https://discord.com/api/webhooks/123/abc".to_string(),
            rationale: "High signal".to_string(),
            evidence_locations: None,
            extracted_urls: None,
            extracted_commands: None,
            extracted_file_paths: None,
        });

        let verdict = heuristic_verdict(&findings, &empty_profile(), "no-ai");
        assert_eq!(verdict.result, "SUSPICIOUS");
    }
}

fn build_request(
    config: &AiConfig,
    messages: Value,
) -> (String, Vec<(&'static str, String)>, Value) {
    let endpoint = config.endpoint.trim_end_matches('/');
    let deployment = config
        .deployment
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let is_azure = !deployment.is_empty() || endpoint.contains("openai.azure.com");

    if is_azure {
        let deployment_name = if deployment.is_empty() {
            config
                .model
                .as_deref()
                .unwrap_or("gpt-4o")
                .trim()
                .to_string()
        } else {
            deployment.to_string()
        };

        let url = format!(
            "{endpoint}/openai/deployments/{deployment_name}/chat/completions?api-version={}",
            config.api_version
        );

        let body = json!({
            "messages": messages,
            "temperature": 0.1,
            "max_tokens": 700,
            "response_format": { "type": "json_object" }
        });

        return (url, vec![("api-key", config.api_key.clone())], body);
    }

    let url = if endpoint.ends_with("/chat/completions") {
        endpoint.to_string()
    } else if endpoint.ends_with("/v1") {
        format!("{endpoint}/chat/completions")
    } else {
        format!("{endpoint}/v1/chat/completions")
    };

    let body = json!({
        "model": config.model.as_deref().unwrap_or("gpt-4o"),
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 700,
        "response_format": { "type": "json_object" }
    });

    (
        url,
        vec![("Authorization", format!("Bearer {}", config.api_key))],
        body,
    )
}

fn extract_message_content(payload: &Value) -> Option<&str> {
    if let Some(content) = payload
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
    {
        if let Some(raw) = content.as_str() {
            return Some(raw);
        }

        if let Some(parts) = content.as_array() {
            for part in parts {
                if let Some(raw) = part.get("text").and_then(Value::as_str) {
                    return Some(raw);
                }
            }
        }
    }

    if let Some(raw) = payload.get("output_text").and_then(Value::as_str) {
        return Some(raw);
    }

    if let Some(raw) = payload
        .get("output")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("content"))
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
    {
        return Some(raw);
    }

    None
}

fn normalize_verdict(value: Option<&str>) -> String {
    let normalized = value.unwrap_or("UNKNOWN").trim().to_ascii_uppercase();
    match normalized.as_str() {
        "CLEAN" | "SUSPICIOUS" | "MALICIOUS" => normalized,
        _ => "UNKNOWN".to_string(),
    }
}

fn parse_verdict_content(content: &str) -> Result<AiVerdictResponse> {
    if let Some(parsed) = decode_verdict_json(content) {
        return Ok(parsed);
    }

    let trimmed = content.trim();
    if let Some(stripped) = trim_code_fence(trimmed) {
        if let Some(parsed) = decode_verdict_json(stripped) {
            return Ok(parsed);
        }
    }

    if let Some((start, end)) = json_object_span(trimmed) {
        let candidate = &trimmed[start..=end];
        if let Some(parsed) = decode_verdict_json(candidate) {
            return Ok(parsed);
        }
    }

    anyhow::bail!("failed to parse AI verdict content")
}

fn decode_verdict_json(candidate: &str) -> Option<AiVerdictResponse> {
    let payload = serde_json::from_str::<Value>(candidate).ok()?;
    let object = payload.as_object()?;

    let verdict = object
        .get("verdict")
        .and_then(value_to_string)
        .or_else(|| object.get("result").and_then(value_to_string));
    let confidence = object
        .get("confidence")
        .and_then(value_to_f64)
        .or_else(|| object.get("confidence_score").and_then(value_to_f64));
    let risk_score = object
        .get("risk_score")
        .and_then(value_to_u8)
        .or_else(|| object.get("score").and_then(value_to_u8));
    let explanation = object
        .get("explanation")
        .and_then(value_to_string)
        .or_else(|| object.get("summary").and_then(value_to_string))
        .or_else(|| object.get("reasoning").and_then(value_to_string));

    let capabilities_assessment = object
        .get("capabilities_assessment")
        .and_then(Value::as_object)
        .map(|items| {
            items
                .iter()
                .map(|(key, value)| {
                    let rendered = value_to_string(value).unwrap_or_else(|| value.to_string());
                    (key.clone(), rendered)
                })
                .collect::<BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    Some(AiVerdictResponse {
        verdict,
        confidence,
        risk_score,
        explanation,
        capabilities_assessment,
    })
}

fn trim_code_fence(value: &str) -> Option<&str> {
    let without_prefix = value.strip_prefix("```")?;
    let without_lang = if let Some(idx) = without_prefix.find('\n') {
        &without_prefix[idx + 1..]
    } else {
        without_prefix
    };

    without_lang.strip_suffix("```").map(str::trim)
}

fn json_object_span(value: &str) -> Option<(usize, usize)> {
    let start = value.find('{')?;
    let end = value.rfind('}')?;
    if end > start {
        Some((start, end))
    } else {
        None
    }
}

fn value_to_string(value: &Value) -> Option<String> {
    match value {
        Value::String(raw) => Some(raw.trim().to_string()),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(flag) => Some(flag.to_string()),
        _ => None,
    }
}

fn value_to_f64(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(raw) => raw.trim().parse::<f64>().ok(),
        _ => None,
    }
}

fn value_to_u8(value: &Value) -> Option<u8> {
    match value {
        Value::Number(number) => number.as_u64().and_then(|v| u8::try_from(v).ok()),
        Value::String(raw) => raw.trim().parse::<u8>().ok(),
        _ => None,
    }
}

fn severity_weight(severity: &str) -> u32 {
    match severity {
        "critical" => 5,
        "high" => 3,
        "med" | "medium" => 1,
        _ => 0,
    }
}

fn indicator_weight(indicator: &crate::Indicator, severity: &str) -> u32 {
    if indicator.source == "yara" || indicator.source == "signature" {
        return match severity {
            "critical" => 6,
            "high" => 4,
            "med" | "medium" => 2,
            "low" => 1,
            _ => 0,
        };
    }

    if indicator.source != "detector" {
        return severity_weight(severity);
    }

    if indicator.id.starts_with("DETC-08") || indicator.id.starts_with("DETC-05") {
        return match severity {
            "critical" | "high" => 4,
            "med" | "medium" => 3,
            _ => 0,
        };
    }

    if indicator.id.starts_with("DETC-01") {
        return match severity {
            "critical" | "high" => 4,
            "med" | "medium" => 2,
            _ => 0,
        };
    }

    if indicator.id.starts_with("DETC-07") {
        return match severity {
            "critical" | "high" => 3,
            "med" | "medium" => 2,
            _ => 0,
        };
    }

    // The baseline network primitive detector is intentionally broad; many benign mods
    // include update checks and documentation URLs. Keep it as a correlation input, but
    // do not let it drive heuristic verdicts on its own.
    if indicator.id == "DETC-02.NETWORK_PRIMITIVE" {
        return match severity {
            "critical" | "high" => 2,
            _ => 0,
        };
    }

    if indicator.id.starts_with("DETC-02") {
        return match severity {
            "critical" | "high" => 2,
            "med" | "medium" => 1,
            _ => 0,
        };
    }

    if indicator.id.starts_with("DETC-04") {
        return match severity {
            "critical" | "high" => 2,
            "med" | "medium" => 1,
            _ => 0,
        };
    }

    if indicator.id.starts_with("DETC-03") || indicator.id.starts_with("DETC-06") {
        return match severity {
            "critical" | "high" => 2,
            _ => 0,
        };
    }

    severity_weight(severity)
}
