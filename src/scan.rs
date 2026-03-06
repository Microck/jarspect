use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use tokio::fs;
use tracing::warn;
use uuid::Uuid;

use crate::analysis;
use crate::malwarebazaar;
use crate::profile;
use crate::verdict;
use crate::{AppState, IntakeResult, ScanRequest, ScanRunResponse, Verdict, validate_artifact_id};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MalwareBazaarMatchMode {
    ShortCircuit,
    ContinueStaticAnalysis,
}

fn malwarebazaar_match_mode() -> MalwareBazaarMatchMode {
    let raw = std::env::var("JARSPECT_MB_MATCH_CONTINUE_ANALYSIS").unwrap_or_default();
    let normalized = raw.trim().to_ascii_lowercase();

    if normalized.is_empty()
        || normalized == "0"
        || normalized == "false"
        || normalized == "no"
        || normalized == "off"
    {
        MalwareBazaarMatchMode::ShortCircuit
    } else {
        MalwareBazaarMatchMode::ContinueStaticAnalysis
    }
}

fn malwarebazaar_hash_match_enabled() -> bool {
    let raw = std::env::var("JARSPECT_MB_HASH_MATCH_ENABLED").unwrap_or_default();
    let normalized = raw.trim().to_ascii_lowercase();

    // Default: enabled.
    if normalized.is_empty() {
        return true;
    }

    !(normalized == "0" || normalized == "false" || normalized == "no" || normalized == "off")
}

pub async fn run_scan(
    state: &AppState,
    request: ScanRequest,
    scan_id_override: Option<&str>,
) -> Result<ScanRunResponse> {
    validate_artifact_id(&request.upload_id)?;
    let upload_path = state.uploads_dir.join(format!("{}.jar", request.upload_id));
    if !upload_path.exists() {
        anyhow::bail!("Upload not found")
    }

    let bytes = fs::read(&upload_path)
        .await
        .with_context(|| format!("Failed to read upload: {}", upload_path.display()))?;
    let sha256_hash = format!("{:x}", Sha256::digest(bytes.as_slice()));

    let mb_mode = malwarebazaar_match_mode();
    let malwarebazaar_match = if malwarebazaar_hash_match_enabled() {
        lookup_malwarebazaar(state, &sha256_hash).await
    } else {
        None
    };

    if mb_mode == MalwareBazaarMatchMode::ShortCircuit {
        if let Some(known_malware) = malwarebazaar_match.clone() {
            let explanation = match known_malware.family.as_deref() {
                Some(family) => format!("Known malware detected by hash match: {family}."),
                None => "Known malware detected by hash match in MalwareBazaar.".to_string(),
            };

            let response = ScanRunResponse {
                scan_id: build_scan_id(scan_id_override)?,
                sha256: Some(sha256_hash),
                verdict: Verdict {
                    result: "MALICIOUS".to_string(),
                    confidence: 1.0,
                    risk_score: 100,
                    method: "malwarebazaar_hash".to_string(),
                    explanation,
                    capabilities_assessment: std::collections::BTreeMap::new(),
                },
                malwarebazaar: Some(known_malware),
                static_findings: None,
                capabilities: None,
                yara_hits: None,
                metadata: None,
                profile: None,
                intake: IntakeResult {
                    upload_id: request.upload_id.clone(),
                    storage_path: upload_path.to_string_lossy().into_owned(),
                    file_count: 0,
                    class_file_count: 0,
                },
            };

            persist_scan_result(state, &response).await?;
            return Ok(response);
        }
    }

    let root_label = format!("{}.jar", request.upload_id);
    let entries = match analysis::read_archive_entries_recursive(root_label.as_str(), &bytes) {
        Ok(entries) => entries,
        Err(error) => {
            warn!(error = %error, "archive parsing failed; attempting raw fallback scan");
            if let Some(known_malware) = malwarebazaar_match {
                let explanation = match known_malware.family.as_deref() {
                    Some(family) => format!("Known malware detected by hash match: {family}."),
                    None => "Known malware detected by hash match in MalwareBazaar.".to_string(),
                };

                let response = ScanRunResponse {
                    scan_id: build_scan_id(scan_id_override)?,
                    sha256: Some(sha256_hash),
                    verdict: Verdict {
                        result: "MALICIOUS".to_string(),
                        confidence: 1.0,
                        risk_score: 100,
                        method: "malwarebazaar_hash".to_string(),
                        explanation,
                        capabilities_assessment: std::collections::BTreeMap::new(),
                    },
                    malwarebazaar: Some(known_malware),
                    static_findings: None,
                    capabilities: None,
                    yara_hits: None,
                    metadata: None,
                    profile: None,
                    intake: IntakeResult {
                        upload_id: request.upload_id.clone(),
                        storage_path: upload_path.to_string_lossy().into_owned(),
                        file_count: 0,
                        class_file_count: 0,
                    },
                };

                persist_scan_result(state, &response).await?;
                return Ok(response);
            }

            // Fallback: treat the raw upload bytes as a single analyzable artifact so we can
            // still surface YARA/signature/pattern hits.
            let fallback_entries = vec![analysis::ArchiveEntry {
                path: root_label.clone(),
                bytes: bytes.clone(),
                text: best_effort_text(bytes.as_slice()),
            }];
            let static_findings = crate::run_static_analysis(
                &fallback_entries,
                None,
                &state.signatures,
                &state.yara_rulepacks,
            )?;
            let capability_profile =
                profile::build_profile(&static_findings, &fallback_entries, None, 0, bytes.len());

            let forced_malicious_reason = high_confidence_static_reason(&static_findings);
            let (result, confidence, risk_score, method, explanation) = if let Some(reason) =
                forced_malicious_reason
            {
                (
                    "MALICIOUS".to_string(),
                    0.9,
                    90,
                    "archive_fallback_static_override".to_string(),
                    format!(
                        "Archive could not be parsed as a valid .jar, but high-confidence static indicators were found ({reason}). Original error: {:#}",
                        error
                    ),
                )
            } else {
                (
                    "SUSPICIOUS".to_string(),
                    0.78,
                    72,
                    "archive_validation_failure".to_string(),
                    format!(
                        "Archive structure is invalid or intentionally malformed and could not be fully analyzed. Partial static scan ran on raw bytes. Original error: {:#}",
                        error
                    ),
                )
            };

            let response = ScanRunResponse {
                scan_id: build_scan_id(scan_id_override)?,
                sha256: Some(sha256_hash),
                verdict: Verdict {
                    result,
                    confidence,
                    risk_score,
                    method,
                    explanation,
                    capabilities_assessment: std::collections::BTreeMap::new(),
                },
                malwarebazaar: None,
                static_findings: Some(static_findings),
                capabilities: Some(capability_profile.capabilities.clone()),
                yara_hits: Some(capability_profile.yara_hits.clone()),
                metadata: Some(capability_profile.mod_metadata.clone()),
                profile: Some(capability_profile),
                intake: IntakeResult {
                    upload_id: request.upload_id.clone(),
                    storage_path: upload_path.to_string_lossy().into_owned(),
                    file_count: 1,
                    class_file_count: 0,
                },
            };

            persist_scan_result(state, &response).await?;
            return Ok(response);
        }
    };

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
    let static_findings = crate::run_static_analysis(
        &entries,
        bytecode_evidence.as_ref(),
        &state.signatures,
        &state.yara_rulepacks,
    )?;
    let capability_profile = profile::build_profile(
        &static_findings,
        &entries,
        bytecode_evidence.as_ref(),
        intake.class_file_count,
        bytes.len(),
    );

    if let Some(known_malware) = malwarebazaar_match {
        let explanation = match known_malware.family.as_deref() {
            Some(family) => format!("Known malware detected by hash match: {family}."),
            None => "Known malware detected by hash match in MalwareBazaar.".to_string(),
        };

        let response = ScanRunResponse {
            scan_id: build_scan_id(scan_id_override)?,
            sha256: Some(sha256_hash),
            verdict: Verdict {
                result: "MALICIOUS".to_string(),
                confidence: 1.0,
                risk_score: 100,
                method: "malwarebazaar_hash".to_string(),
                explanation,
                capabilities_assessment: std::collections::BTreeMap::new(),
            },
            malwarebazaar: Some(known_malware),
            static_findings: Some(static_findings),
            capabilities: Some(capability_profile.capabilities.clone()),
            yara_hits: Some(capability_profile.yara_hits.clone()),
            metadata: Some(capability_profile.mod_metadata.clone()),
            profile: Some(capability_profile),
            intake,
        };

        persist_scan_result(state, &response).await?;
        return Ok(response);
    }

    let (mut ai_verdict, mut method) = match state.ai_config.as_ref() {
        Some(ai_config) => {
            match verdict::ai_verdict(&capability_profile, &static_findings, ai_config).await {
                Ok(verdict) => (verdict, "ai_verdict".to_string()),
                Err(error) => {
                    warn!(error = %error, "AI verdict failed; falling back to heuristic verdict");
                    (
                        verdict::heuristic_verdict(
                            &static_findings,
                            &capability_profile,
                            "AI verdict failed.",
                        ),
                        "heuristic_fallback".to_string(),
                    )
                }
            }
        }
        None => (
            verdict::heuristic_verdict(
                &static_findings,
                &capability_profile,
                "AI configuration missing.",
            ),
            "heuristic_fallback".to_string(),
        ),
    };

    if let Some(reason) = high_confidence_static_reason(&static_findings) {
        if ai_verdict.result != "MALICIOUS" {
            ai_verdict.result = "MALICIOUS".to_string();
            ai_verdict.confidence = ai_verdict.confidence.max(0.9);
            ai_verdict.risk_score = ai_verdict.risk_score.max(90);
            ai_verdict.explanation = format!(
                "High-confidence static indicator detected ({reason}). {}",
                ai_verdict.explanation
            );
            method = format!("static_override({method})");
        }
    }

    let response = ScanRunResponse {
        scan_id: build_scan_id(scan_id_override)?,
        sha256: Some(sha256_hash),
        verdict: Verdict {
            result: ai_verdict.result,
            confidence: ai_verdict.confidence,
            risk_score: ai_verdict.risk_score,
            method,
            explanation: ai_verdict.explanation,
            capabilities_assessment: ai_verdict.capabilities_assessment,
        },
        malwarebazaar: None,
        static_findings: Some(static_findings),
        capabilities: Some(capability_profile.capabilities.clone()),
        yara_hits: Some(capability_profile.yara_hits.clone()),
        metadata: Some(capability_profile.mod_metadata.clone()),
        profile: Some(capability_profile),
        intake,
    };

    persist_scan_result(state, &response).await?;
    Ok(response)
}

fn best_effort_text(bytes: &[u8]) -> Option<String> {
    const MAX_BYTES: usize = 256 * 1024;
    if bytes.is_empty() {
        return None;
    }
    if bytes.len() <= MAX_BYTES {
        return Some(String::from_utf8_lossy(bytes).into_owned());
    }

    let chunk = MAX_BYTES / 2;
    let head = &bytes[..chunk.min(bytes.len())];
    let tail_start = bytes.len().saturating_sub(chunk);
    let tail = &bytes[tail_start..];

    let mut out = String::new();
    out.push_str(&String::from_utf8_lossy(head));
    out.push_str("\n...snip...\n");
    out.push_str(&String::from_utf8_lossy(tail));
    Some(out)
}

fn high_confidence_static_reason(static_findings: &crate::StaticFindings) -> Option<String> {
    for indicator in &static_findings.matches {
        let severity = indicator.severity.trim().to_ascii_lowercase();

        if indicator.source == "yara"
            && indicator.id.starts_with("YARA-PROD-")
            && matches!(severity.as_str(), "high" | "critical")
        {
            return Some(indicator.id.clone());
        }

        if indicator.source == "pattern"
            && indicator.id == "NET-DISCORD-WEBHOOK"
            && matches!(severity.as_str(), "high" | "critical")
        {
            return Some(indicator.id.clone());
        }

        // Only truly high-confidence malware-specific detectors trigger the static
        // override. Remote code load/fetch/write and dynamic load are too broad — they
        // fire on legitimate mod loaders (OptiFine LaunchClassLoader, Fabric MixinLoader,
        // etc.) and should be evaluated by the AI in context instead.
        if indicator.source == "detector"
            && matches!(
                indicator.id.as_str(),
                "DETC-03.BASE64_STAGER" | "DETC-02.DISCORD_WEBHOOK"
            )
            && matches!(severity.as_str(), "high" | "critical")
        {
            return Some(indicator.id.clone());
        }
    }

    None
}

async fn lookup_malwarebazaar(
    state: &AppState,
    sha256_hash: &str,
) -> Option<malwarebazaar::MalwareBazaarResult> {
    let api_key = state.malwarebazaar_api_key.as_deref()?;
    match malwarebazaar::check_hash(sha256_hash, api_key).await {
        Ok(result) => result,
        Err(error) => {
            warn!(error = %error, "MalwareBazaar lookup failed; continuing with local analysis");
            None
        }
    }
}

fn build_scan_id(scan_id_override: Option<&str>) -> Result<String> {
    if let Some(scan_id) = scan_id_override {
        validate_artifact_id(scan_id)?;
        return Ok(scan_id.to_string());
    }

    Ok(Uuid::new_v4().simple().to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::high_confidence_static_reason;
    use crate::{Indicator, StaticFindings};

    fn make_indicator(source: &str, id: &str, severity: &str) -> Indicator {
        Indicator {
            source: source.to_string(),
            id: id.to_string(),
            title: "t".to_string(),
            category: "c".to_string(),
            severity: severity.to_string(),
            file_path: None,
            evidence: "e".to_string(),
            rationale: "r".to_string(),
            evidence_locations: None,
            extracted_urls: None,
            extracted_commands: None,
            extracted_file_paths: None,
        }
    }

    fn findings(indicators: Vec<Indicator>) -> StaticFindings {
        StaticFindings {
            matches: indicators,
            counts_by_category: HashMap::new(),
            counts_by_severity: HashMap::new(),
            matched_pattern_ids: Vec::new(),
            matched_signature_ids: Vec::new(),
            analyzed_files: 1,
        }
    }

    #[test]
    fn returns_reason_for_high_severity_prod_yara() {
        let f = findings(vec![make_indicator("yara", "YARA-PROD-FOO", "high")]);
        assert_eq!(
            high_confidence_static_reason(&f),
            Some("YARA-PROD-FOO".to_string())
        );
    }

    #[test]
    fn ignores_medium_severity_prod_yara() {
        let f = findings(vec![make_indicator("yara", "YARA-PROD-FOO", "med")]);
        assert_eq!(high_confidence_static_reason(&f), None);
    }

    #[test]
    fn ignores_demo_yara_even_if_high() {
        let f = findings(vec![make_indicator("yara", "YARA-DEMO-FOO", "high")]);
        assert_eq!(high_confidence_static_reason(&f), None);
    }

    #[test]
    fn returns_reason_for_discord_webhook_pattern() {
        let f = findings(vec![make_indicator(
            "pattern",
            "NET-DISCORD-WEBHOOK",
            "high",
        )]);
        assert_eq!(
            high_confidence_static_reason(&f),
            Some("NET-DISCORD-WEBHOOK".to_string())
        );
    }

    #[test]
    fn returns_reason_for_high_detector_ids() {
        let f = findings(vec![make_indicator(
            "detector",
            "DETC-03.BASE64_STAGER",
            "high",
        )]);
        assert_eq!(
            high_confidence_static_reason(&f),
            Some("DETC-03.BASE64_STAGER".to_string())
        );
    }

    #[test]
    fn dynamic_load_no_longer_triggers_static_override() {
        // DETC-03.DYNAMIC_LOAD is too broad (fires on legitimate mod loaders like
        // OptiFine LaunchClassLoader) so it is evaluated by AI, not static override.
        let f = findings(vec![make_indicator(
            "detector",
            "DETC-03.DYNAMIC_LOAD",
            "high",
        )]);
        assert_eq!(high_confidence_static_reason(&f), None);
    }

    #[test]
    fn remote_code_fetch_no_longer_triggers_static_override() {
        let f = findings(vec![make_indicator(
            "detector",
            "DETC-02.REMOTE_CODE_FETCH",
            "high",
        )]);
        assert_eq!(high_confidence_static_reason(&f), None);
    }

    #[test]
    fn discord_webhook_detector_still_triggers_static_override() {
        let f = findings(vec![make_indicator(
            "detector",
            "DETC-02.DISCORD_WEBHOOK",
            "high",
        )]);
        assert_eq!(
            high_confidence_static_reason(&f),
            Some("DETC-02.DISCORD_WEBHOOK".to_string())
        );
    }
}

async fn persist_scan_result(state: &AppState, payload: &ScanRunResponse) -> Result<()> {
    let path = state.scans_dir.join(format!("{}.json", payload.scan_id));
    let payload_bytes =
        serde_json::to_vec_pretty(payload).context("Failed to serialize scan result")?;
    fs::write(&path, payload_bytes)
        .await
        .with_context(|| format!("Failed to persist scan result: {}", path.display()))?;
    Ok(())
}
