use std::collections::{BTreeMap, BTreeSet};

use regex::Regex;
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) struct PredictedBehavior {
    pub(crate) kind: String,
    pub(crate) value: String,
    pub(crate) confidence: f64,
    pub(crate) supporting_indicator_ids: Vec<String>,
    pub(crate) rationale: String,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct DerivedBehavior {
    pub(crate) predicted_network_urls: Vec<String>,
    pub(crate) predicted_commands: Vec<String>,
    pub(crate) predicted_file_writes: Vec<String>,
    pub(crate) predicted_persistence: Vec<String>,
    pub(crate) predictions: Vec<PredictedBehavior>,
    pub(crate) confidence: f64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum ObservableEvidenceSource {
    Regex,
    ExtractedFields,
}

#[derive(Debug, Clone)]
struct Observable {
    source: ObservableEvidenceSource,
    supporting_indicator_ids: BTreeSet<String>,
    has_detector_support: bool,
}

impl Observable {
    fn new(source: ObservableEvidenceSource) -> Self {
        Self {
            source,
            supporting_indicator_ids: BTreeSet::new(),
            has_detector_support: false,
        }
    }
}

pub(crate) fn derive_behavior(static_indicators: &[crate::Indicator]) -> DerivedBehavior {
    let mut network_urls: BTreeMap<String, Observable> = BTreeMap::new();
    let mut commands: BTreeMap<String, Observable> = BTreeMap::new();
    let mut file_writes: BTreeMap<String, Observable> = BTreeMap::new();
    let mut persistence: BTreeMap<String, Observable> = BTreeMap::new();

    for indicator in static_indicators {
        if let Some(values) = indicator.extracted_urls.as_ref() {
            for value in values {
                if let Some(normalized) = normalize_url(value) {
                    record_observable(
                        &mut network_urls,
                        normalized,
                        ObservableEvidenceSource::ExtractedFields,
                        indicator,
                    );
                }
            }
        }

        if let Some(values) = indicator.extracted_commands.as_ref() {
            for value in values {
                if let Some(normalized) = normalize_text_observable(value) {
                    record_observable(
                        &mut commands,
                        normalized.clone(),
                        ObservableEvidenceSource::ExtractedFields,
                        indicator,
                    );
                    if is_persistence_marker(normalized.as_str()) {
                        record_observable(
                            &mut persistence,
                            normalized,
                            ObservableEvidenceSource::ExtractedFields,
                            indicator,
                        );
                    }
                }
            }
        }

        if let Some(values) = indicator.extracted_file_paths.as_ref() {
            for value in values {
                if let Some(normalized) = normalize_text_observable(value) {
                    record_observable(
                        &mut file_writes,
                        normalized.clone(),
                        ObservableEvidenceSource::ExtractedFields,
                        indicator,
                    );
                    if is_persistence_marker(normalized.as_str()) {
                        record_observable(
                            &mut persistence,
                            normalized,
                            ObservableEvidenceSource::ExtractedFields,
                            indicator,
                        );
                    }
                }
            }
        }

        for text in [&indicator.evidence, &indicator.rationale] {
            for candidate in extract_urls_from_text(text) {
                if !network_urls.contains_key(candidate.as_str()) {
                    record_observable(
                        &mut network_urls,
                        candidate,
                        ObservableEvidenceSource::Regex,
                        indicator,
                    );
                }
            }

            for candidate in extract_commands_from_text(text) {
                if !commands.contains_key(candidate.as_str()) {
                    record_observable(
                        &mut commands,
                        candidate.clone(),
                        ObservableEvidenceSource::Regex,
                        indicator,
                    );
                }

                if is_persistence_marker(candidate.as_str())
                    && !persistence.contains_key(candidate.as_str())
                {
                    record_observable(
                        &mut persistence,
                        candidate,
                        ObservableEvidenceSource::Regex,
                        indicator,
                    );
                }
            }

            for candidate in extract_paths_from_text(text) {
                if !file_writes.contains_key(candidate.as_str()) {
                    record_observable(
                        &mut file_writes,
                        candidate.clone(),
                        ObservableEvidenceSource::Regex,
                        indicator,
                    );
                }

                if is_persistence_marker(candidate.as_str())
                    && !persistence.contains_key(candidate.as_str())
                {
                    record_observable(
                        &mut persistence,
                        candidate,
                        ObservableEvidenceSource::Regex,
                        indicator,
                    );
                }
            }

            for marker in extract_persistence_markers(text) {
                if !persistence.contains_key(marker.as_str()) {
                    record_observable(
                        &mut persistence,
                        marker,
                        ObservableEvidenceSource::Regex,
                        indicator,
                    );
                }
            }
        }
    }

    let mut predictions = Vec::new();
    for (value, observable) in &network_urls {
        predictions.push(to_prediction("network_url", value, observable));
    }
    for (value, observable) in &commands {
        predictions.push(to_prediction("command", value, observable));
    }
    for (value, observable) in &file_writes {
        predictions.push(to_prediction("file_write", value, observable));
    }
    for (value, observable) in &persistence {
        predictions.push(to_prediction("persistence", value, observable));
    }

    let confidence = predictions
        .iter()
        .map(|prediction| prediction.confidence)
        .fold(0.0_f64, f64::max)
        .clamp(0.0, 1.0);

    DerivedBehavior {
        predicted_network_urls: network_urls.keys().cloned().collect(),
        predicted_commands: commands.keys().cloned().collect(),
        predicted_file_writes: file_writes.keys().cloned().collect(),
        predicted_persistence: persistence.keys().cloned().collect(),
        predictions,
        confidence,
    }
}

fn to_prediction(kind: &str, value: &str, observable: &Observable) -> PredictedBehavior {
    let confidence = match observable.source {
        ObservableEvidenceSource::ExtractedFields if observable.has_detector_support => 0.9,
        ObservableEvidenceSource::ExtractedFields => 0.8,
        ObservableEvidenceSource::Regex => 0.6,
    };

    let supporting_indicator_ids = observable
        .supporting_indicator_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let source_label = match observable.source {
        ObservableEvidenceSource::ExtractedFields => "extracted indicator fields",
        ObservableEvidenceSource::Regex => "regex extraction from indicator evidence/rationale",
    };

    PredictedBehavior {
        kind: kind.to_string(),
        value: value.to_string(),
        confidence,
        supporting_indicator_ids: supporting_indicator_ids.clone(),
        rationale: format!(
            "Derived from {source_label}; supporting indicators: {}.",
            supporting_indicator_ids.join(", "),
        ),
    }
}

fn record_observable(
    observables: &mut BTreeMap<String, Observable>,
    value: String,
    source: ObservableEvidenceSource,
    indicator: &crate::Indicator,
) {
    let entry = observables
        .entry(value)
        .or_insert_with(|| Observable::new(source));

    if source > entry.source {
        entry.source = source;
    }

    entry.supporting_indicator_ids.insert(indicator.id.clone());
    if indicator.source == "detector" {
        entry.has_detector_support = true;
    }
}

fn normalize_url(raw: &str) -> Option<String> {
    let sanitized = sanitize_candidate(raw);
    let parsed = Url::parse(sanitized.as_str()).ok()?;
    let host = parsed.host_str()?.to_ascii_lowercase();

    let mut normalized = format!("{}://{}", parsed.scheme(), host);
    if let Some(port) = parsed.port() {
        normalized.push_str(format!(":{port}").as_str());
    }
    normalized.push_str(parsed.path());
    Some(normalized)
}

fn normalize_text_observable(raw: &str) -> Option<String> {
    let sanitized = sanitize_candidate(raw);
    if sanitized.is_empty() {
        return None;
    }
    Some(sanitized)
}

fn sanitize_candidate(raw: &str) -> String {
    raw.trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | ',' | ';' | '.' | ')' | ']' | '}'))
        .to_string()
}

fn extract_urls_from_text(text: &str) -> Vec<String> {
    let regex = Regex::new(r#"https?://[^\s\"'<>\)]+"#).expect("valid URL regex");
    let mut urls = BTreeSet::new();

    for url in regex.find_iter(text) {
        if let Some(normalized) = normalize_url(url.as_str()) {
            urls.insert(normalized);
        }
    }

    urls.into_iter().collect()
}

fn extract_commands_from_text(text: &str) -> Vec<String> {
    let regex = Regex::new(
        r"(?i)(powershell|cmd\\.exe|/bin/sh|\\bbash\\b|\\bcurl\\b|\\bwget\\b|schtasks|reg\\s+add|java\\s+-jar)",
    )
    .expect("valid command regex");
    let mut commands = BTreeSet::new();

    for command in regex.find_iter(text) {
        if let Some(normalized) = normalize_text_observable(command.as_str()) {
            commands.insert(normalized);
        }
    }

    commands.into_iter().collect()
}

fn extract_paths_from_text(text: &str) -> Vec<String> {
    let regex = Regex::new(
        r#"(?i)([A-Za-z]:\\[^\s\"'<>]+|/(?:[A-Za-z0-9._-]+/)*[A-Za-z0-9._-]+|(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+)"#,
    )
    .expect("valid file path regex");
    let mut paths = BTreeSet::new();

    for path in regex.find_iter(text) {
        if path.as_str().contains("://") {
            continue;
        }

        if let Some(normalized) = normalize_text_observable(path.as_str()) {
            paths.insert(normalized);
        }
    }

    paths.into_iter().collect()
}

fn extract_persistence_markers(text: &str) -> Vec<String> {
    let lowered = text.to_ascii_lowercase();
    let mut markers = BTreeSet::new();

    for marker in persistence_markers() {
        if lowered.contains(marker) {
            markers.insert(marker.to_string());
        }
    }

    markers.into_iter().collect()
}

fn is_persistence_marker(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    persistence_markers()
        .iter()
        .any(|marker| lowered.contains(marker))
}

fn persistence_markers() -> &'static [&'static str] {
    &[
        "software\\microsoft\\windows\\currentversion\\run",
        "schtasks",
        "/etc/systemd/system",
        "startup",
        "launchd",
        "cron",
        "rc.local",
    ]
}
