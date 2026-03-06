use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::Location;

use super::DetectorFinding;
use super::index::EvidenceIndex;
use super::spec::{NETWORK_PRIMITIVE_MATCHERS, extract_urls};

const DETECTOR_ID: &str = "DETC-03.BASE64_STAGER";

const MIN_B64_LEN: usize = 180;

const BASE64_PRIMITIVES: &[(&str, &str, &str)] = &[
    (
        "java/util/Base64",
        "getDecoder",
        "java/util/Base64.getDecoder",
    ),
    (
        "java/util/Base64",
        "getMimeDecoder",
        "java/util/Base64.getMimeDecoder",
    ),
    (
        "java/util/Base64",
        "getUrlDecoder",
        "java/util/Base64.getUrlDecoder",
    ),
    (
        "java/util/Base64$Decoder",
        "decode",
        "java/util/Base64$Decoder.decode",
    ),
];

const DYNAMIC_LOAD_PRIMITIVES: &[(&str, &str, &str)] = &[
    (
        "java/net/URLClassLoader",
        "<init>",
        "java/net/URLClassLoader.<init>",
    ),
    (
        "java/net/URLClassLoader",
        "newInstance",
        "java/net/URLClassLoader.newInstance",
    ),
    (
        "java/lang/ClassLoader",
        "defineClass",
        "java/lang/ClassLoader.defineClass",
    ),
    (
        "java/lang/invoke/MethodHandles$Lookup",
        "defineClass",
        "java/lang/invoke/MethodHandles$Lookup.defineClass",
    ),
];

#[derive(Default)]
struct ClassSignals {
    locations: Vec<Location>,
    base64_values: BTreeSet<String>,
    base64_primitives: BTreeSet<String>,
    dynamic_primitives: BTreeSet<String>,
    network_primitives: BTreeSet<String>,
}

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let mut by_class: BTreeMap<(String, String), ClassSignals> = BTreeMap::new();

    // First collect long base64-like literals by class.
    for string_hit in index.all_strings() {
        if !is_base64ish_long(&string_hit.value) {
            continue;
        }

        let key = class_key(&string_hit.location);
        let entry = by_class.entry(key).or_default();
        entry.locations.push(string_hit.location.clone());
        if entry.base64_values.len() < 3 {
            entry
                .base64_values
                .insert(truncate_string(string_hit.value.as_str(), 220));
        }
    }

    if by_class.is_empty() {
        return Vec::new();
    }

    // Collect correlated base64 decode primitives.
    for (owner, name, primitive_label) in BASE64_PRIMITIVES {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        for hit in hits {
            let key = class_key(&hit.location);
            let Some(entry) = by_class.get_mut(&key) else {
                continue;
            };
            entry.locations.push(hit.location.clone());
            entry
                .base64_primitives
                .insert((*primitive_label).to_string());
        }
    }

    // Collect correlated dynamic loading primitives.
    for (owner, name, primitive_label) in DYNAMIC_LOAD_PRIMITIVES {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        for hit in hits {
            let key = class_key(&hit.location);
            let Some(entry) = by_class.get_mut(&key) else {
                continue;
            };
            entry.locations.push(hit.location.clone());
            entry
                .dynamic_primitives
                .insert((*primitive_label).to_string());
        }
    }

    // Collect any correlated network primitives (optional enrichment).
    for (owner, name, primitive_label) in NETWORK_PRIMITIVE_MATCHERS {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        for hit in hits {
            let key = class_key(&hit.location);
            let Some(entry) = by_class.get_mut(&key) else {
                continue;
            };
            entry.locations.push(hit.location.clone());
            entry
                .network_primitives
                .insert((*primitive_label).to_string());
        }
    }

    let mut matched_classes = Vec::new();
    let mut evidence_locations = Vec::new();
    let mut extracted_urls = BTreeSet::new();
    let mut extracted_file_paths = Vec::new();
    let mut matched_base64_primitives = BTreeSet::new();
    let mut matched_dynamic_primitives = BTreeSet::new();
    let mut matched_network_primitives = BTreeSet::new();
    let mut base64_samples = BTreeSet::new();

    for ((entry_path, class_name), signals) in &by_class {
        if signals.base64_values.is_empty() {
            continue;
        }
        if signals.base64_primitives.is_empty() {
            continue;
        }
        if signals.dynamic_primitives.is_empty() {
            continue;
        }

        matched_classes.push((entry_path.clone(), class_name.clone()));
        evidence_locations.extend(signals.locations.iter().cloned());
        matched_base64_primitives.extend(signals.base64_primitives.iter().cloned());
        matched_dynamic_primitives.extend(signals.dynamic_primitives.iter().cloned());
        matched_network_primitives.extend(signals.network_primitives.iter().cloned());
        base64_samples.extend(signals.base64_values.iter().cloned());

        let strings = index
            .strings_in_class(entry_path, class_name)
            .iter()
            .map(|hit| hit.value.as_str());
        for url in extract_urls(strings) {
            extracted_urls.insert(url);
        }
    }

    if matched_classes.is_empty() {
        return Vec::new();
    }

    extracted_file_paths.extend(base64_samples.into_iter());

    let rationale = format!(
        "Found long base64-like payload(s) with Base64 decode primitive(s) ({}) and dynamic code loading primitive(s) ({}). Network primitives observed: ({}).",
        matched_base64_primitives
            .into_iter()
            .collect::<Vec<_>>()
            .join(", "),
        matched_dynamic_primitives
            .into_iter()
            .collect::<Vec<_>>()
            .join(", "),
        matched_network_primitives
            .into_iter()
            .collect::<Vec<_>>()
            .join(", "),
    );

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Base64 staged payload indicator detected".to_string(),
        category: "capability".to_string(),
        severity: "high".to_string(),
        rationale,
        evidence_locations,
        extracted_urls: extracted_urls.into_iter().collect(),
        extracted_commands: Vec::new(),
        // Reuse file_paths slot to carry short base64 samples (this is surfaced to the AI summary).
        extracted_file_paths,
    }]
}

fn is_base64ish_long(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < MIN_B64_LEN {
        return false;
    }
    // Reject Windows-style paths; base64 alphabet does not include backslash.
    if trimmed.contains('\\') {
        return false;
    }

    let mut total = 0usize;
    let mut base64ish = 0usize;
    for ch in trimmed.chars() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        total += 1;
        if ch.is_ascii_alphanumeric()
            || ch == '+'
            || ch == '/'
            || ch == '='
            || ch == '-'
            || ch == '_'
        {
            base64ish += 1;
        }
    }

    total >= MIN_B64_LEN && base64ish * 100 / total >= 95
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

fn class_key(location: &Location) -> (String, String) {
    (location.entry_path.clone(), location.class_name.clone())
}

#[cfg(test)]
mod tests {
    use crate::analysis::{BytecodeEvidence, BytecodeEvidenceItem, LocationMethod};

    use super::*;

    fn invoke(owner: &str, name: &str, entry_path: &str, class_name: &str) -> BytecodeEvidenceItem {
        BytecodeEvidenceItem::InvokeResolved {
            owner: owner.to_string(),
            name: name.to_string(),
            descriptor: "()V".to_string(),
            location: Location {
                entry_path: entry_path.to_string(),
                class_name: class_name.to_string(),
                method: Some(LocationMethod {
                    name: "fixture".to_string(),
                    descriptor: "()V".to_string(),
                }),
                pc: Some(13),
            },
        }
    }

    fn string(value: &str, entry_path: &str, class_name: &str) -> BytecodeEvidenceItem {
        BytecodeEvidenceItem::CpStringLiteral {
            value: value.to_string(),
            location: Location {
                entry_path: entry_path.to_string(),
                class_name: class_name.to_string(),
                method: None,
                pc: None,
            },
        }
    }

    #[test]
    fn base64_decode_and_dynamic_load_in_same_class_emits_high() {
        let long_b64 = "A".repeat(220);
        let evidence = BytecodeEvidence {
            items: vec![
                string(long_b64.as_str(), "sample.jar!/A.class", "A"),
                invoke("java/util/Base64", "getDecoder", "sample.jar!/A.class", "A"),
                invoke(
                    "java/util/Base64$Decoder",
                    "decode",
                    "sample.jar!/A.class",
                    "A",
                ),
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/A.class",
                    "A",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, DETECTOR_ID);
        assert_eq!(findings[0].severity, "high");
        assert!(!findings[0].extracted_file_paths.is_empty());
    }

    #[test]
    fn base64_with_slash_characters_is_detected() {
        // Base64 alphabet commonly includes '/', so the detector must not reject it.
        let long_b64 = "QUJDREVGR0g=/+".repeat(30);
        assert!(long_b64.contains('/'));

        let evidence = BytecodeEvidence {
            items: vec![
                string(long_b64.as_str(), "sample.jar!/A.class", "A"),
                invoke("java/util/Base64", "getDecoder", "sample.jar!/A.class", "A"),
                invoke(
                    "java/util/Base64$Decoder",
                    "decode",
                    "sample.jar!/A.class",
                    "A",
                ),
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/A.class",
                    "A",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, DETECTOR_ID);
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn base64_without_dynamic_load_does_not_emit() {
        let long_b64 = "A".repeat(220);
        let evidence = BytecodeEvidence {
            items: vec![
                string(long_b64.as_str(), "sample.jar!/A.class", "A"),
                invoke(
                    "java/util/Base64$Decoder",
                    "decode",
                    "sample.jar!/A.class",
                    "A",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);
        assert!(findings.is_empty());
    }
}
