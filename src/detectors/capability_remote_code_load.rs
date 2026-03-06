use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::Location;

use super::DetectorFinding;
use super::index::EvidenceIndex;
use super::spec::{NETWORK_PRIMITIVE_MATCHERS, extract_urls, matching_token_strings};

const DETECTOR_ID_NETWORK: &str = "DETC-02.REMOTE_CODE_FETCH";
const DETECTOR_ID_FILESYSTEM: &str = "DETC-04.REMOTE_CODE_WRITE";
const DETECTOR_ID_DYNAMIC: &str = "DETC-03.REMOTE_CODE_LOAD";

const FILE_WRITE_PRIMITIVES: &[(&str, &str, &str)] = &[
    ("java/nio/file/Files", "copy", "java/nio/file/Files.copy"),
    ("java/nio/file/Files", "write", "java/nio/file/Files.write"),
    (
        "java/nio/file/Files",
        "newOutputStream",
        "java/nio/file/Files.newOutputStream",
    ),
    (
        "java/io/FileOutputStream",
        "<init>",
        "java/io/FileOutputStream.<init>",
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

const ENRICHMENT_TOKENS: &[&str] = &[
    "../",
    "..\\",
    ".jar",
    "mods/",
    "mods\\",
    "meta-inf/",
    "meta-inf\\",
];

#[derive(Default)]
struct ClassSignals {
    network_primitives: BTreeSet<String>,
    filesystem_primitives: BTreeSet<String>,
    dynamic_primitives: BTreeSet<String>,
    locations: Vec<Location>,
}

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let mut by_class: BTreeMap<(String, String), ClassSignals> = BTreeMap::new();

    let mut classes_with_network = BTreeSet::new();
    let mut classes_with_write = BTreeSet::new();
    let mut classes_with_dynamic = BTreeSet::new();

    for (owner, name, primitive_label) in NETWORK_PRIMITIVE_MATCHERS {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        for hit in hits {
            let key = class_key(&hit.location);
            classes_with_network.insert(key.clone());
            let signals = by_class.entry(key).or_default();
            signals
                .network_primitives
                .insert((*primitive_label).to_string());
            signals.locations.push(hit.location.clone());
        }
    }

    for (owner, name, primitive_label) in FILE_WRITE_PRIMITIVES {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        for hit in hits {
            let key = class_key(&hit.location);
            classes_with_write.insert(key.clone());
            let signals = by_class.entry(key).or_default();
            signals
                .filesystem_primitives
                .insert((*primitive_label).to_string());
            signals.locations.push(hit.location.clone());
        }
    }

    for (owner, name, primitive_label) in DYNAMIC_LOAD_PRIMITIVES {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        for hit in hits {
            let key = class_key(&hit.location);
            classes_with_dynamic.insert(key.clone());
            let signals = by_class.entry(key).or_default();
            signals
                .dynamic_primitives
                .insert((*primitive_label).to_string());
            signals.locations.push(hit.location.clone());
        }
    }

    let candidates: BTreeSet<(String, String)> = classes_with_network
        .intersection(&classes_with_write)
        .cloned()
        .collect();
    let candidates: BTreeSet<(String, String)> = candidates
        .intersection(&classes_with_dynamic)
        .cloned()
        .collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    let mut evidence_locations = Vec::new();
    let mut extracted_urls = BTreeSet::new();
    let mut extracted_file_paths = BTreeSet::new();
    let mut matched_network = BTreeSet::new();
    let mut matched_fs = BTreeSet::new();
    let mut matched_dyn = BTreeSet::new();

    for (entry_path, class_name) in &candidates {
        if let Some(signals) = by_class.get(&(entry_path.clone(), class_name.clone())) {
            evidence_locations.extend(signals.locations.iter().cloned());
            matched_network.extend(signals.network_primitives.iter().cloned());
            matched_fs.extend(signals.filesystem_primitives.iter().cloned());
            matched_dyn.extend(signals.dynamic_primitives.iter().cloned());
        }

        let strings = index
            .strings_in_class(entry_path, class_name)
            .iter()
            .map(|hit| hit.value.as_str());
        for url in extract_urls(strings) {
            extracted_urls.insert(url);
        }

        let path_tokens = matching_token_strings(
            index
                .strings_in_class(entry_path, class_name)
                .iter()
                .map(|hit| hit.value.as_str()),
            ENRICHMENT_TOKENS,
        );
        for token in path_tokens {
            extracted_file_paths.insert(token);
        }
    }

    let rationale = format!(
        "Matched remote code loading primitive combo in {} class(es): network=({}), file_write=({}), dynamic=({}).",
        candidates.len(),
        matched_network
            .iter()
            .cloned()
            .collect::<Vec<_>>()
            .join(", "),
        matched_fs.iter().cloned().collect::<Vec<_>>().join(", "),
        matched_dyn.iter().cloned().collect::<Vec<_>>().join(", "),
    );

    let extracted_file_paths_vec = extracted_file_paths.into_iter().collect::<Vec<_>>();

    vec![
        DetectorFinding {
            id: DETECTOR_ID_NETWORK.to_string(),
            title: "Remote payload fetch-and-load indicator detected".to_string(),
            category: "capability".to_string(),
            severity: "high".to_string(),
            rationale: rationale.clone(),
            evidence_locations: evidence_locations.clone(),
            extracted_urls: extracted_urls.into_iter().collect(),
            extracted_commands: Vec::new(),
            extracted_file_paths: extracted_file_paths_vec.clone(),
        },
        DetectorFinding {
            id: DETECTOR_ID_FILESYSTEM.to_string(),
            title: "Remote payload fetch-and-load indicator detected".to_string(),
            category: "capability".to_string(),
            severity: "high".to_string(),
            rationale: rationale.clone(),
            evidence_locations: evidence_locations.clone(),
            extracted_urls: Vec::new(),
            extracted_commands: Vec::new(),
            extracted_file_paths: extracted_file_paths_vec.clone(),
        },
        DetectorFinding {
            id: DETECTOR_ID_DYNAMIC.to_string(),
            title: "Remote payload fetch-and-load indicator detected".to_string(),
            category: "capability".to_string(),
            severity: "high".to_string(),
            rationale,
            evidence_locations,
            extracted_urls: Vec::new(),
            extracted_commands: Vec::new(),
            extracted_file_paths: extracted_file_paths_vec,
        },
    ]
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
                pc: Some(11),
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
    fn correlated_network_write_and_dynamic_load_emits_findings() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke("java/net/URL", "openStream", "sample.jar!/A.class", "A"),
                invoke("java/nio/file/Files", "copy", "sample.jar!/A.class", "A"),
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/A.class",
                    "A",
                ),
                string("../mods/payload.jar", "sample.jar!/A.class", "A"),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 3);
        let ids = findings
            .iter()
            .map(|f| f.id.as_str())
            .collect::<BTreeSet<_>>();
        assert!(ids.contains(DETECTOR_ID_NETWORK));
        assert!(ids.contains(DETECTOR_ID_FILESYSTEM));
        assert!(ids.contains(DETECTOR_ID_DYNAMIC));
        assert!(findings.iter().all(|f| f.severity == "high"));
        assert!(findings.iter().any(|f| {
            f.extracted_file_paths
                .contains(&"../mods/payload.jar".to_string())
        }));
    }

    #[test]
    fn missing_write_primitive_does_not_emit() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke("java/net/URL", "openStream", "sample.jar!/A.class", "A"),
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
        assert!(findings.is_empty());
    }

    #[test]
    fn primitives_in_different_classes_do_not_correlate() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke("java/net/URL", "openStream", "sample.jar!/A.class", "A"),
                invoke("java/nio/file/Files", "copy", "sample.jar!/B.class", "B"),
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/C.class",
                    "C",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);
        assert!(findings.is_empty());
    }
}
