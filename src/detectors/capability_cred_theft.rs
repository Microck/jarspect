use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::Location;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{
    contains_any_token, extract_urls, matching_token_strings, NETWORK_PRIMITIVE_MATCHERS,
};
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-08.CREDENTIAL_THEFT";
const CREDENTIAL_TOKEN_MARKERS: &[&str] = &[
    "discord",
    "local storage",
    "leveldb",
    "token",
    "login data",
    "cookies",
    "local state",
    "user data",
    "default",
    ".minecraft",
    "launcher_profiles.json",
    "accounts.json",
    "session",
];
const CREDENTIAL_PATH_MARKERS: &[&str] = &[
    "local storage",
    "leveldb",
    "login data",
    "cookies",
    "local state",
    "user data",
    "default",
    ".minecraft",
    "launcher_profiles.json",
    "accounts.json",
];

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let mut token_classes: BTreeMap<(String, String), Vec<Location>> = BTreeMap::new();
    let mut token_values = BTreeSet::new();

    for string_hit in index.all_strings() {
        if !contains_any_token(&string_hit.value, CREDENTIAL_TOKEN_MARKERS) {
            continue;
        }

        token_classes
            .entry(class_key(&string_hit.location))
            .or_default()
            .push(string_hit.location.clone());
        token_values.insert(string_hit.value.clone());
    }

    if token_classes.is_empty() {
        return Vec::new();
    }

    let file_read_primitives = [
        (
            "java/nio/file/Files",
            "readAllBytes",
            "java/nio/file/Files.readAllBytes",
        ),
        (
            "java/nio/file/Files",
            "newInputStream",
            "java/nio/file/Files.newInputStream",
        ),
        (
            "java/io/FileInputStream",
            "<init>",
            "java/io/FileInputStream.<init>",
        ),
    ];

    let mut evidence_locations = token_classes
        .values()
        .flat_map(|locations| locations.iter().cloned())
        .collect::<Vec<_>>();

    let mut correlated_read_classes = BTreeSet::new();
    let mut correlated_network_classes = BTreeSet::new();
    let mut matched_read_primitives = BTreeSet::new();
    let mut matched_network_primitives = BTreeSet::new();

    for (owner, name, primitive_label) in file_read_primitives {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        if collect_correlated_hits(
            hits,
            &token_classes,
            &mut evidence_locations,
            &mut correlated_read_classes,
        ) {
            matched_read_primitives.insert(primitive_label.to_string());
        }
    }

    for (owner, name, primitive_label) in NETWORK_PRIMITIVE_MATCHERS {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        if collect_correlated_hits(
            hits,
            &token_classes,
            &mut evidence_locations,
            &mut correlated_network_classes,
        ) {
            matched_network_primitives.insert((*primitive_label).to_string());
        }
    }

    let has_correlated_read = !correlated_read_classes.is_empty();
    let has_correlated_network = !correlated_network_classes.is_empty();
    let severity = if has_correlated_read && has_correlated_network {
        "high"
    } else if has_correlated_read {
        "med"
    } else {
        "low"
    };

    let rationale = if severity == "high" {
        format!(
            "Matched credential/token markers with same-class file-read primitives ({}) and network primitives ({}).",
            matched_read_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", "),
            matched_network_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if severity == "med" {
        format!(
            "Matched credential/token markers with same-class file-read primitive(s) ({}).",
            matched_read_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        "Matched credential/token markers without same-class file-read correlation.".to_string()
    };

    let extracted_file_paths = matching_token_strings(
        token_values.iter().map(|value| value.as_str()),
        CREDENTIAL_PATH_MARKERS,
    );
    let extracted_urls = extract_urls(index.all_strings().map(|hit| hit.value.as_str()));

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Credential/token theft indicator detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls,
        extracted_commands: Vec::new(),
        extracted_file_paths,
    }]
}

fn collect_correlated_hits(
    hits: &[InvokeHit],
    token_classes: &BTreeMap<(String, String), Vec<Location>>,
    evidence_locations: &mut Vec<Location>,
    correlated_classes: &mut BTreeSet<(String, String)>,
) -> bool {
    let mut correlated = false;

    for hit in hits {
        let key = class_key(&hit.location);
        if !token_classes.contains_key(&key) {
            continue;
        }

        correlated = true;
        correlated_classes.insert(key);
        evidence_locations.push(hit.location.clone());
    }

    correlated
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
                pc: Some(27),
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

    fn has_invoke_callsite(finding: &DetectorFinding) -> bool {
        finding.evidence_locations.iter().any(|location| {
            location
                .method
                .as_ref()
                .map(|method| method.name == "fixture")
                .unwrap_or(false)
                && location.pc.is_some()
        })
    }

    #[test]
    fn token_only_stays_low() {
        let evidence = BytecodeEvidence {
            items: vec![string(
                "discord Local Storage leveldb token",
                "sample.jar!/Steal.class",
                "Steal",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
    }

    #[test]
    fn token_plus_file_read_escalates_to_med() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    ".minecraft/launcher_profiles.json",
                    "sample.jar!/Steal.class",
                    "Steal",
                ),
                invoke(
                    "java/nio/file/Files",
                    "readAllBytes",
                    "sample.jar!/Steal.class",
                    "Steal",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
        assert_eq!(
            findings[0].extracted_file_paths,
            vec![".minecraft/launcher_profiles.json"]
        );
        assert!(has_invoke_callsite(&findings[0]));
    }

    #[test]
    fn token_plus_network_without_file_read_stays_low() {
        let evidence = BytecodeEvidence {
            items: vec![
                string("Login Data", "sample.jar!/Steal.class", "Steal"),
                invoke(
                    "java/net/URL",
                    "openConnection",
                    "sample.jar!/Steal.class",
                    "Steal",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
    }

    #[test]
    fn token_plus_file_read_plus_network_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                string("Cookies", "sample.jar!/Steal.class", "Steal"),
                string(
                    "upload to https://example.invalid/collector",
                    "sample.jar!/Steal.class",
                    "Steal",
                ),
                invoke(
                    "java/io/FileInputStream",
                    "<init>",
                    "sample.jar!/Steal.class",
                    "Steal",
                ),
                invoke(
                    "java/net/URLConnection",
                    "connect",
                    "sample.jar!/Steal.class",
                    "Steal",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(
            findings[0].extracted_urls,
            vec!["https://example.invalid/collector"]
        );
        assert!(has_invoke_callsite(&findings[0]));
    }
}
