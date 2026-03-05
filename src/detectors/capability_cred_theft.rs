use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::Location;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{
    contains_any_token, extract_urls, matching_token_strings, NETWORK_PRIMITIVE_MATCHERS,
};
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-08.CREDENTIAL_THEFT";
const CREDENTIAL_TOKEN_MARKERS: &[&str] = &[
    // High-signal browser/app credential artifacts.
    "login data",
    "web data",
    "logins.json",
    "key4.db",
    "cookies.sqlite",
    // Token stores (keep these broad, but validate before firing).
    "local storage",
    "leveldb",
    // Very generic; can appear in HTTP libraries. Treat as weak unless path/context is present.
    "cookies",
];
const CREDENTIAL_PATH_MARKERS: &[&str] = &[
    "login data",
    "web data",
    "logins.json",
    "key4.db",
    "cookies.sqlite",
    "local storage",
    "leveldb",
    "network/cookies",
    "network\\cookies",
];

#[derive(Default)]
struct TokenEvidence {
    locations: Vec<Location>,
    values: BTreeSet<String>,
}

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let mut token_classes: BTreeMap<(String, String), TokenEvidence> = BTreeMap::new();

    for string_hit in index.all_strings() {
        if !contains_any_token(&string_hit.value, CREDENTIAL_TOKEN_MARKERS) {
            continue;
        }

        let evidence = token_classes
            .entry(class_key(&string_hit.location))
            .or_default();
        evidence.locations.push(string_hit.location.clone());
        evidence.values.insert(string_hit.value.clone());
    }

    if token_classes.is_empty() {
        return Vec::new();
    }

    let strong_token_classes = token_classes
        .iter()
        .filter(|(_, evidence)| has_strong_credential_marker(&evidence.values))
        .map(|(key, _)| key.clone())
        .collect::<BTreeSet<_>>();

    // If we don't see strong local credential-store markers in any class, don't fire.
    // This avoids false positives from HTTP cookie parsing libraries, etc.
    if strong_token_classes.is_empty() {
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

    let mut evidence_locations = strong_token_classes
        .iter()
        .filter_map(|key| token_classes.get(key))
        .flat_map(|evidence| evidence.locations.iter().cloned())
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
            &strong_token_classes,
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
            &strong_token_classes,
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
    } else if has_correlated_network {
        "low"
    } else {
        return Vec::new();
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
        "Matched strong credential/token markers with same-class network correlation, but no file-read primitive in the same class."
            .to_string()
    };

    let extracted_file_paths = matching_token_strings(
        strong_token_classes
            .iter()
            .filter_map(|key| token_classes.get(key))
            .flat_map(|evidence| evidence.values.iter().map(|value| value.as_str())),
        CREDENTIAL_PATH_MARKERS,
    );
    let mut extracted_url_set = BTreeSet::new();
    for (entry_path, class_name) in token_classes.keys() {
        if !strong_token_classes.contains(&(entry_path.clone(), class_name.clone())) {
            continue;
        }
        let strings = index
            .strings_in_class(entry_path, class_name)
            .iter()
            .map(|hit| hit.value.as_str());
        for url in extract_urls(strings) {
            extracted_url_set.insert(url);
        }
    }
    let extracted_urls = extracted_url_set.into_iter().collect::<Vec<_>>();

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

fn has_strong_credential_marker(token_values: &BTreeSet<String>) -> bool {
    for value in token_values {
        let normalized = value.to_ascii_lowercase();

        // Strong local credential-store file names (common in stealers).
        if contains_any_token(
            &normalized,
            &[
                "login data",
                "web data",
                "logins.json",
                "key4.db",
                "cookies.sqlite",
            ],
        ) {
            return true;
        }

        // Token stores are strong only when the LevelDB context is explicit.
        if normalized.contains("local storage") && normalized.contains("leveldb") {
            return true;
        }

        // "cookies" is extremely generic (HTTP parsing, etc). Only treat it as strong
        // when it looks like a browser cookie database path.
        if normalized.contains("cookies")
            && (normalized.contains("network/cookies")
                || normalized.contains("network\\cookies")
                || normalized.contains("default/network/cookies")
                || normalized.contains("default\\network\\cookies")
                || normalized.contains("default/cookies")
                || normalized.contains("default\\cookies")
                || (normalized.contains("/cookies") || normalized.contains("\\cookies"))
                    && (normalized.contains("user data")
                        || normalized.contains("appdata")
                        || normalized.contains("mozilla")
                        || normalized.contains("chrome")
                        || normalized.contains("edge")
                        || normalized.contains("firefox")
                        || normalized.contains("profile")))
        {
            return true;
        }
    }

    false
}

fn collect_correlated_hits(
    hits: &[InvokeHit],
    allowed_classes: &BTreeSet<(String, String)>,
    evidence_locations: &mut Vec<Location>,
    correlated_classes: &mut BTreeSet<(String, String)>,
) -> bool {
    let mut correlated = false;

    for hit in hits {
        let key = class_key(&hit.location);
        if !allowed_classes.contains(&key) {
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

        assert!(findings.is_empty());
    }

    #[test]
    fn token_plus_file_read_escalates_to_med() {
        let evidence = BytecodeEvidence {
            items: vec![
                string("Login Data", "sample.jar!/Steal.class", "Steal"),
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
        assert_eq!(findings[0].extracted_file_paths, vec!["Login Data"]);
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
                string("Login Data", "sample.jar!/Steal.class", "Steal"),
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

    #[test]
    fn cookies_without_browser_path_does_not_trigger() {
        let evidence = BytecodeEvidence {
            items: vec![
                string("Cookies", "sample.jar!/Jetty.class", "Jetty"),
                invoke(
                    "java/io/FileInputStream",
                    "<init>",
                    "sample.jar!/Jetty.class",
                    "Jetty",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert!(findings.is_empty());
    }

    #[test]
    fn cookie_db_path_with_file_read_triggers() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    "Default/Network/Cookies",
                    "sample.jar!/Steal.class",
                    "Steal",
                ),
                invoke(
                    "java/io/FileInputStream",
                    "<init>",
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
            vec!["Default/Network/Cookies"]
        );
        assert!(has_invoke_callsite(&findings[0]));
    }

    #[test]
    fn local_state_does_not_trigger() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    "Local State",
                    "sample.jar!/MaybeLauncher.class",
                    "MaybeLauncher",
                ),
                invoke(
                    "java/io/FileInputStream",
                    "<init>",
                    "sample.jar!/MaybeLauncher.class",
                    "MaybeLauncher",
                ),
                invoke(
                    "java/net/URL",
                    "openConnection",
                    "sample.jar!/MaybeLauncher.class",
                    "MaybeLauncher",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert!(findings.is_empty());
    }

    #[test]
    fn user_data_does_not_trigger() {
        let evidence = BytecodeEvidence {
            items: vec![
                string("User Data", "sample.jar!/Steal.class", "Steal"),
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

        assert!(findings.is_empty());
    }

    #[test]
    fn launcher_profiles_json_does_not_trigger() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    ".minecraft/launcher_profiles.json",
                    "sample.jar!/MaybeLauncher.class",
                    "MaybeLauncher",
                ),
                invoke(
                    "java/io/FileInputStream",
                    "<init>",
                    "sample.jar!/MaybeLauncher.class",
                    "MaybeLauncher",
                ),
                invoke(
                    "java/net/URLConnection",
                    "connect",
                    "sample.jar!/MaybeLauncher.class",
                    "MaybeLauncher",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert!(findings.is_empty());
    }
}
