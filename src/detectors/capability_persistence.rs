use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::Location;

use super::DetectorFinding;
use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{contains_any_token, matching_token_strings};

const DETECTOR_ID: &str = "DETC-05.PERSISTENCE";
const PERSISTENCE_TOKENS: &[&str] = &[
    "software\\microsoft\\windows\\currentversion\\run",
    "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
    "schtasks",
    "crontab",
    "/etc/cron",
    "cron.d",
    "/etc/systemd/system",
    "systemctl",
    ".service",
];
const CONCRETE_HIGH_TOKENS: &[&str] = &[
    "software\\microsoft\\windows\\currentversion\\run",
    "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
    "/etc/systemd/system",
];
const PATH_EXTRACTION_TOKENS: &[&str] = &[
    "software\\microsoft\\windows\\currentversion\\run",
    "hkcu\\software\\microsoft\\windows\\currentversion\\run",
    "hklm\\software\\microsoft\\windows\\currentversion\\run",
    "/etc/cron",
    "cron.d",
    "/etc/systemd/system",
    ".service",
];
const COMMAND_EXTRACTION_TOKENS: &[&str] = &["schtasks", "systemctl"];

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let mut token_classes: BTreeMap<(String, String), Vec<Location>> = BTreeMap::new();
    let mut persistence_token_values = BTreeSet::new();

    for string_hit in index.all_strings() {
        if !contains_any_token(&string_hit.value, PERSISTENCE_TOKENS) {
            continue;
        }

        token_classes
            .entry(class_key(&string_hit.location))
            .or_default()
            .push(string_hit.location.clone());
        persistence_token_values.insert(string_hit.value.clone());
    }

    if token_classes.is_empty() {
        return Vec::new();
    }

    let exec_primitives = [
        ("java/lang/Runtime", "exec", "java/lang/Runtime.exec"),
        (
            "java/lang/ProcessBuilder",
            "start",
            "java/lang/ProcessBuilder.start",
        ),
    ];
    let write_primitives = [
        (
            "java/io/FileOutputStream",
            "<init>",
            "java/io/FileOutputStream.<init>",
        ),
        (
            "java/io/FileOutputStream",
            "write",
            "java/io/FileOutputStream.write",
        ),
        ("java/nio/file/Files", "write", "java/nio/file/Files.write"),
        (
            "java/nio/file/Files",
            "newOutputStream",
            "java/nio/file/Files.newOutputStream",
        ),
        ("java/nio/file/Files", "move", "java/nio/file/Files.move"),
        ("java/nio/file/Files", "copy", "java/nio/file/Files.copy"),
        (
            "java/nio/file/Files",
            "delete",
            "java/nio/file/Files.delete",
        ),
        (
            "java/util/zip/ZipOutputStream",
            "putNextEntry",
            "java/util/zip/ZipOutputStream.putNextEntry",
        ),
        (
            "java/util/zip/ZipOutputStream",
            "write",
            "java/util/zip/ZipOutputStream.write",
        ),
        (
            "java/util/zip/ZipOutputStream",
            "closeEntry",
            "java/util/zip/ZipOutputStream.closeEntry",
        ),
        (
            "java/util/jar/JarOutputStream",
            "<init>",
            "java/util/jar/JarOutputStream.<init>",
        ),
    ];

    let mut evidence_locations = token_classes
        .values()
        .flat_map(|locations| locations.iter().cloned())
        .collect::<Vec<_>>();

    let mut correlated_exec_classes = BTreeSet::new();
    let mut correlated_write_classes = BTreeSet::new();
    let mut matched_exec_primitives = BTreeSet::new();
    let mut matched_write_primitives = BTreeSet::new();

    for (owner, name, primitive_label) in exec_primitives {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        if collect_correlated_hits(
            hits,
            &token_classes,
            &mut evidence_locations,
            &mut correlated_exec_classes,
        ) {
            matched_exec_primitives.insert(primitive_label.to_string());
        }
    }

    for (owner, name, primitive_label) in write_primitives {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        if collect_correlated_hits(
            hits,
            &token_classes,
            &mut evidence_locations,
            &mut correlated_write_classes,
        ) {
            matched_write_primitives.insert(primitive_label.to_string());
        }
    }

    let persistence_values = persistence_token_values.iter().map(|value| value.as_str());
    let extracted_file_paths =
        matching_token_strings(persistence_values.clone(), PATH_EXTRACTION_TOKENS);
    let extracted_commands = matching_token_strings(persistence_values, COMMAND_EXTRACTION_TOKENS);

    let has_exec_correlation = !correlated_exec_classes.is_empty();
    let has_write_correlation = !correlated_write_classes.is_empty();
    let has_concrete_high_token = persistence_token_values
        .iter()
        .any(|value| contains_any_token(value, CONCRETE_HIGH_TOKENS));

    let severity = if has_exec_correlation && has_concrete_high_token {
        "high"
    } else if has_exec_correlation || has_write_correlation {
        "med"
    } else {
        "low"
    };

    let rationale = if severity == "high" {
        format!(
            "Matched persistence tokens with correlated exec primitive(s) ({}) and concrete path/key markers.",
            matched_exec_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if severity == "med" {
        let mut correlators = Vec::new();
        if !matched_exec_primitives.is_empty() {
            correlators.push(format!(
                "exec primitives: {}",
                matched_exec_primitives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        if !matched_write_primitives.is_empty() {
            correlators.push(format!(
                "write primitives: {}",
                matched_write_primitives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
        format!(
            "Matched persistence tokens with same-class correlation to {}.",
            correlators.join("; ")
        )
    } else {
        "Matched persistence tokens without same-class exec or write primitive correlation."
            .to_string()
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Persistence indicator detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls: Vec::new(),
        extracted_commands,
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
    use crate::analysis::{BytecodeEvidence, BytecodeEvidenceItem, Location, LocationMethod};

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
                pc: Some(17),
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
            items: vec![string("crontab -l", "sample.jar!/Persist.class", "Persist")],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
        assert!(findings[0].extracted_commands.is_empty());
    }

    #[test]
    fn token_plus_write_escalates_to_med() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    "/etc/cron/demo-task",
                    "sample.jar!/Persist.class",
                    "Persist",
                ),
                invoke(
                    "java/nio/file/Files",
                    "write",
                    "sample.jar!/Persist.class",
                    "Persist",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
        assert!(has_invoke_callsite(&findings[0]));
    }

    #[test]
    fn token_plus_exec_with_concrete_marker_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "sample.jar!/Persist.class",
                    "Persist",
                ),
                invoke(
                    "java/lang/Runtime",
                    "exec",
                    "sample.jar!/Persist.class",
                    "Persist",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert!(has_invoke_callsite(&findings[0]));
        assert_eq!(
            findings[0].extracted_file_paths,
            vec!["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"]
        );
    }
}
