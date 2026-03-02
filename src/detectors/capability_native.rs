use std::collections::BTreeSet;

use crate::analysis::{ArchiveEntry, Location};

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::contains_any_token;
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-07.NATIVE_LOAD";
const ABS_OR_TEMP_PATH_TOKENS: &[&str] = &[
    "/tmp/",
    "/var/tmp/",
    "/private/tmp/",
    "\\temp\\",
    "c:\\users\\",
    "c:/users/",
    "/users/",
];
const NATIVE_LIBRARY_EXTENSIONS: &[&str] = &[".dll", ".so", ".dylib", ".jnilib"];

pub fn detect(index: &EvidenceIndex, entries: &[ArchiveEntry]) -> Vec<DetectorFinding> {
    let primitive_matchers = [
        ("java/lang/System", "load", "java/lang/System.load"),
        (
            "java/lang/System",
            "loadLibrary",
            "java/lang/System.loadLibrary",
        ),
    ];

    let mut evidence_locations = Vec::new();
    let mut touched_classes = BTreeSet::new();
    let mut matched_primitives = BTreeSet::new();

    for (owner, name, primitive_label) in primitive_matchers {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        matched_primitives.insert(primitive_label.to_string());
        collect_hits(hits, &mut evidence_locations, &mut touched_classes);
    }

    let embedded_native_paths = collect_embedded_native_paths(entries);
    let mut has_path_correlation = false;
    for (entry_path, class_name) in &touched_classes {
        if index
            .strings_in_class(entry_path, class_name)
            .iter()
            .any(|string_hit| contains_any_token(&string_hit.value, ABS_OR_TEMP_PATH_TOKENS))
        {
            has_path_correlation = true;
            break;
        }
    }

    if evidence_locations.is_empty() && embedded_native_paths.is_empty() {
        return Vec::new();
    }

    for path in &embedded_native_paths {
        evidence_locations.push(archive_entry_location(path));
    }

    let has_invoke_primitive = !matched_primitives.is_empty();
    let has_embedded_native = !embedded_native_paths.is_empty();
    let severity = if has_invoke_primitive {
        if has_embedded_native || has_path_correlation {
            "high"
        } else {
            "med"
        }
    } else {
        "low"
    };

    let rationale = if has_invoke_primitive {
        if has_embedded_native {
            format!(
                "Matched native loading primitives ({}) with {} embedded native archive entr{}.",
                matched_primitives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", "),
                embedded_native_paths.len(),
                if embedded_native_paths.len() == 1 {
                    "y"
                } else {
                    "ies"
                }
            )
        } else if has_path_correlation {
            format!(
                "Matched native loading primitives ({}) with same-class absolute/temp path markers.",
                matched_primitives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            format!(
                "Matched native loading primitives ({}), but found no embedded native archive entries or suspicious native load path markers.",
                matched_primitives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    } else {
        format!(
            "Found {} embedded native archive entr{} without System.load/loadLibrary callsites.",
            embedded_native_paths.len(),
            if embedded_native_paths.len() == 1 {
                "y"
            } else {
                "ies"
            }
        )
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Native library loading indicator detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls: Vec::new(),
        extracted_commands: Vec::new(),
        extracted_file_paths: embedded_native_paths,
    }]
}

fn collect_hits(
    hits: &[InvokeHit],
    evidence_locations: &mut Vec<Location>,
    touched_classes: &mut BTreeSet<(String, String)>,
) {
    for hit in hits {
        evidence_locations.push(hit.location.clone());
        touched_classes.insert((
            hit.location.entry_path.clone(),
            hit.location.class_name.clone(),
        ));
    }
}

fn collect_embedded_native_paths(entries: &[ArchiveEntry]) -> Vec<String> {
    entries
        .iter()
        .filter(|entry| {
            let normalized = entry.path.to_ascii_lowercase();
            NATIVE_LIBRARY_EXTENSIONS
                .iter()
                .any(|ext| normalized.ends_with(ext))
        })
        .map(|entry| entry.path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>()
}

fn archive_entry_location(entry_path: &str) -> Location {
    Location {
        entry_path: entry_path.to_string(),
        class_name: "<archive-entry>".to_string(),
        method: None,
        pc: None,
    }
}

#[cfg(test)]
mod tests {
    use crate::analysis::{BytecodeEvidence, BytecodeEvidenceItem, LocationMethod};

    use super::*;

    fn invoke(owner: &str, name: &str, entry_path: &str, class_name: &str) -> BytecodeEvidenceItem {
        BytecodeEvidenceItem::InvokeResolved {
            owner: owner.to_string(),
            name: name.to_string(),
            descriptor: "(Ljava/lang/String;)V".to_string(),
            location: Location {
                entry_path: entry_path.to_string(),
                class_name: class_name.to_string(),
                method: Some(LocationMethod {
                    name: "fixture".to_string(),
                    descriptor: "()V".to_string(),
                }),
                pc: Some(21),
            },
        }
    }

    fn archive_entry(path: &str) -> ArchiveEntry {
        ArchiveEntry {
            path: path.to_string(),
            bytes: vec![0_u8],
            text: None,
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
    fn system_load_without_embedded_native_stays_med() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/lang/System",
                "loadLibrary",
                "sample.jar!/Native.class",
                "Native",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index, &[]);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
        assert!(findings[0].extracted_file_paths.is_empty());
        assert!(has_invoke_callsite(&findings[0]));
    }

    #[test]
    fn system_load_with_embedded_native_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/lang/System",
                "load",
                "sample.jar!/Native.class",
                "Native",
            )],
        };
        let entries = vec![
            archive_entry("sample.jar!/native/dummy.dll"),
            archive_entry("sample.jar!/assets/demo.txt"),
        ];

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index, &entries);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(
            findings[0].extracted_file_paths,
            vec!["sample.jar!/native/dummy.dll"]
        );
        assert!(has_invoke_callsite(&findings[0]));
    }
}
