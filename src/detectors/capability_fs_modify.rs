use std::collections::BTreeSet;

use crate::analysis::Location;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{contains_any_token, matching_token_strings};
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-04.FS_MODIFY";
const ENRICHMENT_TOKENS: &[&str] = &["../", "..\\", ".jar", "mods/", "meta-inf/", ".service"];
const HIGH_ESCALATION_TOKENS: &[&str] = &["../", "..\\", ".jar"];

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let zip_or_jar_primitives = [
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
    let generic_file_write_primitives = [
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
    ];

    let mut evidence_locations = Vec::new();
    let mut touched_classes = BTreeSet::new();
    let mut zip_or_jar_classes = BTreeSet::new();
    let mut matched_primitives = BTreeSet::new();
    let mut has_zip_or_jar_primitive = false;
    let mut has_generic_write_primitive = false;

    for (owner, name, primitive_label) in zip_or_jar_primitives {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        has_zip_or_jar_primitive = true;
        matched_primitives.insert(primitive_label.to_string());
        collect_hits(
            hits,
            &mut evidence_locations,
            &mut touched_classes,
            Some(&mut zip_or_jar_classes),
        );
    }

    for (owner, name, primitive_label) in generic_file_write_primitives {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        has_generic_write_primitive = true;
        matched_primitives.insert(primitive_label.to_string());
        collect_hits(hits, &mut evidence_locations, &mut touched_classes, None);
    }

    if evidence_locations.is_empty() {
        return Vec::new();
    }

    let mut extracted_file_paths = BTreeSet::new();
    let mut has_high_escalation_enrichment = false;

    for (entry_path, class_name) in &touched_classes {
        let class_strings = index.strings_in_class(entry_path, class_name);
        for token_match in matching_token_strings(
            class_strings.iter().map(|hit| hit.value.as_str()),
            ENRICHMENT_TOKENS,
        ) {
            extracted_file_paths.insert(token_match);
        }

        if zip_or_jar_classes.contains(&(entry_path.clone(), class_name.clone()))
            && class_strings
                .iter()
                .any(|hit| contains_any_token(&hit.value, HIGH_ESCALATION_TOKENS))
        {
            has_high_escalation_enrichment = true;
        }
    }

    let severity = if has_zip_or_jar_primitive {
        if has_high_escalation_enrichment {
            "high"
        } else {
            "med"
        }
    } else if has_generic_write_primitive {
        "low"
    } else {
        return Vec::new();
    };

    let rationale = if has_zip_or_jar_primitive {
        if has_high_escalation_enrichment {
            format!(
                "Matched jar/zip rewrite primitives ({}) with correlated traversal or .jar markers in the same class.",
                matched_primitives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        } else {
            format!(
                "Matched jar/zip rewrite primitives ({}), but no correlated traversal or .jar markers in the same class.",
                matched_primitives
                    .into_iter()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    } else {
        format!(
            "Matched generic filesystem write primitives ({}) without jar/zip rewrite primitives.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Jar/filesystem modification primitive detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls: Vec::new(),
        extracted_commands: Vec::new(),
        extracted_file_paths: extracted_file_paths.into_iter().collect(),
    }]
}

fn collect_hits(
    hits: &[InvokeHit],
    evidence_locations: &mut Vec<Location>,
    touched_classes: &mut BTreeSet<(String, String)>,
    mut subset_classes: Option<&mut BTreeSet<(String, String)>>,
) {
    for hit in hits {
        evidence_locations.push(hit.location.clone());
        let class_key = (
            hit.location.entry_path.clone(),
            hit.location.class_name.clone(),
        );
        touched_classes.insert(class_key.clone());
        if let Some(class_set) = subset_classes.as_mut() {
            class_set.insert(class_key);
        }
    }
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
                pc: Some(5),
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
    fn zip_put_next_entry_alone_is_med() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/util/zip/ZipOutputStream",
                "putNextEntry",
                "sample.jar!/Writer.class",
                "Writer",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
        assert!(findings[0].extracted_file_paths.is_empty());
        assert!(has_invoke_callsite(&findings[0]));
    }

    #[test]
    fn zip_with_traversal_or_jar_marker_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/util/zip/ZipOutputStream",
                    "putNextEntry",
                    "sample.jar!/Writer.class",
                    "Writer",
                ),
                string("../mods/payload.jar", "sample.jar!/Writer.class", "Writer"),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(
            findings[0].extracted_file_paths,
            vec!["../mods/payload.jar"]
        );
        assert!(has_invoke_callsite(&findings[0]));
    }

    #[test]
    fn file_output_stream_write_alone_is_low() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/io/FileOutputStream",
                "write",
                "sample.jar!/Writer.class",
                "Writer",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
        assert!(has_invoke_callsite(&findings[0]));
    }
}
