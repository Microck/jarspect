use std::collections::BTreeSet;

use crate::analysis::Location;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::contains_any_token;
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-03.DYNAMIC_LOAD";
const SENSITIVE_DYNAMIC_TOKENS: &[&str] =
    &["java/lang/runtime", "exec", "defineclass", "loadlibrary"];

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let primitive_matchers = [
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
        ("java/lang/Class", "forName", "java/lang/Class.forName"),
        (
            "java/lang/reflect/Method",
            "invoke",
            "java/lang/reflect/Method.invoke",
        ),
        (
            "java/lang/reflect/Constructor",
            "newInstance",
            "java/lang/reflect/Constructor.newInstance",
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

    if evidence_locations.is_empty() {
        return Vec::new();
    }

    let mut correlated_sensitive_strings = BTreeSet::new();
    for (entry_path, class_name) in &touched_classes {
        for string_hit in index.strings_in_class(entry_path, class_name) {
            if contains_any_token(&string_hit.value, SENSITIVE_DYNAMIC_TOKENS) {
                correlated_sensitive_strings.insert(string_hit.value.clone());
            }
        }
    }

    let severity = if correlated_sensitive_strings.is_empty() {
        "med"
    } else {
        "high"
    };
    let extracted_file_paths = evidence_locations
        .iter()
        .map(|location| location.entry_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let rationale = if correlated_sensitive_strings.is_empty() {
        format!(
            "Matched dynamic-loading primitives ({}), without correlated sensitive class/method tokens in the same class.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "Matched dynamic-loading primitives ({}) with {} correlated sensitive string token(s) in the same class.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", "),
            correlated_sensitive_strings.len()
        )
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Dynamic loading primitive detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls: Vec::new(),
        extracted_commands: Vec::new(),
        extracted_file_paths,
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
                pc: Some(9),
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
    fn primitive_without_sensitive_strings_stays_med() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/lang/Class",
                "forName",
                "sample.jar!/Dyn.class",
                "Dyn",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");

        let has_invoke_location = findings[0].evidence_locations.iter().any(|location| {
            location
                .method
                .as_ref()
                .map(|method| method.name == "fixture")
                .unwrap_or(false)
                && location.pc.is_some()
        });
        assert!(has_invoke_location);
    }

    #[test]
    fn correlated_sensitive_string_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/lang/reflect/Method",
                    "invoke",
                    "sample.jar!/Dyn.class",
                    "Dyn",
                ),
                string("java/lang/Runtime", "sample.jar!/Dyn.class", "Dyn"),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
    }

    #[test]
    fn unrelated_class_string_does_not_escalate() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/Dyn.class",
                    "Dyn",
                ),
                string("defineClass", "sample.jar!/Other.class", "Other"),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
    }
}
