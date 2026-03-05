use std::collections::BTreeSet;

use crate::analysis::Location;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{extract_urls, NETWORK_PRIMITIVE_MATCHERS};
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-03.DYNAMIC_LOAD";

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    // Only treat explicit class loading/definition primitives as "dynamic loading".
    // Reflection alone (Class.forName / Method.invoke) is extremely common in benign code.
    let loader_primitives = [
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

    let mut evidence_locations = Vec::new();
    let mut touched_classes = BTreeSet::new();
    let mut matched_loader_primitives = BTreeSet::new();

    for (owner, name, primitive_label) in loader_primitives {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        matched_loader_primitives.insert(primitive_label.to_string());
        collect_hits(hits, &mut evidence_locations, &mut touched_classes);
    }

    if evidence_locations.is_empty() {
        return Vec::new();
    }

    let mut correlated_network_primitives = BTreeSet::new();
    for (owner, name, primitive_label) in NETWORK_PRIMITIVE_MATCHERS {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        for hit in hits {
            let key = (
                hit.location.entry_path.clone(),
                hit.location.class_name.clone(),
            );
            if !touched_classes.contains(&key) {
                continue;
            }
            correlated_network_primitives.insert((*primitive_label).to_string());
            evidence_locations.push(hit.location.clone());
        }
    }

    let mut extracted_urls = BTreeSet::new();
    for (entry_path, class_name) in &touched_classes {
        let strings = index
            .strings_in_class(entry_path, class_name)
            .iter()
            .map(|hit| hit.value.as_str());
        for url in extract_urls(strings) {
            extracted_urls.insert(url);
        }
    }

    // Baseline: medium (explicit loader primitives). Escalate to high if we can correlate it
    // with outbound networking or literal URLs in the same class.
    let severity = if !correlated_network_primitives.is_empty() || !extracted_urls.is_empty() {
        "high"
    } else {
        "med"
    };

    let primitive_labels = matched_loader_primitives
        .into_iter()
        .collect::<Vec<_>>()
        .join(", ");
    let extracted_file_paths = evidence_locations
        .iter()
        .map(|location| location.entry_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let rationale = if !extracted_urls.is_empty() {
        format!(
            "Matched explicit dynamic code loading primitives ({primitive_labels}) with correlated URL evidence in the same class."
        )
    } else if !correlated_network_primitives.is_empty() {
        format!(
            "Matched explicit dynamic code loading primitives ({primitive_labels}) with correlated outbound networking primitive(s): {}.",
            correlated_network_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "Matched explicit dynamic code loading primitives ({primitive_labels}) without correlated network or URL evidence."
        )
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Dynamic loading primitive detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls: extracted_urls.into_iter().collect(),
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
    fn reflection_only_does_not_emit_dynamic_loading() {
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

        assert!(findings.is_empty());
    }

    #[test]
    fn loader_primitive_without_network_is_med() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/net/URLClassLoader",
                "<init>",
                "sample.jar!/Dyn.class",
                "Dyn",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
    }

    #[test]
    fn loader_primitive_with_url_string_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/Dyn.class",
                    "Dyn",
                ),
                string(
                    "fetch https://example.invalid/payload.jar",
                    "sample.jar!/Dyn.class",
                    "Dyn",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert!(findings[0]
            .extracted_urls
            .iter()
            .any(|url| url == "https://example.invalid/payload.jar"));
    }

    #[test]
    fn loader_primitive_with_correlated_network_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/Dyn.class",
                    "Dyn",
                ),
                invoke(
                    "java/net/URL",
                    "openConnection",
                    "sample.jar!/Dyn.class",
                    "Dyn",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert!(findings[0].evidence_locations.len() >= 2);
    }

    #[test]
    fn network_in_other_class_does_not_escalate() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/net/URLClassLoader",
                    "<init>",
                    "sample.jar!/Dyn.class",
                    "Dyn",
                ),
                invoke(
                    "java/net/URL",
                    "openConnection",
                    "sample.jar!/Other.class",
                    "Other",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
    }
}
