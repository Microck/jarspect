use std::collections::BTreeSet;

use super::DetectorFinding;
use super::index::EvidenceIndex;

const DETECTOR_ID: &str = "DETC-06.UNSAFE_DESERIALIZATION";

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let hits = index.invokes("java/io/ObjectInputStream", "readObject");
    if hits.is_empty() {
        return Vec::new();
    }

    let evidence_locations = hits
        .iter()
        .map(|hit| hit.location.clone())
        .collect::<Vec<_>>();
    let extracted_file_paths = evidence_locations
        .iter()
        .map(|location| location.entry_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Unsafe deserialization sink detected".to_string(),
        category: "vulnerability".to_string(),
        severity: "med".to_string(),
        rationale: format!(
            "Matched ObjectInputStream.readObject at {} callsite(s). This is reported as vulnerability-risk and remains conservative without exploitability context.",
            evidence_locations.len()
        ),
        evidence_locations,
        extracted_urls: Vec::new(),
        extracted_commands: Vec::new(),
        extracted_file_paths,
    }]
}

#[cfg(test)]
mod tests {
    use crate::analysis::{BytecodeEvidence, BytecodeEvidenceItem, Location, LocationMethod};

    use super::*;

    fn invoke(owner: &str, name: &str, entry_path: &str, class_name: &str) -> BytecodeEvidenceItem {
        BytecodeEvidenceItem::InvokeResolved {
            owner: owner.to_string(),
            name: name.to_string(),
            descriptor: "()Ljava/lang/Object;".to_string(),
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

    #[test]
    fn read_object_emits_single_med_vulnerability_indicator_with_callsite() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/io/ObjectInputStream",
                "readObject",
                "sample.jar!/Deserialize.class",
                "Deserialize",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "DETC-06.UNSAFE_DESERIALIZATION");
        assert_eq!(findings[0].category, "vulnerability");
        assert_eq!(findings[0].severity, "med");
        assert!(findings[0].extracted_urls.is_empty());
        assert!(findings[0].extracted_commands.is_empty());

        let has_callsite = findings[0].evidence_locations.iter().any(|location| {
            location
                .method
                .as_ref()
                .map(|method| method.name == "fixture")
                .unwrap_or(false)
                && location.pc.is_some()
        });
        assert!(has_callsite);
    }
}
