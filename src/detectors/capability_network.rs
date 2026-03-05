use std::collections::BTreeSet;

use crate::analysis::Location;
use url::Url;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{extract_urls, NETWORK_PRIMITIVE_MATCHERS};
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-02.NETWORK_PRIMITIVE";

fn is_benign_url_host(host: &str) -> bool {
    matches!(
        host.trim().to_ascii_lowercase().as_str(),
        "github.com"
            | "polyformproject.org"
            | "irisshaders.dev"
            | "caffeinemc.net"
            | "link.caffeinemc.net"
            | "fabricmc.net"
            | "quiltmc.org"
            | "modrinth.com"
            | "api.modrinth.com"
    )
}

fn urls_are_all_benign(urls: &BTreeSet<String>) -> bool {
    if urls.is_empty() {
        return false;
    }

    urls.iter().all(|raw| {
        let Ok(parsed) = Url::parse(raw.as_str()) else {
            return false;
        };
        let Some(host) = parsed.host_str() else {
            return false;
        };
        is_benign_url_host(host)
    })
}

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let mut evidence_locations = Vec::new();
    let mut touched_classes = BTreeSet::new();
    let mut matched_primitives = BTreeSet::new();

    for (owner, name, primitive_label) in NETWORK_PRIMITIVE_MATCHERS {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        matched_primitives.insert((*primitive_label).to_string());
        collect_hits(hits, &mut evidence_locations, &mut touched_classes);
    }

    if evidence_locations.is_empty() {
        return Vec::new();
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

    let urls_look_benign = urls_are_all_benign(&extracted_urls);
    let severity = if extracted_urls.is_empty() {
        "low"
    } else if urls_look_benign {
        "low"
    } else {
        "med"
    };
    let extracted_file_paths = evidence_locations
        .iter()
        .map(|location| location.entry_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let rationale = if extracted_urls.is_empty() {
        format!(
            "Matched networking primitives ({}); no correlated URL string evidence in triggering classes.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else if urls_look_benign {
        format!(
            "Matched networking primitives ({}) with {} correlated URL(s), but all hosts look benign/documentation-related.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", "),
            extracted_urls.len()
        )
    } else {
        format!(
            "Matched networking primitives ({}) with {} correlated URL(s) in triggering classes.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", "),
            extracted_urls.len()
        )
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Outbound networking primitive detected".to_string(),
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
                pc: Some(3),
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
    fn primitive_without_url_stays_low() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/net/Socket",
                "connect",
                "sample.jar!/Net.class",
                "Net",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
        assert!(findings[0].extracted_urls.is_empty());

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
    fn correlated_url_escalates_to_med() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/net/URL",
                    "openConnection",
                    "sample.jar!/Net.class",
                    "Net",
                ),
                string(
                    "download from https://example.invalid/payload",
                    "sample.jar!/Net.class",
                    "Net",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
        assert_eq!(
            findings[0].extracted_urls,
            vec!["https://example.invalid/payload"]
        );
    }

    #[test]
    fn github_url_is_treated_as_low_signal() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/net/URL",
                    "openConnection",
                    "sample.jar!/Net.class",
                    "Net",
                ),
                string(
                    "docs: https://github.com/CaffeineMC/sodium/wiki",
                    "sample.jar!/Net.class",
                    "Net",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
        assert_eq!(
            findings[0].extracted_urls,
            vec!["https://github.com/CaffeineMC/sodium/wiki"]
        );
    }

    #[test]
    fn url_in_different_class_does_not_escalate() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke("java/net/URL", "<init>", "sample.jar!/A.class", "A"),
                string(
                    "https://example.invalid/not-correlated",
                    "sample.jar!/B.class",
                    "B",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
        assert!(findings[0].extracted_urls.is_empty());
    }
}
