use std::collections::BTreeSet;

use crate::analysis::Location;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{contains_any_token, extract_urls, NETWORK_PRIMITIVE_MATCHERS};
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-02.DISCORD_WEBHOOK";

const WEBHOOK_TOKEN_MARKERS: &[&str] = &[
    "api/webhooks",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
];

const WEBHOOK_URL_MARKERS: &[&str] = &["discord.com/api/webhooks", "discordapp.com/api/webhooks"];

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let mut touched_classes = BTreeSet::new();
    let mut evidence_locations = Vec::new();

    for string_hit in index.all_strings() {
        if !contains_any_token(&string_hit.value, WEBHOOK_TOKEN_MARKERS) {
            continue;
        }

        touched_classes.insert(class_key(&string_hit.location));
        evidence_locations.push(string_hit.location.clone());
    }

    if touched_classes.is_empty() {
        return Vec::new();
    }

    let mut extracted_urls = BTreeSet::new();
    for (entry_path, class_name) in &touched_classes {
        let strings = index
            .strings_in_class(entry_path, class_name)
            .iter()
            .map(|hit| hit.value.as_str());

        for url in extract_urls(strings) {
            if contains_any_token(url.as_str(), WEBHOOK_URL_MARKERS) {
                extracted_urls.insert(url);
            }
        }
    }

    let mut matched_primitives = BTreeSet::new();
    let mut has_correlated_network = false;
    for (owner, name, primitive_label) in NETWORK_PRIMITIVE_MATCHERS {
        let hits = index.invokes(owner, name);
        if hits.is_empty() {
            continue;
        }

        if collect_correlated_hits(hits, &touched_classes, &mut evidence_locations) {
            has_correlated_network = true;
            matched_primitives.insert((*primitive_label).to_string());
        }
    }

    let severity = if has_correlated_network {
        "high"
    } else {
        "med"
    };
    let rationale = if has_correlated_network {
        format!(
            "Found Discord webhook URL marker(s) with correlated network primitive(s) ({}) in the same class.",
            matched_primitives.into_iter().collect::<Vec<_>>().join(", ")
        )
    } else {
        "Found Discord webhook URL marker(s) without correlated network primitives in the same class."
            .to_string()
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Discord webhook exfiltration indicator detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls: extracted_urls.into_iter().collect(),
        extracted_commands: Vec::new(),
        extracted_file_paths: Vec::new(),
    }]
}

fn collect_correlated_hits(
    hits: &[InvokeHit],
    allowed_classes: &BTreeSet<(String, String)>,
    evidence_locations: &mut Vec<Location>,
) -> bool {
    let mut correlated = false;
    for hit in hits {
        let key = class_key(&hit.location);
        if !allowed_classes.contains(&key) {
            continue;
        }

        correlated = true;
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
                pc: Some(7),
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
    fn webhook_string_alone_is_med() {
        let evidence = BytecodeEvidence {
            items: vec![string(
                "https://discord.com/api/webhooks/123/abcdef",
                "sample.jar!/A.class",
                "A",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "med");
        assert_eq!(
            findings[0].extracted_urls,
            vec!["https://discord.com/api/webhooks/123/abcdef"]
        );
        assert!(!has_invoke_callsite(&findings[0]));
    }

    #[test]
    fn webhook_with_correlated_network_is_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    "exfil https://discordapp.com/api/webhooks/999/token",
                    "sample.jar!/A.class",
                    "A",
                ),
                invoke("java/net/URL", "openConnection", "sample.jar!/A.class", "A"),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert!(has_invoke_callsite(&findings[0]));
        assert_eq!(
            findings[0].extracted_urls,
            vec!["https://discordapp.com/api/webhooks/999/token"]
        );
    }

    #[test]
    fn discord_invite_urls_do_not_trigger() {
        let evidence = BytecodeEvidence {
            items: vec![
                string(
                    "join us https://discord.gg/example",
                    "sample.jar!/A.class",
                    "A",
                ),
                invoke("java/net/URL", "openConnection", "sample.jar!/A.class", "A"),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);
        assert!(findings.is_empty());
    }
}
