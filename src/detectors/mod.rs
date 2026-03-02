use std::collections::HashMap;

use crate::analysis::{ArchiveEntry, BytecodeEvidence, Location};

pub mod capability_dynamic_load;
pub mod capability_exec;
pub mod capability_fs_modify;
pub mod capability_network;
pub mod index;
pub mod spec;

#[derive(Debug, Clone)]
pub struct DetectorFinding {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: String,
    pub rationale: String,
    pub evidence_locations: Vec<Location>,
    pub extracted_urls: Vec<String>,
    pub extracted_commands: Vec<String>,
    pub extracted_file_paths: Vec<String>,
}

pub fn run_capability_detectors(
    evidence: &BytecodeEvidence,
    entries: &[ArchiveEntry],
) -> Vec<DetectorFinding> {
    let _ = entries;

    let index = index::EvidenceIndex::new(evidence);
    let mut findings = Vec::new();
    findings.extend(capability_exec::detect(&index));
    findings.extend(capability_network::detect(&index));
    findings.extend(capability_dynamic_load::detect(&index));
    findings.extend(capability_fs_modify::detect(&index));
    dedup_findings(findings)
}

pub(crate) fn dedup_findings(findings: Vec<DetectorFinding>) -> Vec<DetectorFinding> {
    let mut merged: Vec<DetectorFinding> = Vec::new();
    let mut by_id: HashMap<String, usize> = HashMap::new();

    for finding in findings {
        if let Some(index) = by_id.get(&finding.id).copied() {
            let target = &mut merged[index];
            merge_locations(&mut target.evidence_locations, finding.evidence_locations);
            merge_strings(&mut target.extracted_urls, finding.extracted_urls);
            merge_strings(&mut target.extracted_commands, finding.extracted_commands);
            merge_strings(
                &mut target.extracted_file_paths,
                finding.extracted_file_paths,
            );
            continue;
        }

        let mut normalized = finding;
        normalize_finding(&mut normalized);
        by_id.insert(normalized.id.clone(), merged.len());
        merged.push(normalized);
    }

    merged
}

fn normalize_finding(finding: &mut DetectorFinding) {
    dedup_locations(&mut finding.evidence_locations);
    dedup_and_sort(&mut finding.extracted_urls);
    dedup_and_sort(&mut finding.extracted_commands);
    dedup_and_sort(&mut finding.extracted_file_paths);
}

fn merge_locations(target: &mut Vec<Location>, mut incoming: Vec<Location>) {
    target.append(&mut incoming);
    dedup_locations(target);
}

fn merge_strings(target: &mut Vec<String>, mut incoming: Vec<String>) {
    target.append(&mut incoming);
    dedup_and_sort(target);
}

fn dedup_and_sort(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn dedup_locations(locations: &mut Vec<Location>) {
    locations.sort_by(|left, right| location_key(left).cmp(&location_key(right)));
    locations.dedup_by(|left, right| left == right);
}

fn location_key(location: &Location) -> (String, String, String, String, Option<u32>) {
    let (method_name, method_descriptor) = match &location.method {
        Some(method) => (method.name.clone(), method.descriptor.clone()),
        None => (String::new(), String::new()),
    };

    (
        location.entry_path.clone(),
        location.class_name.clone(),
        method_name,
        method_descriptor,
        location.pc,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::LocationMethod;

    fn location(entry: &str, class_name: &str, method: Option<&str>, pc: Option<u32>) -> Location {
        Location {
            entry_path: entry.to_string(),
            class_name: class_name.to_string(),
            method: method.map(|name| LocationMethod {
                name: name.to_string(),
                descriptor: "()V".to_string(),
            }),
            pc,
        }
    }

    #[test]
    fn dedup_findings_merges_locations_and_extracted_evidence_by_id() {
        let finding_a = DetectorFinding {
            id: "DETC-01.RUNTIME_EXEC".to_string(),
            title: "Execution primitive detected".to_string(),
            category: "capability".to_string(),
            severity: "med".to_string(),
            rationale: "primitive only".to_string(),
            evidence_locations: vec![location("a.class", "A", Some("run"), Some(11))],
            extracted_urls: vec!["https://example.invalid/a".to_string()],
            extracted_commands: vec!["powershell -enc 1".to_string()],
            extracted_file_paths: vec!["a.class".to_string()],
        };

        let finding_b = DetectorFinding {
            id: "DETC-01.RUNTIME_EXEC".to_string(),
            title: "Execution primitive detected".to_string(),
            category: "capability".to_string(),
            severity: "high".to_string(),
            rationale: "correlated command".to_string(),
            evidence_locations: vec![
                location("a.class", "A", Some("run"), Some(11)),
                location("a.class", "A", Some("bootstrap"), Some(2)),
            ],
            extracted_urls: vec![
                "https://example.invalid/a".to_string(),
                "https://example.invalid/b".to_string(),
            ],
            extracted_commands: vec!["cmd.exe /c whoami".to_string()],
            extracted_file_paths: vec!["a.class".to_string(), "b.class".to_string()],
        };

        let merged = dedup_findings(vec![finding_a, finding_b]);
        assert_eq!(merged.len(), 1);

        let finding = &merged[0];
        assert_eq!(finding.id, "DETC-01.RUNTIME_EXEC");
        assert_eq!(finding.evidence_locations.len(), 2);
        assert_eq!(
            finding.extracted_urls,
            vec![
                "https://example.invalid/a".to_string(),
                "https://example.invalid/b".to_string(),
            ]
        );
        assert_eq!(finding.extracted_commands.len(), 2);
        assert_eq!(
            finding.extracted_file_paths,
            vec!["a.class".to_string(), "b.class".to_string()]
        );
    }
}
