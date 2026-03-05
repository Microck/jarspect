use std::collections::BTreeSet;

use crate::analysis::Location;

use super::index::{EvidenceIndex, InvokeHit};
use super::spec::{contains_any_token, COMMAND_TOKENS};
use super::DetectorFinding;

const DETECTOR_ID: &str = "DETC-01.RUNTIME_EXEC";

pub fn detect(index: &EvidenceIndex) -> Vec<DetectorFinding> {
    let runtime_exec = index.invokes("java/lang/Runtime", "exec");
    let process_builder_start = index.invokes("java/lang/ProcessBuilder", "start");

    if runtime_exec.is_empty() && process_builder_start.is_empty() {
        return Vec::new();
    }

    let mut evidence_locations = Vec::new();
    let mut touched_classes = BTreeSet::new();
    let mut matched_primitives = BTreeSet::new();

    collect_hits(
        runtime_exec,
        "java/lang/Runtime.exec",
        &mut evidence_locations,
        &mut touched_classes,
        &mut matched_primitives,
    );
    collect_hits(
        process_builder_start,
        "java/lang/ProcessBuilder.start",
        &mut evidence_locations,
        &mut touched_classes,
        &mut matched_primitives,
    );

    let mut extracted_commands = BTreeSet::new();
    for (entry_path, class_name) in &touched_classes {
        for string_hit in index.strings_in_class(entry_path, class_name) {
            if is_command_like_string(string_hit.value.as_str())
                && contains_any_token(&string_hit.value, COMMAND_TOKENS)
            {
                extracted_commands.insert(string_hit.value.clone());
            }
        }
    }

    // Process execution is uncommon in typical mods, but it does appear in benign cases
    // (e.g. environment probing). Treat the primitive alone as low-signal and only
    // escalate when correlated command-like strings are present.
    let severity = if extracted_commands.is_empty() {
        "low"
    } else {
        "high"
    };

    let extracted_file_paths = evidence_locations
        .iter()
        .map(|location| location.entry_path.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let rationale = if extracted_commands.is_empty() {
        format!(
            "Matched execution primitives ({}), but found no correlated command-like strings in the same class.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", ")
        )
    } else {
        format!(
            "Matched execution primitives ({}) with {} correlated command-like string(s) in the same class.",
            matched_primitives
                .into_iter()
                .collect::<Vec<_>>()
                .join(", "),
            extracted_commands.len()
        )
    };

    vec![DetectorFinding {
        id: DETECTOR_ID.to_string(),
        title: "Process execution primitive detected".to_string(),
        category: "capability".to_string(),
        severity: severity.to_string(),
        rationale,
        evidence_locations,
        extracted_urls: Vec::new(),
        extracted_commands: extracted_commands.into_iter().collect(),
        extracted_file_paths,
    }]
}

fn is_command_like_string(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    // Avoid treating arbitrary long strings / descriptors as command lines.
    if trimmed.len() > 240 {
        return false;
    }

    // Filter Java type descriptors / internal class names that frequently contain tokens (e.g. "PowerShellUtils").
    let looks_like_descriptor = (trimmed.starts_with('L') && trimmed.ends_with(';'))
        || (trimmed.contains('(') && trimmed.contains(')'))
        || (trimmed.contains('/')
            && !trimmed.contains(' ')
            && !trimmed.eq_ignore_ascii_case("/bin/sh")
            && !trimmed.to_ascii_lowercase().contains("/bin/sh "));
    if looks_like_descriptor {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();

    // PowerShell: require evidence of an actual invocation (flags / args), not just the word.
    if lower.contains("powershell") {
        return lower.contains(" -")
            || lower.contains("/c")
            || lower.contains("-enc")
            || lower.contains("-command")
            || lower.contains("-executionpolicy")
            || lower.contains("-nop")
            || lower.contains("-noprofile");
    }

    // cmd.exe: require /c or /k.
    if lower.contains("cmd.exe") {
        return lower.contains("/c") || lower.contains("/k");
    }

    // /bin/sh: require evidence of an invocation.
    if lower.contains("/bin/sh") {
        return lower.contains(" -c") || lower.ends_with("/bin/sh") || lower.contains("/bin/sh ");
    }

    // curl / wget: require at least a URL or flags.
    if lower.contains("curl") || lower.contains("wget") {
        return lower.contains("http://") || lower.contains("https://") || lower.contains(" -");
    }

    false
}

fn collect_hits(
    hits: &[InvokeHit],
    primitive_label: &str,
    evidence_locations: &mut Vec<Location>,
    touched_classes: &mut BTreeSet<(String, String)>,
    matched_primitives: &mut BTreeSet<String>,
) {
    if hits.is_empty() {
        return;
    }

    matched_primitives.insert(primitive_label.to_string());
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

    #[test]
    fn primitive_without_correlated_command_is_low_signal() {
        let evidence = BytecodeEvidence {
            items: vec![invoke(
                "java/lang/Runtime",
                "exec",
                "sample.jar!/Exec.class",
                "Exec",
            )],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
        assert!(findings[0].extracted_commands.is_empty());

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
    fn correlated_command_string_escalates_to_high() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/lang/ProcessBuilder",
                    "start",
                    "sample.jar!/Exec.class",
                    "Exec",
                ),
                string("powershell -enc demo", "sample.jar!/Exec.class", "Exec"),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "high");
        assert_eq!(findings[0].extracted_commands, vec!["powershell -enc demo"]);
    }

    #[test]
    fn powershell_keyword_in_error_message_is_not_a_command() {
        let evidence = BytecodeEvidence {
            items: vec![
                invoke(
                    "java/lang/ProcessBuilder",
                    "start",
                    "sample.jar!/Exec.class",
                    "Exec",
                ),
                string(
                    "Persistent PowerShell host terminated unexpectedly.",
                    "sample.jar!/Exec.class",
                    "Exec",
                ),
            ],
        };

        let index = EvidenceIndex::new(&evidence);
        let findings = detect(&index);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, "low");
        assert!(findings[0].extracted_commands.is_empty());
    }
}
