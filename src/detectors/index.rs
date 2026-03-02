use std::collections::HashMap;

use crate::analysis::{BytecodeEvidence, BytecodeEvidenceItem, Location};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeHit {
    pub descriptor: String,
    pub location: Location,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringHit {
    pub value: String,
    pub location: Location,
}

#[derive(Debug, Default)]
pub struct EvidenceIndex {
    invokes_by_owner_name: HashMap<(String, String), Vec<InvokeHit>>,
    strings_by_entry_class: HashMap<(String, String), Vec<StringHit>>,
    all_strings: Vec<StringHit>,
}

impl EvidenceIndex {
    pub fn new(evidence: &BytecodeEvidence) -> Self {
        let mut index = Self::default();

        for item in &evidence.items {
            match item {
                BytecodeEvidenceItem::InvokeResolved {
                    owner,
                    name,
                    descriptor,
                    location,
                } => {
                    index
                        .invokes_by_owner_name
                        .entry((owner.clone(), name.clone()))
                        .or_default()
                        .push(InvokeHit {
                            descriptor: descriptor.clone(),
                            location: location.clone(),
                        });
                }
                BytecodeEvidenceItem::CpUtf8 { value, location }
                | BytecodeEvidenceItem::CpStringLiteral { value, location }
                | BytecodeEvidenceItem::ReconstructedString { value, location } => {
                    let hit = StringHit {
                        value: value.clone(),
                        location: location.clone(),
                    };

                    index
                        .strings_by_entry_class
                        .entry(class_key(&hit.location))
                        .or_default()
                        .push(hit.clone());
                    index.all_strings.push(hit);
                }
                BytecodeEvidenceItem::InvokeDynamic { .. } => {}
            }
        }

        index
    }

    pub fn invokes(&self, owner: &str, name: &str) -> &[InvokeHit] {
        self.invokes_by_owner_name
            .get(&(owner.to_string(), name.to_string()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn strings_in_class(&self, entry_path: &str, class_name: &str) -> &[StringHit] {
        self.strings_by_entry_class
            .get(&(entry_path.to_string(), class_name.to_string()))
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    #[allow(dead_code)]
    pub fn all_strings(&self) -> impl Iterator<Item = &StringHit> {
        self.all_strings.iter()
    }
}

fn class_key(location: &Location) -> (String, String) {
    (location.entry_path.clone(), location.class_name.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::{BytecodeEvidenceItem, LocationMethod};

    fn sample_location(
        entry_path: &str,
        class_name: &str,
        method: Option<&str>,
        pc: Option<u32>,
    ) -> Location {
        Location {
            entry_path: entry_path.to_string(),
            class_name: class_name.to_string(),
            method: method.map(|name| LocationMethod {
                name: name.to_string(),
                descriptor: "()V".to_string(),
            }),
            pc,
        }
    }

    #[test]
    fn indexes_invokes_and_strings_by_lookup_keys() {
        let evidence = BytecodeEvidence {
            items: vec![
                BytecodeEvidenceItem::InvokeResolved {
                    owner: "java/lang/Runtime".to_string(),
                    name: "exec".to_string(),
                    descriptor: "(Ljava/lang/String;)Ljava/lang/Process;".to_string(),
                    location: sample_location("sample.jar!/A.class", "A", Some("run"), Some(12)),
                },
                BytecodeEvidenceItem::CpUtf8 {
                    value: "powershell -enc demo".to_string(),
                    location: sample_location("sample.jar!/A.class", "A", None, None),
                },
                BytecodeEvidenceItem::ReconstructedString {
                    value: "https://example.invalid/payload".to_string(),
                    location: sample_location(
                        "sample.jar!/B.class",
                        "B",
                        Some("bootstrap"),
                        Some(2),
                    ),
                },
            ],
        };

        let index = EvidenceIndex::new(&evidence);

        let invokes = index.invokes("java/lang/Runtime", "exec");
        assert_eq!(invokes.len(), 1);
        assert_eq!(
            invokes[0].descriptor,
            "(Ljava/lang/String;)Ljava/lang/Process;"
        );

        let strings_a = index.strings_in_class("sample.jar!/A.class", "A");
        assert_eq!(strings_a.len(), 1);
        assert_eq!(strings_a[0].value, "powershell -enc demo");

        let strings_b = index.strings_in_class("sample.jar!/B.class", "B");
        assert_eq!(strings_b.len(), 1);
        assert_eq!(strings_b[0].value, "https://example.invalid/payload");

        let all_strings = index.all_strings().collect::<Vec<_>>();
        assert_eq!(all_strings.len(), 2);
    }
}
