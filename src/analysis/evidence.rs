use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BytecodeEvidence {
    pub items: Vec<BytecodeEvidenceItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BytecodeEvidenceItem {
    #[serde(rename = "cp_utf8")]
    CpUtf8 { value: String, location: Location },
    #[serde(rename = "cp_string_literal")]
    CpStringLiteral { value: String, location: Location },
    #[serde(rename = "reconstructed_string")]
    ReconstructedString { value: String, location: Location },
    #[serde(rename = "invoke_resolved")]
    InvokeResolved {
        owner: String,
        name: String,
        descriptor: String,
        location: Location,
    },
    #[serde(rename = "invoke_dynamic")]
    InvokeDynamic {
        name: String,
        descriptor: String,
        bootstrap_attr_index: u16,
        location: Location,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Location {
    pub entry_path: String,
    pub class_name: String,
    pub method: Option<LocationMethod>,
    pub pc: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LocationMethod {
    pub name: String,
    pub descriptor: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bytecode_evidence_item_json_shape_is_stable() {
        let item = BytecodeEvidenceItem::CpUtf8 {
            value: "Runtime.getRuntime".to_string(),
            location: Location {
                entry_path: "mods/example.jar!/com/example/Agent.class".to_string(),
                class_name: "com/example/Agent".to_string(),
                method: Some(LocationMethod {
                    name: "run".to_string(),
                    descriptor: "()V".to_string(),
                }),
                pc: Some(17),
            },
        };

        let expected = json!({
            "kind": "cp_utf8",
            "value": "Runtime.getRuntime",
            "location": {
                "entry_path": "mods/example.jar!/com/example/Agent.class",
                "class_name": "com/example/Agent",
                "method": {
                    "name": "run",
                    "descriptor": "()V"
                },
                "pc": 17
            }
        });

        let serialized =
            serde_json::to_value(&item).expect("failed to serialize bytecode evidence item");
        assert_eq!(serialized, expected);

        let roundtrip: BytecodeEvidenceItem =
            serde_json::from_value(expected).expect("failed to deserialize bytecode evidence item");
        assert_eq!(roundtrip, item);
    }

    #[test]
    fn invoke_resolved_json_shape_is_stable() {
        let item = BytecodeEvidenceItem::InvokeResolved {
            owner: "java/lang/Runtime".to_string(),
            name: "exec".to_string(),
            descriptor: "(Ljava/lang/String;)Ljava/lang/Process;".to_string(),
            location: Location {
                entry_path: "mods/example.jar!/com/example/Agent.class".to_string(),
                class_name: "com/example/Agent".to_string(),
                method: Some(LocationMethod {
                    name: "run".to_string(),
                    descriptor: "()V".to_string(),
                }),
                pc: Some(43),
            },
        };

        let expected = json!({
            "kind": "invoke_resolved",
            "owner": "java/lang/Runtime",
            "name": "exec",
            "descriptor": "(Ljava/lang/String;)Ljava/lang/Process;",
            "location": {
                "entry_path": "mods/example.jar!/com/example/Agent.class",
                "class_name": "com/example/Agent",
                "method": {
                    "name": "run",
                    "descriptor": "()V"
                },
                "pc": 43
            }
        });

        let serialized =
            serde_json::to_value(&item).expect("failed to serialize invoke_resolved evidence item");
        assert_eq!(serialized, expected);

        let roundtrip: BytecodeEvidenceItem = serde_json::from_value(expected)
            .expect("failed to deserialize invoke_resolved evidence item");
        assert_eq!(roundtrip, item);
    }

    #[test]
    fn reconstructed_string_json_shape_is_stable() {
        let item = BytecodeEvidenceItem::ReconstructedString {
            value: "Hello".to_string(),
            location: Location {
                entry_path: "mods/example.jar!/com/example/Agent.class".to_string(),
                class_name: "com/example/Agent".to_string(),
                method: Some(LocationMethod {
                    name: "bootstrap".to_string(),
                    descriptor: "()V".to_string(),
                }),
                pc: Some(32),
            },
        };

        let expected = json!({
            "kind": "reconstructed_string",
            "value": "Hello",
            "location": {
                "entry_path": "mods/example.jar!/com/example/Agent.class",
                "class_name": "com/example/Agent",
                "method": {
                    "name": "bootstrap",
                    "descriptor": "()V"
                },
                "pc": 32
            }
        });

        let serialized = serde_json::to_value(&item)
            .expect("failed to serialize reconstructed_string evidence item");
        assert_eq!(serialized, expected);

        let roundtrip: BytecodeEvidenceItem = serde_json::from_value(expected)
            .expect("failed to deserialize reconstructed_string evidence item");
        assert_eq!(roundtrip, item);
    }

    #[test]
    fn invoke_dynamic_json_shape_is_stable() {
        let item = BytecodeEvidenceItem::InvokeDynamic {
            name: "run".to_string(),
            descriptor: "()Ljava/lang/Runnable;".to_string(),
            bootstrap_attr_index: 1,
            location: Location {
                entry_path: "mods/example.jar!/com/example/Agent.class".to_string(),
                class_name: "com/example/Agent".to_string(),
                method: Some(LocationMethod {
                    name: "bootstrap".to_string(),
                    descriptor: "()V".to_string(),
                }),
                pc: Some(7),
            },
        };

        let expected = json!({
            "kind": "invoke_dynamic",
            "name": "run",
            "descriptor": "()Ljava/lang/Runnable;",
            "bootstrap_attr_index": 1,
            "location": {
                "entry_path": "mods/example.jar!/com/example/Agent.class",
                "class_name": "com/example/Agent",
                "method": {
                    "name": "bootstrap",
                    "descriptor": "()V"
                },
                "pc": 7
            }
        });

        let serialized =
            serde_json::to_value(&item).expect("failed to serialize invoke_dynamic evidence item");
        assert_eq!(serialized, expected);

        let roundtrip: BytecodeEvidenceItem = serde_json::from_value(expected)
            .expect("failed to deserialize invoke_dynamic evidence item");
        assert_eq!(roundtrip, item);
    }
}
