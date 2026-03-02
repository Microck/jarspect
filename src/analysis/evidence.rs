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
}
