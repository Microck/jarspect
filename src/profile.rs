use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_yml::Value as YamlValue;
use toml::Value as TomlValue;
use tracing::debug;

use crate::analysis::{ArchiveEntry, BytecodeEvidence, BytecodeEvidenceItem};
use crate::{Indicator, StaticFindings};

const CAPABILITY_KEYS: [&str; 8] = [
    "network",
    "dynamic_loading",
    "execution",
    "credential_theft",
    "persistence",
    "native_loading",
    "filesystem",
    "deserialization",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityProfile {
    pub mod_metadata: ModMetadata,
    pub capabilities: BTreeMap<String, CapabilitySignal>,
    pub yara_hits: Vec<YaraHit>,
    pub low_signal_indicators: Vec<String>,
    pub reconstructed_strings: Vec<String>,
    pub suspicious_manifest_entries: Vec<String>,
    pub class_count: usize,
    pub jar_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ModMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loader: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mod_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default)]
    pub authors: Vec<String>,
    #[serde(default)]
    pub entrypoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySignal {
    pub present: bool,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct YaraHit {
    pub id: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    pub evidence: String,
}

pub fn build_profile(
    static_findings: &StaticFindings,
    entries: &[ArchiveEntry],
    bytecode_evidence: Option<&BytecodeEvidence>,
    class_count: usize,
    jar_size_bytes: usize,
) -> CapabilityProfile {
    let mut capabilities = BTreeMap::new();
    for key in CAPABILITY_KEYS {
        capabilities.insert(
            key.to_string(),
            CapabilitySignal {
                present: false,
                evidence: Vec::new(),
            },
        );
    }

    let mut low_signal_indicators = Vec::new();
    for finding in static_findings
        .matches
        .iter()
        .filter(|indicator| indicator.source == "detector")
    {
        let Some(capability_key) = capability_key_for_detector(&finding.id) else {
            continue;
        };

        if !is_medium_or_higher(finding.severity.as_str()) {
            low_signal_indicators.push(detector_evidence_line(finding));
            continue;
        }

        if let Some(signal) = capabilities.get_mut(capability_key) {
            signal.present = true;
            signal.evidence.push(detector_evidence_line(finding));
        }
    }

    for signal in capabilities.values_mut() {
        signal.evidence.sort();
        signal.evidence.dedup();
    }
    low_signal_indicators.sort();
    low_signal_indicators.dedup();

    let yara_hits = static_findings
        .matches
        .iter()
        .filter(|indicator| indicator.source == "yara")
        .map(|indicator| YaraHit {
            id: indicator.id.clone(),
            severity: indicator.severity.clone(),
            file_path: indicator.file_path.clone(),
            evidence: indicator.evidence.clone(),
        })
        .collect::<Vec<_>>();

    let reconstructed_strings = bytecode_evidence
        .map(|evidence| {
            evidence
                .items
                .iter()
                .filter_map(|item| match item {
                    BytecodeEvidenceItem::ReconstructedString { value, .. } => Some(value.clone()),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let suspicious_manifest_entries = static_findings
        .matches
        .iter()
        .filter(|indicator| {
            indicator.source == "metadata" && indicator.id.starts_with("META-MANIFEST")
        })
        .map(detector_evidence_line)
        .collect::<Vec<_>>();

    CapabilityProfile {
        mod_metadata: extract_mod_metadata(entries),
        capabilities,
        yara_hits,
        low_signal_indicators,
        reconstructed_strings,
        suspicious_manifest_entries,
        class_count,
        jar_size_bytes,
    }
}

fn is_medium_or_higher(severity: &str) -> bool {
    matches!(
        severity.trim().to_ascii_lowercase().as_str(),
        "med" | "medium" | "high" | "critical"
    )
}

fn capability_key_for_detector(id: &str) -> Option<&'static str> {
    if id.starts_with("DETC-01") {
        Some("execution")
    } else if id.starts_with("DETC-02") {
        Some("network")
    } else if id.starts_with("DETC-03") {
        Some("dynamic_loading")
    } else if id.starts_with("DETC-04") {
        Some("filesystem")
    } else if id.starts_with("DETC-05") {
        Some("persistence")
    } else if id.starts_with("DETC-06") {
        Some("deserialization")
    } else if id.starts_with("DETC-07") {
        Some("native_loading")
    } else if id.starts_with("DETC-08") {
        Some("credential_theft")
    } else {
        None
    }
}

fn detector_evidence_line(finding: &Indicator) -> String {
    let mut pieces = Vec::new();
    if let Some(path) = finding.file_path.as_deref() {
        pieces.push(path.to_string());
    }
    pieces.push(finding.id.clone());

    if !finding.evidence.trim().is_empty() {
        pieces.push(finding.evidence.trim().to_string());
    }

    if !finding.rationale.trim().is_empty() {
        pieces.push(finding.rationale.trim().to_string());
    }

    pieces.join(" - ")
}

fn extract_mod_metadata(entries: &[ArchiveEntry]) -> ModMetadata {
    if let Some(metadata) = parse_fabric_metadata(entries) {
        debug!(
            loader = "fabric",
            mod_id = ?metadata.mod_id,
            name = ?metadata.name,
            "detected fabric mod metadata"
        );
        return metadata;
    }

    if let Some(metadata) = parse_forge_metadata(entries) {
        debug!(
            loader = ?metadata.loader,
            mod_id = ?metadata.mod_id,
            name = ?metadata.name,
            "detected forge/neoforge mod metadata"
        );
        return metadata;
    }

    if let Some(metadata) = parse_mcmod_info(entries) {
        debug!(
            loader = "legacy-forge",
            mod_id = ?metadata.mod_id,
            name = ?metadata.name,
            "detected mcmod.info metadata"
        );
        return metadata;
    }

    if let Some(metadata) = parse_spigot_metadata(entries) {
        debug!(
            loader = "spigot",
            mod_id = ?metadata.mod_id,
            name = ?metadata.name,
            "detected spigot plugin metadata"
        );
        return metadata;
    }

    debug!("no mod metadata found");
    ModMetadata::default()
}

fn jar_layer_depth(path: &str) -> usize {
    path.match_indices("!/").count()
}

fn find_shallowest_entry<'a, F>(
    entries: &'a [ArchiveEntry],
    predicate: F,
) -> Option<&'a ArchiveEntry>
where
    F: Fn(&ArchiveEntry) -> bool,
{
    entries
        .iter()
        .filter(|entry| predicate(entry))
        .min_by_key(|entry| jar_layer_depth(entry.path.as_str()))
}

fn parse_fabric_metadata(entries: &[ArchiveEntry]) -> Option<ModMetadata> {
    let entry = find_shallowest_entry(entries, |entry| {
        entry
            .path
            .to_ascii_lowercase()
            .ends_with("!/fabric.mod.json")
    })?;

    let text = entry.text.as_deref()?;
    let payload = serde_json::from_str::<JsonValue>(text).ok()?;

    let authors = payload
        .get("authors")
        .and_then(JsonValue::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| match item {
                    JsonValue::String(value) => Some(value.clone()),
                    JsonValue::Object(object) => object
                        .get("name")
                        .and_then(JsonValue::as_str)
                        .map(ToOwned::to_owned),
                    _ => None,
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let mut entrypoints = Vec::new();
    if let Some(entrypoint_map) = payload.get("entrypoints").and_then(JsonValue::as_object) {
        for value in entrypoint_map.values() {
            collect_fabric_entrypoints(value, &mut entrypoints);
        }
    }

    Some(ModMetadata {
        loader: Some("fabric".to_string()),
        mod_id: payload
            .get("id")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        name: payload
            .get("name")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        version: payload
            .get("version")
            .and_then(JsonValue::as_str)
            .map(ToOwned::to_owned),
        authors,
        entrypoints,
    })
}

fn parse_forge_metadata(entries: &[ArchiveEntry]) -> Option<ModMetadata> {
    let entry = find_shallowest_entry(entries, |entry| {
        let path = entry.path.to_ascii_lowercase();
        path.ends_with("!/meta-inf/mods.toml") || path.ends_with("!/meta-inf/neoforge.mods.toml")
    })?;

    let loader = if entry
        .path
        .to_ascii_lowercase()
        .ends_with("!/meta-inf/neoforge.mods.toml")
    {
        "neoforge"
    } else {
        "forge"
    };

    let text = entry.text.as_deref()?;
    let payload = toml::from_str::<TomlValue>(text).ok()?;
    let first_mod = payload.get("mods")?.as_array()?.first()?;

    Some(ModMetadata {
        loader: Some(loader.to_string()),
        mod_id: first_mod
            .get("modId")
            .and_then(TomlValue::as_str)
            .map(ToOwned::to_owned),
        name: first_mod
            .get("displayName")
            .and_then(TomlValue::as_str)
            .map(ToOwned::to_owned),
        version: first_mod
            .get("version")
            .and_then(TomlValue::as_str)
            .map(ToOwned::to_owned),
        authors: first_mod
            .get("authors")
            .and_then(TomlValue::as_str)
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|name| !name.is_empty())
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        entrypoints: Vec::new(),
    })
}

fn parse_spigot_metadata(entries: &[ArchiveEntry]) -> Option<ModMetadata> {
    let entry = find_shallowest_entry(entries, |entry| {
        entry.path.to_ascii_lowercase().ends_with("!/plugin.yml")
    })?;

    let text = entry.text.as_deref()?;
    let payload = serde_yml::from_str::<YamlValue>(text).ok()?;
    let mapping = payload.as_mapping()?;

    let main_entrypoint = mapping
        .get(YamlValue::String("main".to_string()))
        .and_then(YamlValue::as_str)
        .map(ToOwned::to_owned)
        .into_iter()
        .collect::<Vec<_>>();

    Some(ModMetadata {
        loader: Some("spigot".to_string()),
        mod_id: mapping
            .get(YamlValue::String("name".to_string()))
            .and_then(YamlValue::as_str)
            .map(ToOwned::to_owned),
        name: mapping
            .get(YamlValue::String("name".to_string()))
            .and_then(YamlValue::as_str)
            .map(ToOwned::to_owned),
        version: mapping
            .get(YamlValue::String("version".to_string()))
            .and_then(YamlValue::as_str)
            .map(ToOwned::to_owned),
        authors: mapping
            .get(YamlValue::String("authors".to_string()))
            .and_then(YamlValue::as_sequence)
            .map(|authors| {
                authors
                    .iter()
                    .filter_map(YamlValue::as_str)
                    .map(ToOwned::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        entrypoints: main_entrypoint,
    })
}

fn parse_mcmod_info(entries: &[ArchiveEntry]) -> Option<ModMetadata> {
    let entry = find_shallowest_entry(entries, |entry| {
        entry.path.to_ascii_lowercase().ends_with("!/mcmod.info")
    })?;

    let text = entry.text.as_deref()?;
    let payload = serde_json::from_str::<JsonValue>(text).ok()?;

    let first_mod: &JsonValue = if let JsonValue::Array(items) = &payload {
        items.first()?
    } else if let JsonValue::Object(object) = &payload {
        object
            .get("modList")
            .and_then(JsonValue::as_array)
            .and_then(|items| items.first())
            .unwrap_or(&payload)
    } else {
        return None;
    };

    let object = first_mod.as_object()?;
    let mod_id = object
        .get("modid")
        .and_then(JsonValue::as_str)
        .or_else(|| object.get("modId").and_then(JsonValue::as_str))
        .map(ToOwned::to_owned);
    let name = object
        .get("name")
        .and_then(JsonValue::as_str)
        .map(ToOwned::to_owned);
    let version = object
        .get("version")
        .and_then(JsonValue::as_str)
        .map(ToOwned::to_owned);

    let authors = object
        .get("authorList")
        .and_then(JsonValue::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(JsonValue::as_str)
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .or_else(|| {
            object
                .get("authorList")
                .and_then(JsonValue::as_str)
                .map(|raw| {
                    raw.split(',')
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .map(ToOwned::to_owned)
                        .collect::<Vec<_>>()
                })
        })
        .unwrap_or_default();

    if mod_id.is_none() && name.is_none() {
        return None;
    }

    Some(ModMetadata {
        loader: Some("forge".to_string()),
        mod_id,
        name,
        version,
        authors,
        entrypoints: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::extract_mod_metadata;
    use crate::analysis::ArchiveEntry;

    fn entry(path: &str, text: &str) -> ArchiveEntry {
        ArchiveEntry {
            path: path.to_string(),
            bytes: Vec::new(),
            text: Some(text.to_string()),
        }
    }

    #[test]
    fn prefers_shallowest_metadata_file() {
        let entries = vec![
            entry(
                "upload.jar!/META-INF/jars/inner.jar!/fabric.mod.json",
                r#"{"id":"inner","name":"Inner","version":"1.0"}"#,
            ),
            entry(
                "upload.jar!/fabric.mod.json",
                r#"{"id":"outer","name":"Outer","version":"2.0"}"#,
            ),
        ];

        let metadata = extract_mod_metadata(&entries);
        assert_eq!(metadata.loader.as_deref(), Some("fabric"));
        assert_eq!(metadata.mod_id.as_deref(), Some("outer"));
        assert_eq!(metadata.name.as_deref(), Some("Outer"));
        assert_eq!(metadata.version.as_deref(), Some("2.0"));
    }

    #[test]
    fn parses_neoforge_mods_toml() {
        let entries = vec![entry(
            "upload.jar!/META-INF/neoforge.mods.toml",
            r#"
mods = [
  { modId = "cloth-config", displayName = "Cloth Config API", version = "1.2.3", authors = "A, B" }
]
"#,
        )];

        let metadata = extract_mod_metadata(&entries);
        assert_eq!(metadata.loader.as_deref(), Some("neoforge"));
        assert_eq!(metadata.mod_id.as_deref(), Some("cloth-config"));
        assert_eq!(metadata.name.as_deref(), Some("Cloth Config API"));
        assert_eq!(metadata.version.as_deref(), Some("1.2.3"));
        assert_eq!(metadata.authors, vec!["A", "B"]);
    }
}

fn collect_fabric_entrypoints(value: &JsonValue, entrypoints: &mut Vec<String>) {
    match value {
        JsonValue::String(raw) => entrypoints.push(raw.clone()),
        JsonValue::Array(items) => {
            for item in items {
                collect_fabric_entrypoints(item, entrypoints);
            }
        }
        JsonValue::Object(object) => {
            if let Some(inner) = object.get("value") {
                collect_fabric_entrypoints(inner, entrypoints);
            }
        }
        _ => {}
    }
}
