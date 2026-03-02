use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::Value as JsonValue;
use serde_yml::Value as YamlValue;
use toml::Value as TomlValue;

use super::ArchiveEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataFinding {
    pub id: String,
    pub title: String,
    pub severity: String,
    pub file_path: String,
    pub evidence: String,
    pub rationale: String,
}

struct LayerEntryRef<'a> {
    rel_path: String,
    entry: &'a ArchiveEntry,
}

static FABRIC_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-_]{1,63}$").expect("valid fabric id regex"));
static FORGE_MOD_ID_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9_]{1,63}$").expect("valid forge id regex"));
static SPIGOT_NAME_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_]+$").expect("valid spigot name regex"));

const SUSPICIOUS_MANIFEST_KEYS: [(&str, &str, &str, &str); 5] = [
    (
        "Premain-Class",
        "META-MANIFEST-PREMAIN",
        "Manifest declares Premain-Class",
        "Java agent premain hook in manifest is suspicious for a Minecraft mod jar.",
    ),
    (
        "Agent-Class",
        "META-MANIFEST-AGENT",
        "Manifest declares Agent-Class",
        "Java instrumentation agent entrypoint is uncommon for legitimate mod/plugin jars.",
    ),
    (
        "Can-Redefine-Classes",
        "META-MANIFEST-REDEFINE",
        "Manifest enables class redefinition",
        "Class redefinition capability indicates instrumentation behavior with elevated risk.",
    ),
    (
        "Can-Retransform-Classes",
        "META-MANIFEST-RETRANSFORM",
        "Manifest enables class retransformation",
        "Class retransformation capability indicates runtime instrumentation behavior.",
    ),
    (
        "Boot-Class-Path",
        "META-MANIFEST-BOOTCLASSPATH",
        "Manifest sets Boot-Class-Path",
        "Boot class path manipulation is a high-suspicion JVM instrumentation signal.",
    ),
];

pub fn analyze_metadata(entries: &[ArchiveEntry]) -> Vec<MetadataFinding> {
    let grouped_entries = group_entries_by_jar_layer(entries);
    let mut findings = Vec::new();

    for layer_entries in grouped_entries.values() {
        analyze_layer(layer_entries.as_slice(), &mut findings);
    }

    findings
}

fn group_entries_by_jar_layer<'a>(
    entries: &'a [ArchiveEntry],
) -> BTreeMap<String, Vec<LayerEntryRef<'a>>> {
    let mut grouped = BTreeMap::new();

    for entry in entries {
        if let Some((jar_key, rel_path)) = split_archive_entry_path(entry.path.as_str()) {
            grouped
                .entry(jar_key)
                .or_insert_with(Vec::new)
                .push(LayerEntryRef { rel_path, entry });
        }
    }

    grouped
}

fn split_archive_entry_path(path: &str) -> Option<(String, String)> {
    let (jar_key, rel_path) = path.rsplit_once("!/")?;
    Some((jar_key.to_string(), normalize_rel_path(rel_path)))
}

fn analyze_layer(layer_entries: &[LayerEntryRef<'_>], findings: &mut Vec<MetadataFinding>) {
    let rel_paths = layer_entries
        .iter()
        .map(|entry| entry.rel_path.clone())
        .collect::<HashSet<_>>();
    let class_paths = layer_entries
        .iter()
        .filter(|entry| entry.rel_path.ends_with(".class"))
        .map(|entry| entry.rel_path.clone())
        .collect::<HashSet<_>>();

    if let Some(entry) = layer_entries
        .iter()
        .find(|entry| entry.rel_path.eq_ignore_ascii_case("fabric.mod.json"))
    {
        analyze_fabric_metadata(entry.entry, &rel_paths, &class_paths, findings);
    }

    if let Some(entry) = layer_entries
        .iter()
        .find(|entry| entry.rel_path.eq_ignore_ascii_case("META-INF/mods.toml"))
    {
        analyze_forge_metadata(entry.entry, findings);
    }

    if let Some(entry) = layer_entries
        .iter()
        .find(|entry| entry.rel_path.eq_ignore_ascii_case("plugin.yml"))
    {
        analyze_spigot_metadata(entry.entry, &class_paths, findings);
    }

    if let Some(entry) = layer_entries
        .iter()
        .find(|entry| entry.rel_path.eq_ignore_ascii_case("META-INF/MANIFEST.MF"))
    {
        analyze_manifest_metadata(entry.entry, findings);
    }
}

fn analyze_fabric_metadata(
    entry: &ArchiveEntry,
    rel_paths: &HashSet<String>,
    class_paths: &HashSet<String>,
    findings: &mut Vec<MetadataFinding>,
) {
    let text = entry_text(entry);
    let parsed = match serde_json::from_str::<JsonValue>(text.as_ref()) {
        Ok(parsed) => parsed,
        Err(error) => {
            push_finding(
                findings,
                "META-FABRIC-PARSE-ERROR",
                "Fabric metadata parse failure",
                "low",
                entry.path.as_str(),
                format!("Failed to parse fabric.mod.json: {error}"),
                "Malformed Fabric metadata reduces trust in declared mod identity and entrypoints.",
            );
            return;
        }
    };

    let fabric_id = parsed.get("id").and_then(JsonValue::as_str);
    if !matches!(fabric_id, Some(value) if FABRIC_ID_RE.is_match(value)) {
        push_finding(
            findings,
            "META-FABRIC-ID-INVALID",
            "Fabric mod id is missing or invalid",
            "low",
            entry.path.as_str(),
            format!("id={}", fabric_id.unwrap_or("<missing>")),
            "Fabric id should follow the expected lowercase format for stable identity tracking.",
        );
    }

    match parsed.get("entrypoints") {
        Some(JsonValue::Object(entrypoints)) => {
            for (entrypoint_kind, value) in entrypoints {
                let mut targets = Vec::new();
                collect_fabric_entrypoint_targets(value, &mut targets);
                if targets.is_empty() {
                    push_finding(
                        findings,
                        "META-FABRIC-ENTRYPOINT-INVALID",
                        "Fabric entrypoint declaration is malformed",
                        "low",
                        entry.path.as_str(),
                        format!("entrypoints.{entrypoint_kind} has unsupported shape"),
                        "Entrypoint definitions should be explicit strings or objects with value fields.",
                    );
                    continue;
                }

                for target in targets {
                    let Some(class_path) = entrypoint_class_to_rel_path(target.as_str()) else {
                        push_finding(
                            findings,
                            "META-FABRIC-ENTRYPOINT-INVALID",
                            "Fabric entrypoint declaration is malformed",
                            "low",
                            entry.path.as_str(),
                            format!("entrypoints.{entrypoint_kind} target '{target}' is invalid"),
                            "Entrypoint target should point to a class name (optionally with ::method suffix).",
                        );
                        continue;
                    };

                    if !class_paths.contains(&class_path) {
                        push_finding(
                            findings,
                            "META-FABRIC-ENTRYPOINT-MISSING",
                            "Fabric entrypoint class is missing",
                            "med",
                            entry.path.as_str(),
                            format!(
                                "entrypoints.{entrypoint_kind} references '{target}' -> '{class_path}', but class entry was not found in this jar layer"
                            ),
                            "Entrypoint metadata should map to a class that actually exists in the same jar layer.",
                        );
                    }
                }
            }
        }
        Some(_) => push_finding(
            findings,
            "META-FABRIC-ENTRYPOINT-INVALID",
            "Fabric entrypoints block is malformed",
            "low",
            entry.path.as_str(),
            "entrypoints field is present but not an object".to_string(),
            "Entrypoints should be an object keyed by environment (main/client/server).",
        ),
        None => push_finding(
            findings,
            "META-FABRIC-ENTRYPOINT-INVALID",
            "Fabric entrypoints block is missing",
            "low",
            entry.path.as_str(),
            "entrypoints field is missing".to_string(),
            "Missing entrypoint metadata reduces confidence in declared runtime behavior.",
        ),
    }

    if let Some(jars) = parsed.get("jars").and_then(JsonValue::as_array) {
        for (index, jar_ref) in jars.iter().enumerate() {
            let Some(file_value) = jar_ref.get("file").and_then(JsonValue::as_str) else {
                push_finding(
                    findings,
                    "META-FABRIC-NESTEDJAR-INVALID",
                    "Fabric nested jar declaration is malformed",
                    "low",
                    entry.path.as_str(),
                    format!("jars[{index}] missing string file path"),
                    "Each Fabric nested jar declaration should include a file path string.",
                );
                continue;
            };

            let normalized = normalize_rel_path(file_value);
            if normalized.is_empty() {
                push_finding(
                    findings,
                    "META-FABRIC-NESTEDJAR-INVALID",
                    "Fabric nested jar declaration is malformed",
                    "low",
                    entry.path.as_str(),
                    format!("jars[{index}] references an empty file path"),
                    "Nested jar declaration should point at a concrete jar entry path.",
                );
                continue;
            }

            if !rel_paths.contains(&normalized) {
                push_finding(
                    findings,
                    "META-FABRIC-NESTEDJAR-MISSING",
                    "Fabric nested jar entry is missing",
                    "med",
                    entry.path.as_str(),
                    format!("jars[{index}].file='{normalized}' was not found in this jar layer"),
                    "Declared Fabric nested jars should exist as entries in the same archive layer.",
                );
            }
        }
    }
}

fn analyze_forge_metadata(entry: &ArchiveEntry, findings: &mut Vec<MetadataFinding>) {
    let text = entry_text(entry);
    let parsed = match toml::from_str::<TomlValue>(text.as_ref()) {
        Ok(parsed) => parsed,
        Err(error) => {
            push_finding(
                findings,
                "META-FORGE-PARSE-ERROR",
                "Forge metadata parse failure",
                "low",
                entry.path.as_str(),
                format!("Failed to parse mods.toml: {error}"),
                "Malformed Forge metadata reduces trust in declared mod identity.",
            );
            return;
        }
    };

    let Some(mods) = parsed.get("mods").and_then(TomlValue::as_array) else {
        push_finding(
            findings,
            "META-FORGE-MODS-MISSING",
            "Forge mods table is missing",
            "low",
            entry.path.as_str(),
            "[[mods]] table is missing or not an array".to_string(),
            "Forge metadata should include at least one [[mods]] entry with a valid modId.",
        );
        return;
    };

    for (index, mod_entry) in mods.iter().enumerate() {
        let mod_id = mod_entry.get("modId").and_then(TomlValue::as_str);
        if !matches!(mod_id, Some(value) if FORGE_MOD_ID_RE.is_match(value)) {
            push_finding(
                findings,
                "META-FORGE-MODID-INVALID",
                "Forge modId is missing or invalid",
                "low",
                entry.path.as_str(),
                format!("mods[{index}].modId={}", mod_id.unwrap_or("<missing>")),
                "Forge mod identifiers should be lowercase and match expected modId format.",
            );
        }
    }
}

fn analyze_spigot_metadata(
    entry: &ArchiveEntry,
    class_paths: &HashSet<String>,
    findings: &mut Vec<MetadataFinding>,
) {
    let text = entry_text(entry);
    let parsed = match serde_yml::from_str::<YamlValue>(text.as_ref()) {
        Ok(parsed) => parsed,
        Err(error) => {
            push_finding(
                findings,
                "META-SPIGOT-PARSE-ERROR",
                "Spigot plugin metadata parse failure",
                "low",
                entry.path.as_str(),
                format!("Failed to parse plugin.yml: {error}"),
                "Malformed plugin.yml reduces confidence in declared plugin metadata.",
            );
            return;
        }
    };

    let Some(mapping) = parsed.as_mapping() else {
        push_finding(
            findings,
            "META-SPIGOT-PARSE-ERROR",
            "Spigot plugin metadata parse failure",
            "low",
            entry.path.as_str(),
            "plugin.yml root is not a mapping".to_string(),
            "plugin.yml should be a key-value mapping with required fields.",
        );
        return;
    };

    let name = yaml_mapping_string(mapping, "name");
    if name.as_deref().map(str::is_empty).unwrap_or(true) {
        push_finding(
            findings,
            "META-SPIGOT-MISSING-FIELD",
            "Spigot required field is missing",
            "low",
            entry.path.as_str(),
            "plugin.yml missing required field: name".to_string(),
            "Spigot plugins should declare a stable plugin name.",
        );
    } else if !SPIGOT_NAME_RE.is_match(name.as_deref().unwrap_or_default()) {
        push_finding(
            findings,
            "META-SPIGOT-NAME-INVALID",
            "Spigot plugin name format is invalid",
            "low",
            entry.path.as_str(),
            format!("name={}", name.unwrap_or_default()),
            "Spigot plugin name should use alphanumeric and underscore characters.",
        );
    }

    let version = yaml_mapping_string(mapping, "version");
    if version.as_deref().map(str::is_empty).unwrap_or(true) {
        push_finding(
            findings,
            "META-SPIGOT-MISSING-FIELD",
            "Spigot required field is missing",
            "low",
            entry.path.as_str(),
            "plugin.yml missing required field: version".to_string(),
            "Spigot plugins should declare a version to support traceability.",
        );
    }

    let main = yaml_mapping_string(mapping, "main");
    match main {
        Some(main_value) if !main_value.is_empty() => {
            let Some(class_path) = entrypoint_class_to_rel_path(main_value.as_str()) else {
                push_finding(
                    findings,
                    "META-SPIGOT-MAINCLASS-INVALID",
                    "Spigot main class declaration is invalid",
                    "low",
                    entry.path.as_str(),
                    format!("main={main_value}"),
                    "Spigot main should reference a Java class name.",
                );
                return;
            };

            if !class_paths.contains(&class_path) {
                push_finding(
                    findings,
                    "META-SPIGOT-MAINCLASS-MISSING",
                    "Spigot main class is missing",
                    "med",
                    entry.path.as_str(),
                    format!(
                        "main='{main_value}' -> '{class_path}' was not found in this jar layer"
                    ),
                    "Spigot main class should exist as a .class entry in the same jar layer.",
                );
            }
        }
        _ => push_finding(
            findings,
            "META-SPIGOT-MISSING-FIELD",
            "Spigot required field is missing",
            "low",
            entry.path.as_str(),
            "plugin.yml missing required field: main".to_string(),
            "Spigot plugins should declare the main entrypoint class.",
        ),
    }
}

fn analyze_manifest_metadata(entry: &ArchiveEntry, findings: &mut Vec<MetadataFinding>) {
    let text = entry_text(entry);
    let mut emitted_ids = HashSet::new();

    for line in text.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };

        let key = key.trim();
        let value = value.trim();

        for (needle, id, title, rationale) in SUSPICIOUS_MANIFEST_KEYS {
            if key.eq_ignore_ascii_case(needle) && emitted_ids.insert(id) {
                push_finding(
                    findings,
                    id,
                    title,
                    "high",
                    entry.path.as_str(),
                    format!("{needle}: {value}"),
                    rationale,
                );
            }
        }
    }
}

fn collect_fabric_entrypoint_targets(value: &JsonValue, targets: &mut Vec<String>) {
    match value {
        JsonValue::String(value) => targets.push(value.clone()),
        JsonValue::Array(values) => {
            for value in values {
                collect_fabric_entrypoint_targets(value, targets);
            }
        }
        JsonValue::Object(values) => {
            if let Some(value) = values.get("value") {
                collect_fabric_entrypoint_targets(value, targets);
            }
        }
        _ => {}
    }
}

fn entrypoint_class_to_rel_path(raw: &str) -> Option<String> {
    let class_target = raw.trim().split("::").next()?.trim();
    if class_target.is_empty() || class_target.chars().any(char::is_whitespace) {
        return None;
    }

    let normalized = normalize_rel_path(class_target.replace('.', "/").as_str());
    if normalized.is_empty() {
        return None;
    }

    if normalized.ends_with(".class") {
        Some(normalized)
    } else {
        Some(format!("{normalized}.class"))
    }
}

fn normalize_rel_path(path: &str) -> String {
    path.replace('\\', "/")
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string()
}

fn entry_text(entry: &ArchiveEntry) -> Cow<'_, str> {
    if let Some(text) = entry.text.as_deref() {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(String::from_utf8_lossy(entry.bytes.as_slice()).into_owned())
    }
}

fn yaml_mapping_string(mapping: &serde_yml::Mapping, field: &str) -> Option<String> {
    let key = YamlValue::String(field.to_string());
    let value = mapping.get(&key)?;
    match value {
        YamlValue::String(value) => Some(value.trim().to_string()),
        YamlValue::Number(value) => Some(value.to_string()),
        YamlValue::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn push_finding(
    findings: &mut Vec<MetadataFinding>,
    id: &str,
    title: &str,
    severity: &str,
    file_path: &str,
    evidence: String,
    rationale: &str,
) {
    findings.push(MetadataFinding {
        id: id.to_string(),
        title: title.to_string(),
        severity: severity.to_string(),
        file_path: file_path.to_string(),
        evidence,
        rationale: rationale.to_string(),
    });
}

#[cfg(test)]
mod tests {
    use super::{analyze_metadata, group_entries_by_jar_layer};
    use crate::analysis::ArchiveEntry;

    #[test]
    fn groups_entries_by_outer_and_inner_jar_layers() {
        let entries = vec![
            archive_entry("outer.jar!/fabric.mod.json", "{}"),
            archive_entry("outer.jar!/META-INF/jars/inner.jar", "zip-bytes"),
            archive_entry(
                "outer.jar!/META-INF/jars/inner.jar!/plugin.yml",
                "name: Demo",
            ),
        ];

        let grouped = group_entries_by_jar_layer(entries.as_slice());

        assert_eq!(grouped.len(), 2);
        assert!(grouped.contains_key("outer.jar"));
        assert!(grouped.contains_key("outer.jar!/META-INF/jars/inner.jar"));
    }

    #[test]
    fn emits_fabric_findings_for_missing_entrypoint_and_nested_jar() {
        let entries = vec![archive_entry(
            "outer.jar!/fabric.mod.json",
            r#"{
  "id": "Bad-Id",
  "entrypoints": {
    "main": ["com.example.MissingEntrypoint"]
  },
  "jars": [{"file": "META-INF/jars/missing.jar"}]
}"#,
        )];

        let findings = analyze_metadata(entries.as_slice());
        let ids = findings
            .iter()
            .map(|finding| finding.id.as_str())
            .collect::<Vec<_>>();

        assert!(ids.contains(&"META-FABRIC-ID-INVALID"));
        assert!(ids.contains(&"META-FABRIC-ENTRYPOINT-MISSING"));
        assert!(ids.contains(&"META-FABRIC-NESTEDJAR-MISSING"));
    }

    #[test]
    fn emits_high_severity_manifest_findings_for_agent_keys() {
        let entries = vec![archive_entry(
            "outer.jar!/META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nPremain-Class: com.example.Agent\nBoot-Class-Path: libs/agent.jar\n",
        )];

        let findings = analyze_metadata(entries.as_slice());
        let premain = findings
            .iter()
            .find(|finding| finding.id == "META-MANIFEST-PREMAIN")
            .expect("expected premain finding");
        let boot_class_path = findings
            .iter()
            .find(|finding| finding.id == "META-MANIFEST-BOOTCLASSPATH")
            .expect("expected boot class path finding");

        assert_eq!(premain.severity, "high");
        assert_eq!(boot_class_path.severity, "high");
    }

    #[test]
    fn emits_spigot_main_class_missing_when_plugin_main_class_is_not_present() {
        let entries = vec![archive_entry(
            "outer.jar!/plugin.yml",
            "name: DemoPlugin\nversion: 1.0.0\nmain: com.jarspect.demo.MainPlugin\n",
        )];

        let findings = analyze_metadata(entries.as_slice());

        assert!(
            findings
                .iter()
                .any(|finding| finding.id == "META-SPIGOT-MAINCLASS-MISSING")
        );
    }

    fn archive_entry(path: &str, text: &str) -> ArchiveEntry {
        ArchiveEntry {
            path: path.to_string(),
            bytes: text.as_bytes().to_vec(),
            text: Some(text.to_string()),
        }
    }
}
