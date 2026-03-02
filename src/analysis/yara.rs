use anyhow::Result;
use yara_x::{MetaValue, Rule, Rules, Scanner};

use crate::analysis::ArchiveEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulepackKind {
    Demo,
    Prod,
}

impl RulepackKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Demo => "demo",
            Self::Prod => "prod",
        }
    }

    pub fn indicator_prefix(self) -> &'static str {
        match self {
            Self::Demo => "DEMO",
            Self::Prod => "PROD",
        }
    }

    pub fn default_severity(self) -> &'static str {
        match self {
            Self::Demo => "high",
            Self::Prod => "med",
        }
    }

    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "demo" => Some(Self::Demo),
            "prod" => Some(Self::Prod),
            _ => None,
        }
    }
}

pub struct YaraRulepack {
    pub kind: RulepackKind,
    pub rules: Rules,
}

pub struct YaraFinding {
    pub pack: RulepackKind,
    pub rule_identifier: String,
    pub severity: String,
    pub evidence: String,
}

pub fn scan_yara_rulepacks(
    entries: &[ArchiveEntry],
    packs: &[YaraRulepack],
) -> Result<Vec<(String, YaraFinding)>> {
    let mut findings = Vec::new();

    for pack in packs {
        for entry in entries {
            let mut scanner = Scanner::new(&pack.rules);
            let scan_results = scanner.scan(entry.bytes.as_slice())?;
            for rule in scan_results.matching_rules() {
                findings.push((
                    entry.path.clone(),
                    YaraFinding {
                        pack: pack.kind,
                        rule_identifier: rule.identifier().to_string(),
                        severity: derive_rule_severity(&rule, pack.kind).to_string(),
                        evidence: build_match_evidence(&rule),
                    },
                ));
            }
        }
    }

    Ok(findings)
}

fn derive_rule_severity(rule: &Rule<'_, '_>, pack: RulepackKind) -> &'static str {
    for (key, value) in rule.metadata() {
        if key.eq_ignore_ascii_case("severity") {
            if let MetaValue::String(severity) = value {
                if let Some(canonical) = canonicalize_severity(severity) {
                    return canonical;
                }
            }
        }
    }

    for (key, value) in rule.metadata() {
        if key.eq_ignore_ascii_case("threat_level") {
            if let MetaValue::Integer(level) = value {
                return severity_from_threat_level(level);
            }
        }
    }

    for tag in rule.tags() {
        if let Some(canonical) = severity_from_tag(tag.identifier()) {
            return canonical;
        }
    }

    pack.default_severity()
}

fn canonicalize_severity(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Some("critical"),
        "high" => Some("high"),
        "med" | "medium" => Some("med"),
        "low" => Some("low"),
        "info" | "informational" => Some("info"),
        _ => None,
    }
}

fn severity_from_threat_level(level: i64) -> &'static str {
    match level {
        i64::MIN..=1 => "info",
        2 => "low",
        3 => "med",
        4 => "high",
        _ => "critical",
    }
}

fn severity_from_tag(tag: &str) -> Option<&'static str> {
    if let Some(canonical) = canonicalize_severity(tag) {
        return Some(canonical);
    }

    for token in tag.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        if let Some(canonical) = canonicalize_severity(token) {
            return Some(canonical);
        }
    }

    None
}

fn build_match_evidence(rule: &Rule<'_, '_>) -> String {
    let mut ranges = Vec::new();

    for pattern in rule.patterns() {
        for matched in pattern.matches() {
            ranges.push(format!(
                "{}@{}..{}",
                pattern.identifier(),
                matched.range().start,
                matched.range().end
            ));
            if ranges.len() >= 3 {
                break;
            }
        }

        if ranges.len() >= 3 {
            break;
        }
    }

    if ranges.is_empty() {
        format!("Matched rule {}", rule.identifier())
    } else {
        format!("Matched rule {} ({})", rule.identifier(), ranges.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use yara_x::Compiler;

    use super::{RulepackKind, YaraRulepack, scan_yara_rulepacks};
    use crate::analysis::ArchiveEntry;

    #[test]
    fn uses_meta_severity_and_reports_entry_path() {
        let rules = compile_rules(
            r#"
rule meta_severity {
  meta:
    severity = "low"
  strings:
    $needle = "Runtime.getRuntime().exec"
  condition:
    $needle
}
"#,
        );

        let pack = YaraRulepack {
            kind: RulepackKind::Demo,
            rules,
        };
        let entry = ArchiveEntry {
            path: "outer.jar!/META-INF/jars/inner.jar!/Example.class".to_string(),
            bytes: b"Runtime.getRuntime().exec".to_vec(),
            text: None,
        };

        let findings =
            scan_yara_rulepacks(std::slice::from_ref(&entry), std::slice::from_ref(&pack))
                .expect("expected YARA scan to pass");

        assert_eq!(findings.len(), 1);
        let (path, finding) = &findings[0];
        assert_eq!(path, &entry.path);
        assert_eq!(finding.pack, RulepackKind::Demo);
        assert_eq!(finding.rule_identifier, "meta_severity");
        assert_eq!(finding.severity, "low");
    }

    #[test]
    fn falls_back_to_threat_level_then_tag_then_pack_default() {
        let threat_level_rules = compile_rules(
            r#"
rule threat_level_rule {
  meta:
    threat_level = 4
  strings:
    $a = "alpha"
  condition:
    $a
}
"#,
        );
        let tag_rules = compile_rules(
            r#"
rule tag_rule : informational {
  strings:
    $b = "beta"
  condition:
    $b
}
"#,
        );
        let default_rules = compile_rules(
            r#"
rule default_rule {
  strings:
    $c = "gamma"
  condition:
    $c
}
"#,
        );

        let findings = scan_yara_rulepacks(
            &[
                ArchiveEntry {
                    path: "a.txt".to_string(),
                    bytes: b"alpha".to_vec(),
                    text: None,
                },
                ArchiveEntry {
                    path: "b.txt".to_string(),
                    bytes: b"beta".to_vec(),
                    text: None,
                },
                ArchiveEntry {
                    path: "c.txt".to_string(),
                    bytes: b"gamma".to_vec(),
                    text: None,
                },
            ],
            &[
                YaraRulepack {
                    kind: RulepackKind::Prod,
                    rules: threat_level_rules,
                },
                YaraRulepack {
                    kind: RulepackKind::Prod,
                    rules: tag_rules,
                },
                YaraRulepack {
                    kind: RulepackKind::Prod,
                    rules: default_rules,
                },
            ],
        )
        .expect("expected fallback scan to pass");

        let severities = findings
            .into_iter()
            .map(|(_, finding)| finding.severity)
            .collect::<Vec<_>>();

        assert!(severities.contains(&"high".to_string()));
        assert!(severities.contains(&"info".to_string()));
        assert!(severities.contains(&"med".to_string()));
    }

    fn compile_rules(source: &str) -> yara_x::Rules {
        let mut compiler = Compiler::new();
        compiler
            .add_source(source)
            .expect("expected in-test rules to compile");
        compiler.build()
    }
}
