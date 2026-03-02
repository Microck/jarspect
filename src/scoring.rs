use std::collections::{BTreeMap, BTreeSet};

const TOP_CONTRIBUTOR_COUNT: usize = 5;
const SYNERGY_CAP_POINTS: i32 = 35;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScoredVerdict {
    pub(crate) risk_tier: String,
    pub(crate) raw_score: i32,
    pub(crate) risk_score: i32,
    pub(crate) explanation: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

fn severity_weight(severity: Severity) -> i32 {
    match severity {
        Severity::Info => 1,
        Severity::Low => 3,
        Severity::Medium => 8,
        Severity::High => 16,
        Severity::Critical => 30,
    }
}

fn normalize_severity(raw: &str) -> Severity {
    match raw.trim().to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Info,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum ScoreCategory {
    CredentialTheft,
    Deserialization,
    DynamicLoading,
    Execution,
    Filesystem,
    KnownMalware,
    NativeLoading,
    Network,
    Other,
    Persistence,
}

impl ScoreCategory {
    fn as_str(self) -> &'static str {
        match self {
            ScoreCategory::CredentialTheft => "credential_theft",
            ScoreCategory::Deserialization => "deserialization",
            ScoreCategory::DynamicLoading => "dynamic_loading",
            ScoreCategory::Execution => "execution",
            ScoreCategory::Filesystem => "filesystem",
            ScoreCategory::KnownMalware => "known_malware",
            ScoreCategory::NativeLoading => "native_loading",
            ScoreCategory::Network => "network",
            ScoreCategory::Other => "other",
            ScoreCategory::Persistence => "persistence",
        }
    }
}

#[derive(Debug, Clone)]
struct ScoreUnit {
    category: ScoreCategory,
    fingerprint: String,
    severity: Severity,
    sources: BTreeSet<String>,
    evidence_refs: BTreeSet<String>,
}

impl ScoreUnit {
    fn unit_id(&self) -> String {
        format!("{}:{}", self.category.as_str(), self.fingerprint)
    }
}

#[derive(Debug, Clone)]
struct Contributor {
    points: i32,
    category: ScoreCategory,
    severity: Severity,
    fingerprint: String,
    evidence_ref: String,
}

impl Contributor {
    fn unit_id(&self) -> String {
        format!("{}:{}", self.category.as_str(), self.fingerprint)
    }
}

#[derive(Debug, Clone)]
struct SynergyContribution {
    points: i32,
    combo_name: String,
    supporting_units: Vec<String>,
}

pub(crate) fn score_static_indicators(
    static_indicators: &[crate::Indicator],
    reputation: Option<&crate::ReputationResult>,
) -> ScoredVerdict {
    let units = build_score_units(static_indicators);
    let deduped_unit_count = units.len();

    let mut units_by_category: BTreeMap<ScoreCategory, Vec<ScoreUnit>> = BTreeMap::new();
    for unit in units.into_values() {
        units_by_category
            .entry(unit.category)
            .or_default()
            .push(unit);
    }

    let mut contributors = Vec::new();
    let mut base_points = 0;

    for units in units_by_category.values_mut() {
        units.sort_by(|left, right| {
            severity_weight(right.severity)
                .cmp(&severity_weight(left.severity))
                .then_with(|| left.unit_id().cmp(&right.unit_id()))
        });

        let max_unit_weight = units
            .first()
            .map(|unit| severity_weight(unit.severity))
            .unwrap_or(0);
        let category_cap_points = (max_unit_weight * 5) / 2;
        let mut remaining_cap_points = category_cap_points;

        for (index, unit) in units.iter().enumerate() {
            let (num, denom) = diminishing_multiplier(index);
            let unit_points_pre_cap = severity_weight(unit.severity) * num / denom;
            let unit_points_effective = unit_points_pre_cap.min(remaining_cap_points);
            remaining_cap_points -= unit_points_effective;
            base_points += unit_points_effective;

            let evidence_ref = unit
                .evidence_refs
                .iter()
                .next()
                .cloned()
                .unwrap_or_else(|| "n/a".to_string());

            contributors.push(Contributor {
                points: unit_points_effective,
                category: unit.category,
                severity: unit.severity,
                fingerprint: unit.fingerprint.clone(),
                evidence_ref,
            });
        }
    }

    let synergy_lines = compute_synergy_lines(&units_by_category);
    let synergy_points: i32 = synergy_lines.iter().map(|line| line.points).sum();

    let reputation_points = compute_reputation_points(reputation);
    let raw_score = base_points + synergy_points + reputation_points;
    let risk_score = raw_score.clamp(0, 100);
    let risk_tier = tier_for_score(risk_score, deduped_unit_count, reputation_points).to_string();

    let explanation = render_explanation(
        deduped_unit_count,
        contributors,
        &synergy_lines,
        reputation,
        reputation_points,
    );

    ScoredVerdict {
        risk_tier,
        raw_score,
        risk_score,
        explanation,
    }
}

fn build_score_units(
    static_indicators: &[crate::Indicator],
) -> BTreeMap<(ScoreCategory, String), ScoreUnit> {
    let mut units: BTreeMap<(ScoreCategory, String), ScoreUnit> = BTreeMap::new();

    for indicator in static_indicators {
        let category = score_category_for_indicator(indicator);
        let fingerprint = fingerprint_indicator(indicator, category);
        let key = (category, fingerprint.clone());

        let entry = units.entry(key).or_insert_with(|| ScoreUnit {
            category,
            fingerprint,
            severity: Severity::Info,
            sources: BTreeSet::new(),
            evidence_refs: BTreeSet::new(),
        });

        let severity = normalize_severity(&indicator.severity);
        if severity > entry.severity {
            entry.severity = severity;
        }

        entry
            .sources
            .insert(indicator.source.trim().to_ascii_lowercase());
        entry
            .evidence_refs
            .insert(evidence_ref_for_indicator(indicator));
    }

    units
}

fn score_category_for_indicator(indicator: &crate::Indicator) -> ScoreCategory {
    let source = indicator.source.trim().to_ascii_lowercase();

    if source == "detector" {
        if let Some(category) = detector_category_from_id(&indicator.id) {
            return category;
        }
        return score_category_from_label(&indicator.category);
    }

    if source == "yara" || source == "signature" {
        return ScoreCategory::KnownMalware;
    }

    score_category_from_label(&indicator.category)
}

fn detector_category_from_id(indicator_id: &str) -> Option<ScoreCategory> {
    let normalized = indicator_id.trim().to_ascii_uppercase();
    if normalized.starts_with("DETC-01") {
        Some(ScoreCategory::Execution)
    } else if normalized.starts_with("DETC-02") {
        Some(ScoreCategory::Network)
    } else if normalized.starts_with("DETC-03") {
        Some(ScoreCategory::DynamicLoading)
    } else if normalized.starts_with("DETC-04") {
        Some(ScoreCategory::Filesystem)
    } else if normalized.starts_with("DETC-05") {
        Some(ScoreCategory::Persistence)
    } else if normalized.starts_with("DETC-06") {
        Some(ScoreCategory::Deserialization)
    } else if normalized.starts_with("DETC-07") {
        Some(ScoreCategory::NativeLoading)
    } else if normalized.starts_with("DETC-08") {
        Some(ScoreCategory::CredentialTheft)
    } else {
        None
    }
}

fn score_category_from_label(raw_category: &str) -> ScoreCategory {
    let normalized = normalize_token(raw_category);
    match normalized.as_str() {
        "execution" => ScoreCategory::Execution,
        "network" => ScoreCategory::Network,
        "filesystem" | "file_system" | "fs" => ScoreCategory::Filesystem,
        "persistence" => ScoreCategory::Persistence,
        "dynamic_loading" | "dynamic_load" | "loader" => ScoreCategory::DynamicLoading,
        "native_loading" | "native_load" => ScoreCategory::NativeLoading,
        "deserialization" => ScoreCategory::Deserialization,
        "credential_theft" | "creds" => ScoreCategory::CredentialTheft,
        "obfuscation" => ScoreCategory::DynamicLoading,
        "signature" | "reputation" => ScoreCategory::KnownMalware,
        _ => ScoreCategory::Other,
    }
}

fn fingerprint_indicator(indicator: &crate::Indicator, category: ScoreCategory) -> String {
    let location_component = location_component(indicator);
    let anchor_component = anchor_component(indicator);

    let mut pieces = vec![category.as_str().to_string()];
    if !location_component.is_empty() {
        pieces.push(location_component);
    }
    if !anchor_component.is_empty() {
        pieces.push(anchor_component);
    }

    if pieces.len() == 1 {
        let id_fallback = normalize_piece(&indicator.id, 64).to_ascii_lowercase();
        pieces.push(format!("id={id_fallback}"));
    }

    pieces.join("|")
}

fn location_component(indicator: &crate::Indicator) -> String {
    let mut parts: BTreeSet<String> = BTreeSet::new();

    if let Some(path) = indicator.file_path.as_ref() {
        let normalized_path = normalize_piece(path, 96).to_ascii_lowercase();
        if !normalized_path.is_empty() {
            parts.insert(format!("path={normalized_path}"));
        }
    }

    for summary in location_summaries(indicator) {
        parts.insert(format!("loc={summary}"));
    }

    parts.into_iter().take(2).collect::<Vec<_>>().join("|")
}

fn anchor_component(indicator: &crate::Indicator) -> String {
    let observables = observable_tokens(indicator);
    if let Some(first) = observables.first() {
        return format!("observable={}", normalize_piece(first, 64));
    }

    let snippet = normalize_piece(&indicator.evidence, 64);
    if !snippet.is_empty() {
        return format!("evidence={snippet}");
    }

    String::new()
}

fn evidence_ref_for_indicator(indicator: &crate::Indicator) -> String {
    let observables = observable_tokens(indicator);
    let location = location_summaries(indicator).into_iter().next();

    if let Some(first) = observables.first() {
        if let Some(location_summary) = location {
            return format!("{first} @ {location_summary}");
        }
        return first.clone();
    }

    let snippet = normalize_piece(&indicator.evidence, 80);
    match (snippet.is_empty(), location) {
        (false, Some(location_summary)) => format!("{snippet} @ {location_summary}"),
        (false, None) => snippet,
        (true, Some(location_summary)) => location_summary,
        (true, None) => {
            let id_fallback = normalize_piece(&indicator.id, 64);
            if id_fallback.is_empty() {
                "n/a".to_string()
            } else {
                id_fallback
            }
        }
    }
}

fn observable_tokens(indicator: &crate::Indicator) -> Vec<String> {
    let mut values: BTreeSet<String> = BTreeSet::new();

    for value in indicator.extracted_urls.as_deref().unwrap_or(&[]) {
        let normalized = normalize_piece(value, 120).to_ascii_lowercase();
        if !normalized.is_empty() {
            values.insert(normalized);
        }
    }
    for value in indicator.extracted_commands.as_deref().unwrap_or(&[]) {
        let normalized = normalize_piece(value, 120).to_ascii_lowercase();
        if !normalized.is_empty() {
            values.insert(normalized);
        }
    }
    for value in indicator.extracted_file_paths.as_deref().unwrap_or(&[]) {
        let normalized = normalize_piece(value, 120).to_ascii_lowercase();
        if !normalized.is_empty() {
            values.insert(normalized);
        }
    }

    values.into_iter().collect()
}

fn location_summaries(indicator: &crate::Indicator) -> Vec<String> {
    let mut summaries: BTreeSet<String> = BTreeSet::new();

    for location in indicator.evidence_locations.as_deref().unwrap_or(&[]) {
        let mut summary = normalize_piece(&location.entry_path, 80).to_ascii_lowercase();
        if !location.class_name.trim().is_empty() {
            summary.push('#');
            summary.push_str(&normalize_piece(&location.class_name, 80).to_ascii_lowercase());
        }
        if let Some(method) = location.method.as_ref() {
            summary.push_str("::");
            summary.push_str(&normalize_piece(&method.name, 32).to_ascii_lowercase());
            summary.push_str(&normalize_piece(&method.descriptor, 48).to_ascii_lowercase());
        }
        if let Some(pc) = location.pc {
            summary.push('@');
            summary.push_str(pc.to_string().as_str());
        }

        if !summary.is_empty() {
            summaries.insert(summary);
        }
    }

    summaries.into_iter().collect()
}

fn normalize_token(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_separator = false;

    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_separator = false;
            continue;
        }

        if !last_separator {
            out.push('_');
            last_separator = true;
        }
    }

    out.trim_matches('_').to_string()
}

fn normalize_piece(raw: &str, max_chars: usize) -> String {
    let compact = raw.split_whitespace().collect::<Vec<_>>().join(" ");
    compact.chars().take(max_chars).collect()
}

fn diminishing_multiplier(index: usize) -> (i32, i32) {
    if index < 3 {
        (1, 1)
    } else if index < 6 {
        (1, 2)
    } else {
        (1, 4)
    }
}

fn compute_synergy_lines(
    units_by_category: &BTreeMap<ScoreCategory, Vec<ScoreUnit>>,
) -> Vec<SynergyContribution> {
    let mut ids_by_category: BTreeMap<ScoreCategory, Vec<String>> = BTreeMap::new();
    for (category, units) in units_by_category {
        let mut ids = units.iter().map(ScoreUnit::unit_id).collect::<Vec<_>>();
        ids.sort();
        ids.dedup();
        if !ids.is_empty() {
            ids_by_category.insert(*category, ids);
        }
    }

    let candidates = vec![
        (
            "execution + network",
            12,
            vec![ScoreCategory::Execution, ScoreCategory::Network],
        ),
        (
            "dynamic_loading + network",
            10,
            vec![ScoreCategory::DynamicLoading, ScoreCategory::Network],
        ),
        (
            "credential_theft + network",
            18,
            vec![ScoreCategory::CredentialTheft, ScoreCategory::Network],
        ),
        (
            "persistence + execution",
            8,
            vec![ScoreCategory::Persistence, ScoreCategory::Execution],
        ),
        (
            "persistence + network",
            8,
            vec![ScoreCategory::Persistence, ScoreCategory::Network],
        ),
        (
            "known_malware + execution",
            15,
            vec![ScoreCategory::KnownMalware, ScoreCategory::Execution],
        ),
    ];

    let mut matched = Vec::new();

    for (combo_name, points, required_categories) in candidates {
        let mut supporting_units = Vec::new();
        let mut all_present = true;

        for category in required_categories {
            if let Some(ids) = ids_by_category.get(&category) {
                if let Some(first) = ids.first() {
                    supporting_units.push(first.clone());
                } else {
                    all_present = false;
                    break;
                }
            } else {
                all_present = false;
                break;
            }
        }

        if all_present {
            supporting_units.sort();
            matched.push(SynergyContribution {
                points,
                combo_name: combo_name.to_string(),
                supporting_units,
            });
        }
    }

    matched.sort_by(|left, right| {
        right
            .points
            .cmp(&left.points)
            .then_with(|| left.combo_name.cmp(&right.combo_name))
    });

    let mut capped = Vec::new();
    let mut remaining_cap = SYNERGY_CAP_POINTS;
    for mut line in matched {
        if remaining_cap == 0 {
            break;
        }
        let effective_points = line.points.min(remaining_cap);
        if effective_points == 0 {
            continue;
        }
        line.points = effective_points;
        remaining_cap -= effective_points;
        capped.push(line);
    }

    capped
}

fn compute_reputation_points(reputation: Option<&crate::ReputationResult>) -> i32 {
    let Some(reputation) = reputation else {
        return 0;
    };

    let raw = ((1.0 - reputation.author_score).clamp(0.0, 1.0) * 20.0).round() as i32;
    raw.min(19)
}

fn tier_for_score(risk_score: i32, deduped_units: usize, reputation_points: i32) -> &'static str {
    if deduped_units == 0 && reputation_points == 0 {
        return "CLEAN";
    }

    if risk_score <= 19 {
        "LOW"
    } else if risk_score <= 49 {
        "MEDIUM"
    } else if risk_score <= 79 {
        "HIGH"
    } else {
        "CRITICAL"
    }
}

fn render_explanation(
    deduped_unit_count: usize,
    mut contributors: Vec<Contributor>,
    synergy_lines: &[SynergyContribution],
    reputation: Option<&crate::ReputationResult>,
    reputation_points: i32,
) -> Vec<String> {
    contributors.sort_by(|left, right| {
        right
            .points
            .cmp(&left.points)
            .then_with(|| left.unit_id().cmp(&right.unit_id()))
    });

    let mut explanation = vec![
        format!("Indicators: {deduped_unit_count}"),
        "Top contributors:".to_string(),
    ];

    for contributor in contributors.iter().take(TOP_CONTRIBUTOR_COUNT) {
        explanation.push(format!(
            "- +{} {}/{} [{}] evidence: {}",
            contributor.points,
            contributor.category.as_str(),
            contributor.severity.as_str(),
            contributor.unit_id(),
            contributor.evidence_ref,
        ));
    }

    if let Some(reputation) = reputation {
        explanation.push(format!(
            "Reputation adjustment: +{} (author_score={:.3}, capped)",
            reputation_points, reputation.author_score
        ));
    }

    explanation.push("Synergy bonuses:".to_string());
    if synergy_lines.is_empty() {
        explanation.push("- none".to_string());
    } else {
        for line in synergy_lines {
            let supporting_refs = line.supporting_units.join(", ");
            explanation.push(format!(
                "- +{} {} via [{}]",
                line.points, line.combo_name, supporting_refs
            ));
        }
    }

    explanation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn indicator(
        source: &str,
        id: &str,
        category: &str,
        severity: &str,
        evidence: &str,
    ) -> crate::Indicator {
        crate::Indicator {
            source: source.to_string(),
            id: id.to_string(),
            title: id.to_string(),
            category: category.to_string(),
            severity: severity.to_string(),
            file_path: Some("mods/sample.jar!/Example.class".to_string()),
            evidence: evidence.to_string(),
            rationale: "test fixture".to_string(),
            evidence_locations: None,
            extracted_urls: None,
            extracted_commands: None,
            extracted_file_paths: None,
        }
    }

    fn with_url(mut indicator: crate::Indicator, value: &str) -> crate::Indicator {
        indicator.extracted_urls = Some(vec![value.to_string()]);
        indicator
    }

    fn with_command(mut indicator: crate::Indicator, value: &str) -> crate::Indicator {
        indicator.extracted_commands = Some(vec![value.to_string()]);
        indicator
    }

    fn with_path(mut indicator: crate::Indicator, value: &str) -> crate::Indicator {
        indicator.extracted_file_paths = Some(vec![value.to_string()]);
        indicator
    }

    fn contributor_lines(explanation: &[String]) -> Vec<String> {
        let mut in_contributors = false;
        let mut lines = Vec::new();

        for line in explanation {
            if line == "Top contributors:" {
                in_contributors = true;
                continue;
            }
            if line == "Synergy bonuses:" {
                break;
            }
            if in_contributors && line.starts_with("- +") {
                lines.push(line.clone());
            }
        }

        lines
    }

    fn synergy_lines(explanation: &[String]) -> Vec<String> {
        let mut in_synergy = false;
        let mut lines = Vec::new();

        for line in explanation {
            if line == "Synergy bonuses:" {
                in_synergy = true;
                continue;
            }
            if in_synergy && line.starts_with("- +") {
                lines.push(line.clone());
            }
        }

        lines
    }

    fn parse_unit_id(contributor_line: &str) -> String {
        let start = contributor_line
            .find('[')
            .expect("expected [ in contributor line");
        let end = contributor_line[start + 1..]
            .find(']')
            .expect("expected ] in contributor line")
            + start
            + 1;
        contributor_line[start + 1..end].to_string()
    }

    fn parse_synergy_line(synergy_line: &str) -> (i32, String) {
        let stripped = synergy_line
            .strip_prefix("- +")
            .expect("synergy line must start with '- +'");
        let (points_raw, rest) = stripped
            .split_once(' ')
            .expect("synergy line should include points and combo");
        let points: i32 = points_raw
            .parse()
            .expect("synergy points should parse as i32");
        let combo_name = rest
            .split(" via ")
            .next()
            .expect("synergy line should include combo and refs")
            .to_string();
        (points, combo_name)
    }

    #[test]
    fn clean_verdict_is_reachable_with_zero_score() {
        let verdict = score_static_indicators(&[], None);

        assert_eq!(verdict.risk_tier, "CLEAN");
        assert_eq!(verdict.raw_score, 0);
        assert_eq!(verdict.risk_score, 0);
        assert!(verdict
            .explanation
            .iter()
            .any(|line| line.contains("Indicators: 0")));
    }

    #[test]
    fn duplicate_fingerprints_do_not_double_count() {
        let duplicate_low = with_url(
            indicator(
                "pattern",
                "NET-URL",
                "network",
                "low",
                "https://same.invalid/payload",
            ),
            "https://same.invalid/payload",
        );
        let duplicate_high = with_url(
            indicator(
                "detector",
                "DETC-02.NETWORK_IO",
                "capability",
                "high",
                "https://same.invalid/payload",
            ),
            "https://same.invalid/payload",
        );

        let deduped = score_static_indicators(&[duplicate_low, duplicate_high.clone()], None);
        let single = score_static_indicators(&[duplicate_high], None);

        assert_eq!(deduped.raw_score, single.raw_score);
        assert!(deduped
            .explanation
            .iter()
            .any(|line| line.contains("Indicators: 1")));
    }

    #[test]
    fn diminishing_returns_prevent_linear_scaling() {
        let mut indicators = Vec::new();

        for index in 0..8 {
            indicators.push(with_url(
                indicator(
                    "detector",
                    "DETC-02.NETWORK_IO",
                    "capability",
                    "low",
                    "network primitive",
                ),
                format!("https://example.invalid/{index}").as_str(),
            ));
        }

        let verdict = score_static_indicators(&indicators, None);
        let linear_sum = severity_weight(Severity::Low) * indicators.len() as i32;

        assert!(
            verdict.raw_score < linear_sum,
            "expected diminishing returns to reduce score below linear sum"
        );
    }

    #[test]
    fn execution_and_network_synergy_increases_score() {
        let execution = with_command(
            indicator(
                "detector",
                "DETC-01.RUNTIME_EXEC",
                "capability",
                "high",
                "Runtime.exec",
            ),
            "powershell -enc AAAA",
        );
        let network = with_url(
            indicator(
                "detector",
                "DETC-02.NETWORK_IO",
                "capability",
                "high",
                "URLConnection.connect",
            ),
            "https://example.invalid/c2",
        );

        let score_without_synergy = score_static_indicators(std::slice::from_ref(&execution), None);
        let score_with_synergy = score_static_indicators(&[execution, network], None);

        assert!(score_with_synergy.raw_score > score_without_synergy.raw_score);
        assert!(score_with_synergy
            .explanation
            .iter()
            .any(|line| line == "Synergy bonuses:"));
        assert!(score_with_synergy
            .explanation
            .iter()
            .any(|line| { line.contains("execution + network") && line.contains("+12") }));
    }

    #[test]
    fn top_contributors_are_stable_under_ties() {
        let execution = with_command(
            indicator(
                "detector",
                "DETC-01.RUNTIME_EXEC",
                "capability",
                "medium",
                "Runtime.exec",
            ),
            "cmd.exe /c whoami",
        );
        let filesystem = with_path(
            indicator(
                "detector",
                "DETC-04.FILESYSTEM_WRITE",
                "capability",
                "medium",
                "FileOutputStream.write",
            ),
            "mods/cache.bin",
        );

        let verdict = score_static_indicators(&[filesystem, execution], None);
        let lines = contributor_lines(&verdict.explanation);
        assert!(lines.len() >= 2);

        let first = parse_unit_id(&lines[0]);
        let second = parse_unit_id(&lines[1]);
        assert!(first <= second, "expected contributor tie-break by unit id");
    }

    #[test]
    fn synergy_lines_are_sorted_deterministically() {
        let execution = with_command(
            indicator(
                "detector",
                "DETC-01.RUNTIME_EXEC",
                "capability",
                "high",
                "Runtime.exec",
            ),
            "cmd.exe /c whoami",
        );
        let network = with_url(
            indicator(
                "detector",
                "DETC-02.NETWORK_IO",
                "capability",
                "high",
                "URLConnection.connect",
            ),
            "https://example.invalid/c2",
        );
        let persistence = with_path(
            indicator(
                "detector",
                "DETC-05.PERSISTENCE_TOKEN",
                "capability",
                "high",
                "Run key",
            ),
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        );

        let verdict = score_static_indicators(&[execution, network, persistence], None);
        let lines = synergy_lines(&verdict.explanation);
        assert!(lines.len() >= 2, "expected at least two synergy lines");

        let parsed = lines
            .iter()
            .map(|line| parse_synergy_line(line))
            .collect::<Vec<_>>();
        let mut expected = parsed.clone();
        expected.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

        assert_eq!(parsed, expected);
    }

    #[test]
    fn explanation_includes_top_contributors_with_evidence() {
        let execution = with_command(
            indicator(
                "detector",
                "DETC-01.RUNTIME_EXEC",
                "capability",
                "high",
                "Runtime.exec",
            ),
            "powershell -enc AAAA",
        );
        let network = with_url(
            indicator(
                "detector",
                "DETC-02.NETWORK_IO",
                "capability",
                "medium",
                "URLConnection.connect",
            ),
            "https://example.invalid/c2",
        );
        let persistence = with_path(
            indicator(
                "detector",
                "DETC-05.PERSISTENCE_TOKEN",
                "capability",
                "medium",
                "Run key",
            ),
            "mods/startup.task",
        );

        let verdict = score_static_indicators(&[execution, network, persistence], None);

        assert!(verdict
            .explanation
            .iter()
            .any(|line| line == "Top contributors:"));

        let lines = contributor_lines(&verdict.explanation);
        assert!(
            lines.len() >= 3,
            "expected at least three contributor lines"
        );

        for line in lines.iter().take(3) {
            assert!(line.contains("- +"));
            assert!(line.contains("evidence:"));
            assert!(line.contains('['));
            assert!(line.contains(':'));
            assert!(line.contains(']'));
        }

        let joined = verdict.explanation.join("\n");
        assert!(
            joined.contains("example.invalid")
                || joined.contains("powershell")
                || joined.contains("mods/startup")
        );
    }

    #[test]
    fn score_is_clamped_but_raw_score_is_exposed() {
        let indicators = vec![
            with_command(
                indicator(
                    "detector",
                    "DETC-01.RUNTIME_EXEC",
                    "capability",
                    "critical",
                    "Runtime.exec",
                ),
                "cmd.exe /c whoami",
            ),
            with_url(
                indicator(
                    "detector",
                    "DETC-02.NETWORK_IO",
                    "capability",
                    "critical",
                    "URLConnection.connect",
                ),
                "https://example.invalid/c2",
            ),
            with_url(
                indicator(
                    "detector",
                    "DETC-03.DYNAMIC_LOAD",
                    "capability",
                    "critical",
                    "URLClassLoader",
                ),
                "https://example.invalid/loader",
            ),
            with_path(
                indicator(
                    "detector",
                    "DETC-04.FILESYSTEM_WRITE",
                    "capability",
                    "critical",
                    "JarOutputStream",
                ),
                "mods/cache.bin",
            ),
            with_path(
                indicator(
                    "detector",
                    "DETC-05.PERSISTENCE_TOKEN",
                    "capability",
                    "critical",
                    "Run key",
                ),
                "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            ),
            with_url(
                indicator(
                    "detector",
                    "DETC-08.CREDENTIAL_COLLECTION",
                    "capability",
                    "critical",
                    "token theft",
                ),
                "https://example.invalid/exfil",
            ),
        ];

        let verdict = score_static_indicators(&indicators, None);

        assert!(verdict.raw_score > 100);
        assert_eq!(verdict.risk_score, 100);
        assert_eq!(verdict.risk_tier, "CRITICAL");
    }
}
