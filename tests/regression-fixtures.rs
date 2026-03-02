use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use jarspect::analysis::RulepackKind;
use jarspect::{AppState, ScanRequest, load_signatures, load_yara_rules, run_scan};
use serde_json::Value;
use tempfile::tempdir;
use tokio::fs;

const UPLOAD_ID: &str = "0123456789abcdef0123456789abcdef";
const SCAN_ID_OVERRIDE: &str = "fedcba9876543210fedcba9876543210";

#[tokio::test]
async fn e2e_scan_compiled_fixture_hits_capability_indicators() -> Result<()> {
    let payload = run_scan_for_fixture("tests/fixtures/bytecode/all-capabilities.jar").await?;

    assert_eq!(
        payload["result"]["intake"]["upload_id"].as_str(),
        Some(UPLOAD_ID)
    );

    let class_file_count = payload["result"]["intake"]["class_file_count"]
        .as_u64()
        .context("missing intake.class_file_count")?;
    assert!(class_file_count >= 1);

    let verdict_ids = verdict_indicator_ids(&payload)?;
    assert!(verdict_ids.contains("SIG-TOKEN-RUNTIME-EXEC"));
    assert!(verdict_ids.contains("SIG-TOKEN-DROPPER-URL"));
    assert_has_one_of(
        &verdict_ids,
        &["YARA-RUNTIME_EXEC_MARKER", "YARA-DEMO-RUNTIME_EXEC_MARKER"],
    );
    assert_has_one_of(
        &verdict_ids,
        &[
            "YARA-SUSPICIOUS_PAYLOAD_URL",
            "YARA-DEMO-SUSPICIOUS_PAYLOAD_URL",
        ],
    );

    let detector_ids = verdict_detector_ids(&payload)?;
    for prefix in [
        "DETC-01",
        "DETC-02",
        "DETC-03",
        "DETC-04",
        "DETC-05",
        "DETC-06",
        "DETC-07",
        "DETC-08",
    ] {
        assert!(
            detector_ids.iter().any(|id| id.starts_with(prefix)),
            "missing detector prefix {prefix} in {detector_ids:?}"
        );
    }

    let risk_tier = payload["result"]["verdict"]["risk_tier"]
        .as_str()
        .context("missing verdict.risk_tier")?;
    assert_ne!(risk_tier, "CLEAN");

    let risk_score = payload["result"]["verdict"]["risk_score"]
        .as_u64()
        .context("missing verdict.risk_score")?;
    assert!((40..=100).contains(&risk_score));

    let static_matches = payload["result"]["static"]["matches"]
        .as_array()
        .context("missing static.matches")?;
    assert!(
        static_matches
            .iter()
            .any(|entry| entry["file_path"].as_str().is_some())
    );
    assert!(
        static_matches
            .iter()
            .any(|entry| is_non_empty_string(entry.get("evidence")))
    );

    Ok(())
}

#[tokio::test]
async fn demo_sample_still_hits_demo_signature_and_yara_ids() -> Result<()> {
    let payload = run_scan_for_fixture("demo/suspicious_sample.jar").await?;
    let verdict_ids = verdict_indicator_ids(&payload)?;

    assert!(verdict_ids.contains("SIG-TOKEN-RUNTIME-EXEC"));
    assert_has_one_of(
        &verdict_ids,
        &["YARA-RUNTIME_EXEC_MARKER", "YARA-DEMO-RUNTIME_EXEC_MARKER"],
    );

    Ok(())
}

async fn run_scan_for_fixture(relative_fixture_path: &str) -> Result<Value> {
    let temp = tempdir().context("failed creating temp dir")?;
    let uploads_dir = temp.path().join("uploads");
    let scans_dir = temp.path().join("scans");
    fs::create_dir_all(&uploads_dir)
        .await
        .context("failed creating uploads dir")?;
    fs::create_dir_all(&scans_dir)
        .await
        .context("failed creating scans dir")?;

    let fixture_path = repo_root().join(relative_fixture_path);
    let fixture_bytes = fs::read(&fixture_path)
        .await
        .with_context(|| format!("failed reading fixture: {}", fixture_path.display()))?;
    let upload_path = uploads_dir.join(format!("{UPLOAD_ID}.jar"));
    fs::write(&upload_path, fixture_bytes)
        .await
        .with_context(|| format!("failed writing upload fixture: {}", upload_path.display()))?;

    let state = load_state_for_tests(uploads_dir, scans_dir)?;
    let request = ScanRequest {
        upload_id: UPLOAD_ID.to_string(),
        author: None,
    };

    let scan_payload = run_scan(&state, request, Some(SCAN_ID_OVERRIDE)).await?;
    serde_json::to_value(scan_payload).context("failed serializing scan payload")
}

fn load_state_for_tests(uploads_dir: PathBuf, scans_dir: PathBuf) -> Result<AppState> {
    let root = repo_root();
    let active_packs = [RulepackKind::Demo];
    let signatures = Arc::new(load_signatures(root.as_path(), &active_packs)?);
    let yara_rulepacks = Arc::new(load_yara_rules(root.as_path(), &active_packs)?);

    Ok(AppState {
        uploads_dir,
        scans_dir,
        web_dir: root.join("web"),
        signatures,
        yara_rulepacks,
        upload_max_bytes: 50 * 1024 * 1024,
    })
}

fn verdict_indicator_ids(payload: &Value) -> Result<BTreeSet<String>> {
    let indicators = payload["result"]["verdict"]["indicators"]
        .as_array()
        .context("missing verdict.indicators")?;
    Ok(indicators
        .iter()
        .filter_map(|entry| entry["id"].as_str().map(ToOwned::to_owned))
        .collect())
}

fn verdict_detector_ids(payload: &Value) -> Result<BTreeSet<String>> {
    let indicators = payload["result"]["verdict"]["indicators"]
        .as_array()
        .context("missing verdict.indicators")?;
    Ok(indicators
        .iter()
        .filter(|entry| entry["source"].as_str() == Some("detector"))
        .filter_map(|entry| entry["id"].as_str().map(ToOwned::to_owned))
        .collect())
}

fn assert_has_one_of(ids: &BTreeSet<String>, expected_ids: &[&str]) {
    assert!(
        expected_ids.iter().any(|expected_id| ids.contains(*expected_id)),
        "expected one of {expected_ids:?} in {ids:?}"
    );
}

fn is_non_empty_string(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .map(|text| !text.trim().is_empty())
        .unwrap_or(false)
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
