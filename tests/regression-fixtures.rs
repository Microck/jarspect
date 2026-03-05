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
async fn e2e_scan_compiled_fixture_returns_capability_profile() -> Result<()> {
    let payload = run_scan_for_fixture("tests/fixtures/bytecode/all-capabilities.jar").await?;

    assert_eq!(payload["scan_id"].as_str(), Some(SCAN_ID_OVERRIDE));
    assert_eq!(payload["intake"]["upload_id"].as_str(), Some(UPLOAD_ID));

    let class_file_count = payload["intake"]["class_file_count"]
        .as_u64()
        .context("missing intake.class_file_count")?;
    assert!(class_file_count >= 1);

    assert_eq!(
        payload["verdict"]["method"].as_str(),
        Some("heuristic_fallback")
    );
    assert!(
        matches!(
            payload["verdict"]["result"].as_str(),
            Some("SUSPICIOUS") | Some("MALICIOUS")
        ),
        "expected suspicious or malicious fallback verdict"
    );
    assert!(payload["malwarebazaar"].is_null());

    let capabilities = payload["capabilities"]
        .as_object()
        .context("missing capabilities object")?;
    assert!(capability_present(capabilities, "execution"));
    assert!(capability_present(capabilities, "credential_theft"));

    let yara_ids = yara_hit_ids(&payload)?;
    assert!(yara_ids.iter().any(|id| id.contains("RUNTIME_EXEC_MARKER")));
    assert!(
        yara_ids
            .iter()
            .any(|id| id.contains("SUSPICIOUS_PAYLOAD_URL"))
    );

    assert!(payload["metadata"].is_object());
    let profile_class_count = payload["profile"]["class_count"]
        .as_u64()
        .context("missing profile.class_count")?;
    assert!(profile_class_count >= 1);

    Ok(())
}

#[tokio::test]
async fn demo_sample_still_reports_demo_yara_signatures() -> Result<()> {
    let payload = run_scan_for_fixture("demo/suspicious_sample.jar").await?;
    let yara_ids = yara_hit_ids(&payload)?;

    assert!(yara_ids.iter().any(|id| id.contains("RUNTIME_EXEC_MARKER")));
    Ok(())
}

#[test]
fn prod_yara_rulepack_compiles() -> Result<()> {
    let root = repo_root();
    let active_packs = [RulepackKind::Prod];
    load_yara_rules(root.as_path(), &active_packs)?;
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
        malwarebazaar_api_key: None,
        ai_config: None,
    })
}

fn capability_present(capabilities: &serde_json::Map<String, Value>, key: &str) -> bool {
    capabilities
        .get(key)
        .and_then(|entry| entry.get("present"))
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

fn yara_hit_ids(payload: &Value) -> Result<BTreeSet<String>> {
    let hits = payload["yara_hits"]
        .as_array()
        .context("missing yara_hits")?;
    Ok(hits
        .iter()
        .filter_map(|entry| entry["id"].as_str().map(ToOwned::to_owned))
        .collect())
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
