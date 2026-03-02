use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{DefaultBodyLimit, Multipart, Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum::extract::rejection::JsonRejection;
use serde_json::Value;
use tokio::fs;
use tower_http::services::ServeDir;
use tracing::info;
use uuid::Uuid;

use jarspect::{AppState, ScanRequest, ScanRunResponse};

#[derive(Debug)]
struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: message.into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let payload = Json(serde_json::json!({ "detail": self.message }));
        (self.status, payload).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::internal(error.to_string())
    }
}

impl From<JsonRejection> for AppError {
    fn from(rejection: JsonRejection) -> Self {
        Self::bad_request(format!("Invalid JSON payload: {rejection}"))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "jarspect=info,tower_http=info".into()),
        )
        .init();

    let cwd = std::env::current_dir()?;
    let uploads_dir = cwd.join(".local-data/uploads");
    let scans_dir = cwd.join(".local-data/scans");
    let web_dir = cwd.join("web");

    fs::create_dir_all(&uploads_dir).await?;
    fs::create_dir_all(&scans_dir).await?;

    let active_rulepacks = jarspect::parse_active_rulepacks()?;
    let signatures = Arc::new(jarspect::load_signatures(cwd.as_path(), &active_rulepacks)?);
    let yara_rulepacks = Arc::new(jarspect::load_yara_rules(cwd.as_path(), &active_rulepacks)?);
    let rulepack_names = active_rulepacks
        .iter()
        .map(|pack| pack.as_str())
        .collect::<Vec<_>>();
    info!(rulepacks = ?rulepack_names, "loaded signature and YARA rulepacks");

    let state = AppState {
        uploads_dir,
        scans_dir,
        web_dir: web_dir.clone(),
        signatures,
        yara_rulepacks,
        upload_max_bytes: 50 * 1024 * 1024,
    };

    let bind_addr =
        std::env::var("JARSPECT_BIND").unwrap_or_else(|_| "127.0.0.1:18000".to_string());

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/upload", post(upload))
        .route("/scan", post(scan))
        .route("/scans/{scan_id}", get(get_scan))
        .nest_service("/static", ServeDir::new(web_dir))
        .layer(DefaultBodyLimit::max(100 * 1024 * 1024))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!("jarspect listening on http://{bind_addr}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn index(State(state): State<AppState>) -> Result<Html<String>, AppError> {
    let index_path = state.web_dir.join("index.html");
    let content = fs::read_to_string(&index_path)
        .await
        .map_err(|_| AppError::not_found("Missing web/index.html"))?;
    Ok(Html(content))
}

async fn health() -> Json<Value> {
    Json(serde_json::json!({
        "status": "ok",
        "service": "jarspect",
        "version": "0.1.0"
    }))
}

async fn upload(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<Json<Value>, AppError> {
    let mut filename = None;
    let mut bytes = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| AppError::bad_request(format!("Invalid multipart payload: {e}")))?
    {
        if field.name() != Some("file") {
            continue;
        }
        filename = field.file_name().map(ToString::to_string);
        let data = field
            .bytes()
            .await
            .map_err(|e| AppError::bad_request(format!("Failed to read upload: {e}")))?;
        if data.len() > state.upload_max_bytes {
            return Err(AppError::bad_request("Uploaded file exceeds max size"));
        }
        bytes = Some(data.to_vec());
        break;
    }

    let filename = filename.ok_or_else(|| AppError::bad_request("Missing upload file"))?;
    if !filename.to_lowercase().ends_with(".jar") {
        return Err(AppError::bad_request("Only .jar files are supported"));
    }
    let content = bytes.ok_or_else(|| AppError::bad_request("Missing upload file bytes"))?;

    let upload_id = Uuid::new_v4().simple().to_string();
    let output_path = state.uploads_dir.join(format!("{upload_id}.jar"));
    fs::write(&output_path, &content)
        .await
        .map_err(|e| AppError::internal(format!("Failed to persist upload: {e}")))?;

    Ok(Json(serde_json::json!({
        "upload_id": upload_id,
        "filename": filename,
        "size_bytes": content.len(),
        "storage_url": output_path.to_string_lossy(),
    })))
}

async fn scan(
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> Result<Json<ScanRunResponse>, AppError> {
    match jarspect::run_scan(&state, request, None).await {
        Ok(scan_payload) => Ok(Json(scan_payload)),
        Err(error) => Err(map_scan_error(error)),
    }
}

async fn get_scan(
    State(state): State<AppState>,
    AxumPath(scan_id): AxumPath<String>,
) -> Result<Json<ScanRunResponse>, AppError> {
    jarspect::validate_artifact_id(&scan_id).map_err(|error| AppError::bad_request(error.to_string()))?;

    let path: PathBuf = state.scans_dir.join(format!("{scan_id}.json"));
    if !path.exists() {
        return Err(AppError::not_found("Scan not found"));
    }

    let data = fs::read_to_string(path)
        .await
        .map_err(|e| AppError::internal(format!("Failed to read scan result: {e}")))?;
    let payload: ScanRunResponse = serde_json::from_str(&data)
        .map_err(|e| AppError::internal(format!("Corrupted scan payload: {e}")))?;
    Ok(Json(payload))
}

fn map_scan_error(error: anyhow::Error) -> AppError {
    let message = error.to_string();
    if message.contains("Invalid identifier format (expected 32 hex chars)") {
        return AppError::bad_request(message);
    }

    if message == "Upload not found" {
        return AppError::not_found(message);
    }

    AppError::internal(message)
}
