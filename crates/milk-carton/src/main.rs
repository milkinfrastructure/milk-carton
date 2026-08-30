mod records;
mod route;

use std::collections::HashSet;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use actix_web::http::header::{HeaderMap, HeaderName, HeaderValue};
use actix_web::http::{StatusCode, header};
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use anyhow::{Context as _, Result, bail};
use bytes::Bytes;
use chrono::{DateTime, TimeDelta, Timelike, Utc};
use clap::{Parser, Subcommand};
use futures::Stream;
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use url::{Host, Url};
use uuid::Uuid;

use records::{
    CAPTURE_SAMPLER_ID, CaptureState, EnqueueResult, MAX_PROVIDER_TEARDOWN_RESULT_BYTES,
    MAX_STUDENT_ARTIFACT_BYTES, MAX_STUDENT_ARTIFACT_FILES, MAX_STUDENT_RESULT_BYTES,
    MAX_STUDENT_UPLOAD_BYTES, MAX_WINNER_DEPLOYMENT_RESULT_BYTES, OutcomeDisposition, OutcomeKind,
    OutcomeSubmission, OutcomeValue, PartitionedObjectStore, ProviderTeardownResult, Records,
    RouteFallbackReason, RouteObservation, SamplingIndependence, SamplingUnitKind, Scope,
    SnapshotAnalysisAuthorization, SnapshotAnalyzerConfig, SnapshotAnalyzerExecution,
    SnapshotAnalyzerReasoningEffort, StoreAccess, StorePartition, StudentArtifactInput,
    StudentArtifactSource, StudentBranchMaterialization, StudentBranchResult, StudentTrainResult,
    StudentUpload, StudentVariant, StudentWinnerDeploymentResult, TICK_LEASE_TTL_SECONDS,
    TeacherGpuTickWrite, TraceCapture, TraceCatalog, current_effective_uid, is_not_found,
};
use route::{
    CandidateReasoningEffort, CandidateRoute, ED25519_SIGNATURE_BYTES, MAX_ROUTE_MANIFEST_BYTES,
    RouteDecision, RouteEndpoint, RoutePolicy, RoutePublication, RouteRequest, RouteScope,
    RouteStartupConfig, RouteTarget, WINNER_CANARY_BASIS_POINTS, WINNER_CANARY_VALID_FOR_SECONDS,
    WINNER_ZERO_VALID_FOR_SECONDS, WinnerRouteAdvanceAction, WinnerRoutePhase,
    advance_winner_route, prepare_operator_route_manifest, prepare_route_manifest,
};

const CHAT_PATH: &str = "/v1/chat/completions";
const RESPONSES_PATH: &str = "/v1/responses";
const OUTCOME_PATH: &str = "/v1/milk/outcomes";
const CANDIDATE_CREDENTIAL_PATH: &str = "/healthz/candidate-credential";
const CONFIG_SHA256_HEADER: &str = "x-milk-config-sha256";
const OUTCOME_KEY_HEADER: &str = "x-milk-key";
const TRACE_ID_HEADER: &str = "x-milk-trace-id";
const CAPTURE_INTENT_HEADER: &str = "x-milk-capture-intent";
const SESSION_ID_HEADER: &str = "x-milk-session-id";
const ERROR_SOURCE_HEADER: &str = "x-milk-error-source";
const ROUTE_REVISION_HEADER: &str = "x-milk-route-revision";
const ROUTE_TARGET_HEADER: &str = "x-milk-route-target";
const CANDIDATE_SHA256_HEADER: &str = "x-milk-candidate-sha256";
const ARTIFACT_SHA256_HEADER: &str = "x-milk-artifact-sha256";
const DEPLOYMENT_SHA256_HEADER: &str = "x-milk-deployment-sha256";
const CANDIDATE_API_KEY_SHA256_HEADER: &str = "x-milk-candidate-api-key-sha256";
const CANDIDATE_CREDENTIAL_STATE_HEADER: &str = "x-milk-candidate-credential-state";
const ROUTE_SECRET_ENV: &str = "MILK_CARTON_ROUTE_SECRET_HEX";
const CONFIG_JSON_ENV: &str = "MILK_CARTON_CONFIG_JSON";
const OPENAI_API_KEY_ENV: &str = "MILK_CARTON_OPENAI_API_KEY";
const TEACHER_API_KEY_ENV: &str = "MILK_CARTON_TEACHER_API_KEY";
const CANDIDATE_API_KEY_ENV: &str = "MILK_CARTON_CANDIDATE_API_KEY";
const CAPTURE_SAMPLING_KEY_ENV: &str = "MILK_CAPTURE_SAMPLING_KEY_HEX";
const CAPTURE_SAMPLING_KEY_VERSION_ENV: &str = "MILK_CAPTURE_SAMPLING_KEY_VERSION";
const NO_CAPTURE_SAMPLING_KEY_VERSION: &str = "not-applicable";
const MAX_CONFIG_BYTES: usize = 64 * 1_024;
const MAX_PROVIDER_API_KEY_BYTES: usize = 4_096;
const MAX_TRAFFIC_KEYS: usize = 64;
const TICK_LEASE_IO_TIMEOUT: Duration = Duration::from_secs(30);
const TICK_MUTATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const _: () = assert!(
    TICK_MUTATION_TIMEOUT.as_secs() + 2 * TICK_LEASE_IO_TIMEOUT.as_secs() < TICK_LEASE_TTL_SECONDS
);
const ROUTE_PUBLICATION_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const ROUTE_REFRESH_INTERVAL: Duration = Duration::from_secs(10);
#[cfg(not(test))]
const OUTCOME_TRACE_RETRY_LIMIT: Duration = Duration::from_secs(1);
#[cfg(test)]
const OUTCOME_TRACE_RETRY_LIMIT: Duration = Duration::from_millis(100);
const OUTCOME_TRACE_RETRY_DELAY: Duration = Duration::from_millis(25);
static DROPPED_CAPTURE_EVENTS: AtomicU64 = AtomicU64::new(0);
static OUTCOME_PERSISTENCE_FAILURES: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Parser)]
struct Cli {
    #[arg(long, env = "MILK_CARTON_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    Serve,
    Tick {
        #[arg(long, action = clap::ArgAction::SetTrue, required = true)]
        once: bool,
    },
    Status,
    #[command(hide = true)]
    GenerationStatus,
    #[command(hide = true)]
    BeginTeacherRun {
        #[arg(long)]
        teacher_run_id: String,
    },
    #[command(hide = true)]
    ExecuteTeacherRun {
        #[arg(long)]
        teacher_run_id: String,
    },
    #[command(hide = true)]
    TerminalizeTeacherRun {
        #[arg(long)]
        teacher_run_id: String,
    },
    #[command(hide = true)]
    MaterializeStudentJob {
        #[arg(long)]
        student_job_id: String,
        #[arg(long)]
        stage_dir: PathBuf,
    },
    #[command(hide = true)]
    MaterializeStudentWinner {
        #[arg(long)]
        student_job_id: String,
        #[arg(long)]
        stage_dir: PathBuf,
    },
    #[command(hide = true)]
    IngestStudentTrainExecution {
        #[arg(long)]
        result: PathBuf,
        #[arg(long)]
        upload: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
    },
    #[command(hide = true)]
    MaterializeStudentBranch {
        #[arg(long)]
        student_job_id: String,
        #[arg(long)]
        variant: String,
        #[arg(long)]
        stage_dir: PathBuf,
    },
    #[command(hide = true)]
    IngestStudentBranchExecution {
        #[arg(long)]
        result: PathBuf,
        #[arg(long)]
        upload: PathBuf,
        #[arg(long)]
        artifact_dir: PathBuf,
    },
    #[command(hide = true)]
    IngestStudentWinnerDeploymentResult {
        #[arg(long)]
        result: PathBuf,
    },
    #[command(hide = true)]
    IngestProviderTeardownResult {
        #[arg(long)]
        result: PathBuf,
    },
    #[command(hide = true)]
    AdvanceWinnerRoute {
        #[arg(long)]
        student_job_id: String,
        #[arg(long)]
        phase: WinnerRoutePhase,
        #[arg(long)]
        manifest: PathBuf,
    },
    #[command(hide = true)]
    PrepareRoute {
        #[arg(long)]
        student_job_id: String,
        #[arg(long)]
        rollback: bool,
        #[arg(long)]
        reasoning_effort: Option<CandidateReasoningEffort>,
        #[arg(long)]
        manifest: PathBuf,
    },
    #[command(hide = true)]
    PrepareRouteProposal {
        #[arg(long)]
        proposal: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    #[command(hide = true)]
    PublishRoute {
        #[arg(long)]
        manifest: PathBuf,
        #[arg(
            long,
            required_unless_present = "check_only",
            conflicts_with = "check_only"
        )]
        signature: Option<PathBuf>,
        #[arg(long, conflicts_with = "signature")]
        check_only: bool,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileConfig {
    listen: SocketAddr,
    traffic_keys: Vec<TrafficKeyConfig>,
    outcome_key_id: Uuid,
    outcome_key_sha256: String,
    scope_id: Uuid,
    max_request_bytes: usize,
    max_in_flight: usize,
    max_outcomes_in_flight: usize,
    max_active_body_bytes: usize,
    request_body_timeout_ms: u64,
    connect_timeout_ms: u64,
    read_timeout_ms: u64,
    total_timeout_ms: u64,
    storage_timeout_ms: u64,
    capture_mode: CaptureMode,
    capture_basis_points: u16,
    capture_response_bytes: usize,
    capture_record_bytes: usize,
    capture_queue_bytes: usize,
    capture_policy_version: String,
    capture_rights_state: String,
    capture_retention_days: i64,
    outcome_kind: OutcomeKind,
    outcome_verifier_id: String,
    outcome_rights_state: String,
    outcome_retention_days: i64,
    stores: StoresConfig,
    baseline: OpenAiCompatibleEndpoint,
    teacher: Option<TeacherConfig>,
    route: Option<RouteStartupConfig>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrafficKeyConfig {
    api_key_sha256: String,
    capture_allowed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ObjectStoreConfig {
    Local {
        root: PathBuf,
    },
    S3 {
        endpoint: String,
        region: String,
        bucket: String,
    },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoresConfig {
    capture: ObjectStoreConfig,
    control: ObjectStoreConfig,
    routes: ObjectStoreConfig,
}

impl StoresConfig {
    fn get(&self, partition: StorePartition) -> &ObjectStoreConfig {
        match partition {
            StorePartition::Capture => &self.capture,
            StorePartition::Control => &self.control,
            StorePartition::Routes => &self.routes,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct StoreAccessPlan {
    capture: Option<StoreAccess>,
    control: Option<StoreAccess>,
    routes: Option<StoreAccess>,
}

impl StoreAccessPlan {
    fn for_command(command: &Command) -> Self {
        use StoreAccess::{ReadOnly, ReadWrite};
        match command {
            Command::Serve => Self {
                capture: Some(ReadWrite),
                routes: Some(ReadOnly),
                ..Self::default()
            },
            Command::Tick { .. } => Self {
                capture: Some(ReadWrite),
                control: Some(ReadWrite),
                ..Self::default()
            },
            Command::Status => Self {
                capture: Some(ReadOnly),
                routes: Some(ReadOnly),
                ..Self::default()
            },
            Command::GenerationStatus => Self {
                capture: Some(ReadOnly),
                control: Some(ReadOnly),
                ..Self::default()
            },
            Command::BeginTeacherRun { .. } | Command::TerminalizeTeacherRun { .. } => Self {
                control: Some(ReadWrite),
                ..Self::default()
            },
            Command::ExecuteTeacherRun { .. } => Self {
                capture: Some(ReadOnly),
                control: Some(ReadWrite),
                ..Self::default()
            },
            Command::MaterializeStudentJob { .. } => Self {
                control: Some(ReadOnly),
                ..Self::default()
            },
            Command::MaterializeStudentWinner { .. } | Command::MaterializeStudentBranch { .. } => {
                Self {
                    control: Some(ReadOnly),
                    ..Self::default()
                }
            }
            Command::IngestStudentTrainExecution { .. }
            | Command::IngestStudentBranchExecution { .. }
            | Command::IngestStudentWinnerDeploymentResult { .. }
            | Command::IngestProviderTeardownResult { .. } => Self {
                control: Some(ReadWrite),
                routes: matches!(command, Command::IngestProviderTeardownResult { .. })
                    .then_some(ReadOnly),
                ..Self::default()
            },
            Command::AdvanceWinnerRoute { .. } | Command::PrepareRoute { .. } => Self {
                control: Some(ReadOnly),
                routes: Some(ReadOnly),
                ..Self::default()
            },
            Command::PrepareRouteProposal { .. } => Self {
                routes: Some(ReadOnly),
                ..Self::default()
            },
            Command::PublishRoute { check_only, .. } => Self {
                control: Some(if *check_only { ReadOnly } else { ReadWrite }),
                routes: Some(if *check_only { ReadOnly } else { ReadWrite }),
                ..Self::default()
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAiCompatibleEndpoint {
    api_base_url: String,
    allow_loopback_http: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TeacherConfig {
    chat_completions_url: String,
    allow_loopback_http: bool,
    model: String,
    reasoning_effort: SnapshotAnalyzerReasoningEffort,
    execution: SnapshotAnalyzerExecution,
    deployment_sha256: String,
    terms_sha256: String,
    authorization_id: String,
    authorization_not_after: DateTime<Utc>,
    max_decisions: u32,
    max_projected_bytes: u64,
    max_input_tokens: u64,
    max_output_tokens: u16,
    input_rate_microusd_per_million_tokens: u64,
    output_rate_microusd_per_million_tokens: u64,
    max_cost_microusd: u64,
    student_recipe_sha256: String,
    student_train_runtime_image_reference: String,
    student_branch_runtime_image_reference: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum CaptureMode {
    Disabled,
    WholeBodyAuthorized,
}

#[derive(Clone)]
struct CaptureConfig {
    mode: CaptureMode,
    basis_points: u16,
    response_bytes: usize,
    record_bytes: usize,
    policy_version: String,
    rights_state: String,
    retention_days: i64,
}

#[derive(Clone)]
struct Gateway {
    client: reqwest::Client,
    upstream_api_base: Url,
    config_sha256: [u8; 32],
    route_runtime: Arc<RwLock<Arc<RouteRuntime>>>,
    candidate_api_key_sha256: Option<[u8; 32]>,
    traffic_keys: Arc<[TrafficKey]>,
    outcome_key_id: Uuid,
    outcome_key_sha256: [u8; 32],
    scope: Scope,
    records: Option<Records>,
    capture: CaptureConfig,
    capture_sampling_key: ring::hmac::Key,
    capture_sampling_key_version: String,
    outcome_max_bytes: usize,
    max_request_bytes: usize,
    request_body_timeout: Duration,
    upstream_total_timeout: Duration,
    storage_timeout: Duration,
    in_flight: Arc<Semaphore>,
    outcomes_in_flight: Arc<Semaphore>,
    outcome_kind: OutcomeKind,
    outcome_verifier_id: String,
    outcome_rights_state: String,
    outcome_retention_days: i64,
}

#[derive(Clone)]
struct TrafficKey {
    api_key_sha256: [u8; 32],
    capture_allowed: bool,
}

#[derive(Clone)]
struct CandidateTransport {
    client: reqwest::Client,
    in_flight: Arc<Semaphore>,
    healthy: Arc<AtomicBool>,
}

struct RouteRuntime {
    policy: RoutePolicy,
    candidate: Option<CandidateTransport>,
}

impl Gateway {
    fn production(
        config: &FileConfig,
        config_sha256: [u8; 32],
        records: Option<Records>,
        candidate_api_key: Option<&str>,
    ) -> Result<Self> {
        let upstream = parse_openai_compatible_api_base_url(
            &config.baseline.api_base_url,
            config.baseline.allow_loopback_http,
        )?;
        let openai_api_key = required_env(OPENAI_API_KEY_ENV)?;
        Self::with_route_config_identity(
            config,
            config_sha256,
            upstream,
            records,
            RoutePolicy::baseline(),
            Some(&openai_api_key),
            candidate_api_key,
        )
    }

    #[cfg(test)]
    fn new(config: &FileConfig, upstream: Url, records: Option<Records>) -> Result<Self> {
        Self::with_route(
            config,
            upstream,
            records,
            RoutePolicy::baseline(),
            Some("test-managed-openai-key"),
            None,
        )
    }

    #[cfg(test)]
    fn with_route(
        config: &FileConfig,
        upstream_api_base: Url,
        records: Option<Records>,
        route: RoutePolicy,
        openai_api_key: Option<&str>,
        candidate_api_key: Option<&str>,
    ) -> Result<Self> {
        Self::with_route_config_identity(
            config,
            Sha256::digest(b"milk-carton-test-config").into(),
            upstream_api_base,
            records,
            route,
            openai_api_key,
            candidate_api_key,
        )
    }

    fn with_route_config_identity(
        config: &FileConfig,
        config_sha256: [u8; 32],
        upstream_api_base: Url,
        records: Option<Records>,
        route: RoutePolicy,
        openai_api_key: Option<&str>,
        candidate_api_key: Option<&str>,
    ) -> Result<Self> {
        if config.max_request_bytes == 0 {
            bail!("max_request_bytes must be positive");
        }
        if config.max_in_flight == 0 {
            bail!("max_in_flight must be positive");
        }
        if config.max_outcomes_in_flight == 0 {
            bail!("max_outcomes_in_flight must be positive");
        }
        if config.max_active_body_bytes == 0 {
            bail!("max_active_body_bytes must be positive");
        }
        if config.request_body_timeout_ms == 0
            || config.connect_timeout_ms == 0
            || config.read_timeout_ms == 0
            || config.total_timeout_ms == 0
            || config.storage_timeout_ms == 0
        {
            bail!("timeouts must be positive");
        }
        if config.connect_timeout_ms > config.total_timeout_ms
            || config.read_timeout_ms > config.total_timeout_ms
        {
            bail!("connect and read timeouts cannot exceed the total timeout");
        }
        if config.capture_basis_points > 10_000 {
            bail!("capture_basis_points cannot exceed 10000");
        }
        if config.capture_response_bytes == 0
            || config.capture_record_bytes == 0
            || config.capture_queue_bytes == 0
        {
            bail!("capture byte limits must be positive");
        }
        if config.capture_record_bytes > config.capture_queue_bytes {
            bail!("capture_record_bytes cannot exceed capture_queue_bytes");
        }
        if config.capture_retention_days <= 0 || config.capture_retention_days > 3650 {
            bail!("capture_retention_days must be in 1..=3650");
        }
        if config.outcome_retention_days <= 0 || config.outcome_retention_days > 3650 {
            bail!("outcome_retention_days must be in 1..=3650");
        }
        if config.capture_mode == CaptureMode::WholeBodyAuthorized
            && (config.capture_basis_points == 0
                || config.capture_policy_version.is_empty()
                || config.capture_rights_state.is_empty())
        {
            bail!("whole-body capture requires a sample rate, policy version, and rights state");
        }
        if config.capture_policy_version.len() > 256 {
            bail!("capture_policy_version cannot exceed 256 bytes");
        }
        if config.capture_rights_state.is_empty() || config.capture_rights_state.len() > 128 {
            bail!("capture_rights_state must contain 1..=128 bytes");
        }
        if config.outcome_verifier_id.is_empty() || config.outcome_verifier_id.len() > 256 {
            bail!("outcome_verifier_id must contain 1..=256 bytes");
        }
        if config.outcome_rights_state.is_empty() || config.outcome_rights_state.len() > 128 {
            bail!("outcome_rights_state must contain 1..=128 bytes");
        }
        let capture_bytes = if config.capture_mode == CaptureMode::WholeBodyAuthorized {
            config.capture_record_bytes
        } else {
            0
        };
        let chat_bytes = config
            .max_request_bytes
            .checked_add(capture_bytes)
            .and_then(|bytes| bytes.checked_mul(config.max_in_flight))
            .context("chat body limits overflow usize")?;
        let outcome_bytes = config
            .capture_record_bytes
            .checked_mul(config.max_outcomes_in_flight)
            .context("outcome body limits overflow usize")?;
        let active_body_bytes = chat_bytes
            .checked_add(outcome_bytes)
            .context("active body limits overflow usize")?;
        if active_body_bytes > config.max_active_body_bytes {
            bail!("configured request concurrency exceeds max_active_body_bytes");
        }
        let traffic_keys = configured_traffic_keys(&config.traffic_keys)?;
        let outcome_key_sha256 = decode_sha256(&config.outcome_key_sha256)?;
        if traffic_keys
            .iter()
            .any(|key| key.api_key_sha256 == outcome_key_sha256)
        {
            bail!("traffic and outcome keys must differ");
        }

        let client = upstream_client(config, openai_api_key)?;
        let route_runtime = build_route_runtime(config, route, candidate_api_key)?;
        let candidate_api_key_sha256 =
            candidate_api_key.map(provider_api_key_sha256).transpose()?;
        let (capture_sampling_key, capture_sampling_key_version) = capture_sampling_config()?;

        Ok(Self {
            client,
            upstream_api_base,
            config_sha256,
            route_runtime: Arc::new(RwLock::new(route_runtime)),
            candidate_api_key_sha256,
            traffic_keys: traffic_keys.into(),
            outcome_key_id: config.outcome_key_id,
            outcome_key_sha256,
            scope: config_scope(config),
            records,
            capture: CaptureConfig {
                mode: config.capture_mode,
                basis_points: config.capture_basis_points,
                response_bytes: config.capture_response_bytes,
                record_bytes: config.capture_record_bytes,
                policy_version: config.capture_policy_version.clone(),
                rights_state: config.capture_rights_state.clone(),
                retention_days: config.capture_retention_days,
            },
            capture_sampling_key,
            capture_sampling_key_version,
            outcome_max_bytes: config.capture_record_bytes,
            max_request_bytes: config.max_request_bytes,
            request_body_timeout: Duration::from_millis(config.request_body_timeout_ms),
            upstream_total_timeout: Duration::from_millis(config.total_timeout_ms),
            storage_timeout: Duration::from_millis(config.storage_timeout_ms),
            in_flight: Arc::new(Semaphore::new(config.max_in_flight)),
            outcomes_in_flight: Arc::new(Semaphore::new(config.max_outcomes_in_flight)),
            outcome_kind: config.outcome_kind,
            outcome_verifier_id: config.outcome_verifier_id.clone(),
            outcome_rights_state: config.outcome_rights_state.clone(),
            outcome_retention_days: config.outcome_retention_days,
        })
    }

    fn route_runtime(&self) -> Arc<RouteRuntime> {
        self.route_runtime
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn replace_route_runtime(&self, runtime: Arc<RouteRuntime>) {
        *self
            .route_runtime
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = runtime;
    }
}

fn capture_sampling_config() -> Result<(ring::hmac::Key, String)> {
    let key_hex = match optional_env(CAPTURE_SAMPLING_KEY_ENV)? {
        Some(value) => value,
        None if cfg!(test) => "11".repeat(32),
        None => bail!("{CAPTURE_SAMPLING_KEY_ENV} is required when capture is enabled"),
    };
    let version = match optional_env(CAPTURE_SAMPLING_KEY_VERSION_ENV)? {
        Some(value) => value,
        None if cfg!(test) => "test-v1".to_owned(),
        None => bail!("{CAPTURE_SAMPLING_KEY_VERSION_ENV} is required when capture is enabled"),
    };
    if version.is_empty()
        || version.len() > 128
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("{CAPTURE_SAMPLING_KEY_VERSION_ENV} must be a bounded identifier");
    }
    let key = decode_lowercase_sha256(&key_hex)?;
    Ok((ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &key), version))
}

fn build_route_runtime(
    config: &FileConfig,
    policy: RoutePolicy,
    candidate_api_key: Option<&str>,
) -> Result<Arc<RouteRuntime>> {
    let candidate = policy
        .candidate()
        .map(|candidate| -> Result<CandidateTransport> {
            let api_key = candidate_api_key.context("active candidate API key is missing")?;
            let admitted_key_sha256 = decode_lowercase_sha256(candidate.candidate_api_key_sha256)?;
            let configured_key_sha256: [u8; 32] = Sha256::digest(api_key.as_bytes()).into();
            if admitted_key_sha256
                .ct_eq(&configured_key_sha256)
                .unwrap_u8()
                != 1
            {
                bail!("candidate API key differs from the admitted credential");
            }
            Ok(CandidateTransport {
                client: upstream_client(config, Some(api_key))?,
                in_flight: Arc::new(Semaphore::new(candidate.max_in_flight)),
                healthy: Arc::new(AtomicBool::new(true)),
            })
        })
        .transpose()?;
    Ok(Arc::new(RouteRuntime { policy, candidate }))
}

fn upstream_client(config: &FileConfig, provider_api_key: Option<&str>) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(Policy::none())
        .retry(reqwest::retry::never())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
        .read_timeout(Duration::from_millis(config.read_timeout_ms))
        .timeout(Duration::from_millis(config.total_timeout_ms));
    if let Some(api_key) = provider_api_key {
        provider_api_key_sha256(api_key)?;
        let mut authorization =
            reqwest::header::HeaderValue::from_str(&format!("Bearer {api_key}"))
                .context("provider API key is not a valid HTTP credential")?;
        authorization.set_sensitive(true);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        builder = builder.default_headers(headers);
    }
    Ok(builder.build()?)
}

fn provider_api_key_sha256(api_key: &str) -> Result<[u8; 32]> {
    if api_key.is_empty() || api_key.len() > MAX_PROVIDER_API_KEY_BYTES {
        bail!("provider API key must contain 1..={MAX_PROVIDER_API_KEY_BYTES} bytes");
    }
    reqwest::header::HeaderValue::from_str(&format!("Bearer {api_key}"))
        .context("provider API key is not a valid HTTP credential")?;
    Ok(Sha256::digest(api_key.as_bytes()).into())
}

#[derive(Serialize)]
struct ErrorEnvelope<'a> {
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    message: &'a str,
    r#type: &'a str,
    param: Option<&'a str>,
    code: &'a str,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    config_sha256: String,
    capture: &'static str,
    candidate: &'static str,
    writer_alive: bool,
    recent_persist_failure: bool,
    consecutive_persist_failures: u64,
    queued: u64,
    dropped: u64,
    traces_persisted: u64,
    trace_persist_failures: u64,
    stats_persist_failures: u64,
    outcome_persist_failures: u64,
}

#[derive(Serialize)]
struct CandidateCredentialResponse<'a> {
    schema_version: &'static str,
    candidate_api_key_sha256: Option<&'a str>,
    state: &'static str,
}

#[derive(Serialize)]
struct CandidateCredentialMismatch {
    schema_version: &'static str,
    state: &'static str,
}

#[derive(Serialize)]
struct RouteStatusWrite {
    configured: bool,
    state: &'static str,
    route_revision: Option<String>,
    student_job_id: Option<String>,
    candidate_basis_points: Option<u16>,
    not_after: Option<DateTime<Utc>>,
}

#[derive(Serialize)]
struct WinnerRouteAdvanceWrite {
    schema_version: &'static str,
    action: WinnerRouteAdvanceAction,
    route_revision: String,
    not_after: DateTime<Utc>,
}

#[derive(Serialize)]
struct StatusWrite {
    schema_version: &'static str,
    records: records::DataPlaneStatusWrite,
    route: RouteStatusWrite,
}

#[derive(Serialize)]
struct GenerationStatusWrite {
    schema_version: &'static str,
    scope_id: Uuid,
    max_decisions: u32,
    claimed_decisions: u32,
    remaining_decisions: u32,
    generation_done: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeRequest {
    trace_id: Uuid,
    outcome_version: i64,
    value: OutcomeValue,
}

#[derive(Deserialize)]
struct ResponsesSessionHints<'a> {
    #[serde(borrow)]
    conversation: Option<&'a RawValue>,
    previous_response_id: Option<&'a str>,
}

#[derive(Deserialize)]
struct ResponsesConversation<'a> {
    id: &'a str,
}

#[derive(Deserialize)]
struct RequestAnalytics {
    stream: Option<bool>,
}

struct SamplingIdentity {
    kind: SamplingUnitKind,
    hmac_sha256: [u8; 32],
    independence: SamplingIndependence,
    previous_response_hmac_sha256: Option<[u8; 32]>,
    content_capture_allowed: bool,
}

struct UpstreamBody {
    inner: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
    _permit: OwnedSemaphorePermit,
    _candidate_permit: Option<OwnedSemaphorePermit>,
    stream_error_class: &'static str,
    candidate_health: Option<Arc<AtomicBool>>,
    recorder: Option<TraceRecorder>,
}

struct TraceRecorder {
    records: Option<Records>,
    catalog: Option<TraceCatalog>,
    started: Instant,
    first_byte: Option<Duration>,
    request: Option<Bytes>,
    request_content_type: Option<String>,
    request_content_encoding: Option<String>,
    response: Vec<u8>,
    response_content_type: Option<String>,
    response_content_encoding: Option<String>,
    response_limit: usize,
    record_limit: usize,
    selected: bool,
    oversized: bool,
    stream_protocol: Option<RouteEndpoint>,
    stream_terminal_seen: bool,
    stream_terminal_tail: Vec<u8>,
}

impl Stream for UpstreamBody {
    type Item = actix_web::Result<Bytes>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.inner.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(bytes))) => {
                if let Some(recorder) = self.recorder.as_mut() {
                    recorder.observe(&bytes);
                }
                Poll::Ready(Some(Ok(bytes)))
            }
            Poll::Ready(Some(Err(_))) => {
                if let Some(healthy) = &self.candidate_health {
                    healthy.store(false, Ordering::Release);
                }
                let stream_error_class = self.stream_error_class;
                if let Some(recorder) = self.recorder.as_mut() {
                    recorder.finish(Some(stream_error_class));
                }
                Poll::Ready(Some(Err(actix_web::error::ErrorBadGateway(
                    "upstream response stream failed",
                ))))
            }
            Poll::Ready(None) => {
                if let Some(recorder) = self.recorder.as_mut() {
                    recorder.finish(None);
                }
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for UpstreamBody {
    fn drop(&mut self) {
        if let Some(recorder) = self.recorder.as_mut() {
            let error_class = (!recorder.stream_terminal_seen).then_some("downstream_disconnected");
            recorder.finish(error_class);
        }
    }
}

impl TraceRecorder {
    fn observe(&mut self, bytes: &Bytes) {
        if !bytes.is_empty() && self.first_byte.is_none() {
            self.first_byte = Some(self.started.elapsed());
        }
        if let Some(catalog) = self.catalog.as_mut() {
            catalog.response_bytes = catalog.response_bytes.saturating_add(bytes.len() as u64);
        }
        self.observe_stream_terminal(bytes);
        if bytes.is_empty() || !self.selected || self.oversized {
            return;
        }
        let Some(response_bytes) = self.response.len().checked_add(bytes.len()) else {
            self.mark_oversized();
            return;
        };
        if response_bytes > self.response_limit || self.response.try_reserve(bytes.len()).is_err() {
            self.mark_oversized();
            return;
        }
        if self.capture_memory_bytes() > self.record_limit {
            self.mark_oversized();
            return;
        }
        self.response.extend_from_slice(bytes);
        debug_assert_eq!(self.response.len(), response_bytes);
    }

    fn observe_stream_terminal(&mut self, bytes: &[u8]) {
        let Some(endpoint) = self.stream_protocol else {
            return;
        };
        if self.stream_terminal_seen || bytes.is_empty() {
            return;
        }
        let markers: &[&[u8]] = match endpoint {
            RouteEndpoint::ChatCompletions => &[b"data: [DONE]"],
            RouteEndpoint::Responses => &[
                b"event: response.completed",
                b"event: response.failed",
                b"event: response.incomplete",
            ],
        };
        let tail_limit = markers
            .iter()
            .map(|marker| marker.len().saturating_sub(1))
            .max()
            .unwrap_or(0);
        if markers.iter().any(|marker| contains_bytes(bytes, marker)) {
            self.stream_terminal_seen = true;
            self.stream_terminal_tail.clear();
            return;
        }
        if !self.stream_terminal_tail.is_empty() {
            let prefix_len = bytes.len().min(tail_limit);
            let mut boundary = Vec::with_capacity(self.stream_terminal_tail.len() + prefix_len);
            boundary.extend_from_slice(&self.stream_terminal_tail);
            boundary.extend_from_slice(&bytes[..prefix_len]);
            if markers
                .iter()
                .any(|marker| contains_bytes(&boundary, marker))
            {
                self.stream_terminal_seen = true;
                self.stream_terminal_tail.clear();
                return;
            }
        }
        if bytes.len() >= tail_limit {
            self.stream_terminal_tail.clear();
            self.stream_terminal_tail
                .extend_from_slice(&bytes[bytes.len().saturating_sub(tail_limit)..]);
        } else {
            let old_start = self
                .stream_terminal_tail
                .len()
                .saturating_sub(tail_limit.saturating_sub(bytes.len()));
            self.stream_terminal_tail.drain(..old_start);
            self.stream_terminal_tail.extend_from_slice(bytes);
        }
    }

    fn capture_memory_bytes(&self) -> usize {
        self.catalog
            .as_ref()
            .map_or(0, TraceCatalog::memory_bytes)
            .saturating_add(self.request.as_ref().map_or(0, Bytes::len))
            .saturating_add(self.response.capacity())
            .saturating_add(self.stream_terminal_tail.capacity())
            .saturating_add(
                self.request_content_type
                    .as_ref()
                    .map_or(0, String::capacity),
            )
            .saturating_add(
                self.request_content_encoding
                    .as_ref()
                    .map_or(0, String::capacity),
            )
            .saturating_add(
                self.response_content_type
                    .as_ref()
                    .map_or(0, String::capacity),
            )
            .saturating_add(
                self.response_content_encoding
                    .as_ref()
                    .map_or(0, String::capacity),
            )
    }

    fn mark_oversized(&mut self) {
        self.oversized = true;
        self.request = None;
        self.request_content_type = None;
        self.request_content_encoding = None;
        self.response = Vec::new();
        self.response_content_type = None;
        self.response_content_encoding = None;
    }

    fn finish(&mut self, error_class: Option<&str>) {
        let Some(mut catalog) = self.catalog.take() else {
            return;
        };
        catalog.ttft_ms = self.first_byte.map(duration_ms);
        catalog.completion_ms = Some(duration_ms(self.started.elapsed()));
        let error_class = error_class.or_else(|| {
            (self.stream_protocol.is_some() && !self.stream_terminal_seen)
                .then_some("upstream_stream_incomplete")
        });
        if let Some(error_class) = error_class {
            catalog.error_class = Some(error_class.to_owned());
        }
        let Some(records) = &self.records else {
            return;
        };
        let result = if error_class.is_some() {
            records.try_observe(catalog, CaptureState::Interrupted)
        } else if self.oversized {
            records.try_observe(catalog, CaptureState::Oversized)
        } else if self.selected {
            records.try_capture(TraceCapture {
                catalog,
                request_content_type: self.request_content_type.take(),
                request_content_encoding: self.request_content_encoding.take(),
                request: self.request.take().unwrap_or_default(),
                response_content_type: self.response_content_type.take(),
                response_content_encoding: self.response_content_encoding.take(),
                response: std::mem::take(&mut self.response),
            })
        } else {
            records.try_observe(catalog, CaptureState::NotSelected)
        };
        log_enqueue_failure(result);
    }
}

fn contains_bytes(value: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && value.windows(needle.len()).any(|window| window == needle)
}

#[actix_web::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let config_json = std::env::var_os(CONFIG_JSON_ENV);
    let selected_config = load_selected_config(
        cli.config.as_deref(),
        config_json
            .as_deref()
            .map(std::ffi::OsStr::as_encoded_bytes),
        cli.command.as_ref(),
    )?;
    let config = selected_config.value;
    let config_sha256 = selected_config.sha256;
    let command = cli.command.unwrap_or(Command::Serve);
    let store_access = StoreAccessPlan::for_command(&command);
    match command {
        Command::Serve => {
            let records = match tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            {
                Ok(Ok(records)) => Some(records),
                Ok(Err(error)) if config.capture_mode == CaptureMode::WholeBodyAuthorized => {
                    return Err(error.context("capture storage failed startup qualification"));
                }
                Ok(Err(error)) => {
                    tracing::error!(error = %error, "statistics, capture, and outcome storage unavailable; baseline proxy remains active");
                    None
                }
                Err(_) if config.capture_mode == CaptureMode::WholeBodyAuthorized => {
                    bail!("capture storage initialization timed out");
                }
                Err(_) => {
                    tracing::error!(
                        "statistics, capture, and outcome storage initialization timed out; baseline proxy remains active"
                    );
                    None
                }
            };
            let candidate_api_key = optional_env(CANDIDATE_API_KEY_ENV)?;
            let gateway = Gateway::production(
                &config,
                config_sha256,
                records.clone(),
                candidate_api_key.as_deref(),
            )?;
            if config.route.is_some()
                && let Some(records) = &records
            {
                let route_secret = optional_env(ROUTE_SECRET_ENV)?;
                match refresh_live_route(
                    &config,
                    records,
                    &gateway,
                    route_secret.as_deref(),
                    candidate_api_key.as_deref(),
                    Utc::now(),
                )
                .await
                {
                    Ok(true) => tracing::info!(
                        route_revision = gateway.route_runtime().policy.revision(),
                        "live route loaded before startup"
                    ),
                    Ok(false) => {}
                    Err(error) => tracing::error!(
                        error = %error,
                        "live route startup refresh failed; starting on baseline"
                    ),
                }
                spawn_live_route_poller(
                    config.clone(),
                    records.clone(),
                    gateway.clone(),
                    route_secret,
                    candidate_api_key,
                );
            }
            let listener = TcpListener::bind(config.listen)
                .with_context(|| format!("failed to bind {}", config.listen))?;
            let server_result = build_server(listener, gateway)?.await;
            let flush_result = if let Some(records) = records {
                tokio::time::timeout(
                    Duration::from_millis(config.storage_timeout_ms),
                    records.flush(),
                )
                .await
                .context("capture storage flush timed out")
                .and_then(|result| result)
            } else {
                Ok(())
            };
            server_result?;
            flush_result
        }
        Command::Tick { once } => {
            if !once {
                bail!("tick requires --once");
            }
            println!("{}", tick_once(&config).await?);
            Ok(())
        }
        Command::Status => {
            println!("{}", status_once(&config, Utc::now()).await?);
            Ok(())
        }
        Command::GenerationStatus => {
            println!("{}", generation_status_once(&config, Utc::now()).await?);
            Ok(())
        }
        Command::BeginTeacherRun { teacher_run_id } => {
            let teacher_run_id = decode_lowercase_sha256(&teacher_run_id)?;
            let records = start_records_with_timeout(&config, store_access, true).await?;
            let analyzer = snapshot_analyzer_config(&config, None)?;
            let receipt = records
                .begin_teacher_gpu_run(
                    &config_scope(&config),
                    &teacher_run_id,
                    analyzer,
                    Utc::now(),
                )
                .await?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::ExecuteTeacherRun { teacher_run_id } => {
            let teacher_run_id = decode_lowercase_sha256(&teacher_run_id)?;
            let (_, max_gpu_seconds, _, _) = teacher_config(&config)?.execution.gpu_job();
            let records = start_records_with_timeout(&config, store_access, true).await?;
            let analyzer =
                snapshot_analyzer_config(&config, Some(required_env(TEACHER_API_KEY_ENV)?))?;
            let timeout = Duration::from_secs(
                max_gpu_seconds
                    .checked_add(5 * 60)
                    .context("teacher GPU execution timeout overflow")?,
            );
            let receipt = tokio::time::timeout(
                timeout,
                records.execute_teacher_gpu_run(
                    &config_scope(&config),
                    &teacher_run_id,
                    analyzer,
                    Utc::now(),
                ),
            )
            .await
            .context("teacher GPU execution exceeded its bounded deadline")??;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::TerminalizeTeacherRun { teacher_run_id } => {
            let teacher_run_id = decode_lowercase_sha256(&teacher_run_id)?;
            let records = start_records_with_timeout(&config, store_access, true).await?;
            let analyzer = snapshot_analyzer_config(&config, None)?;
            let receipt = records
                .terminalize_teacher_gpu_run(
                    &config_scope(&config),
                    &teacher_run_id,
                    analyzer,
                    Utc::now(),
                )
                .await?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::MaterializeStudentJob {
            student_job_id,
            stage_dir,
        } => {
            let student_job_id = decode_lowercase_sha256(&student_job_id)?;
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let claim = records
                .export_student_job_claim(&config_scope(&config), &student_job_id)
                .await?;
            let input = records
                .export_student_input(&config_scope(&config), &student_job_id, Utc::now())
                .await?;
            stage_student_job(&stage_dir, &claim, &input)?;
            println!("{}", bytes_hex(&student_job_id));
            Ok(())
        }
        Command::MaterializeStudentWinner {
            student_job_id,
            stage_dir,
        } => {
            let student_job_id = decode_lowercase_sha256(&student_job_id)?;
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let receipt = records
                .materialize_student_winner(&config_scope(&config), &student_job_id, &stage_dir)
                .await?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::IngestStudentTrainExecution {
            result,
            upload,
            artifact_dir,
        } => {
            let mut result_input = OperatorInput::open_private(
                &result,
                MAX_STUDENT_RESULT_BYTES,
                "student train result",
            )?;
            let mut upload_input =
                OperatorInput::open_private(&upload, MAX_STUDENT_UPLOAD_BYTES, "student upload")?;
            let result = StudentTrainResult::parse(result_input.initial())?;
            let upload = StudentUpload::parse(upload_input.initial())?;
            let mut artifacts = StableStudentArtifactDirectory::open(&artifact_dir)?;
            if StudentTrainResult::parse(&result_input.reread_unchanged()?)? != result
                || StudentUpload::parse(&upload_input.reread_unchanged()?)? != upload
            {
                bail!("student train execution inputs changed after validation");
            }
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let receipt = records
                .ingest_student_train_execution(
                    &config_scope(&config),
                    result,
                    upload,
                    &mut artifacts,
                )
                .await?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::MaterializeStudentBranch {
            student_job_id,
            variant,
            stage_dir,
        } => {
            let student_job_id = decode_lowercase_sha256(&student_job_id)?;
            let variant = StudentVariant::parse(&variant)?;
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let materialization = records
                .export_student_branch(&config_scope(&config), &student_job_id, variant, Utc::now())
                .await?;
            stage_student_branch(&stage_dir, &materialization)?;
            if let Err(error) = records
                .materialize_student_branch_model(
                    &config_scope(&config),
                    &student_job_id,
                    &stage_dir.join("merged-model"),
                )
                .await
            {
                cleanup_student_branch_json(&stage_dir);
                return Err(error);
            }
            seal_student_branch_stage(&stage_dir)?;
            println!("{}", bytes_hex(&student_job_id));
            Ok(())
        }
        Command::IngestStudentBranchExecution {
            result,
            upload,
            artifact_dir,
        } => {
            let mut result_input = OperatorInput::open_private(
                &result,
                MAX_STUDENT_RESULT_BYTES,
                "student branch result",
            )?;
            let mut upload_input =
                OperatorInput::open_private(&upload, MAX_STUDENT_UPLOAD_BYTES, "student upload")?;
            let result = StudentBranchResult::parse(result_input.initial())?;
            let upload = StudentUpload::parse(upload_input.initial())?;
            let mut artifacts = StableStudentArtifactDirectory::open(&artifact_dir)?;
            if StudentBranchResult::parse(&result_input.reread_unchanged()?)? != result
                || StudentUpload::parse(&upload_input.reread_unchanged()?)? != upload
            {
                bail!("student branch execution inputs changed after validation");
            }
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let receipt = records
                .ingest_student_branch_execution(
                    &config_scope(&config),
                    result,
                    upload,
                    &mut artifacts,
                )
                .await?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::IngestStudentWinnerDeploymentResult { result } => {
            let mut result_input = OperatorInput::open_private(
                &result,
                MAX_WINNER_DEPLOYMENT_RESULT_BYTES,
                "student winner deployment result",
            )?;
            let result = StudentWinnerDeploymentResult::parse(result_input.initial())?;
            if StudentWinnerDeploymentResult::parse(&result_input.reread_unchanged()?)? != result {
                bail!("student winner deployment result changed after validation");
            }
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let receipt = records
                .ingest_student_winner_deployment_result(&config_scope(&config), result)
                .await?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::IngestProviderTeardownResult { result } => {
            let mut result_input = OperatorInput::open_private(
                &result,
                MAX_PROVIDER_TEARDOWN_RESULT_BYTES,
                "provider teardown result",
            )?;
            let result = ProviderTeardownResult::parse(result_input.initial())?;
            if ProviderTeardownResult::parse(&result_input.reread_unchanged()?)? != result {
                bail!("provider teardown result changed after validation");
            }
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let receipt = records
                .ingest_provider_teardown_result(&config_scope(&config), result, Utc::now())
                .await?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Command::AdvanceWinnerRoute {
            student_job_id,
            phase,
            manifest,
        } => {
            let route_config = config
                .route
                .as_ref()
                .context("winner route advance requires startup route configuration")?;
            let student_job_id = decode_lowercase_sha256(&student_job_id)?;
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let scope = config_scope(&config);
            let winner = records
                .verified_route_winner(&scope, &student_job_id)
                .await?;
            let admission_bytes = records
                .verified_winner_admission(&scope, &student_job_id)
                .await?;
            let live = load_verified_live_route(&config, route_config, &records).await?;
            let (live_publication, live_previous) = match &live {
                Some((publication, previous)) => (Some(publication), previous.as_ref()),
                None => (None, None),
            };
            let advance = advance_winner_route(
                route_config,
                &config_route_scope(&config),
                &winner,
                &admission_bytes,
                &required_env(ROUTE_SECRET_ENV)?,
                phase,
                live_publication,
                live_previous,
                Utc::now(),
            )?;
            if let Some(manifest_bytes) = &advance.manifest {
                let previous = if advance.publication.previous_route_revision.is_some() {
                    Some(
                        live_publication
                            .context("prepared zero route is missing its live canary")?,
                    )
                } else {
                    None
                };
                records
                    .verify_route_publication(&scope, &advance.publication, previous)
                    .await?;
                write_private_output(&manifest, manifest_bytes, "route manifest")?;
            }
            println!(
                "{}",
                serde_json::to_string(&WinnerRouteAdvanceWrite {
                    schema_version: "milk.winner-route-advance.v1",
                    action: advance.action,
                    route_revision: advance.publication.revision_hex(),
                    not_after: advance.publication.not_after,
                })?
            );
            Ok(())
        }
        Command::PrepareRoute {
            student_job_id,
            rollback,
            reasoning_effort,
            manifest,
        } => {
            let route_config = config
                .route
                .as_ref()
                .context("route preparation requires startup route configuration")?;
            let student_job_id = decode_lowercase_sha256(&student_job_id)?;
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let scope = config_scope(&config);
            let winner = records
                .verified_route_winner(&scope, &student_job_id)
                .await?;
            let admission_bytes = records
                .verified_winner_admission(&scope, &student_job_id)
                .await?;
            let previous = match records.load_live_route(&scope).await? {
                Some((pointer, previous_manifest, previous_signature)) => {
                    let publication = RoutePublication::parse_archived(
                        route_config,
                        &config_route_scope(&config),
                        &previous_manifest,
                        &previous_signature,
                    )?;
                    if publication.revision != pointer.route_revision {
                        bail!("live route pointer differs from its verified publication");
                    }
                    Some(publication)
                }
                None => None,
            };
            if rollback && previous.is_none() {
                bail!("route rollback requires a verified live route");
            }
            let (manifest_bytes, publication) = prepare_route_manifest(
                route_config,
                &config_route_scope(&config),
                &winner,
                &admission_bytes,
                &required_env(ROUTE_SECRET_ENV)?,
                if rollback {
                    0
                } else {
                    WINNER_CANARY_BASIS_POINTS
                },
                reasoning_effort,
                previous.as_ref(),
                Utc::now(),
                if rollback {
                    WINNER_ZERO_VALID_FOR_SECONDS
                } else {
                    WINNER_CANARY_VALID_FOR_SECONDS
                },
            )?;
            records
                .verify_route_publication(&scope, &publication, previous.as_ref())
                .await?;
            write_private_output(&manifest, &manifest_bytes, "route manifest")?;
            println!("{}", publication.revision_hex());
            Ok(())
        }
        Command::PrepareRouteProposal { proposal, manifest } => {
            let route_config = config
                .route
                .as_ref()
                .context("route proposal preparation requires startup route configuration")?;
            let mut proposal =
                OperatorInput::open(&proposal, MAX_ROUTE_MANIFEST_BYTES, "route proposal")?;
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let route_scope = config_route_scope(&config);
            let previous = match records.load_live_route(&config_scope(&config)).await? {
                Some((pointer, previous_manifest, previous_signature)) => {
                    let publication = RoutePublication::parse_archived(
                        route_config,
                        &route_scope,
                        &previous_manifest,
                        &previous_signature,
                    )?;
                    if publication.revision != pointer.route_revision {
                        bail!("live route pointer differs from its verified publication");
                    }
                    Some(publication)
                }
                None => None,
            };
            let proposal_bytes = proposal.reread_unchanged()?;
            let route_secret = optional_env(ROUTE_SECRET_ENV)?;
            let candidate_api_key = optional_env(CANDIDATE_API_KEY_ENV)?;
            let (manifest_bytes, publication) = prepare_operator_route_manifest(
                route_config,
                &route_scope,
                &proposal_bytes,
                route_secret.as_deref(),
                candidate_api_key.as_deref(),
                previous.as_ref(),
                Utc::now(),
            )?;
            records
                .verify_route_publication(&config_scope(&config), &publication, previous.as_ref())
                .await?;
            write_private_output(&manifest, &manifest_bytes, "route manifest")?;
            println!("{}", publication.revision_hex());
            Ok(())
        }
        Command::PublishRoute {
            manifest,
            signature,
            check_only,
        } => {
            let route_config = config
                .route
                .as_ref()
                .context("route publication requires startup route configuration")?;
            let mut manifest =
                OperatorInput::open(&manifest, MAX_ROUTE_MANIFEST_BYTES, "route manifest")?;
            let mut signature = signature
                .as_deref()
                .map(|path| OperatorInput::open(path, ED25519_SIGNATURE_BYTES, "route signature"))
                .transpose()?;
            let records = tokio::time::timeout(
                Duration::from_millis(config.storage_timeout_ms),
                start_records(&config, store_access),
            )
            .await
            .context("storage initialization timed out")??;
            let manifest_bytes = manifest.reread_unchanged()?;
            let signature_bytes = signature
                .as_mut()
                .map(OperatorInput::reread_unchanged)
                .transpose()?;
            let route_scope = config_route_scope(&config);
            let publication = RoutePublication::parse_for_publication(
                route_config,
                &route_scope,
                &manifest_bytes,
                signature_bytes.as_deref(),
                Utc::now(),
            )?;
            let previous = if let Some(revision) = publication.previous_route_revision {
                let (prior_manifest, prior_signature) = tokio::time::timeout(
                    ROUTE_PUBLICATION_TIMEOUT,
                    records.load_route_publication(&config_scope(&config), &revision),
                )
                .await
                .context("previous route verification exceeded the 300 second deadline")??;
                Some(RoutePublication::parse_archived(
                    route_config,
                    &route_scope,
                    &prior_manifest,
                    &prior_signature,
                )?)
            } else {
                None
            };
            if check_only {
                tokio::time::timeout(
                    ROUTE_PUBLICATION_TIMEOUT,
                    records.verify_route_publication(
                        &config_scope(&config),
                        &publication,
                        previous.as_ref(),
                    ),
                )
                .await
                .context("route publication preflight exceeded the 300 second deadline")??;
                println!("{}", publication.revision_hex());
                return Ok(());
            }
            let signature_bytes = signature_bytes.context("route signature is required")?;
            let receipt = tokio::time::timeout(
                ROUTE_PUBLICATION_TIMEOUT,
                records.publish_route(
                    &config_scope(&config),
                    &publication,
                    previous.as_ref(),
                    manifest_bytes,
                    signature_bytes,
                    Utc::now(),
                ),
            )
            .await
            .context("route publication exceeded the 300 second deadline")??;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
    }
}

async fn tick_once(config: &FileConfig) -> Result<String> {
    require_tick_capture(config)?;
    let records = start_records_with_timeout(
        config,
        StoreAccessPlan::for_command(&Command::Tick { once: true }),
        true,
    )
    .await?;
    tick_once_with_records(config, Utc::now(), records).await
}

async fn tick_once_with_records(
    config: &FileConfig,
    now: DateTime<Utc>,
    records: Records,
) -> Result<String> {
    let scope = config_scope(config);
    let lease = tokio::time::timeout(
        TICK_LEASE_IO_TIMEOUT,
        records.acquire_tick_lease(&scope, now),
    )
    .await
    .context("tick lease acquisition exceeded the 30 second deadline")??;
    let Some(lease) = lease else {
        return Ok(serde_json::to_string(&records::TickAction::Hold)?);
    };
    let action = tokio::time::timeout(TICK_MUTATION_TIMEOUT, async {
        records.reconcile_gpu_launch_frontiers(&scope, now).await?;
        if let Some(expiry) = records.expire_due(&scope, now).await? {
            return Ok(serde_json::to_string(&expiry)?);
        }
        tick_action_with_records(config, now, &records).await
    })
    .await
    .context("tick mutation exceeded the 300 second deadline")
    .and_then(|result| result);
    let release = tokio::time::timeout(
        TICK_LEASE_IO_TIMEOUT,
        records.release_tick_lease(lease, Utc::now()),
    )
    .await
    .context("tick lease release exceeded the 30 second deadline")
    .and_then(|result| result);
    release?;
    action
}

async fn tick_action_with_records(
    config: &FileConfig,
    now: DateTime<Utc>,
    records: &Records,
) -> Result<String> {
    let analyzer = snapshot_analyzer_config(config, None)?;
    let teacher = teacher_config(config)?;
    let scope = config_scope(config);
    let provider_binding = decode_lowercase_sha256(&analyzer.current_provider_binding_hex()?)?;
    let (authorization, authorization_sha256) = SnapshotAnalysisAuthorization::root_owned(
        teacher.authorization_id.clone(),
        scope.clone(),
        config.capture_policy_version.clone(),
        config.capture_rights_state.clone(),
        provider_binding,
        teacher.max_decisions,
        teacher.authorization_not_after,
    )?;
    let recipe_sha256 = decode_lowercase_sha256(&teacher.student_recipe_sha256)?;
    let train_runtime_image_reference = &teacher.student_train_runtime_image_reference;
    let branch_runtime_image_reference = &teacher.student_branch_runtime_image_reference;
    if let Some(route) = &config.route
        && let Some(launch) = records
            .claim_student_winner_deployment(
                &scope,
                &provider_binding,
                route.winner_deployment_authority()?,
                now,
            )
            .await?
    {
        return Ok(serde_json::to_string(&launch)?);
    }
    if let Some(launch) = records
        .advance_student_fanout(
            &scope,
            &provider_binding,
            &recipe_sha256,
            train_runtime_image_reference,
            branch_runtime_image_reference,
            now,
        )
        .await?
    {
        return Ok(serde_json::to_string(&launch)?);
    }
    if let Some(claim) = records
        .claim_student_job(
            &scope,
            &provider_binding,
            &recipe_sha256,
            train_runtime_image_reference,
            branch_runtime_image_reference,
            now,
        )
        .await?
    {
        return Ok(serde_json::to_string(&claim)?);
    }
    match records
        .claim_teacher_gpu_run(&scope, authorization, authorization_sha256, analyzer, now)
        .await?
    {
        TeacherGpuTickWrite::Launch(write) => Ok(serde_json::to_string(&write)?),
        TeacherGpuTickWrite::Advanced(write) => Ok(serde_json::to_string(&write)?),
        TeacherGpuTickWrite::Hold => Ok(serde_json::to_string(&records::TickAction::Hold)?),
    }
}

fn require_tick_capture(config: &FileConfig) -> Result<()> {
    if config.capture_mode != CaptureMode::WholeBodyAuthorized {
        bail!("tick requires whole-body authorized capture");
    }
    Ok(())
}

async fn status_once(config: &FileConfig, now: DateTime<Utc>) -> Result<String> {
    let records = start_records_with_timeout(
        config,
        StoreAccessPlan::for_command(&Command::Status),
        false,
    )
    .await?;
    let record_status = records
        .data_plane_status(&config_scope(config), now)
        .await?;
    let route = route_status(config, &records, now).await?;
    Ok(serde_json::to_string(&StatusWrite {
        schema_version: "milk.status.v3",
        records: record_status,
        route,
    })?)
}

async fn generation_status_once(config: &FileConfig, now: DateTime<Utc>) -> Result<String> {
    let records = start_records_with_timeout(
        config,
        StoreAccessPlan::for_command(&Command::GenerationStatus),
        false,
    )
    .await?;
    let provider_binding = snapshot_provider_binding(config)?;
    let max_decisions = teacher_config(config)?.max_decisions;
    let status = records
        .status(&config_scope(config), &provider_binding, max_decisions, now)
        .await?;
    let generation = status.generation;
    Ok(serde_json::to_string(&GenerationStatusWrite {
        schema_version: "milk.generation-status.v1",
        scope_id: config.scope_id,
        max_decisions: generation.max_decisions,
        claimed_decisions: generation.claimed_decisions,
        remaining_decisions: generation.remaining_decisions,
        generation_done: generation.remaining_decisions == 0,
    })?)
}

async fn route_status(
    config: &FileConfig,
    records: &Records,
    now: DateTime<Utc>,
) -> Result<RouteStatusWrite> {
    let Some(route_config) = &config.route else {
        return Ok(RouteStatusWrite {
            configured: false,
            state: "disabled",
            route_revision: None,
            student_job_id: None,
            candidate_basis_points: None,
            not_after: None,
        });
    };
    let Some((pointer, manifest, signature)) =
        records.load_live_route(&config_scope(config)).await?
    else {
        return Ok(RouteStatusWrite {
            configured: true,
            state: "baseline",
            route_revision: None,
            student_job_id: None,
            candidate_basis_points: None,
            not_after: None,
        });
    };
    let route_scope = config_route_scope(config);
    let publication =
        RoutePublication::parse_archived(route_config, &route_scope, &manifest, &signature)?;
    if publication.revision_hex() != bytes_hex(&pointer.route_revision) {
        bail!("live route pointer differs from its verified publication");
    }
    let previous = if let Some(revision) = publication.previous_route_revision {
        let (manifest, signature) = records
            .load_route_publication(&config_scope(config), &revision)
            .await?;
        Some(RoutePublication::parse_archived(
            route_config,
            &route_scope,
            &manifest,
            &signature,
        )?)
    } else {
        None
    };
    records
        .verify_route_publication(&config_scope(config), &publication, previous.as_ref())
        .await?;
    if publication.candidate_basis_points == 0 && !publication.is_operator_proposal() {
        records
            .verify_zero_route_retirement(&config_scope(config), &publication)
            .await?;
    }
    let state = if publication.not_after <= now {
        "expired"
    } else if publication.candidate_basis_points == 0 {
        "zero"
    } else {
        "active"
    };
    Ok(RouteStatusWrite {
        configured: true,
        state,
        route_revision: Some(publication.revision_hex()),
        student_job_id: (!publication.is_operator_proposal())
            .then(|| bytes_hex(&publication.student_job_id)),
        candidate_basis_points: Some(publication.candidate_basis_points),
        not_after: Some(publication.not_after),
    })
}

async fn load_verified_live_route(
    config: &FileConfig,
    route_config: &RouteStartupConfig,
    records: &Records,
) -> Result<Option<(RoutePublication, Option<RoutePublication>)>> {
    let scope = config_scope(config);
    let Some((pointer, manifest, signature)) = records.load_live_route(&scope).await? else {
        return Ok(None);
    };
    let route_scope = config_route_scope(config);
    let publication =
        RoutePublication::parse_archived(route_config, &route_scope, &manifest, &signature)?;
    if publication.revision != pointer.route_revision {
        bail!("live route pointer differs from its verified publication");
    }
    let previous = if let Some(revision) = publication.previous_route_revision {
        let (manifest, signature) = records.load_route_publication(&scope, &revision).await?;
        Some(RoutePublication::parse_archived(
            route_config,
            &route_scope,
            &manifest,
            &signature,
        )?)
    } else {
        None
    };
    records
        .verify_route_publication(&scope, &publication, previous.as_ref())
        .await?;
    if publication.candidate_basis_points == 0 {
        records
            .verify_zero_route_retirement(&scope, &publication)
            .await?;
    }
    Ok(Some((publication, previous)))
}

fn command_uses_deployment_config(command: Option<&Command>) -> bool {
    matches!(command, None | Some(Command::Serve))
}

fn config_scope(config: &FileConfig) -> Scope {
    Scope {
        scope_id: config.scope_id,
    }
}

fn config_route_scope(config: &FileConfig) -> RouteScope {
    RouteScope {
        scope_id: config.scope_id,
    }
}

async fn refresh_live_route(
    config: &FileConfig,
    records: &Records,
    gateway: &Gateway,
    route_secret: Option<&str>,
    candidate_api_key: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool> {
    let route_config = config
        .route
        .as_ref()
        .context("live route refresh requires route configuration")?;
    let Some((pointer, manifest, signature)) =
        records.load_live_route(&config_scope(config)).await?
    else {
        return Ok(false);
    };
    let revision = bytes_hex(&pointer.route_revision);
    if gateway.route_runtime().policy.revision() == revision {
        return Ok(false);
    }
    let policy = RoutePolicy::from_signed_bytes(
        route_config,
        &config_route_scope(config),
        route_secret,
        candidate_api_key,
        config.max_in_flight,
        now,
        Instant::now(),
        &manifest,
        &signature,
    )?;
    if policy.revision() != revision {
        bail!("live route pointer differs from its signed publication");
    }
    gateway.replace_route_runtime(build_route_runtime(config, policy, candidate_api_key)?);
    Ok(true)
}

fn spawn_live_route_poller(
    config: FileConfig,
    records: Records,
    gateway: Gateway,
    route_secret: Option<String>,
    candidate_api_key: Option<String>,
) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + ROUTE_REFRESH_INTERVAL,
            ROUTE_REFRESH_INTERVAL,
        );
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            match refresh_live_route(
                &config,
                &records,
                &gateway,
                route_secret.as_deref(),
                candidate_api_key.as_deref(),
                Utc::now(),
            )
            .await
            {
                Ok(true) => tracing::info!(
                    route_revision = gateway.route_runtime().policy.revision(),
                    "live route refreshed"
                ),
                Ok(false) => {}
                Err(error) => tracing::error!(
                    error = %error,
                    "live route refresh failed; retaining the last verified route"
                ),
            }
        }
    });
}

async fn start_records(config: &FileConfig, access: StoreAccessPlan) -> Result<Records> {
    open_records(config, access, true).await
}

async fn start_records_with_timeout(
    config: &FileConfig,
    access: StoreAccessPlan,
    qualify_s3: bool,
) -> Result<Records> {
    tokio::time::timeout(
        Duration::from_millis(config.storage_timeout_ms),
        open_records(config, access, qualify_s3),
    )
    .await
    .context("storage initialization timed out")?
}

async fn open_records(
    config: &FileConfig,
    access: StoreAccessPlan,
    qualify_s3: bool,
) -> Result<Records> {
    let capture =
        open_store_partition(config, StorePartition::Capture, access.capture, qualify_s3).await?;
    let control =
        open_store_partition(config, StorePartition::Control, access.control, qualify_s3).await?;
    let routes =
        open_store_partition(config, StorePartition::Routes, access.routes, qualify_s3).await?;
    let objects = Arc::new(PartitionedObjectStore::new(capture, control, routes));
    let sampling_key_version = records_sampling_key_version(access)?;
    Records::start_with_sampling(
        objects,
        config.capture_queue_bytes,
        config.capture_record_bytes,
        config_scope(config),
        config.capture_basis_points,
        (!config.capture_policy_version.is_empty()).then(|| config.capture_policy_version.clone()),
        sampling_key_version,
    )
    .await
}

fn records_sampling_key_version(access: StoreAccessPlan) -> Result<String> {
    if access.capture.is_none() {
        return Ok(NO_CAPTURE_SAMPLING_KEY_VERSION.to_owned());
    }
    Ok(capture_sampling_config()?.1)
}

async fn open_store_partition(
    config: &FileConfig,
    partition: StorePartition,
    access: Option<StoreAccess>,
    qualify_s3: bool,
) -> Result<Option<(Arc<dyn object_store::ObjectStore>, StoreAccess)>> {
    let Some(access) = access else {
        return Ok(None);
    };
    let (objects, s3) = match config.stores.get(partition) {
        ObjectStoreConfig::Local { root } => (records::build_local(root)?, false),
        ObjectStoreConfig::S3 {
            endpoint,
            region,
            bucket,
        } => (
            records::build_s3(endpoint, region, bucket, partition)?,
            true,
        ),
    };
    if qualify_s3 && s3 {
        match access {
            StoreAccess::ReadOnly => records::probe_s3_read(&objects).await?,
            StoreAccess::ReadWrite => records::probe_s3(&objects).await?,
        }
    }
    Ok(Some((objects, access)))
}

#[derive(Debug)]
struct SelectedConfig {
    value: FileConfig,
    sha256: [u8; 32],
}

fn load_config(path: &Path, command: Option<&Command>) -> Result<SelectedConfig> {
    let deployment = command_uses_deployment_config(command);
    let mut input = if deployment {
        OperatorInput::open_serve(path, MAX_CONFIG_BYTES, "gateway config")?
    } else {
        OperatorInput::open(path, MAX_CONFIG_BYTES, "gateway config")?
    };
    let bytes = input.reread_unchanged()?;
    let config = parse_config(&bytes, &format!("config {}", path.display()), command)?;
    if deployment {
        validate_serve_config_owner(&config.value, input.owner)?;
    }
    Ok(config)
}

fn load_selected_config(
    path: Option<&Path>,
    config_json: Option<&[u8]>,
    command: Option<&Command>,
) -> Result<SelectedConfig> {
    match (path, config_json) {
        (Some(_), Some(_)) => {
            bail!("gateway config path and {CONFIG_JSON_ENV} are mutually exclusive")
        }
        (None, None) => bail!("gateway config path or {CONFIG_JSON_ENV} is required"),
        (Some(path), None) => load_config(path, command),
        (None, Some(bytes)) => {
            if !command_uses_deployment_config(command) {
                bail!("{CONFIG_JSON_ENV} is only accepted by serve");
            }
            if bytes.len() > MAX_CONFIG_BYTES {
                bail!("{CONFIG_JSON_ENV} exceeds {MAX_CONFIG_BYTES} bytes");
            }
            parse_config(bytes, CONFIG_JSON_ENV, command)
        }
    }
}

fn parse_config(
    bytes: &[u8],
    description: &str,
    command: Option<&Command>,
) -> Result<SelectedConfig> {
    let config = serde_json::from_slice(bytes).with_context(|| format!("invalid {description}"))?;
    validate_config_identity(&config)?;
    validate_config_for_command(&config, command)?;
    Ok(SelectedConfig {
        value: config,
        sha256: Sha256::digest(bytes).into(),
    })
}

fn validate_serve_config_owner(config: &FileConfig, owner: InputOwner) -> Result<()> {
    if owner == InputOwner::CurrentPrivate
        && (!config.listen.ip().is_loopback() || !all_local_stores(&config.stores))
    {
        bail!("current-owner serve config requires loopback listen and Local stores");
    }
    Ok(())
}

fn validate_config_identity(config: &FileConfig) -> Result<()> {
    let identities = [config.outcome_key_id, config.scope_id];
    if identities.iter().any(Uuid::is_nil) {
        bail!("outcome key ID and scope_id must be non-nil");
    }
    if identities.into_iter().collect::<HashSet<_>>().len() != identities.len() {
        bail!("outcome key ID and scope_id must differ");
    }
    configured_traffic_keys(&config.traffic_keys)?;
    if let Some(route) = &config.route {
        route.validate_common(config.max_in_flight)?;
    }
    for store in [
        &config.stores.capture,
        &config.stores.control,
        &config.stores.routes,
    ] {
        match store {
            ObjectStoreConfig::Local { root } => {
                records::validate_local_store_identity(root)?;
            }
            ObjectStoreConfig::S3 {
                endpoint,
                region,
                bucket,
            } => {
                records::validate_s3_identity(endpoint, region, bucket)?;
            }
        }
    }
    Ok(())
}

fn validate_config_for_command(config: &FileConfig, command: Option<&Command>) -> Result<()> {
    match command.unwrap_or(&Command::Serve) {
        Command::Serve => {
            parse_openai_compatible_api_base_url(
                &config.baseline.api_base_url,
                config.baseline.allow_loopback_http,
            )?;
        }
        Command::Status => {}
        Command::Tick { .. }
        | Command::GenerationStatus
        | Command::BeginTeacherRun { .. }
        | Command::ExecuteTeacherRun { .. }
        | Command::TerminalizeTeacherRun { .. } => validate_teacher_config(config)?,
        Command::MaterializeStudentJob { .. }
        | Command::MaterializeStudentWinner { .. }
        | Command::IngestStudentTrainExecution { .. }
        | Command::MaterializeStudentBranch { .. }
        | Command::IngestStudentBranchExecution { .. }
        | Command::IngestStudentWinnerDeploymentResult { .. }
        | Command::IngestProviderTeardownResult { .. }
        | Command::PrepareRouteProposal { .. }
        | Command::PublishRoute { .. } => {}
        Command::AdvanceWinnerRoute { .. } | Command::PrepareRoute { .. } => config
            .route
            .as_ref()
            .context("student route operation requires route configuration")?
            .validate(config.max_in_flight)?,
    }
    Ok(())
}

fn validate_teacher_config(config: &FileConfig) -> Result<()> {
    let teacher = teacher_config(config)?;
    records::validate_teacher_max_decisions(teacher.max_decisions)?;
    parse_openai_compatible_endpoint(&teacher.chat_completions_url, teacher.allow_loopback_http)?;
    decode_lowercase_sha256(&teacher.deployment_sha256)?;
    decode_lowercase_sha256(&teacher.terms_sha256)?;
    decode_lowercase_sha256(&teacher.student_recipe_sha256)?;
    route::validate_distinct_runtime_image_references(
        &teacher.student_train_runtime_image_reference,
        &teacher.student_branch_runtime_image_reference,
    )?;
    snapshot_analyzer_config(config, None)?;
    if let Some(route) = &config.route {
        route.validate_common(config.max_in_flight)?;
        if route.has_winner_deployment_authority() {
            if route
                .authorized_student_branch_runtime_image_reference
                .as_deref()
                != Some(teacher.student_branch_runtime_image_reference.as_str())
            {
                bail!("student branch runtime image must equal the route-authorized runtime image");
            }
            route.validate(config.max_in_flight)?;
        }
    }
    if teacher.authorization_not_after.nanosecond() != 0 {
        bail!("teacher authorization expiry must use whole seconds");
    }
    if !matches!(config.stores.capture, ObjectStoreConfig::S3 { .. })
        || !matches!(config.stores.control, ObjectStoreConfig::S3 { .. })
    {
        bail!("GPU teacher jobs require shared S3-compatible storage");
    }
    Ok(())
}

fn all_local_stores(stores: &StoresConfig) -> bool {
    matches!(stores.capture, ObjectStoreConfig::Local { .. })
        && matches!(stores.control, ObjectStoreConfig::Local { .. })
        && matches!(stores.routes, ObjectStoreConfig::Local { .. })
}

fn teacher_config(config: &FileConfig) -> Result<&TeacherConfig> {
    config
        .teacher
        .as_ref()
        .context("this command requires teacher GPU job configuration")
}

fn parse_openai_compatible_endpoint(value: &str, allow_loopback_http: bool) -> Result<Url> {
    if value.is_empty() || value.len() > 2_048 {
        bail!("OpenAI-compatible endpoint must contain 1..=2048 bytes");
    }
    let endpoint = Url::parse(value).context("OpenAI-compatible endpoint is not a valid URL")?;
    let loopback_http = allow_loopback_http
        && endpoint.scheme() == "http"
        && endpoint.path() == CHAT_PATH
        && match endpoint.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
    if endpoint.as_str() != value
        || (endpoint.scheme() != "https" && !loopback_http)
        || !endpoint.path().ends_with(CHAT_PATH)
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!(
            "OpenAI-compatible endpoint must be canonical credential-free HTTPS, or explicitly enabled literal-loopback HTTP"
        );
    }
    Ok(endpoint)
}

fn parse_openai_compatible_api_base_url(value: &str, allow_loopback_http: bool) -> Result<Url> {
    if value.is_empty() || value.len() > 2_048 {
        bail!("OpenAI-compatible API base URL must contain 1..=2048 bytes");
    }
    let base = Url::parse(value).context("OpenAI-compatible API base URL is not a valid URL")?;
    let loopback_http = allow_loopback_http
        && base.scheme() == "http"
        && base.path() == "/v1/"
        && match base.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
    if base.as_str() != value
        || (base.scheme() != "https" && !loopback_http)
        || !base.path().ends_with("/v1/")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        bail!(
            "OpenAI-compatible API base URL must be canonical credential-free HTTPS ending in /v1/, or explicitly enabled literal-loopback HTTP at /v1/"
        );
    }
    Ok(base)
}

fn api_endpoint_url(base: &Url, endpoint: RouteEndpoint) -> Result<Url> {
    base.join(endpoint.relative_path())
        .context("OpenAI-compatible endpoint could not be derived from API base URL")
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} is required"))
}

fn optional_env(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => bail!("{name} must be valid UTF-8"),
    }
}

fn snapshot_analyzer_config(
    config: &FileConfig,
    teacher_api_key: Option<String>,
) -> Result<SnapshotAnalyzerConfig> {
    let teacher = teacher_config(config)?;
    SnapshotAnalyzerConfig::production(
        &teacher.chat_completions_url,
        teacher.allow_loopback_http,
        teacher_api_key,
        teacher.model.clone(),
        teacher.reasoning_effort,
        teacher.execution.clone(),
        decode_lowercase_sha256(&teacher.deployment_sha256)?,
        decode_lowercase_sha256(&teacher.terms_sha256)?,
        teacher.max_projected_bytes,
        teacher.max_input_tokens,
        teacher.max_output_tokens,
        teacher.input_rate_microusd_per_million_tokens,
        teacher.output_rate_microusd_per_million_tokens,
        teacher.max_cost_microusd,
    )
}

fn snapshot_provider_binding(config: &FileConfig) -> Result<[u8; 32]> {
    let teacher = teacher_config(config)?;
    SnapshotAnalyzerConfig::provider_binding(
        &teacher.chat_completions_url,
        teacher.allow_loopback_http,
        &teacher.model,
        teacher.reasoning_effort,
        teacher.execution.clone(),
        decode_lowercase_sha256(&teacher.deployment_sha256)?,
        decode_lowercase_sha256(&teacher.terms_sha256)?,
        teacher.max_projected_bytes,
        teacher.max_input_tokens,
        teacher.max_output_tokens,
        teacher.input_rate_microusd_per_million_tokens,
        teacher.output_rate_microusd_per_million_tokens,
        teacher.max_cost_microusd,
    )
}

struct OperatorInput {
    path: PathBuf,
    file: fs::File,
    initial: Vec<u8>,
    max_bytes: usize,
    description: &'static str,
    owner: InputOwner,
}

struct StableStudentArtifactDirectory {
    path: PathBuf,
    directory_dev: u64,
    directory_ino: u64,
    names: Vec<String>,
    paths: Vec<PathBuf>,
    metadata: Vec<ArtifactMetadata>,
    files: Vec<StudentArtifactInput>,
}

fn stage_student_job(path: &Path, claim: &[u8], input: &[u8]) -> Result<()> {
    if !path.is_absolute() {
        bail!("student stage directory path must be absolute");
    }
    let parent = path
        .parent()
        .context("student stage directory has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != current_effective_uid()
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!(
            "student stage parent must be a current-owner directory with no group/world write bits"
        );
    }
    if fs::symlink_metadata(path).is_ok() {
        bail!("student stage directory must not already exist");
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let claim_path = path.join("claim.json");
    let input_path = path.join("input.json");
    let staged = (|| -> Result<()> {
        write_create_only(&claim_path, claim)?;
        write_create_only(&input_path, input)?;
        fs::File::open(path)?.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
        Ok(())
    })();
    if let Err(error) = staged {
        for file in [&claim_path, &input_path] {
            match fs::remove_file(file) {
                Ok(()) => {}
                Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => {}
                Err(cleanup) => tracing::error!(
                    path = %file.display(),
                    error = %cleanup,
                    "student stage cleanup failed"
                ),
            }
        }
        if let Err(cleanup) = fs::remove_dir(path) {
            tracing::error!(
                path = %path.display(),
                error = %cleanup,
                "student stage directory cleanup failed"
            );
        }
        return Err(error);
    }
    Ok(())
}

fn stage_student_branch(path: &Path, materialization: &StudentBranchMaterialization) -> Result<()> {
    if !path.is_absolute() {
        bail!("student branch stage directory path must be absolute");
    }
    let parent = path
        .parent()
        .context("student branch stage directory has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != current_effective_uid()
        || parent_metadata.mode() & 0o022 != 0
        || fs::symlink_metadata(path).is_ok()
    {
        bail!("student branch stage requires a safe parent and absent destination");
    }
    fs::DirBuilder::new().mode(0o700).create(path)?;
    let files = [
        ("claim.json", materialization.parent_claim.as_slice()),
        ("input.json", materialization.input.as_slice()),
        ("train-result.json", materialization.train_result.as_slice()),
        ("fanout-claim.json", materialization.fanout_claim.as_slice()),
    ];
    let staged = (|| -> Result<()> {
        for (name, bytes) in files {
            write_create_only(&path.join(name), bytes)?;
        }
        fs::File::open(path)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = staged {
        cleanup_student_branch_json(path);
        return Err(error);
    }
    Ok(())
}

fn seal_student_branch_stage(path: &Path) -> Result<()> {
    let mut names = fs::read_dir(path)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("student branch stage filename is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort_unstable();
    if names
        != [
            "claim.json",
            "fanout-claim.json",
            "input.json",
            "merged-model",
            "train-result.json",
        ]
    {
        bail!("student branch stage has an unexpected inventory");
    }
    let merged = fs::symlink_metadata(path.join("merged-model"))?;
    if !merged.is_dir()
        || merged.uid() != current_effective_uid()
        || merged.mode() & 0o7777 != 0o500
    {
        bail!("student branch merged model is not sealed");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

fn cleanup_student_branch_json(path: &Path) {
    for name in [
        "claim.json",
        "input.json",
        "train-result.json",
        "fanout-claim.json",
    ] {
        if let Err(error) = fs::remove_file(path.join(name))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::error!(path = %path.join(name).display(), error = %error, "student branch stage cleanup failed");
        }
    }
    if let Err(error) = fs::remove_dir(path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        tracing::error!(path = %path.display(), error = %error, "student branch stage directory cleanup failed");
    }
}

fn write_create_only(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o400)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_private_output(path: &Path, bytes: &[u8], description: &str) -> Result<()> {
    if !path.is_absolute() {
        bail!("{description} path must be absolute");
    }
    let parent = path.parent().context("output path has no parent")?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != current_effective_uid()
        || parent_metadata.mode() & 0o022 != 0
    {
        bail!(
            "{description} parent must be a current-owner directory with no group/world write bits"
        );
    }
    let mut created = false;
    let written = (|| -> Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(path)?;
        created = true;
        file.write_all(bytes)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != current_effective_uid()
            || metadata.mode() & 0o7777 != 0o400
            || metadata.nlink() != 1
        {
            bail!("{description} was not created as a private single-link file");
        }
        fs::File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = written {
        if !created {
            return Err(error);
        }
        match fs::remove_file(path) {
            Ok(()) => {}
            Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => {}
            Err(cleanup) => tracing::error!(
                path = %path.display(),
                error = %cleanup,
                "private output cleanup failed"
            ),
        }
        return Err(error);
    }
    Ok(())
}

fn bytes_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ArtifactMetadata {
    dev: u64,
    ino: u64,
    len: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    mtime_nsec: i64,
}

impl ArtifactMetadata {
    fn from(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            ino: metadata.ino(),
            len: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        }
    }
}

impl StableStudentArtifactDirectory {
    fn open(path: &Path) -> Result<Self> {
        if !path.is_absolute() {
            bail!("student artifact directory path must be absolute");
        }
        let directory = fs::symlink_metadata(path)?;
        validate_student_artifact_directory(&directory)?;
        let names = student_artifact_directory_entries(path)?;
        let mut paths = Vec::with_capacity(names.len());
        let mut metadata = Vec::with_capacity(names.len());
        let mut files = Vec::with_capacity(names.len());
        let mut total = 0_u64;
        for name in &names {
            let file_path = path.join(name);
            let (file, file_metadata) = open_stable_student_artifact(&file_path)?;
            total = total
                .checked_add(file_metadata.len)
                .context("student artifact size overflow")?;
            if total > MAX_STUDENT_ARTIFACT_BYTES {
                bail!("student artifact directory exceeds its hard byte ceiling");
            }
            paths.push(file_path);
            metadata.push(file_metadata);
            files.push(StudentArtifactInput {
                relative_path: name.clone(),
                file,
            });
        }
        Ok(Self {
            path: path.to_owned(),
            directory_dev: directory.dev(),
            directory_ino: directory.ino(),
            names,
            paths,
            metadata,
            files,
        })
    }

    fn revalidate(&mut self) -> Result<()> {
        let directory = fs::symlink_metadata(&self.path)?;
        validate_student_artifact_directory(&directory)?;
        if directory.dev() != self.directory_dev
            || directory.ino() != self.directory_ino
            || student_artifact_directory_entries(&self.path)? != self.names
        {
            bail!("student artifact directory changed after validation");
        }
        for (((path, expected), input), name) in self
            .paths
            .iter()
            .zip(&self.metadata)
            .zip(&self.files)
            .zip(&self.names)
        {
            if input.relative_path != *name {
                bail!("student artifact file order changed after validation");
            }
            revalidate_student_artifact(path, &input.file, *expected)?;
        }
        Ok(())
    }
}

impl StudentArtifactSource for StableStudentArtifactDirectory {
    fn files(&mut self) -> &mut [StudentArtifactInput] {
        &mut self.files
    }

    fn revalidate(&mut self) -> Result<()> {
        StableStudentArtifactDirectory::revalidate(self)
    }
}

fn validate_student_artifact_directory(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_dir()
        || metadata.uid() != current_effective_uid()
        || metadata.mode() & 0o7777 != 0o500
    {
        bail!("student artifact directory must be current-owner 0500");
    }
    Ok(())
}

fn student_artifact_directory_entries(path: &Path) -> Result<Vec<String>> {
    let mut names = fs::read_dir(path)?
        .map(|entry| {
            let name = entry?.file_name();
            name.into_string()
                .map_err(|_| anyhow::anyhow!("student artifact filename is not UTF-8"))
        })
        .collect::<Result<Vec<_>>>()?;
    names.sort_unstable();
    if names.len() > MAX_STUDENT_ARTIFACT_FILES
        || names.iter().any(|name| {
            name.len() != 64
                || !name
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        || names.windows(2).any(|pair| pair[0] >= pair[1])
    {
        bail!("student artifact filenames must be unique lowercase SHA-256 digests");
    }
    Ok(names)
}

fn open_stable_student_artifact(path: &Path) -> Result<(fs::File, ArtifactMetadata)> {
    let linked = fs::symlink_metadata(path)?;
    validate_student_artifact(&linked)?;
    let file = fs::File::open(path)?;
    let opened = file.metadata()?;
    let current = fs::symlink_metadata(path)?;
    validate_student_artifact(&opened)?;
    validate_student_artifact(&current)?;
    if linked.dev() != opened.dev()
        || linked.ino() != opened.ino()
        || current.dev() != opened.dev()
        || current.ino() != opened.ino()
    {
        bail!("student artifact changed while it was opened");
    }
    Ok((file, ArtifactMetadata::from(&opened)))
}

fn validate_student_artifact(metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file()
        || metadata.uid() != current_effective_uid()
        || metadata.mode() & 0o7777 != 0o400
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_STUDENT_ARTIFACT_BYTES
    {
        bail!("student artifact must be a bounded current-owner 0400 single-link file");
    }
    Ok(())
}

fn revalidate_student_artifact(
    path: &Path,
    file: &fs::File,
    expected: ArtifactMetadata,
) -> Result<()> {
    let current = fs::symlink_metadata(path)?;
    let opened = file.metadata()?;
    validate_student_artifact(&current)?;
    validate_student_artifact(&opened)?;
    if ArtifactMetadata::from(&current) != expected || ArtifactMetadata::from(&opened) != expected {
        bail!("student artifact changed after validation");
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum InputOwner {
    Current,
    CurrentPrivate,
    RootDeployment,
}

impl OperatorInput {
    fn open(path: &Path, max_bytes: usize, description: &'static str) -> Result<Self> {
        Self::open_for_owner(path, max_bytes, description, InputOwner::Current)
    }

    fn open_serve(path: &Path, max_bytes: usize, description: &'static str) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect {description} {}", path.display()))?;
        let owner = if current_effective_uid() != 0 && metadata.uid() == 0 {
            InputOwner::RootDeployment
        } else {
            InputOwner::CurrentPrivate
        };
        Self::open_for_owner(path, max_bytes, description, owner)
    }

    fn open_private(path: &Path, max_bytes: usize, description: &'static str) -> Result<Self> {
        Self::open_for_owner(path, max_bytes, description, InputOwner::CurrentPrivate)
    }

    fn open_for_owner(
        path: &Path,
        max_bytes: usize,
        description: &'static str,
        owner: InputOwner,
    ) -> Result<Self> {
        if !path.is_absolute() {
            bail!("{description} path must be absolute");
        }
        let linked = fs::symlink_metadata(path)
            .with_context(|| format!("failed to inspect {description} {}", path.display()))?;
        validate_input_metadata(&linked, max_bytes, description, owner)?;
        let mut file = fs::File::open(path)
            .with_context(|| format!("failed to open {description} {}", path.display()))?;
        let opened = file.metadata()?;
        let current = fs::symlink_metadata(path)?;
        validate_input_metadata(&opened, max_bytes, description, owner)?;
        validate_input_metadata(&current, max_bytes, description, owner)?;
        if linked.dev() != opened.dev()
            || linked.ino() != opened.ino()
            || current.dev() != opened.dev()
            || current.ino() != opened.ino()
        {
            bail!("{description} changed while it was opened");
        }
        let initial = read_operator_input(&mut file, max_bytes, description)?;
        Ok(Self {
            path: path.to_owned(),
            file,
            initial,
            max_bytes,
            description,
            owner,
        })
    }

    fn initial(&self) -> &[u8] {
        &self.initial
    }

    fn reread_unchanged(&mut self) -> Result<Vec<u8>> {
        let current = fs::symlink_metadata(&self.path)?;
        let opened = self.file.metadata()?;
        validate_input_metadata(&current, self.max_bytes, self.description, self.owner)?;
        validate_input_metadata(&opened, self.max_bytes, self.description, self.owner)?;
        if current.dev() != opened.dev() || current.ino() != opened.ino() {
            bail!("{} changed after validation", self.description);
        }
        let bytes = read_operator_input(&mut self.file, self.max_bytes, self.description)?;
        if bytes != self.initial {
            bail!("{} changed after validation", self.description);
        }
        Ok(bytes)
    }
}

fn validate_input_metadata(
    metadata: &fs::Metadata,
    max_bytes: usize,
    description: &str,
    owner: InputOwner,
) -> Result<()> {
    if metadata.len() > max_bytes as u64 {
        bail!("{description} exceeds {max_bytes} bytes");
    }
    let owner_is_valid = match owner {
        InputOwner::Current => metadata.uid() == current_effective_uid(),
        InputOwner::CurrentPrivate => {
            metadata.uid() == current_effective_uid()
                && metadata.mode() & 0o7777 == 0o600
                && metadata.nlink() == 1
        }
        InputOwner::RootDeployment => current_effective_uid() != 0 && metadata.uid() == 0,
    };
    if !metadata.is_file() || !owner_is_valid || metadata.mode() & 0o022 != 0 {
        let expected_owner = match owner {
            InputOwner::Current => "current-owner",
            InputOwner::CurrentPrivate => "current-owner 0600 single-link",
            InputOwner::RootDeployment => "root-owned for a non-root service",
        };
        bail!(
            "{description} must be a bounded {expected_owner} regular file with no group/world write bits"
        );
    }
    Ok(())
}

fn read_operator_input(
    file: &mut fs::File,
    max_bytes: usize,
    description: &str,
) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let size = usize::try_from(file.metadata()?.len())
        .with_context(|| format!("{description} size does not fit usize"))?;
    if size > max_bytes {
        bail!("{description} exceeds {max_bytes} bytes");
    }
    let limit = u64::try_from(max_bytes)?
        .checked_add(1)
        .with_context(|| format!("{description} byte limit overflow"))?;
    let mut bytes = Vec::with_capacity(size);
    file.take(limit).read_to_end(&mut bytes)?;
    if bytes.len() > max_bytes || bytes.len() != size {
        bail!("{description} changed while it was read");
    }
    Ok(bytes)
}

fn build_server(listener: TcpListener, gateway: Gateway) -> Result<actix_web::dev::Server> {
    Ok(HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(gateway.clone()))
            .route("/healthz", web::get().to(health))
            .route(
                CANDIDATE_CREDENTIAL_PATH,
                web::get().to(candidate_credential),
            )
            .route(CHAT_PATH, web::post().to(chat))
            .route(RESPONSES_PATH, web::post().to(responses))
            .route(OUTCOME_PATH, web::post().to(outcome))
    })
    .h1_allow_half_closed(false)
    .listen(listener)?
    .run())
}

async fn health(gateway: web::Data<Gateway>) -> HttpResponse {
    let stats = gateway
        .records
        .as_ref()
        .map(Records::health)
        .unwrap_or_default();
    let capture = if gateway.capture.mode == CaptureMode::Disabled {
        "disabled"
    } else if gateway.records.is_some() && stats.ready {
        "available"
    } else if gateway.records.is_some() {
        "unhealthy"
    } else {
        "unavailable"
    };
    let route_runtime = gateway.route_runtime();
    let candidate = match &route_runtime.candidate {
        Some(candidate) if candidate.healthy.load(Ordering::Acquire) => "healthy",
        Some(_) => "unhealthy",
        None => "disabled",
    };
    let degraded = matches!(capture, "unavailable" | "unhealthy")
        || candidate == "unhealthy"
        || gateway.records.is_some() && !stats.ready;
    HttpResponse::build(if degraded {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::OK
    })
    .insert_header((header::CACHE_CONTROL, "no-store"))
    .insert_header((CONFIG_SHA256_HEADER, bytes_hex(&gateway.config_sha256)))
    .json(HealthResponse {
        status: if degraded { "degraded" } else { "ok" },
        config_sha256: bytes_hex(&gateway.config_sha256),
        capture,
        candidate,
        writer_alive: stats.writer_alive,
        recent_persist_failure: stats.recent_persist_failure,
        consecutive_persist_failures: stats.consecutive_persist_failures,
        queued: stats.queued,
        dropped: stats.dropped,
        traces_persisted: stats.traces_persisted,
        trace_persist_failures: stats.trace_persist_failures,
        stats_persist_failures: stats.stats_persist_failures,
        outcome_persist_failures: OUTCOME_PERSISTENCE_FAILURES.load(Ordering::Relaxed),
    })
}

async fn candidate_credential(request: HttpRequest, gateway: web::Data<Gateway>) -> HttpResponse {
    let (value, duplicate) = one_header(request.headers(), CANDIDATE_API_KEY_SHA256_HEADER);
    let Some(value) = value.filter(|_| !duplicate) else {
        return HttpResponse::BadRequest()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(CandidateCredentialMismatch {
                schema_version: "milk.candidate-credential-check.v1",
                state: "invalid",
            });
    };
    let Ok(expected_text) = std::str::from_utf8(value) else {
        return HttpResponse::BadRequest()
            .insert_header((header::CACHE_CONTROL, "no-store"))
            .json(CandidateCredentialMismatch {
                schema_version: "milk.candidate-credential-check.v1",
                state: "invalid",
            });
    };
    let expected = if expected_text == "absent" {
        None
    } else {
        let Ok(expected) = decode_lowercase_sha256(expected_text) else {
            return HttpResponse::BadRequest()
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .json(CandidateCredentialMismatch {
                    schema_version: "milk.candidate-credential-check.v1",
                    state: "invalid",
                });
        };
        Some(expected)
    };
    let state = match (gateway.candidate_api_key_sha256, expected) {
        (Some(actual), Some(expected)) if actual.ct_eq(&expected).unwrap_u8() == 1 => "loaded",
        (None, None) => "absent",
        _ => {
            return HttpResponse::Conflict()
                .insert_header((header::CACHE_CONTROL, "no-store"))
                .json(CandidateCredentialMismatch {
                    schema_version: "milk.candidate-credential-check.v1",
                    state: "mismatch",
                });
        }
    };
    HttpResponse::Ok()
        .insert_header((header::CACHE_CONTROL, "no-store"))
        .insert_header((CANDIDATE_API_KEY_SHA256_HEADER, expected_text))
        .insert_header((CANDIDATE_CREDENTIAL_STATE_HEADER, state))
        .json(CandidateCredentialResponse {
            schema_version: "milk.candidate-credential-check.v1",
            candidate_api_key_sha256: (state == "loaded").then_some(expected_text),
            state,
        })
}

async fn outcome(
    request: HttpRequest,
    payload: web::Payload,
    gateway: web::Data<Gateway>,
) -> HttpResponse {
    let trace_id = Uuid::now_v7();
    if !valid_outcome_key(
        request.headers(),
        gateway.outcome_key_id,
        &gateway.outcome_key_sha256,
    ) {
        return local_error(
            StatusCode::UNAUTHORIZED,
            trace_id,
            "Invalid Milk Carton outcome key.",
            "invalid_outcome_key",
        );
    }
    let Some(records) = &gateway.records else {
        return local_error(
            StatusCode::SERVICE_UNAVAILABLE,
            trace_id,
            "Outcome storage is not configured.",
            "outcome_storage_unavailable",
        );
    };
    let _permit = match Arc::clone(&gateway.outcomes_in_flight).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return local_error(
                StatusCode::SERVICE_UNAVAILABLE,
                trace_id,
                "Milk Carton is at its configured request limit.",
                "gateway_over_capacity",
            );
        }
    };
    let body = match tokio::time::timeout(
        gateway.request_body_timeout,
        payload.to_bytes_limited(gateway.outcome_max_bytes),
    )
    .await
    {
        Ok(Ok(Ok(body))) => body,
        Ok(Err(_)) => {
            return local_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                trace_id,
                "Outcome body exceeds the configured limit.",
                "outcome_too_large",
            );
        }
        Ok(Ok(Err(_))) => {
            return local_error(
                StatusCode::BAD_REQUEST,
                trace_id,
                "Outcome body could not be read.",
                "invalid_outcome",
            );
        }
        Err(_) => {
            return local_error(
                StatusCode::REQUEST_TIMEOUT,
                trace_id,
                "Outcome body exceeded the configured deadline.",
                "request_body_timeout",
            );
        }
    };
    let outcome_request: OutcomeRequest = match serde_json::from_slice(&body) {
        Ok(submission) => submission,
        Err(_) => {
            return local_error(
                StatusCode::BAD_REQUEST,
                trace_id,
                "Outcome body is invalid.",
                "invalid_outcome",
            );
        }
    };
    if outcome_request.value.kind() != gateway.outcome_kind {
        return local_error(
            StatusCode::BAD_REQUEST,
            outcome_request.trace_id,
            "Outcome kind is not configured for this workload.",
            "outcome_kind_not_allowed",
        );
    }
    let submission = OutcomeSubmission {
        trace_id: outcome_request.trace_id,
        outcome_version: outcome_request.outcome_version,
        verifier_id: gateway.outcome_verifier_id.clone(),
        rights_state: gateway.outcome_rights_state.clone(),
        value: outcome_request.value,
    };
    if submission.validate(gateway.outcome_max_bytes).is_err() {
        return local_error(
            StatusCode::BAD_REQUEST,
            submission.trace_id,
            "Outcome body is invalid.",
            "invalid_outcome",
        );
    }
    let retention_until = Utc::now() + TimeDelta::days(gateway.outcome_retention_days);
    let retry_for = gateway
        .storage_timeout
        .saturating_sub(OUTCOME_TRACE_RETRY_DELAY)
        .min(OUTCOME_TRACE_RETRY_LIMIT);
    let write_result = match tokio::time::timeout(gateway.storage_timeout, async {
        let retry_deadline = Instant::now() + retry_for;
        loop {
            match records
                .persist_outcome(&gateway.scope, &submission, retention_until)
                .await
            {
                Ok(write) => return Ok(Some(write)),
                Err(error) if is_not_found(&error) => {
                    let now = Instant::now();
                    if now >= retry_deadline {
                        return Ok(None);
                    }
                    tokio::time::sleep(OUTCOME_TRACE_RETRY_DELAY.min(retry_deadline - now)).await;
                }
                Err(error) => return Err(error),
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("outcome storage deadline exceeded")),
    };
    let write = match write_result {
        Ok(Some(write)) => write,
        Ok(None) => {
            let mut response = local_error(
                StatusCode::from_u16(425).expect("425 is a valid HTTP status"),
                submission.trace_id,
                "Trace is not available yet.",
                "trace_unavailable",
            );
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
            return response;
        }
        Err(error) => {
            let failures = OUTCOME_PERSISTENCE_FAILURES
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1);
            if failures.is_power_of_two() {
                tracing::error!(trace_id = %submission.trace_id, error = %error, failures, "outcome persistence failed");
            }
            return local_error(
                StatusCode::SERVICE_UNAVAILABLE,
                submission.trace_id,
                "Outcome storage is unavailable.",
                "outcome_storage_unavailable",
            );
        }
    };
    let status = match write.disposition {
        OutcomeDisposition::Accepted => StatusCode::CREATED,
        OutcomeDisposition::Idempotent => StatusCode::OK,
        OutcomeDisposition::Conflict => StatusCode::CONFLICT,
    };
    HttpResponse::build(status)
        .insert_header((TRACE_ID_HEADER, submission.trace_id.to_string()))
        .json(write)
}

async fn chat(
    request: HttpRequest,
    payload: web::Payload,
    gateway: web::Data<Gateway>,
) -> HttpResponse {
    proxy_openai(RouteEndpoint::ChatCompletions, request, payload, gateway).await
}

async fn responses(
    request: HttpRequest,
    payload: web::Payload,
    gateway: web::Data<Gateway>,
) -> HttpResponse {
    proxy_openai(RouteEndpoint::Responses, request, payload, gateway).await
}

async fn proxy_openai(
    endpoint: RouteEndpoint,
    request: HttpRequest,
    payload: web::Payload,
    gateway: web::Data<Gateway>,
) -> HttpResponse {
    let trace_id = Uuid::now_v7();
    let Some(traffic_key) = authenticate_traffic_key(request.headers(), &gateway.traffic_keys)
    else {
        return local_error(
            StatusCode::UNAUTHORIZED,
            trace_id,
            "Invalid Milk Carton API key.",
            "invalid_milk_api_key",
        );
    };
    let occurred_at = Utc::now();
    let started = Instant::now();

    let permit = match Arc::clone(&gateway.in_flight).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => {
            return local_error(
                StatusCode::SERVICE_UNAVAILABLE,
                trace_id,
                "Milk Carton is at its configured request limit.",
                "gateway_over_capacity",
            );
        }
    };

    let body = match tokio::time::timeout(
        gateway.request_body_timeout,
        payload.to_bytes_limited(gateway.max_request_bytes),
    )
    .await
    {
        Ok(Ok(Ok(body))) => body,
        Ok(Err(_)) => {
            return local_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                trace_id,
                "Request body exceeds the configured limit.",
                "request_too_large",
            );
        }
        Ok(Ok(Err(_))) => {
            return local_error(
                StatusCode::BAD_REQUEST,
                trace_id,
                "Request body could not be read.",
                "invalid_request_body",
            );
        }
        Err(_) => {
            return local_error(
                StatusCode::REQUEST_TIMEOUT,
                trace_id,
                "Request body exceeded the configured deadline.",
                "request_body_timeout",
            );
        }
    };
    let (content_type, has_multiple_content_types) =
        one_header(request.headers(), header::CONTENT_TYPE.as_str());
    let request_analytics = serde_json::from_slice::<RequestAnalytics>(&body);
    let request_parse_success = request_analytics.is_ok();
    let requested_streaming = request_analytics
        .as_ref()
        .ok()
        .and_then(|analytics| analytics.stream)
        .unwrap_or(false);
    let sampling = sampling_identity(&gateway, endpoint, request.headers(), &body, trace_id);
    let route_runtime = gateway.route_runtime();
    let decision = route_runtime.policy.decide(
        &RouteRequest {
            endpoint,
            body: &body,
            content_type,
            has_multiple_content_types,
            has_content_encoding: request.headers().contains_key(header::CONTENT_ENCODING),
            has_openai_beta: request.headers().contains_key("openai-beta"),
            query: request.query_string(),
            routing_cohort: &sampling.hmac_sha256,
        },
        Instant::now(),
    );
    let mut target = decision.target;
    let mut route_observation = RouteObservation::from_baseline_reason(decision.baseline_reason);
    if target == RouteTarget::Candidate
        && !route_runtime
            .candidate
            .as_ref()
            .is_some_and(|candidate| candidate.healthy.load(Ordering::Acquire))
    {
        target = RouteTarget::Baseline;
        route_observation = RouteObservation::Fallback {
            reason: RouteFallbackReason::CandidateUnhealthy,
        };
    }
    let mut candidate_permit = None;
    if target == RouteTarget::Candidate {
        let candidate = route_runtime
            .candidate
            .as_ref()
            .expect("active route has a candidate transport");
        match Arc::clone(&candidate.in_flight).try_acquire_owned() {
            Ok(permit) => candidate_permit = Some(permit),
            Err(_) => {
                target = RouteTarget::Baseline;
                route_observation = RouteObservation::Fallback {
                    reason: RouteFallbackReason::CandidateCapacity,
                };
            }
        }
    }
    let candidate_route = if target == RouteTarget::Candidate {
        decision.candidate
    } else {
        None
    };
    let (mut catalog, selected, request_capture, request_content_type, request_content_encoding) =
        if gateway.records.is_some() {
            let request_content_type = header_text(request.headers(), header::CONTENT_TYPE);
            let request_content_encoding = header_text(request.headers(), header::CONTENT_ENCODING);
            let capture_eligible = sampling.content_capture_allowed
                && capture_eligible(
                    &gateway,
                    traffic_key.capture_allowed,
                    request_content_type.as_deref(),
                    request.headers(),
                );
            let selected = capture_eligible
                && capture_selected(&sampling.hmac_sha256, gateway.capture.basis_points);
            let request_capture = selected.then(|| body.clone());
            let catalog = TraceCatalog {
                scope: gateway.scope.clone(),
                trace_id,
                occurred_at,
                endpoint: endpoint_name(endpoint).to_owned(),
                request_parse_success,
                streaming: requested_streaming,
                route_revision: decision.route_revision.to_owned(),
                route: route_observation,
                provider_status: None,
                error_class: None,
                ttft_ms: None,
                completion_ms: None,
                request_bytes: body.len() as u64,
                response_bytes: 0,
                sampler_id: CAPTURE_SAMPLER_ID.to_owned(),
                sampling_unit_kind: sampling.kind,
                sampling_unit_hmac_sha256: bytes_hex(&sampling.hmac_sha256),
                sampling_independence: sampling.independence,
                sampling_key_version: gateway.capture_sampling_key_version.clone(),
                previous_response_hmac_sha256: sampling
                    .previous_response_hmac_sha256
                    .as_ref()
                    .map(|digest| bytes_hex(digest)),
                capture_basis_points: gateway.capture.basis_points,
                capture_eligible,
                capture_selected: selected,
                capture_policy_version: (gateway.capture.mode == CaptureMode::WholeBodyAuthorized)
                    .then(|| gateway.capture.policy_version.clone()),
                rights_state: gateway.capture.rights_state.clone(),
                retention_until: selected
                    .then(|| occurred_at + TimeDelta::days(gateway.capture.retention_days)),
            };
            (
                Some(catalog),
                selected,
                request_capture,
                request_content_type,
                request_content_encoding,
            )
        } else {
            (None, false, None, None, None)
        };

    let baseline_headers = match upstream_request_headers(request.headers(), RouteTarget::Baseline)
    {
        Ok(headers) => headers,
        Err(_) => {
            finish_before_headers(&gateway, catalog, started, "invalid_request_headers");
            return routed_local_error(
                StatusCode::BAD_REQUEST,
                trace_id,
                "Request headers could not be forwarded.",
                "invalid_request_headers",
                &decision,
                target,
                candidate_route,
            );
        }
    };
    let candidate_headers = if target == RouteTarget::Candidate {
        match upstream_request_headers(request.headers(), RouteTarget::Candidate) {
            Ok(headers) => headers,
            Err(_) => {
                finish_before_headers(&gateway, catalog, started, "invalid_request_headers");
                return routed_local_error(
                    StatusCode::BAD_REQUEST,
                    trace_id,
                    "Request headers could not be forwarded.",
                    "invalid_request_headers",
                    &decision,
                    target,
                    candidate_route,
                );
            }
        }
    } else {
        baseline_headers.clone()
    };
    let upstream_started = Instant::now();
    let response_result = match target {
        RouteTarget::Baseline => {
            send_baseline_request(
                &gateway,
                endpoint,
                request.query_string(),
                baseline_headers.clone(),
                body.clone(),
                upstream_started,
            )
            .await
        }
        RouteTarget::Candidate => {
            let candidate = candidate_route.expect("candidate decision contains route evidence");
            match api_endpoint_url(candidate.endpoint, endpoint) {
                Ok(candidate_endpoint) => {
                    send_upstream_request(
                        &route_runtime
                            .candidate
                            .as_ref()
                            .expect("active route has a candidate transport")
                            .client,
                        candidate_endpoint,
                        candidate_headers,
                        body.clone(),
                        upstream_started,
                        gateway.upstream_total_timeout,
                    )
                    .await
                }
                Err(error) => Err(error),
            }
        }
    };
    let should_fallback = target == RouteTarget::Candidate
        && match response_result.as_ref() {
            Ok(response) => candidate_response_requires_fallback(response),
            Err(_) => true,
        };
    let response_result = if should_fallback {
        open_candidate_fuse(&route_runtime);
        std::mem::drop(candidate_permit.take());
        std::mem::drop(response_result);
        target = RouteTarget::Baseline;
        route_observation = RouteObservation::Fallback {
            reason: RouteFallbackReason::CandidateFailure,
        };
        if let Some(catalog) = catalog.as_mut() {
            catalog.route = route_observation;
            catalog.provider_status = None;
        }
        send_baseline_request(
            &gateway,
            endpoint,
            request.query_string(),
            baseline_headers,
            body,
            upstream_started,
        )
        .await
    } else {
        response_result
    };
    let response = match response_result {
        Ok(response) => response,
        Err(_) => {
            if target == RouteTarget::Candidate {
                open_candidate_fuse(&route_runtime);
            }
            let (message, code) = match target {
                RouteTarget::Baseline => ("OpenAI could not be reached.", "upstream_unavailable"),
                RouteTarget::Candidate => (
                    "The candidate could not be reached.",
                    "candidate_unavailable",
                ),
            };
            finish_before_headers(&gateway, catalog, started, code);
            return routed_local_error(
                StatusCode::BAD_GATEWAY,
                trace_id,
                message,
                code,
                &decision,
                target,
                candidate_route,
            );
        }
    };

    if response.status().is_redirection() {
        if target == RouteTarget::Candidate {
            open_candidate_fuse(&route_runtime);
        }
        if let Some(catalog) = catalog.as_mut() {
            catalog.provider_status = Some(response.status().as_u16());
        }
        finish_before_headers(&gateway, catalog, started, "upstream_redirect_rejected");
        return routed_local_error(
            StatusCode::BAD_GATEWAY,
            trace_id,
            "The selected provider returned an unsafe redirect.",
            "upstream_redirect_rejected",
            &decision,
            target,
            candidate_route,
        );
    }

    if target == RouteTarget::Candidate && candidate_health_failure(response.status()) {
        open_candidate_fuse(&route_runtime);
    }

    let Ok(status) = StatusCode::from_u16(response.status().as_u16()) else {
        if target == RouteTarget::Candidate {
            open_candidate_fuse(&route_runtime);
        }
        finish_before_headers(&gateway, catalog, started, "invalid_upstream_status");
        return routed_local_error(
            StatusCode::BAD_GATEWAY,
            trace_id,
            "The selected provider returned an invalid status.",
            "invalid_upstream_response",
            &decision,
            target,
            candidate_route,
        );
    };
    let Ok(response_headers) = downstream_response_headers(response.headers(), target) else {
        if target == RouteTarget::Candidate {
            open_candidate_fuse(&route_runtime);
        }
        finish_before_headers(&gateway, catalog, started, "invalid_upstream_headers");
        return routed_local_error(
            StatusCode::BAD_GATEWAY,
            trace_id,
            "The selected provider returned invalid headers.",
            "invalid_upstream_response",
            &decision,
            target,
            candidate_route,
        );
    };
    if let Some(catalog) = catalog.as_mut() {
        catalog.provider_status = Some(status.as_u16());
    }
    let (response_content_type, response_content_encoding) = if catalog.is_some() {
        (
            reqwest_header_text(response.headers(), reqwest::header::CONTENT_TYPE),
            reqwest_header_text(response.headers(), reqwest::header::CONTENT_ENCODING),
        )
    } else {
        (None, None)
    };
    let stream_protocol = response_content_type
        .as_deref()
        .filter(|content_type| is_event_stream_content_type(content_type))
        .map(|_| endpoint);
    if let Some(catalog) = catalog.as_mut() {
        catalog.streaming = stream_protocol.is_some();
    }

    let mut builder = HttpResponse::build(status);
    for (name, value) in response_headers {
        builder.append_header((name, value));
    }
    builder.insert_header((TRACE_ID_HEADER, trace_id.to_string()));
    builder.insert_header((
        CAPTURE_INTENT_HEADER,
        if gateway.records.is_none() {
            "unavailable"
        } else if selected {
            "selected"
        } else {
            "not_selected"
        },
    ));
    let stream_error_class = match target {
        RouteTarget::Baseline => "upstream_stream_error",
        RouteTarget::Candidate => "candidate_stream_error",
    };
    let mut downstream = builder.streaming(UpstreamBody {
        inner: Box::pin(response.bytes_stream()),
        _permit: permit,
        _candidate_permit: candidate_permit,
        stream_error_class,
        candidate_health: (target == RouteTarget::Candidate).then(|| {
            Arc::clone(
                &route_runtime
                    .candidate
                    .as_ref()
                    .expect("active route has a candidate transport")
                    .healthy,
            )
        }),
        recorder: catalog.map(|catalog| TraceRecorder {
            records: gateway.records.clone(),
            catalog: Some(catalog),
            started,
            first_byte: None,
            request: request_capture,
            request_content_type,
            request_content_encoding,
            response: Vec::new(),
            response_content_type,
            response_content_encoding,
            response_limit: gateway.capture.response_bytes,
            record_limit: gateway.capture.record_bytes,
            selected,
            oversized: false,
            stream_protocol,
            stream_terminal_seen: false,
            stream_terminal_tail: Vec::new(),
        }),
    });
    insert_route_headers(downstream.headers_mut(), &decision, target, candidate_route);
    downstream
}

async fn send_baseline_request(
    gateway: &Gateway,
    endpoint: RouteEndpoint,
    query: &str,
    headers: reqwest::header::HeaderMap,
    body: Bytes,
    started: Instant,
) -> Result<reqwest::Response> {
    let mut upstream = api_endpoint_url(&gateway.upstream_api_base, endpoint)?;
    if !query.is_empty() {
        upstream.set_query(Some(query));
    }
    send_upstream_request(
        &gateway.client,
        upstream,
        headers,
        body,
        started,
        gateway.upstream_total_timeout,
    )
    .await
}

async fn send_upstream_request(
    client: &reqwest::Client,
    endpoint: Url,
    headers: reqwest::header::HeaderMap,
    body: Bytes,
    started: Instant,
    total_timeout: Duration,
) -> Result<reqwest::Response> {
    let remaining = total_timeout
        .checked_sub(started.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .context("upstream total deadline elapsed")?;
    Ok(client
        .post(endpoint)
        .headers(headers)
        .body(body)
        .timeout(remaining)
        .send()
        .await?)
}

fn candidate_response_requires_fallback(response: &reqwest::Response) -> bool {
    response.status().is_redirection()
        || candidate_health_failure(response.status())
        || StatusCode::from_u16(response.status().as_u16()).is_err()
        || downstream_response_headers(response.headers(), RouteTarget::Candidate).is_err()
}

fn capture_eligible(
    gateway: &Gateway,
    capture_allowed: bool,
    content_type: Option<&str>,
    request_headers: &HeaderMap,
) -> bool {
    let (content_encoding, multiple_content_encodings) =
        one_header(request_headers, header::CONTENT_ENCODING.as_str());
    gateway.records.is_some()
        && capture_allowed
        && gateway.capture.mode == CaptureMode::WholeBodyAuthorized
        && gateway.capture.basis_points > 0
        && is_json_content_type(content_type)
        && !multiple_content_encodings
        && content_encoding.is_none_or(|value| {
            std::str::from_utf8(value).is_ok_and(|value| value.eq_ignore_ascii_case("identity"))
        })
}

fn endpoint_name(endpoint: RouteEndpoint) -> &'static str {
    match endpoint {
        RouteEndpoint::ChatCompletions => "chat_completions",
        RouteEndpoint::Responses => "responses",
    }
}

fn sampling_identity(
    gateway: &Gateway,
    endpoint: RouteEndpoint,
    headers: &HeaderMap,
    body: &[u8],
    request_id: Uuid,
) -> SamplingIdentity {
    let key = &gateway.capture_sampling_key;
    let previous_response_id = (endpoint == RouteEndpoint::Responses)
        .then(|| serde_json::from_slice::<ResponsesSessionHints<'_>>(body).ok())
        .flatten()
        .and_then(|hints| hints.previous_response_id.map(str::to_owned));
    let previous_response_hmac_sha256 = previous_response_id
        .as_deref()
        .filter(|value| valid_sampling_identifier(value.as_bytes()))
        .map(|value| {
            sampling_hmac(
                key,
                &gateway.scope,
                b"responses_previous_response",
                value.as_bytes(),
            )
        });

    let (session_id, multiple_session_ids) = one_header(headers, SESSION_ID_HEADER);
    let session_id = (!multiple_session_ids)
        .then_some(session_id)
        .flatten()
        .filter(|value| valid_sampling_identifier(value));
    let selected = match endpoint {
        RouteEndpoint::ChatCompletions => session_id.map(|value| {
            (
                SamplingUnitKind::ChatSessionHeader,
                SamplingIndependence::Independent,
                value.to_vec(),
            )
        }),
        RouteEndpoint::Responses => serde_json::from_slice::<ResponsesSessionHints<'_>>(body)
            .ok()
            .and_then(|hints| hints.conversation)
            .and_then(|raw| {
                serde_json::from_str::<String>(raw.get()).ok().or_else(|| {
                    serde_json::from_str::<ResponsesConversation<'_>>(raw.get())
                        .ok()
                        .map(|conversation| conversation.id.to_owned())
                })
            })
            .filter(|value| valid_sampling_identifier(value.as_bytes()))
            .map(|value| {
                (
                    SamplingUnitKind::ResponsesConversation,
                    SamplingIndependence::Independent,
                    value.into_bytes(),
                )
            })
            .or_else(|| {
                session_id.map(|value| {
                    (
                        SamplingUnitKind::ChatSessionHeader,
                        SamplingIndependence::Independent,
                        value.to_vec(),
                    )
                })
            }),
    };
    let content_capture_allowed = selected.is_some() || previous_response_id.is_none();

    let (kind, independence, hmac_sha256) = match selected {
        Some((kind, independence, identifier)) => (
            kind,
            independence,
            sampling_hmac(
                key,
                &gateway.scope,
                sampling_kind_domain(kind),
                identifier.as_ref(),
            ),
        ),
        None => (
            SamplingUnitKind::Request,
            SamplingIndependence::Uncertain,
            sampling_hmac(key, &gateway.scope, b"request", request_id.as_bytes()),
        ),
    };
    SamplingIdentity {
        kind,
        hmac_sha256,
        independence,
        previous_response_hmac_sha256,
        content_capture_allowed,
    }
}

fn valid_sampling_identifier(value: &[u8]) -> bool {
    (1..=1_024).contains(&value.len()) && !value.iter().any(u8::is_ascii_control)
}

fn sampling_kind_domain(kind: SamplingUnitKind) -> &'static [u8] {
    match kind {
        SamplingUnitKind::ChatSessionHeader => b"chat_session_header",
        SamplingUnitKind::ResponsesConversation => b"responses_conversation",
        SamplingUnitKind::Request => b"request",
    }
}

fn sampling_hmac(key: &ring::hmac::Key, scope: &Scope, kind: &[u8], identifier: &[u8]) -> [u8; 32] {
    let mut context = ring::hmac::Context::with_key(key);
    context.update(b"milk.capture-sampling.v1\0");
    context.update(scope.scope_id.as_bytes());
    context.update(b"\0");
    context.update(kind);
    context.update(b"\0");
    context.update(identifier);
    context
        .sign()
        .as_ref()
        .try_into()
        .expect("HMAC-SHA256 is 32 bytes")
}

fn capture_selected(digest: &[u8; 32], basis_points: u16) -> bool {
    let sample = u64::from_be_bytes(digest[..8].try_into().expect("SHA-256 has eight bytes"));
    capture_sample_selected(sample, basis_points)
}

fn capture_sample_selected(sample: u64, basis_points: u16) -> bool {
    if basis_points == 0 {
        return false;
    }
    if basis_points >= 10_000 {
        return true;
    }
    let threshold = u128::from(basis_points) * (u128::from(u64::MAX) + 1) / 10_000;
    u128::from(sample) < threshold
}

fn is_json_content_type(content_type: Option<&str>) -> bool {
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn is_event_stream_content_type(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("text/event-stream"))
}

fn finish_before_headers(
    gateway: &Gateway,
    catalog: Option<TraceCatalog>,
    started: Instant,
    error_class: &str,
) {
    let Some(mut catalog) = catalog else {
        return;
    };
    catalog.error_class = Some(error_class.to_owned());
    catalog.completion_ms = Some(duration_ms(started.elapsed()));
    if let Some(records) = &gateway.records {
        log_enqueue_failure(records.try_observe(catalog, CaptureState::Interrupted));
    }
}

fn duration_ms(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

fn log_enqueue_failure(result: EnqueueResult) {
    if result == EnqueueResult::Queued {
        return;
    }
    let dropped = DROPPED_CAPTURE_EVENTS
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    if dropped.is_power_of_two() {
        tracing::warn!(?result, dropped, "trace observations dropped");
    }
}

fn header_text(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn one_header<'a>(headers: &'a HeaderMap, name: &str) -> (Option<&'a [u8]>, bool) {
    let mut values = headers.get_all(name);
    let value = values.next().map(HeaderValue::as_bytes);
    (value, values.next().is_some())
}

fn reqwest_header_text(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn valid_outcome_key(headers: &HeaderMap, expected_id: Uuid, expected_sha256: &[u8; 32]) -> bool {
    let mut values = headers.get_all(OUTCOME_KEY_HEADER);
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(raw) = value.to_str() else {
        return false;
    };
    let Some(value) = raw.strip_prefix("milk_live_") else {
        return false;
    };
    let Some((key_id, secret)) = value.split_once('_') else {
        return false;
    };
    let Ok(key_id) = Uuid::parse_str(key_id) else {
        return false;
    };
    if key_id != expected_id
        || !(16..=256).contains(&secret.len())
        || !secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
    {
        return false;
    }
    let actual = Sha256::digest(raw.as_bytes());
    actual.as_slice().ct_eq(expected_sha256).into()
}

fn authenticate_traffic_key<'a>(
    headers: &HeaderMap,
    configured: &'a [TrafficKey],
) -> Option<&'a TrafficKey> {
    let mut values = headers.get_all(header::AUTHORIZATION);
    let raw = values.next()?.to_str().ok()?.strip_prefix("Bearer ")?;
    if values.next().is_some() || !valid_traffic_key(raw) {
        return None;
    }
    let actual: [u8; 32] = Sha256::digest(raw.as_bytes()).into();
    let mut authenticated = None;
    for key in configured {
        if key.api_key_sha256.ct_eq(&actual).unwrap_u8() == 1 {
            authenticated = Some(key);
        }
    }
    authenticated
}

fn valid_traffic_key(raw: &str) -> bool {
    let Some(value) = raw.strip_prefix("milk_live_") else {
        return false;
    };
    let Some((key_id, secret)) = value.split_once('_') else {
        return false;
    };
    Uuid::parse_str(key_id).is_ok_and(|value| !value.is_nil())
        && (16..=256).contains(&secret.len())
        && secret
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~'))
}

fn configured_traffic_keys(values: &[TrafficKeyConfig]) -> Result<Vec<TrafficKey>> {
    if values.is_empty() || values.len() > MAX_TRAFFIC_KEYS {
        bail!("traffic_keys must contain 1..={MAX_TRAFFIC_KEYS} entries");
    }
    let mut hashes = HashSet::with_capacity(values.len());
    let mut configured = Vec::with_capacity(values.len());
    for value in values {
        let sha256 = decode_lowercase_sha256(&value.api_key_sha256)?;
        if !hashes.insert(sha256) {
            bail!("traffic_keys contains a duplicate API-key SHA-256");
        }
        configured.push(TrafficKey {
            api_key_sha256: sha256,
            capture_allowed: value.capture_allowed,
        });
    }
    Ok(configured)
}

fn upstream_request_headers(
    headers: &HeaderMap,
    target: RouteTarget,
) -> Result<reqwest::header::HeaderMap> {
    let stripped = stripped_headers(headers);
    let mut forwarded = reqwest::header::HeaderMap::new();
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if stripped.contains(&lower)
            || lower.starts_with("x-milk-")
            || lower == SESSION_ID_HEADER
            || matches!(
                lower.as_str(),
                "authorization" | "openai-organization" | "openai-project"
            )
            || (target == RouteTarget::Candidate && lower == "openai-beta")
            || !allowed_upstream_request_header(&lower)
        {
            continue;
        }
        let name = reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes())?;
        let value = reqwest::header::HeaderValue::from_bytes(value.as_bytes())?;
        forwarded.append(name, value);
    }
    forwarded.insert(
        reqwest::header::ACCEPT_ENCODING,
        reqwest::header::HeaderValue::from_static("identity"),
    );
    Ok(forwarded)
}

fn allowed_upstream_request_header(name: &str) -> bool {
    matches!(
        name,
        "accept"
            | "content-encoding"
            | "content-type"
            | "openai-beta"
            | "user-agent"
            | "x-client-request-id"
    ) || name.starts_with("x-stainless-")
}

fn downstream_response_headers(
    headers: &reqwest::header::HeaderMap,
    target: RouteTarget,
) -> Result<Vec<(HeaderName, HeaderValue)>> {
    let stripped = stripped_reqwest_headers(headers);
    let mut forwarded = Vec::new();
    for (name, value) in headers {
        let lower = name.as_str().to_ascii_lowercase();
        if stripped.contains(&lower)
            || lower.starts_with("x-milk-")
            || (target == RouteTarget::Candidate
                && (lower.starts_with("openai-") || lower.starts_with("x-openai-")))
            || !allowed_downstream_response_header(&lower)
        {
            continue;
        }
        forwarded.push((
            HeaderName::try_from(name.as_str())?,
            HeaderValue::from_bytes(value.as_bytes())?,
        ));
    }
    Ok(forwarded)
}

fn allowed_downstream_response_header(name: &str) -> bool {
    matches!(
        name,
        "cache-control"
            | "content-encoding"
            | "content-length"
            | "content-type"
            | "etag"
            | "retry-after"
            | "vary"
            | "www-authenticate"
            | "x-request-id"
            | "x-should-retry"
    ) || name.starts_with("openai-")
        || name.starts_with("x-openai-")
        || name.starts_with("x-ratelimit-")
}

fn stripped_headers(headers: &HeaderMap) -> HashSet<String> {
    let mut stripped = hop_by_hop_headers();
    stripped.insert("content-length".to_owned());
    stripped.insert("host".to_owned());
    for value in headers.get_all(header::CONNECTION) {
        extend_connection_tokens(&mut stripped, value.as_bytes());
    }
    stripped
}

fn stripped_reqwest_headers(headers: &reqwest::header::HeaderMap) -> HashSet<String> {
    let mut stripped = hop_by_hop_headers();
    for value in headers.get_all(reqwest::header::CONNECTION) {
        extend_connection_tokens(&mut stripped, value.as_bytes());
    }
    stripped
}

fn hop_by_hop_headers() -> HashSet<String> {
    [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn extend_connection_tokens(stripped: &mut HashSet<String>, value: &[u8]) {
    let Ok(value) = std::str::from_utf8(value) else {
        return;
    };
    for token in value.split(',') {
        let token = token.trim();
        if !token.is_empty() {
            stripped.insert(token.to_ascii_lowercase());
        }
    }
}

fn candidate_health_failure(status: reqwest::StatusCode) -> bool {
    matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED
            | reqwest::StatusCode::FORBIDDEN
            | reqwest::StatusCode::NOT_FOUND
            | reqwest::StatusCode::REQUEST_TIMEOUT
            | reqwest::StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

fn open_candidate_fuse(runtime: &RouteRuntime) {
    if let Some(candidate) = &runtime.candidate {
        candidate.healthy.store(false, Ordering::Release);
    }
}

fn routed_local_error(
    status: StatusCode,
    trace_id: Uuid,
    message: &'static str,
    code: &'static str,
    decision: &RouteDecision<'_>,
    target: RouteTarget,
    candidate: Option<CandidateRoute<'_>>,
) -> HttpResponse {
    let mut response = local_error(status, trace_id, message, code);
    insert_route_headers(response.headers_mut(), decision, target, candidate);
    response
}

fn insert_route_headers(
    headers: &mut HeaderMap,
    decision: &RouteDecision<'_>,
    target: RouteTarget,
    candidate: Option<CandidateRoute<'_>>,
) {
    let target = match target {
        RouteTarget::Baseline => "openai",
        RouteTarget::Candidate => "candidate",
    };
    headers.insert(
        HeaderName::from_static(ROUTE_REVISION_HEADER),
        HeaderValue::from_bytes(decision.route_revision.as_bytes())
            .expect("validated route revision is an HTTP header value"),
    );
    headers.insert(
        HeaderName::from_static(ROUTE_TARGET_HEADER),
        HeaderValue::from_static(target),
    );
    if let Some(candidate) = candidate {
        for (name, value) in [
            (CANDIDATE_SHA256_HEADER, candidate.candidate_sha256),
            (ARTIFACT_SHA256_HEADER, candidate.artifact_sha256),
            (DEPLOYMENT_SHA256_HEADER, candidate.deployment_sha256),
        ] {
            headers.insert(
                HeaderName::from_static(name),
                HeaderValue::from_bytes(value.as_bytes())
                    .expect("validated candidate identity is an HTTP header value"),
            );
        }
    }
}

fn local_error(
    status: StatusCode,
    trace_id: Uuid,
    message: &'static str,
    code: &'static str,
) -> HttpResponse {
    HttpResponse::build(status)
        .insert_header((header::CONTENT_TYPE, "application/json"))
        .insert_header((TRACE_ID_HEADER, trace_id.to_string()))
        .insert_header((ERROR_SOURCE_HEADER, "gateway"))
        .json(ErrorEnvelope {
            error: ErrorBody {
                message,
                r#type: "invalid_request_error",
                param: None,
                code,
            },
        })
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 || !value.is_ascii() {
        bail!("SHA-256 must contain 64 hexadecimal characters");
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .context("SHA-256 contains non-hexadecimal characters")?;
    }
    Ok(decoded)
}

fn decode_lowercase_sha256(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("sha256 must be exactly 64 lowercase hexadecimal characters");
    }
    decode_sha256(value)
}

#[cfg(test)]
mod proxy_tests;

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::{CommandFactory, error::ErrorKind};
    use std::ffi::OsString;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::Mutex;

    static STORE_ENVIRONMENT_LOCK: Mutex<()> = Mutex::new(());

    struct EnvironmentRestore(Vec<(&'static str, Option<OsString>)>);

    impl EnvironmentRestore {
        fn set(values: &[(&'static str, Option<&str>)]) -> Self {
            let previous = values
                .iter()
                .map(|(key, _)| (*key, std::env::var_os(key)))
                .collect();
            for (key, value) in values {
                match value {
                    Some(value) => unsafe { std::env::set_var(key, value) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
            Self(previous)
        }
    }

    impl Drop for EnvironmentRestore {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(value) => unsafe { std::env::set_var(key, value) },
                    None => unsafe { std::env::remove_var(key) },
                }
            }
        }
    }

    const REMOVED_COMMANDS: [&str; 47] = [
        "serve-agent",
        "commit-agent-run-lease",
        "verify-agent-run-lease",
        "reconcile",
        "expire",
        "stats",
        "freeze-snapshot-batch",
        "analyze-snapshot-batch",
        "verify-snapshot-analysis",
        "assess-iteration",
        "freeze-release",
        "verify-release",
        "export-release-manifest",
        "verify-analysis",
        "commit-dev-workload-labels",
        "verify-dev-workload-labels",
        "export-dev-workload-labels",
        "export-dev-eval",
        "export-train-curriculum",
        "export-quantization-calibration",
        "prepare-distillation-run",
        "claim-distillation-run",
        "ingest-distillation-run",
        "prepare-adapter-train",
        "claim-adapter-train",
        "ingest-adapter-train",
        "prepare-adapter-merge",
        "claim-adapter-merge",
        "ingest-adapter-merge",
        "prepare-quantization-run",
        "claim-quantization-run",
        "ingest-quantization-run",
        "materialize-adapter-train-candidate",
        "export-adapter-s3-deployment-plan",
        "commit-candidate",
        "verify-candidate",
        "commit-deployment",
        "qualify-candidate",
        "verify-deployment",
        "evaluate-sealed",
        "verify-sealed-gate",
        "benchmark-candidate",
        "analyze-release",
        "approve-analysis",
        "ingest-student-execution",
        "prepare-modal-candidate-credential",
        "ingest-modal-candidate-credential-ack",
    ];

    fn local_example_config(directory: &Path) -> String {
        for name in ["capture", "control", "routes"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(directory.join(name))
                .unwrap();
        }
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/milk-carton-config.example.json"
        ))
        .replace("/var/lib/milk-carton", directory.to_str().unwrap())
    }

    fn s3_store(bucket: &str) -> ObjectStoreConfig {
        ObjectStoreConfig::S3 {
            endpoint: "https://example.r2.cloudflarestorage.com".to_owned(),
            region: "auto".to_owned(),
            bucket: bucket.to_owned(),
        }
    }

    #[test]
    fn public_help_exposes_serve_tick_and_status() {
        let help = Cli::command().render_long_help().to_string();
        assert!(help.contains("\n  serve"));
        assert!(help.contains("\n  tick"));
        assert!(help.contains("\n  status"));
        for hidden in [
            "generation-status",
            "materialize-student-job",
            "materialize-student-winner",
            "ingest-student-train-execution",
            "materialize-student-branch",
            "ingest-student-branch-execution",
            "advance-winner-route",
            "prepare-route",
            "prepare-route-proposal",
            "publish-route",
        ] {
            assert!(!help.contains(hidden), "hidden command leaked: {hidden}");
        }
        for removed in REMOVED_COMMANDS {
            assert!(!help.contains(removed), "removed command leaked: {removed}");
        }
    }

    #[test]
    fn removed_commands_are_rejected() {
        for removed in REMOVED_COMMANDS {
            let error =
                Cli::try_parse_from(["milk-carton", "--config", "/tmp/config.json", removed])
                    .unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::InvalidSubcommand,
                "obsolete command was retained: {removed}"
            );
        }
    }

    #[test]
    fn retained_commands_parse_with_exact_inputs() {
        let inline_serve = Cli::try_parse_from(["milk-carton", "serve"]).unwrap();
        assert!(inline_serve.config.is_none());
        assert!(matches!(inline_serve.command, Some(Command::Serve)));

        let prefix = ["milk-carton", "--config", "/tmp/config.json"];
        assert!(matches!(
            Cli::try_parse_from([prefix[0], prefix[1], prefix[2], "serve"])
                .unwrap()
                .command,
            Some(Command::Serve)
        ));
        assert!(Cli::try_parse_from([prefix[0], prefix[1], prefix[2], "tick"]).is_err());
        assert!(matches!(
            Cli::try_parse_from([prefix[0], prefix[1], prefix[2], "tick", "--once"])
                .unwrap()
                .command,
            Some(Command::Tick { once: true })
        ));
        assert!(matches!(
            Cli::try_parse_from([prefix[0], prefix[1], prefix[2], "status"])
                .unwrap()
                .command,
            Some(Command::Status)
        ));
        assert!(matches!(
            Cli::try_parse_from([prefix[0], prefix[1], prefix[2], "generation-status"])
                .unwrap()
                .command,
            Some(Command::GenerationStatus)
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "materialize-student-job",
                "--student-job-id",
                &"a".repeat(64),
                "--stage-dir",
                "/run/milk-carton/job",
            ])
            .unwrap()
            .command,
            Some(Command::MaterializeStudentJob { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "materialize-student-winner",
                "--student-job-id",
                &"b".repeat(64),
                "--stage-dir",
                "/run/milk-carton/winner",
            ])
            .unwrap()
            .command,
            Some(Command::MaterializeStudentWinner { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "ingest-student-train-execution",
                "--result",
                "/run/milk-carton/train-result.json",
                "--upload",
                "/run/milk-carton/upload.json",
                "--artifact-dir",
                "/run/milk-carton/artifacts",
            ])
            .unwrap()
            .command,
            Some(Command::IngestStudentTrainExecution { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "materialize-student-branch",
                "--student-job-id",
                &"d".repeat(64),
                "--variant",
                "static_fp8",
                "--stage-dir",
                "/run/milk-carton/branch",
            ])
            .unwrap()
            .command,
            Some(Command::MaterializeStudentBranch { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "ingest-student-branch-execution",
                "--result",
                "/run/milk-carton/branch-result.json",
                "--upload",
                "/run/milk-carton/upload.json",
                "--artifact-dir",
                "/run/milk-carton/artifacts",
            ])
            .unwrap()
            .command,
            Some(Command::IngestStudentBranchExecution { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "ingest-student-winner-deployment-result",
                "--result",
                "/run/milk-carton/winner-deployment-result.json",
            ])
            .unwrap()
            .command,
            Some(Command::IngestStudentWinnerDeploymentResult { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "ingest-provider-teardown-result",
                "--result",
                "/run/milk-carton/provider-teardown-result.json",
            ])
            .unwrap()
            .command,
            Some(Command::IngestProviderTeardownResult { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "advance-winner-route",
                "--student-job-id",
                &"c".repeat(64),
                "--phase",
                "canary",
                "--manifest",
                "/run/milk-carton/route.json",
            ])
            .unwrap()
            .command,
            Some(Command::AdvanceWinnerRoute {
                phase: WinnerRoutePhase::Canary,
                ..
            })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "prepare-route",
                "--student-job-id",
                &"c".repeat(64),
                "--manifest",
                "/run/milk-carton/route.json",
            ])
            .unwrap()
            .command,
            Some(Command::PrepareRoute { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "prepare-route-proposal",
                "--proposal",
                "/run/milk-carton/route-proposal.json",
                "--manifest",
                "/run/milk-carton/route.json",
            ])
            .unwrap()
            .command,
            Some(Command::PrepareRouteProposal { .. })
        ));
        assert!(matches!(
            Cli::try_parse_from([
                prefix[0],
                prefix[1],
                prefix[2],
                "publish-route",
                "--manifest",
                "/run/milk-carton/route.json",
                "--check-only",
            ])
            .unwrap()
            .command,
            Some(Command::PublishRoute {
                check_only: true,
                ..
            })
        ));
    }

    #[test]
    fn winner_route_advance_output_is_strict_and_content_free() {
        let output = WinnerRouteAdvanceWrite {
            schema_version: "milk.winner-route-advance.v1",
            action: WinnerRouteAdvanceAction::Observe,
            route_revision: "a".repeat(64),
            not_after: "2026-08-25T12:15:00Z".parse().unwrap(),
        };
        assert_eq!(
            serde_json::to_string(&output).unwrap(),
            format!(
                r#"{{"schema_version":"milk.winner-route-advance.v1","action":"observe","route_revision":"{}","not_after":"2026-08-25T12:15:00Z"}}"#,
                "a".repeat(64)
            )
        );
    }

    #[test]
    fn route_publication_is_strictly_two_phase() {
        let base = [
            "milk-carton",
            "--config",
            "/tmp/config.json",
            "publish-route",
            "--manifest",
            "/tmp/route.json",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        let mut signed = base.to_vec();
        signed.extend(["--signature", "/tmp/route.sig"]);
        assert!(matches!(
            Cli::try_parse_from(signed).unwrap().command,
            Some(Command::PublishRoute {
                check_only: false,
                ..
            })
        ));
        let mut conflict = base.to_vec();
        conflict.extend(["--signature", "/tmp/route.sig", "--check-only"]);
        assert!(Cli::try_parse_from(conflict).is_err());
    }

    #[test]
    fn only_serve_uses_deployment_config_permissions() {
        assert!(command_uses_deployment_config(None));
        assert!(command_uses_deployment_config(Some(&Command::Serve)));
        assert!(!command_uses_deployment_config(Some(&Command::Tick {
            once: true,
        })));
        assert!(!command_uses_deployment_config(Some(
            &Command::GenerationStatus
        )));
    }

    #[test]
    fn commands_receive_only_their_store_authority() {
        use StoreAccess::{ReadOnly, ReadWrite};
        assert_eq!(
            StoreAccessPlan::for_command(&Command::Serve),
            StoreAccessPlan {
                capture: Some(ReadWrite),
                control: None,
                routes: Some(ReadOnly),
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::Tick { once: true }),
            StoreAccessPlan {
                capture: Some(ReadWrite),
                control: Some(ReadWrite),
                routes: None,
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::Status),
            StoreAccessPlan {
                capture: Some(ReadOnly),
                control: None,
                routes: Some(ReadOnly),
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::GenerationStatus),
            StoreAccessPlan {
                capture: Some(ReadOnly),
                control: Some(ReadOnly),
                routes: None,
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::PrepareRoute {
                student_job_id: "a".repeat(64),
                rollback: false,
                reasoning_effort: None,
                manifest: "/tmp/manifest".into(),
            }),
            StoreAccessPlan {
                capture: None,
                control: Some(ReadOnly),
                routes: Some(ReadOnly),
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::AdvanceWinnerRoute {
                student_job_id: "a".repeat(64),
                phase: WinnerRoutePhase::Zero,
                manifest: "/tmp/manifest".into(),
            }),
            StoreAccessPlan {
                capture: None,
                control: Some(ReadOnly),
                routes: Some(ReadOnly),
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::PrepareRouteProposal {
                proposal: "/tmp/proposal".into(),
                manifest: "/tmp/manifest".into(),
            }),
            StoreAccessPlan {
                capture: None,
                control: None,
                routes: Some(ReadOnly),
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::PublishRoute {
                manifest: "/tmp/manifest".into(),
                signature: Some("/tmp/signature".into()),
                check_only: false,
            }),
            StoreAccessPlan {
                capture: None,
                control: Some(ReadWrite),
                routes: Some(ReadWrite),
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::PublishRoute {
                manifest: "/tmp/manifest".into(),
                signature: None,
                check_only: true,
            }),
            StoreAccessPlan {
                capture: None,
                control: Some(ReadOnly),
                routes: Some(ReadOnly),
            }
        );
        assert_eq!(
            StoreAccessPlan::for_command(&Command::IngestProviderTeardownResult {
                result: "/tmp/teardown.json".into(),
            }),
            StoreAccessPlan {
                capture: None,
                control: Some(ReadWrite),
                routes: Some(ReadOnly),
            }
        );
    }

    #[test]
    fn one_s3_bucket_can_back_all_store_roles() {
        let mut config: FileConfig = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/milk-carton-config.example.json"
        )))
        .unwrap();
        let shared = s3_store("milk-pilot-test");
        config.stores = StoresConfig {
            capture: shared.clone(),
            control: shared.clone(),
            routes: shared,
        };

        validate_config_identity(&config).unwrap();
        assert_eq!(config.stores.capture, config.stores.control);
        assert_eq!(config.stores.control, config.stores.routes);
    }

    #[test]
    fn s3_store_config_is_explicit() {
        let parsed: ObjectStoreConfig = serde_json::from_str(
            r#"{"type":"s3","endpoint":"https://objects.example.com","region":"us-east-1","bucket":"milk-test"}"#,
        )
        .unwrap();
        assert_eq!(
            parsed,
            ObjectStoreConfig::S3 {
                endpoint: "https://objects.example.com".to_owned(),
                region: "us-east-1".to_owned(),
                bucket: "milk-test".to_owned(),
            }
        );
        assert!(
            serde_json::from_str::<ObjectStoreConfig>(
                r#"{"type":"cloudflare_r2","account_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bucket":"milk-test"}"#,
            )
            .is_err()
        );
    }

    #[test]
    fn serve_opens_capture_and_routes_without_control_credentials() {
        let _lock = STORE_ENVIRONMENT_LOCK.lock().unwrap();
        let _restore = EnvironmentRestore::set(&[
            ("MILK_CAPTURE_STORE_ACCESS_KEY_ID", Some("capture-access")),
            (
                "MILK_CAPTURE_STORE_SECRET_ACCESS_KEY",
                Some("capture-secret"),
            ),
            ("MILK_CAPTURE_STORE_SESSION_TOKEN", None),
            ("MILK_ROUTE_STORE_ACCESS_KEY_ID", Some("route-access")),
            ("MILK_ROUTE_STORE_SECRET_ACCESS_KEY", Some("route-secret")),
            ("MILK_ROUTE_STORE_SESSION_TOKEN", None),
            ("MILK_CONTROL_STORE_ACCESS_KEY_ID", Some("")),
            ("MILK_CONTROL_STORE_SECRET_ACCESS_KEY", Some("")),
            ("MILK_CONTROL_STORE_SESSION_TOKEN", Some("")),
        ]);
        let mut config: FileConfig = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../deploy/milk-carton-config.example.json"
        )))
        .unwrap();
        config.stores = StoresConfig {
            capture: s3_store("milk-capture-test"),
            control: s3_store("milk-control-test"),
            routes: s3_store("milk-routes-test"),
        };
        let plan = StoreAccessPlan::for_command(&Command::Serve);
        assert_eq!(plan.control, None);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(open_records(&config, plan, false))
            .unwrap();
    }

    #[test]
    fn inline_config_is_bounded_exclusive_and_serve_only() {
        let directory = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("milk-carton-inline-config-test-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let config_json = local_example_config(&directory);
        let config_bytes = config_json.as_bytes();
        let selected = load_selected_config(None, Some(config_bytes), None).unwrap();
        assert_eq!(selected.sha256, Sha256::digest(config_bytes).as_slice());
        load_selected_config(None, Some(config_bytes), Some(&Command::Serve)).unwrap();

        let both = load_selected_config(
            Some(Path::new("/does/not/exist")),
            Some(config_bytes),
            Some(&Command::Serve),
        )
        .unwrap_err()
        .to_string();
        assert!(both.contains("mutually exclusive"));
        assert!(
            load_selected_config(None, None, Some(&Command::Serve))
                .unwrap_err()
                .to_string()
                .contains("is required")
        );
        assert!(
            load_selected_config(
                None,
                Some(config_bytes),
                Some(&Command::Tick { once: true })
            )
            .unwrap_err()
            .to_string()
            .contains("only accepted by serve")
        );
        assert!(
            load_selected_config(
                None,
                Some(config_bytes),
                Some(&Command::MaterializeStudentJob {
                    student_job_id: "a".repeat(64),
                    stage_dir: PathBuf::from("/tmp/stage"),
                })
            )
            .unwrap_err()
            .to_string()
            .contains("only accepted by serve")
        );
        assert!(
            load_selected_config(
                None,
                Some(&vec![b' '; MAX_CONFIG_BYTES + 1]),
                Some(&Command::Serve)
            )
            .unwrap_err()
            .to_string()
            .contains("exceeds")
        );

        let trimmed = config_json.trim_end();
        let unknown = format!("{},\"unknown\":true}}", trimmed.strip_suffix('}').unwrap());
        assert!(
            load_selected_config(None, Some(unknown.as_bytes()), Some(&Command::Serve))
                .unwrap_err()
                .to_string()
                .contains("invalid MILK_CARTON_CONFIG_JSON")
        );
        let legacy = config_json.replacen("\"stores\"", "\"object_store\"", 1);
        assert!(
            load_selected_config(None, Some(legacy.as_bytes()), Some(&Command::Serve))
                .unwrap_err()
                .to_string()
                .contains("invalid MILK_CARTON_CONFIG_JSON")
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn local_serve_and_operator_commands_load_private_config() {
        let directory = fs::canonicalize(std::env::temp_dir())
            .unwrap()
            .join(format!("milk-carton-local-config-test-{}", Uuid::now_v7()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let config_path = directory.join("gateway.json");
        let config_json = local_example_config(&directory);
        fs::write(&config_path, &config_json).unwrap();
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600)).unwrap();

        load_config(&config_path, Some(&Command::Serve)).unwrap();
        assert!(
            load_config(&config_path, Some(&Command::Tick { once: true }))
                .unwrap_err()
                .to_string()
                .contains("requires teacher GPU job configuration")
        );
        load_config(
            &config_path,
            Some(&Command::MaterializeStudentJob {
                student_job_id: "a".repeat(64),
                stage_dir: PathBuf::from("/tmp/stage"),
            }),
        )
        .unwrap();

        let mut config: FileConfig = serde_json::from_str(&config_json).unwrap();
        config.listen = "0.0.0.0:8080".parse().unwrap();
        assert!(validate_serve_config_owner(&config, InputOwner::CurrentPrivate).is_err());
        validate_serve_config_owner(&config, InputOwner::RootDeployment).unwrap();
        config.listen = "127.0.0.1:8080".parse().unwrap();
        config.stores.capture = s3_store("milk-carton-test");
        assert!(validate_serve_config_owner(&config, InputOwner::CurrentPrivate).is_err());
        validate_serve_config_owner(&config, InputOwner::RootDeployment).unwrap();

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn operator_input_rejects_unsafe_files_and_detects_rewrites() {
        let directory = std::env::temp_dir().join(format!(
            "milk-carton-operator-input-test-{}",
            Uuid::now_v7()
        ));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("input.json");
        fs::write(&path, b"one\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o622)).unwrap();
        assert!(OperatorInput::open(&path, 16, "test input").is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(OperatorInput::open(&path, 3, "test input").is_err());
        assert!(
            OperatorInput::open_for_owner(
                &path,
                16,
                "deployment input",
                InputOwner::RootDeployment,
            )
            .is_err()
        );
        let link = directory.join("link.json");
        symlink(&path, &link).unwrap();
        assert!(OperatorInput::open(&link, 16, "test input").is_err());
        let mut input = OperatorInput::open(&path, 16, "test input").unwrap();
        fs::write(&path, b"two\n").unwrap();
        assert!(input.reread_unchanged().is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn private_output_is_create_only_and_exactly_0400() {
        let directory = std::env::temp_dir().join(format!(
            "milk-carton-private-output-test-{}",
            Uuid::now_v7()
        ));
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("route.json");
        write_private_output(&path, b"canonical", "test output").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"canonical");
        assert_eq!(fs::symlink_metadata(&path).unwrap().mode() & 0o7777, 0o400);
        assert!(write_private_output(&path, b"replacement", "test output").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"canonical");
        fs::remove_dir_all(directory).unwrap();
    }
}
