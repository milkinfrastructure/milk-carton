use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::net::TcpListener;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt, symlink};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::dev::{Server, ServerHandle};
use actix_web::{App, HttpRequest, HttpResponse, HttpServer, web};
use bytes::Bytes;
use chrono::{TimeDelta, Timelike, Utc};
use futures::{StreamExt, stream};
use object_store::ObjectStore;
use object_store::memory::InMemory;
use reqwest::redirect::Policy;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Notify, oneshot};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

use super::{
    CANDIDATE_API_KEY_SHA256_HEADER, CANDIDATE_CREDENTIAL_PATH, CANDIDATE_CREDENTIAL_STATE_HEADER,
    CONFIG_SHA256_HEADER, CaptureMode, Command, FileConfig, Gateway, ObjectStoreConfig,
    OpenAiCompatibleEndpoint, OutcomeKind, StoreAccessPlan, StoresConfig, TeacherConfig,
    TraceRecorder, TrafficKeyConfig, TrafficKeyRevocationConfig, authenticate_traffic_key,
    build_route_runtime, build_server, candidate_health_failure, capture_sample_selected,
    config_scope, configured_traffic_keys, decode_lowercase_sha256, generation_status_once,
    is_json_content_type, parse_openai_compatible_api_base_url, parse_openai_compatible_endpoint,
    records_sampling_key_version, sampling_identity, start_records, start_records_with_timeout,
    status_once, tick_once_with_records, validate_config_for_command, validate_config_identity,
    validate_teacher_config,
};
use crate::records::{
    CAPTURE_SAMPLER_ID, Records, RouteBlockReason, RouteObservation, SamplingIndependence,
    SamplingUnitKind, Scope, SnapshotAnalyzerExecution, SnapshotAnalyzerReasoningEffort,
    TraceCapture, TraceCatalog,
};
use crate::route::{RouteEndpoint, RoutePolicy, RouteStartupConfig};

const OUTCOME_KEY_ID: &str = "018f3f54-7a5b-7cc0-8000-000000000002";
const KEY: &str = "milk_live_018f3f54-7a5b-7cc0-8000-000000000001_test-secret-0001";
const SMOKE_KEY: &str = "milk_live_018f3f54-7a5b-7cc0-8000-000000000003_test-smoke-secret-0003";
const SESSION_ID: &str = "production-test-session";
const OUTCOME_KEY: &str = "milk_live_018f3f54-7a5b-7cc0-8000-000000000002_test-outcome-secret-0002";
const CANDIDATE_KEY: &str = "candidate-test-secret";

fn traffic_key(raw: &str, scope_id: Uuid, capture_allowed: bool) -> TrafficKeyConfig {
    let key_id = raw
        .strip_prefix("milk_live_")
        .and_then(|value| value.split_once('_'))
        .map(|(key_id, _)| key_id)
        .unwrap()
        .parse()
        .unwrap();
    TrafficKeyConfig {
        key_id,
        api_key_sha256: format!("{:x}", Sha256::digest(raw.as_bytes())),
        scope_id,
        capture_allowed,
        revocation: None,
    }
}

fn local_stores(root: &Path) -> StoresConfig {
    let create = |name: &str| {
        let path = root.join(name);
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        ObjectStoreConfig::Local { root: path }
    };
    StoresConfig {
        capture: create("capture"),
        control: create("control"),
        routes: create("routes"),
    }
}

fn s3_store(bucket: &str) -> ObjectStoreConfig {
    ObjectStoreConfig::S3 {
        endpoint: "https://example.r2.cloudflarestorage.com".to_owned(),
        region: "auto".to_owned(),
        bucket: bucket.to_owned(),
    }
}

#[test]
fn digest_requires_exact_lowercase_hex() {
    assert!(decode_lowercase_sha256(&"a".repeat(64)).is_ok());
    assert!(decode_lowercase_sha256(&"A".repeat(64)).is_err());
    assert!(decode_lowercase_sha256(&"g".repeat(64)).is_err());
    assert!(decode_lowercase_sha256(&"a".repeat(63)).is_err());
}

#[test]
fn candidate_fuse_status_contract_covers_every_server_error() {
    for status in 500..=599 {
        assert!(candidate_health_failure(
            reqwest::StatusCode::from_u16(status).unwrap()
        ));
    }
    for status in [401, 403, 404, 408, 429] {
        assert!(candidate_health_failure(
            reqwest::StatusCode::from_u16(status).unwrap()
        ));
    }
    for status in [400, 409, 422] {
        assert!(!candidate_health_failure(
            reqwest::StatusCode::from_u16(status).unwrap()
        ));
    }
}

#[test]
fn traffic_authentication_returns_only_capture_authority() {
    let scope_id = Uuid::new_v4();
    let configured = configured_traffic_keys(&[
        traffic_key(KEY, scope_id, true),
        traffic_key(SMOKE_KEY, scope_id, false),
    ])
    .unwrap();
    let mut headers = actix_web::http::header::HeaderMap::new();
    headers.insert(
        actix_web::http::header::AUTHORIZATION,
        actix_web::http::header::HeaderValue::from_str(&format!("Bearer {KEY}")).unwrap(),
    );
    headers.insert(
        actix_web::http::header::HeaderName::from_static("x-milk-route-unit"),
        actix_web::http::header::HeaderValue::from_static("caller-choice"),
    );
    let authenticated = authenticate_traffic_key(&headers, &configured).unwrap();
    assert_eq!(authenticated.key_id.to_string(), &KEY[10..46]);
    assert_eq!(authenticated.scope.scope_id, scope_id);
    assert!(authenticated.capture_allowed);
    headers.insert(
        actix_web::http::header::AUTHORIZATION,
        actix_web::http::header::HeaderValue::from_str(&format!("Bearer {SMOKE_KEY}")).unwrap(),
    );
    let authenticated = authenticate_traffic_key(&headers, &configured).unwrap();
    assert!(!authenticated.capture_allowed);

    let mut wrong_id = traffic_key(KEY, scope_id, true);
    wrong_id.key_id = configured[1].key_id;
    headers.insert(
        actix_web::http::header::AUTHORIZATION,
        actix_web::http::header::HeaderValue::from_str(&format!("Bearer {KEY}")).unwrap(),
    );
    assert!(
        authenticate_traffic_key(&headers, &configured_traffic_keys(&[wrong_id]).unwrap())
            .is_none()
    );

    let mut revoked = traffic_key(KEY, scope_id, true);
    revoked.revocation = Some(TrafficKeyRevocationConfig {
        revoked_at: "2026-08-31T00:00:00Z".parse().unwrap(),
        reason: Some("rotated".to_owned()),
    });
    assert!(
        authenticate_traffic_key(&headers, &configured_traffic_keys(&[revoked]).unwrap()).is_none()
    );
}

#[test]
fn identities_fail_closed_and_sampling_uses_the_full_u64_threshold() {
    let mut invalid = config(1_024, 1);
    invalid.traffic_keys[0].scope_id = Uuid::nil();
    assert!(validate_config_identity(&invalid).is_err());
    let mut duplicate_scope = config(1_024, 1);
    duplicate_scope.traffic_keys[0].scope_id = duplicate_scope.outcome_key_id;
    assert!(validate_config_identity(&duplicate_scope).is_err());
    let mut duplicate_key = config(1_024, 1);
    duplicate_key
        .traffic_keys
        .push(duplicate_key.traffic_keys[0].clone());
    assert!(validate_config_identity(&duplicate_key).is_err());
    let mut no_traffic_key = config(1_024, 1);
    no_traffic_key.traffic_keys.clear();
    assert!(validate_config_identity(&no_traffic_key).is_err());
    let mut too_many_keys = config(1_024, 1);
    let scope_id = config_scope(&too_many_keys).scope_id;
    too_many_keys.traffic_keys = (0..=super::MAX_TRAFFIC_KEYS)
        .map(|index| TrafficKeyConfig {
            key_id: Uuid::from_u128(index as u128 + 1),
            api_key_sha256: format!("{index:064x}"),
            scope_id,
            capture_allowed: true,
            revocation: None,
        })
        .collect();
    assert!(validate_config_identity(&too_many_keys).is_err());
    let threshold = ((u128::from(u64::MAX) + 1) / 10_000) as u64;
    assert!(capture_sample_selected(0, 1));
    assert!(capture_sample_selected(threshold - 1, 1));
    assert!(!capture_sample_selected(threshold, 1));
    assert!(!capture_sample_selected(u64::MAX, 0));
    assert!(capture_sample_selected(u64::MAX, 10_000));
}

#[test]
fn responses_sampling_uses_provable_roots_and_rejects_previous_only_capture() {
    let gateway = Gateway::new(
        &config(1_024, 1),
        Url::parse("http://127.0.0.1:1/v1/").unwrap(),
        None,
    )
    .unwrap();
    let scope = &gateway.traffic_keys[0].scope;
    let empty = actix_web::http::header::HeaderMap::new();
    let previous_only = br#"{"model":"test","previous_response_id":"resp_previous"}"#;
    let previous = sampling_identity(
        &gateway,
        scope,
        RouteEndpoint::Responses,
        &empty,
        previous_only,
        Uuid::now_v7(),
    );
    assert_eq!(previous.kind, SamplingUnitKind::Request);
    assert_eq!(previous.independence, SamplingIndependence::Uncertain);
    assert!(previous.previous_response_hmac_sha256.is_some());
    assert!(!previous.content_capture_allowed);

    let mut session_headers = actix_web::http::header::HeaderMap::new();
    session_headers.insert(
        actix_web::http::header::HeaderName::from_static("x-milk-session-id"),
        actix_web::http::header::HeaderValue::from_static("stable-responses-session"),
    );
    let header_root_a = sampling_identity(
        &gateway,
        scope,
        RouteEndpoint::Responses,
        &session_headers,
        previous_only,
        Uuid::now_v7(),
    );
    let header_root_b = sampling_identity(
        &gateway,
        scope,
        RouteEndpoint::Responses,
        &session_headers,
        previous_only,
        Uuid::now_v7(),
    );
    assert_eq!(header_root_a.kind, SamplingUnitKind::ChatSessionHeader);
    assert_eq!(
        header_root_a.independence,
        SamplingIndependence::Independent
    );
    assert!(header_root_a.content_capture_allowed);
    assert_eq!(header_root_a.hmac_sha256, header_root_b.hmac_sha256);

    let conversation = sampling_identity(
        &gateway,
        scope,
        RouteEndpoint::Responses,
        &empty,
        br#"{"model":"test","conversation":"conv_root","previous_response_id":"resp_previous"}"#,
        Uuid::now_v7(),
    );
    assert_eq!(conversation.kind, SamplingUnitKind::ResponsesConversation);
    assert_eq!(conversation.independence, SamplingIndependence::Independent);
    assert!(conversation.content_capture_allowed);

    let standalone = sampling_identity(
        &gateway,
        scope,
        RouteEndpoint::Responses,
        &empty,
        br#"{"model":"test","input":"standalone"}"#,
        Uuid::now_v7(),
    );
    assert_eq!(standalone.kind, SamplingUnitKind::Request);
    assert_eq!(standalone.independence, SamplingIndependence::Uncertain);
    assert!(standalone.content_capture_allowed);
}

#[test]
fn route_only_records_do_not_load_capture_sampling_secrets() {
    let route_only = StoreAccessPlan {
        routes: Some(crate::records::StoreAccess::ReadOnly),
        ..StoreAccessPlan::default()
    };
    assert_eq!(
        records_sampling_key_version(route_only).unwrap(),
        "not-applicable"
    );
}

#[test]
fn student_runtime_images_are_immutable_and_branch_matches_route_authority() {
    let mut invalid = config(1_024, 4);
    invalid
        .teacher
        .as_mut()
        .unwrap()
        .student_train_runtime_image_reference =
        String::from("ghcr.io/milkinfrastructure/milk-student-train:latest");
    assert!(validate_teacher_config(&invalid).is_err());

    let mut invalid = config(1_024, 4);
    invalid
        .teacher
        .as_mut()
        .unwrap()
        .student_branch_runtime_image_reference =
        String::from("ghcr.io/milkinfrastructure/milk-student-branch:latest");
    assert!(validate_teacher_config(&invalid).is_err());

    let mut same_digest = config(1_024, 4);
    same_digest
        .teacher
        .as_mut()
        .unwrap()
        .student_branch_runtime_image_reference = format!(
        "ghcr.io/another-owner/another-image@sha256:{}",
        "4".repeat(64)
    );
    assert!(validate_teacher_config(&same_digest).is_err());

    let mut routed = config(1_024, 4);
    routed.route = Some(RouteStartupConfig {
        signing_public_key_hex: "5".repeat(64),
        signing_key_id: "route-test".into(),
        allow_private_candidate_http: false,
        candidate_max_in_flight: 1,
    });
    validate_teacher_config(&routed).unwrap();
}

#[test]
fn gpu_teacher_file_config_requires_shared_s3_storage() {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("milk-carton-gpu-local-{}", Uuid::now_v7()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut gpu = config(1_024, 4);
    let teacher = gpu.teacher.as_mut().unwrap();
    teacher.chat_completions_url = "http://127.0.0.1:8000/v1/chat/completions".to_owned();
    teacher.allow_loopback_http = true;
    teacher.execution = SnapshotAnalyzerExecution::GpuJob {
        runtime_image_reference: format!(
            "ghcr.io/milkinfrastructure/milk-teacher-gpt-oss@sha256:{}",
            "9".repeat(64)
        ),
        max_gpu_seconds: 60,
        max_calls: 1,
        max_parallel_runs: 1,
    };
    gpu.stores = local_stores(&root);
    assert!(validate_teacher_config(&gpu).is_err());
    gpu.stores.capture = s3_store("test-capture");
    gpu.stores.control = s3_store("test-control");
    gpu.teacher.as_mut().unwrap().max_decisions = 0;
    assert!(validate_teacher_config(&gpu).is_err());
    gpu.teacher.as_mut().unwrap().max_decisions = 4_097;
    assert!(validate_teacher_config(&gpu).is_err());
    gpu.teacher.as_mut().unwrap().max_decisions = 1;
    validate_teacher_config(&gpu).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn provider_endpoints_require_https_or_explicit_literal_loopback() {
    assert!(
        parse_openai_compatible_endpoint("https://api.openai.com/v1/chat/completions", false)
            .is_ok()
    );
    assert!(
        parse_openai_compatible_api_base_url(
            "https://model-x.api.baseten.co/deployment/y/sync/v1/",
            false
        )
        .is_ok()
    );
    assert!(
        parse_openai_compatible_endpoint("http://127.0.0.1:8000/v1/chat/completions", true).is_ok()
    );
    for (endpoint, allow_loopback) in [
        ("http://127.0.0.1:8000/v1/chat/completions", false),
        ("http://localhost:8000/v1/chat/completions", true),
        ("http://10.0.0.1:8000/v1/chat/completions", true),
        ("http://127.0.0.1:8000/v1/chat/completions?debug=1", true),
    ] {
        assert!(parse_openai_compatible_endpoint(endpoint, allow_loopback).is_err());
    }
}

#[actix_web::test]
async fn keyless_tick_holds_without_reading_the_teacher_key() {
    let mut config = config(1_024, 1);
    config.capture_mode = CaptureMode::WholeBodyAuthorized;
    config.capture_basis_points = 10_000;
    config.capture_policy_version = "test-v1".into();
    config.capture_rights_state = "authorized".into();
    let records = Records::start(
        Arc::new(InMemory::new()),
        config.capture_queue_bytes,
        config.capture_record_bytes,
        config_scope(&config),
        config.capture_basis_points,
    )
    .await
    .unwrap();
    let output = tick_once_with_records(&config, Utc::now(), records)
        .await
        .unwrap();
    assert_eq!(output, r#"{"action":"hold"}"#);
}

#[actix_web::test]
async fn non_production_mechanics_tick_rejects_before_any_object_write() {
    let mut config = config(1_024, 1);
    config.traffic_keys[0].scope_id = "f7f88ff0-5947-440c-a661-e4e35f1d04e0".parse().unwrap();
    let objects: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let records = Records::start(
        Arc::clone(&objects),
        config.capture_queue_bytes,
        config.capture_record_bytes,
        config_scope(&config),
        config.capture_basis_points,
    )
    .await
    .unwrap();

    let error = tick_once_with_records(&config, Utc::now(), records)
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("mechanics scope is not route-admissible")
    );
    assert!(objects.list(None).next().await.is_none());
}

#[actix_web::test]
async fn overlapping_tick_preserves_the_exact_hold_stdout_contract() {
    let mut config = config(1_024, 1);
    config.capture_mode = CaptureMode::WholeBodyAuthorized;
    config.capture_basis_points = 10_000;
    config.capture_policy_version = "test-v1".into();
    config.capture_rights_state = "authorized".into();
    let objects: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let records = Records::start(
        Arc::clone(&objects),
        config.capture_queue_bytes,
        config.capture_record_bytes,
        config_scope(&config),
        config.capture_basis_points,
    )
    .await
    .unwrap();
    let owner = Records::start(
        objects,
        config.capture_queue_bytes,
        config.capture_record_bytes,
        config_scope(&config),
        config.capture_basis_points,
    )
    .await
    .unwrap();
    let now = Utc::now().with_nanosecond(0).unwrap();
    let lease = owner
        .acquire_tick_lease(&config_scope(&config), now)
        .await
        .unwrap()
        .unwrap();

    let output = tick_once_with_records(&config, now, records).await.unwrap();
    assert_eq!(output, r#"{"action":"hold"}"#);
    owner
        .release_tick_lease(lease, now + TimeDelta::seconds(1))
        .await
        .unwrap();
}

#[actix_web::test]
async fn due_expiry_returns_before_teacher_readiness() {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!(
            "milk-carton-expiry-before-teacher-{}",
            Uuid::now_v7()
        ));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut config = config(4_096, 1);
    config.capture_mode = CaptureMode::WholeBodyAuthorized;
    config.capture_basis_points = 10_000;
    config.capture_policy_version = "test-v1".into();
    config.capture_rights_state = "authorized".into();
    config.stores = local_stores(&root);
    let now = Utc::now().with_nanosecond(0).unwrap();
    let occurred_at = now - TimeDelta::days(2);
    let retention_until = now - TimeDelta::days(1);
    let request =
        Bytes::from_static(br#"{"model":"test","messages":[{"role":"user","content":"expired"}]}"#);
    let response = br#"{"choices":[{"message":{"role":"assistant","content":"done"}}]}"#.to_vec();
    let records = start_records(
        &config,
        StoreAccessPlan::for_command(&super::Command::Tick { once: true }),
    )
    .await
    .unwrap();
    assert_eq!(
        records.try_capture(TraceCapture {
            catalog: TraceCatalog {
                scope: config_scope(&config),
                trace_id: Uuid::new_v7(uuid::Timestamp::from_unix(
                    uuid::NoContext,
                    occurred_at.timestamp() as u64,
                    occurred_at.timestamp_subsec_nanos(),
                )),
                occurred_at,
                endpoint: "chat_completions".into(),
                request_parse_success: true,
                streaming: false,
                route_revision: "baseline-v1".into(),
                route: RouteObservation::Ineligible {
                    reason: RouteBlockReason::PolicyAbsent,
                },
                provider_status: Some(200),
                error_class: None,
                ttft_ms: Some(1),
                completion_ms: Some(2),
                request_bytes: request.len() as u64,
                response_bytes: response.len() as u64,
                sampler_id: CAPTURE_SAMPLER_ID.into(),
                sampling_unit_kind: SamplingUnitKind::Request,
                sampling_unit_hmac_sha256: "aa".repeat(32),
                sampling_independence: SamplingIndependence::Uncertain,
                sampling_key_version: "test-key-v1".into(),
                previous_response_hmac_sha256: None,
                capture_basis_points: 10_000,
                capture_eligible: true,
                capture_selected: true,
                capture_policy_version: Some("test-v1".into()),
                rights_state: "authorized".into(),
                retention_until: Some(retention_until),
            },
            request_content_type: Some("application/json".into()),
            request_content_encoding: None,
            request,
            response_content_type: Some("application/json".into()),
            response_content_encoding: None,
            response,
        }),
        crate::records::EnqueueResult::Queued
    );
    records.flush().await.unwrap();
    drop(records);

    let records = start_records_with_timeout(
        &config,
        StoreAccessPlan::for_command(&Command::Tick { once: true }),
        true,
    )
    .await
    .unwrap();
    let output = tick_once_with_records(&config, now, records).await.unwrap();
    assert!(output.starts_with(r#"{"schema_version":"milk.expiry-receipt.v1""#));
    assert!(!output.contains("teacher-required"));
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn status_contract_is_data_plane_only_and_does_not_require_teacher() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CaptureContract {
        from_hour: chrono::DateTime<Utc>,
        through_hour: chrono::DateTime<Utc>,
        shards: u64,
        failed_shards: u64,
        #[serde(rename = "values")]
        _values: crate::records::StatsValues,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExpiryContract {
        batch_limit: u64,
        due_batch_markers: u64,
        grace_deferred_batch_markers: u64,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RecordsContract {
        schema_version: String,
        scope: Scope,
        capture: CaptureContract,
        expiry: ExpiryContract,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RouteContract {
        configured: bool,
        state: String,
        route_revision: Option<String>,
        student_job_id: Option<String>,
        candidate_basis_points: Option<u16>,
        not_after: Option<chrono::DateTime<Utc>>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StatusContract {
        schema_version: String,
        records: RecordsContract,
        route: RouteContract,
    }

    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("milk-carton-status-contract-{}", Uuid::now_v7()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut config: FileConfig = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/milk-carton-config.example.json"
    )))
    .unwrap();
    config.stores = local_stores(&root);
    assert!(config.teacher.is_none());
    validate_config_for_command(&config, Some(&Command::Status)).unwrap();

    let now = Utc::now().with_nanosecond(0).unwrap();
    let raw = status_once(&config, now).await.unwrap();
    let status: StatusContract = serde_json::from_str(&raw).unwrap();
    assert_eq!(status.schema_version, "milk.status.v3");
    assert_eq!(status.records.schema_version, "milk.status-data-plane.v1");
    assert_eq!(status.records.scope, config_scope(&config));
    assert!(status.records.capture.from_hour <= status.records.capture.through_hour);
    assert_eq!(status.records.capture.shards, 0);
    assert_eq!(status.records.capture.failed_shards, 0);
    assert_eq!(status.records.expiry.batch_limit, 1_000);
    assert_eq!(status.records.expiry.due_batch_markers, 0);
    assert_eq!(status.records.expiry.grace_deferred_batch_markers, 0);
    assert!(!status.route.configured);
    assert_eq!(status.route.state, "disabled");
    assert!(status.route.route_revision.is_none());
    assert!(status.route.student_job_id.is_none());
    assert!(status.route.candidate_basis_points.is_none());
    assert!(status.route.not_after.is_none());
    fs::remove_dir_all(root).unwrap();
}

#[actix_web::test]
async fn generation_status_is_content_free_and_scope_bound() {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenerationStatusContract {
        schema_version: String,
        scope_id: Uuid,
        max_decisions: u32,
        claimed_decisions: u32,
        remaining_decisions: u32,
        generation_done: bool,
    }

    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("milk-carton-generation-status-{}", Uuid::now_v7()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut config = config(4_096, 1);
    config.stores = local_stores(&root);
    config.teacher.as_mut().unwrap().max_decisions = 7;

    let raw = generation_status_once(&config, Utc::now().with_nanosecond(0).unwrap())
        .await
        .unwrap();
    let status: GenerationStatusContract = serde_json::from_str(&raw).unwrap();
    assert_eq!(status.schema_version, "milk.generation-status.v1");
    assert_eq!(status.scope_id, config_scope(&config).scope_id);
    assert_eq!(status.max_decisions, 7);
    assert_eq!(status.claimed_decisions, 0);
    assert_eq!(status.remaining_decisions, 7);
    assert!(!status.generation_done);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn serve_example_is_current_and_has_no_teacher_execution_config() {
    let root = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("milk-carton-example-{}", Uuid::now_v7()));
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let json = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../deploy/milk-carton-config.example.json"
    ))
    .replace("/var/lib/milk-carton/objects", root.to_str().unwrap());
    let config: FileConfig = serde_json::from_str(&json).unwrap();
    assert!(config.teacher.is_none());
    validate_config_identity(&config).unwrap();
    Gateway::new(&config, Url::parse("http://127.0.0.1:1/v1/").unwrap(), None).unwrap();
    fs::remove_dir_all(root).unwrap();
}

struct RunningServer {
    address: String,
    handle: ServerHandle,
    task: JoinHandle<std::io::Result<()>>,
}

impl RunningServer {
    fn start(server: Server, address: String) -> Self {
        let handle = server.handle();
        let task = actix_web::rt::spawn(server);
        Self {
            address,
            handle,
            task,
        }
    }

    async fn stop(self) {
        self.handle.stop(true).await;
        self.task.await.expect("server task should join").unwrap();
    }
}

#[derive(Debug)]
struct SeenRequest {
    query: String,
    body: Bytes,
    headers: Vec<(String, Vec<u8>)>,
}

#[derive(Deserialize)]
struct LocalEnvelope {
    error: LocalError,
}

#[derive(Deserialize)]
struct LocalError {
    code: String,
}

#[derive(Deserialize)]
struct StoredTraceProbe {
    schema_version: String,
    catalog: StoredTraceCatalogProbe,
    request: StoredBodyProbe,
    response: StoredBodyProbe,
}

#[derive(Deserialize)]
struct StoredTraceCatalogProbe {
    capture_eligible: bool,
    capture_selected: bool,
}

#[derive(Deserialize)]
struct StoredBodyProbe {
    content_encoding: Option<String>,
}

#[derive(Deserialize)]
struct HealthProbe {
    status: String,
    config_sha256: String,
    capture: String,
    candidate: String,
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

#[derive(Deserialize)]
struct CandidateCredentialProbe {
    schema_version: String,
    candidate_api_key_sha256: Option<String>,
    state: String,
}

#[derive(Deserialize)]
struct StatsProbe {
    values: StatsValuesProbe,
}

#[derive(Deserialize)]
struct StatsValuesProbe {
    observed: u64,
    eligible: u64,
    selected: u64,
    captured: u64,
    not_selected: u64,
    route_eligible: u64,
    route_ineligible: u64,
    route_selected: u64,
    route_not_selected: u64,
    baseline: u64,
    candidate: u64,
    route_blocked_reason_counts: BTreeMap<String, u64>,
    route_fallback_counts: BTreeMap<String, u64>,
}

fn config(max_request_bytes: usize, max_in_flight: usize) -> FileConfig {
    let scope_id = Uuid::new_v4();
    FileConfig {
        listen: "127.0.0.1:0".parse().unwrap(),
        traffic_keys: vec![traffic_key(KEY, scope_id, true)],
        outcome_key_id: Uuid::parse_str(OUTCOME_KEY_ID).unwrap(),
        outcome_key_sha256: format!("{:x}", Sha256::digest(OUTCOME_KEY.as_bytes())),
        max_request_bytes,
        max_in_flight,
        max_outcomes_in_flight: 2,
        max_active_body_bytes: 65_536,
        request_body_timeout_ms: 500,
        connect_timeout_ms: 1_000,
        read_timeout_ms: 2_000,
        total_timeout_ms: 3_000,
        storage_timeout_ms: 3_000,
        capture_mode: CaptureMode::Disabled,
        capture_basis_points: 0,
        capture_response_bytes: 1_024,
        capture_record_bytes: 4_096,
        capture_queue_bytes: 8_192,
        capture_policy_version: "disabled".into(),
        capture_rights_state: "unreviewed".into(),
        capture_retention_days: 1,
        outcome_kind: OutcomeKind::Accepted,
        outcome_verifier_id: "test-verifier-v1".into(),
        outcome_rights_state: "authorized".into(),
        outcome_retention_days: 1,
        stores: StoresConfig {
            capture: s3_store("test-capture"),
            control: s3_store("test-control"),
            routes: s3_store("test-routes"),
        },
        baseline: OpenAiCompatibleEndpoint {
            api_base_url: "https://api.openai.com/v1/".into(),
            allow_loopback_http: false,
        },
        teacher: Some(TeacherConfig {
            chat_completions_url: "http://127.0.0.1:8000/v1/chat/completions".into(),
            allow_loopback_http: true,
            model: "teacher-test".into(),
            reasoning_effort: SnapshotAnalyzerReasoningEffort::High,
            execution: SnapshotAnalyzerExecution::GpuJob {
                runtime_image_reference: format!(
                    "ghcr.io/milkinfrastructure/milk-teacher-gpt-oss@sha256:{}",
                    "5".repeat(64)
                ),
                max_gpu_seconds: 60,
                max_calls: 1,
                max_parallel_runs: 1,
            },
            deployment_sha256: "1".repeat(64),
            terms_sha256: "2".repeat(64),
            authorization_id: "test-authorization".into(),
            authorization_not_after: chrono::DateTime::from_timestamp(2_000_000_000, 0).unwrap(),
            max_decisions: 4_096,
            max_projected_bytes: 1_048_576,
            max_input_tokens: 1_048_576,
            max_output_tokens: 4_096,
            input_rate_microusd_per_million_tokens: 1,
            output_rate_microusd_per_million_tokens: 1,
            max_cost_microusd: 10,
            student_recipe_sha256: "3".repeat(64),
            student_train_runtime_image_reference: format!(
                "ghcr.io/milkinfrastructure/milk-student-train@sha256:{}",
                "4".repeat(64)
            ),
            student_branch_runtime_image_reference: format!(
                "ghcr.io/milkinfrastructure/milk-student-branch@sha256:{}",
                "6".repeat(64)
            ),
        }),
        route: None,
    }
}

#[actix_web::test]
async fn disabled_capture_still_emits_content_free_statistics() {
    let (listener, upstream_address) = listen();
    let upstream = HttpServer::new(move || {
        App::new().default_service(web::to(|| async {
            HttpResponse::Ok()
                .insert_header(("content-type", "application/json"))
                .body(r#"{"choices":[{"message":{"role":"assistant","content":"private response"}}]}"#)
        }))
    })
    .listen(listener)
    .unwrap()
    .run();
    let upstream = RunningServer::start(upstream, upstream_address);

    let gateway_config = config(4_096, 2);
    assert_eq!(gateway_config.capture_mode, CaptureMode::Disabled);
    let scope = Scope {
        scope_id: config_scope(&gateway_config).scope_id,
    };
    let objects: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let records = Records::start(
        Arc::clone(&objects),
        gateway_config.capture_queue_bytes,
        gateway_config.capture_record_bytes,
        scope.clone(),
        gateway_config.capture_basis_points,
    )
    .await
    .unwrap();
    let gateway = start_gateway_with_records(
        &format!("{}/v1/chat/completions", upstream.address),
        gateway_config,
        Some(records),
    );

    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .body(r#"{"model":"test","messages":[{"role":"user","content":"private request"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(response.headers()["x-milk-capture-intent"], "not_selected");
    std::mem::drop(response.bytes().await.unwrap());

    let stats_bytes = timeout(Duration::from_secs(1), async {
        'wait: loop {
            let mut listing = objects.list(None);
            while let Some(meta) = listing.next().await.transpose().unwrap() {
                if meta.location.as_ref().contains("/stats/") {
                    break 'wait objects
                        .get(&meta.location)
                        .await
                        .unwrap()
                        .bytes()
                        .await
                        .unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("observation-only statistics must flush");
    assert!(
        !stats_bytes
            .windows(b"private".len())
            .any(|bytes| bytes == b"private")
    );
    let stats: StatsProbe = serde_json::from_slice(&stats_bytes).unwrap();
    assert_eq!(stats.values.observed, 1);
    assert_eq!(stats.values.eligible, 0);
    assert_eq!(stats.values.selected, 0);
    assert_eq!(stats.values.captured, 0);
    assert_eq!(stats.values.not_selected, 1);
    assert_eq!(stats.values.route_eligible, 0);
    assert_eq!(stats.values.route_ineligible, 1);
    assert_eq!(stats.values.route_selected, 0);
    assert_eq!(stats.values.route_not_selected, 0);
    assert_eq!(stats.values.baseline, 1);
    assert_eq!(stats.values.candidate, 0);
    assert_eq!(
        stats.values.route_blocked_reason_counts,
        BTreeMap::from([("policy_absent".to_owned(), 1)])
    );
    assert!(stats.values.route_fallback_counts.is_empty());

    let object_keys = objects
        .list(None)
        .map(|result| result.unwrap().location.to_string())
        .collect::<Vec<_>>()
        .await;
    assert!(object_keys.iter().any(|key| key.contains("/stats/")));
    assert!(!object_keys.iter().any(|key| key.contains("/traces/")));

    gateway.stop().await;
    upstream.stop().await;
}

fn listen() -> (TcpListener, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = format!("http://{}", listener.local_addr().unwrap());
    (listener, address)
}

fn test_api_base_url(endpoint: &str) -> Url {
    let base = endpoint
        .strip_suffix("chat/completions")
        .or_else(|| endpoint.strip_suffix("responses"))
        .unwrap_or(endpoint);
    Url::parse(base).unwrap()
}

fn start_gateway(upstream: &str, max_request_bytes: usize, max_in_flight: usize) -> RunningServer {
    start_gateway_with_config(upstream, config(max_request_bytes, max_in_flight))
}

fn start_gateway_with_config(upstream: &str, config: FileConfig) -> RunningServer {
    start_gateway_with_records(upstream, config, None)
}

fn start_gateway_with_records(
    upstream: &str,
    config: FileConfig,
    records: Option<Records>,
) -> RunningServer {
    let (listener, address) = listen();
    let gateway = Gateway::new(&config, test_api_base_url(upstream), records).unwrap();
    RunningServer::start(build_server(listener, gateway).unwrap(), address)
}

fn start_gateway_with_route(
    baseline: &str,
    candidate: &str,
    max_in_flight: usize,
    candidate_max_in_flight: usize,
) -> RunningServer {
    start_gateway_with_route_config(
        baseline,
        candidate,
        config(4_096, max_in_flight),
        candidate_max_in_flight,
    )
}

fn start_gateway_with_route_config(
    baseline: &str,
    candidate: &str,
    config: FileConfig,
    candidate_max_in_flight: usize,
) -> RunningServer {
    let (listener, address) = listen();
    let route = RoutePolicy::active_for_test(
        test_api_base_url(candidate),
        candidate_max_in_flight,
        CANDIDATE_KEY,
    );
    let gateway = Gateway::with_route(
        &config,
        test_api_base_url(baseline),
        None,
        route,
        Some("test-managed-openai-key"),
        Some(CANDIDATE_KEY),
    )
    .unwrap();
    RunningServer::start(build_server(listener, gateway).unwrap(), address)
}

#[test]
fn route_runtime_swap_preserves_in_flight_generation() {
    let wrong_key = Gateway::with_route(
        &config(4_096, 2),
        Url::parse("http://127.0.0.1:8/v1/").unwrap(),
        None,
        RoutePolicy::active_for_test(
            Url::parse("http://127.0.0.1:9/v1/").unwrap(),
            1,
            CANDIDATE_KEY,
        ),
        Some("test-managed-openai-key"),
        Some("wrong-candidate-key"),
    )
    .err()
    .unwrap();
    assert!(wrong_key.to_string().contains("admitted credential"));

    let route = RoutePolicy::active_for_test(
        Url::parse("http://127.0.0.1:9/v1/").unwrap(),
        1,
        CANDIDATE_KEY,
    );
    let gateway = Gateway::with_route(
        &config(4_096, 2),
        Url::parse("http://127.0.0.1:8/v1/").unwrap(),
        None,
        route,
        Some("test-managed-openai-key"),
        Some(CANDIDATE_KEY),
    )
    .unwrap();
    let in_flight = gateway.route_runtime();
    assert!(in_flight.policy.candidate().is_some());
    assert!(in_flight.candidate.is_some());

    gateway.replace_route_runtime(
        build_route_runtime(&config(4_096, 2), RoutePolicy::baseline(), None).unwrap(),
    );

    assert!(gateway.route_runtime().policy.candidate().is_none());
    assert!(gateway.route_runtime().candidate.is_none());
    assert!(in_flight.policy.candidate().is_some());
    assert!(in_flight.candidate.is_some());
}

#[actix_web::test]
async fn candidate_credential_check_proves_loaded_absent_and_mismatch_without_key_content() {
    let candidate_sha256 = format!("{:x}", Sha256::digest(CANDIDATE_KEY.as_bytes()));
    let loaded = start_gateway_with_route(
        "http://127.0.0.1:8/v1/chat/completions",
        "http://127.0.0.1:9/v1/chat/completions",
        1,
        1,
    );
    let response = client(false)
        .get(format!("{}{}", loaded.address, CANDIDATE_CREDENTIAL_PATH))
        .header(CANDIDATE_API_KEY_SHA256_HEADER, &candidate_sha256)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CANDIDATE_CREDENTIAL_STATE_HEADER)
            .unwrap(),
        "loaded"
    );
    assert_eq!(
        response
            .headers()
            .get(CANDIDATE_API_KEY_SHA256_HEADER)
            .unwrap(),
        candidate_sha256.as_str()
    );
    let body = response.bytes().await.unwrap();
    assert!(
        !body
            .windows(CANDIDATE_KEY.len())
            .any(|part| part == CANDIDATE_KEY.as_bytes())
    );
    let probe: CandidateCredentialProbe = serde_json::from_slice(&body).unwrap();
    assert_eq!(probe.schema_version, "milk.candidate-credential-check.v1");
    assert_eq!(
        probe.candidate_api_key_sha256.as_deref(),
        Some(candidate_sha256.as_str())
    );
    assert_eq!(probe.state, "loaded");

    let mismatch = client(false)
        .get(format!("{}{}", loaded.address, CANDIDATE_CREDENTIAL_PATH))
        .header(CANDIDATE_API_KEY_SHA256_HEADER, "0".repeat(64))
        .send()
        .await
        .unwrap();
    assert_eq!(mismatch.status(), reqwest::StatusCode::CONFLICT);
    let mismatch_body = mismatch.bytes().await.unwrap();
    assert!(
        !mismatch_body
            .windows(candidate_sha256.len())
            .any(|part| part == candidate_sha256.as_bytes())
    );
    loaded.stop().await;

    let absent = start_gateway("http://127.0.0.1:8/v1/chat/completions", 1_024, 1);
    let response = client(false)
        .get(format!("{}{}", absent.address, CANDIDATE_CREDENTIAL_PATH))
        .header(CANDIDATE_API_KEY_SHA256_HEADER, "absent")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(CANDIDATE_CREDENTIAL_STATE_HEADER)
            .unwrap(),
        "absent"
    );
    let probe: CandidateCredentialProbe = response.json().await.unwrap();
    assert!(probe.candidate_api_key_sha256.is_none());
    assert_eq!(probe.state, "absent");
    absent.stop().await;
}

#[actix_web::test]
async fn health_reports_config_identity_without_credential_content() {
    let mut gateway_config = config(1_024, 1);
    gateway_config.capture_mode = CaptureMode::WholeBodyAuthorized;
    gateway_config.capture_basis_points = 10_000;
    gateway_config.capture_policy_version = "test-authorized-v1".to_owned();
    gateway_config.capture_rights_state = "authorized".to_owned();
    let gateway =
        start_gateway_with_config("http://127.0.0.1:9/v1/chat/completions", gateway_config);
    let response = client(false)
        .get(format!("{}/healthz", gateway.address))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let expected_config_sha256 = format!("{:x}", Sha256::digest(b"milk-carton-test-config"));
    assert_eq!(
        response
            .headers()
            .get(CONFIG_SHA256_HEADER)
            .unwrap()
            .to_str()
            .unwrap(),
        expected_config_sha256.as_str()
    );
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let bytes = response.bytes().await.unwrap();
    assert!(
        !bytes
            .windows(KEY.len())
            .any(|window| window == KEY.as_bytes())
    );
    assert!(
        !bytes
            .windows(SESSION_ID.len())
            .any(|window| window == SESSION_ID.as_bytes())
    );
    let health: HealthProbe = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(health.status, "degraded");
    assert_eq!(health.config_sha256, expected_config_sha256);
    assert_eq!(health.capture, "unavailable");
    assert_eq!(health.candidate, "disabled");
    assert!(!health.writer_alive);
    assert!(!health.recent_persist_failure);
    assert_eq!(health.consecutive_persist_failures, 0);
    assert_eq!(health.queued, 0);
    assert_eq!(health.dropped, 0);
    assert_eq!(health.traces_persisted, 0);
    assert_eq!(health.trace_persist_failures, 0);
    assert_eq!(health.stats_persist_failures, 0);
    assert_eq!(health.outcome_persist_failures, 0);
    gateway.stop().await;
}

#[actix_web::test]
async fn health_readiness_fails_when_capture_writer_dies() {
    let mut gateway_config = config(1_024, 1);
    gateway_config.capture_mode = CaptureMode::WholeBodyAuthorized;
    gateway_config.capture_basis_points = 10_000;
    gateway_config.capture_policy_version = "test-authorized-v1".to_owned();
    gateway_config.capture_rights_state = "authorized".to_owned();
    let records = Records::start(
        Arc::new(InMemory::new()),
        gateway_config.capture_queue_bytes,
        gateway_config.capture_record_bytes,
        config_scope(&gateway_config),
        gateway_config.capture_basis_points,
    )
    .await
    .unwrap();
    records.mark_writer_dead_for_test();
    let gateway = start_gateway_with_records(
        "http://127.0.0.1:9/v1/chat/completions",
        gateway_config,
        Some(records),
    );
    let response = client(false)
        .get(format!("{}/healthz", gateway.address))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let health: HealthProbe = response.json().await.unwrap();
    assert_eq!(health.status, "degraded");
    assert_eq!(health.capture, "unhealthy");
    assert!(!health.writer_alive);
    gateway.stop().await;
}

fn client(follow_redirects: bool) -> reqwest::Client {
    let policy = if follow_redirects {
        Policy::limited(10)
    } else {
        Policy::none()
    };
    reqwest::Client::builder()
        .redirect(policy)
        .retry(reqwest::retry::never())
        .no_proxy()
        .build()
        .unwrap()
}

#[test]
fn stream_terminals_survive_every_chunk_width_and_multi_chunk_fragmentation() {
    fn recorder(endpoint: crate::route::RouteEndpoint) -> TraceRecorder {
        TraceRecorder {
            records: None,
            catalog: None,
            started: Instant::now(),
            first_byte: None,
            request: None,
            request_content_type: None,
            request_content_encoding: None,
            response: Vec::new(),
            response_content_type: None,
            response_content_encoding: None,
            response_limit: 1,
            record_limit: usize::MAX,
            selected: false,
            oversized: false,
            stream_protocol: Some(endpoint),
            stream_terminal_seen: false,
            stream_terminal_tail: Vec::new(),
        }
    }

    for (endpoint, marker) in [
        (
            crate::route::RouteEndpoint::ChatCompletions,
            b"data: [DONE]".as_slice(),
        ),
        (
            crate::route::RouteEndpoint::Responses,
            b"event: response.completed".as_slice(),
        ),
        (
            crate::route::RouteEndpoint::Responses,
            b"event: response.failed".as_slice(),
        ),
        (
            crate::route::RouteEndpoint::Responses,
            b"event: response.incomplete".as_slice(),
        ),
    ] {
        for width in 1..=marker.len() {
            let mut recorder = recorder(endpoint);
            for chunk in marker.chunks(width) {
                recorder.observe(&Bytes::copy_from_slice(chunk));
            }
            assert!(
                recorder.stream_terminal_seen,
                "terminal marker was lost at chunk width {width}"
            );
        }
    }

    let mut recorder = recorder(crate::route::RouteEndpoint::Responses);
    for chunk in b"event: response.in_progress".chunks(1) {
        recorder.observe(&Bytes::copy_from_slice(chunk));
    }
    assert!(!recorder.stream_terminal_seen);
}

#[test]
fn capture_and_memory_admission_are_explicit() {
    assert!(is_json_content_type(Some(
        "Application/JSON; charset=utf-8"
    )));
    assert!(!is_json_content_type(None));
    assert!(!is_json_content_type(Some("text/event-stream")));

    let mut constrained = config(1_024, 2);
    constrained.max_active_body_bytes = 1;
    let error = match Gateway::new(
        &constrained,
        Url::parse("http://127.0.0.1:1/v1/chat/completions").unwrap(),
        None,
    ) {
        Ok(_) => panic!("oversubscribed body buffers must be rejected"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("max_active_body_bytes"));

    let mut shared_authority = config(1_024, 1);
    shared_authority.outcome_key_sha256 = shared_authority.traffic_keys[0].api_key_sha256.clone();
    let error = match Gateway::new(
        &shared_authority,
        Url::parse("http://127.0.0.1:1/v1/chat/completions").unwrap(),
        None,
    ) {
        Ok(_) => panic!("traffic and outcome authority must remain separate"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("keys must differ"));
}

#[test]
fn fragmented_capture_never_retains_capacity_above_record_limit() {
    let scope = Scope {
        scope_id: Uuid::new_v4(),
    };
    let mut recorder = TraceRecorder {
        records: None,
        catalog: Some(TraceCatalog {
            scope,
            trace_id: Uuid::new_v4(),
            occurred_at: Utc::now(),
            endpoint: "chat_completions".to_owned(),
            request_parse_success: true,
            streaming: true,
            route_revision: "openai-baseline-v1".to_owned(),
            route: RouteObservation::Ineligible {
                reason: RouteBlockReason::PolicyAbsent,
            },
            provider_status: Some(200),
            error_class: None,
            ttft_ms: None,
            completion_ms: None,
            request_bytes: 2,
            response_bytes: 0,
            sampler_id: crate::records::CAPTURE_SAMPLER_ID.to_owned(),
            sampling_unit_kind: SamplingUnitKind::Request,
            sampling_unit_hmac_sha256: "aa".repeat(32),
            sampling_independence: SamplingIndependence::Uncertain,
            sampling_key_version: "test-key-v1".to_owned(),
            previous_response_hmac_sha256: None,
            capture_basis_points: 10_000,
            capture_eligible: true,
            capture_selected: true,
            capture_policy_version: Some("test-v1".to_owned()),
            rights_state: "authorized".to_owned(),
            retention_until: None,
        }),
        started: std::time::Instant::now(),
        first_byte: None,
        request: Some(Bytes::from_static(b"{}")),
        request_content_type: Some("application/json".to_owned()),
        request_content_encoding: None,
        response: Vec::new(),
        response_content_type: Some("text/event-stream".to_owned()),
        response_content_encoding: None,
        response_limit: 1_024,
        record_limit: usize::MAX,
        selected: true,
        oversized: false,
        stream_protocol: Some(crate::route::RouteEndpoint::ChatCompletions),
        stream_terminal_seen: false,
        stream_terminal_tail: Vec::new(),
    };
    recorder.record_limit = recorder.capture_memory_bytes() + 8;

    for _ in 0..64 {
        recorder.observe(&Bytes::from_static(b"x"));
        assert!(recorder.oversized || recorder.capture_memory_bytes() <= recorder.record_limit);
        if recorder.oversized {
            break;
        }
    }

    assert!(recorder.oversized);
    assert!(recorder.request.is_none());
    assert!(recorder.response.is_empty());
    assert_eq!(recorder.response.capacity(), 0);
    assert!(recorder.request_content_type.is_none());
    assert!(recorder.response_content_type.is_none());
}

#[actix_web::test]
async fn baseline_is_byte_transparent_and_isolates_headers() {
    let count = Arc::new(AtomicUsize::new(0));
    let (seen_tx, seen_rx) = oneshot::channel();
    let seen_tx = Arc::new(Mutex::new(Some(seen_tx)));
    let (upstream_listener, upstream_address) = listen();
    let upstream = {
        let count = Arc::clone(&count);
        let seen_tx = Arc::clone(&seen_tx);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            let seen_tx = Arc::clone(&seen_tx);
            App::new().route(
                "/v1/chat/completions",
                web::post().to(move |request: HttpRequest, body: Bytes| {
                    let count = Arc::clone(&count);
                    let seen_tx = Arc::clone(&seen_tx);
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        let headers = request
                            .headers()
                            .iter()
                            .map(|(name, value)| {
                                (name.as_str().to_owned(), value.as_bytes().to_vec())
                            })
                            .collect();
                        seen_tx
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(SeenRequest {
                                query: request.query_string().to_owned(),
                                body,
                                headers,
                            })
                            .unwrap();
                        HttpResponse::TooManyRequests()
                            .insert_header(("content-type", "application/json"))
                            .insert_header(("retry-after", "7"))
                            .insert_header(("x-request-id", "provider-request"))
                            .insert_header(("x-openai-proxy-wasm", "diagnostic"))
                            .insert_header(("set-cookie", "provider-cookie=must-not-stick"))
                            .insert_header(("x-milk-trace-id", "spoofed"))
                            .body(Bytes::from_static(b"{ \"provider\": \"error\" }\n"))
                    }
                }),
            )
        })
        .listen(upstream_listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address.clone());
    let gateway = start_gateway(
        &format!("{}/v1/chat/completions", upstream.address),
        1_024,
        2,
    );

    let body = Bytes::from_static(b"{ \"unknown\" : [3, 2, 1] }\n");
    let response = client(false)
        .post(format!("{}/v1/chat/completions?beta=true", gateway.address))
        .bearer_auth(KEY)
        .header("openai-organization", "org-test")
        .header("x-milk-internal", "remove-me")
        .header("cookie", "session=must-not-leak")
        .header("x-forwarded-for", "198.51.100.1")
        .header("connection", "x-remove-me")
        .header("x-remove-me", "remove-me-too")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers()["retry-after"], "7");
    assert_eq!(response.headers()["x-request-id"], "provider-request");
    assert_eq!(response.headers()["x-openai-proxy-wasm"], "diagnostic");
    assert_eq!(response.headers()["x-milk-capture-intent"], "unavailable");
    assert!(response.headers().get("set-cookie").is_none());
    let trace_id = response.headers()["x-milk-trace-id"].to_str().unwrap();
    Uuid::parse_str(trace_id).unwrap();
    assert_ne!(trace_id, "spoofed");
    assert_eq!(
        response.bytes().await.unwrap(),
        Bytes::from_static(b"{ \"provider\": \"error\" }\n")
    );

    let seen = seen_rx.await.unwrap();
    assert_eq!(seen.query, "beta=true");
    assert_eq!(seen.body, body);
    assert_eq!(
        header(&seen.headers, "authorization"),
        Some(b"Bearer test-managed-openai-key".as_slice())
    );
    assert!(header(&seen.headers, "openai-organization").is_none());
    assert!(header(&seen.headers, "x-milk-key").is_none());
    assert!(header(&seen.headers, "x-milk-internal").is_none());
    assert!(header(&seen.headers, "x-remove-me").is_none());
    assert!(header(&seen.headers, "cookie").is_none());
    assert!(header(&seen.headers, "x-forwarded-for").is_none());

    for supplied_key in [None, Some("wrong")] {
        let mut request = client(false).post(format!("{}/v1/chat/completions", gateway.address));
        if let Some(key) = supplied_key {
            request = request.bearer_auth(key);
        }
        let response = request.body("{}").send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
        let error: LocalEnvelope = response.json().await.unwrap();
        assert_eq!(error.error.code, "invalid_milk_api_key");
    }
    let mut duplicate_headers = reqwest::header::HeaderMap::new();
    duplicate_headers.append(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {KEY}")).unwrap(),
    );
    duplicate_headers.append(
        reqwest::header::AUTHORIZATION,
        reqwest::header::HeaderValue::from_str(&format!("Bearer {KEY}")).unwrap(),
    );
    let duplicate = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .headers(duplicate_headers)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    let traffic_key_on_outcomes = client(false)
        .post(format!("{}/v1/milk/outcomes", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        traffic_key_on_outcomes.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
    let outcome_key_without_storage = client(false)
        .post(format!("{}/v1/milk/outcomes", gateway.address))
        .header("x-milk-key", OUTCOME_KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(
        outcome_key_without_storage.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );

    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn responses_is_byte_transparent_and_strips_the_session_header() {
    let (seen_tx, seen_rx) = oneshot::channel();
    let seen_tx = Arc::new(Mutex::new(Some(seen_tx)));
    let (upstream_listener, upstream_address) = listen();
    let upstream = {
        let seen_tx = Arc::clone(&seen_tx);
        HttpServer::new(move || {
            let seen_tx = Arc::clone(&seen_tx);
            App::new().route(
                "/v1/responses",
                web::post().to(move |request: HttpRequest, body: Bytes| {
                    let seen_tx = Arc::clone(&seen_tx);
                    async move {
                        let headers = request
                            .headers()
                            .iter()
                            .map(|(name, value)| {
                                (name.as_str().to_owned(), value.as_bytes().to_vec())
                            })
                            .collect();
                        seen_tx
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(SeenRequest {
                                query: request.query_string().to_owned(),
                                body,
                                headers,
                            })
                            .unwrap();
                        HttpResponse::Ok()
                            .insert_header(("content-type", "application/json"))
                            .body(Bytes::from_static(
                                b"{\"id\":\"resp_test\",\"status\":\"completed\"}",
                            ))
                    }
                }),
            )
        })
        .listen(upstream_listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address);
    let gateway = start_gateway(&format!("{}/v1/", upstream.address), 4_096, 2);
    let body = Bytes::from_static(
        br#"{"model":"customer-model","input":"hello","conversation":"conv_123","unknown_extension":{"keep":true}}"#,
    );
    let response = client(false)
        .post(format!("{}/v1/responses", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .header("x-milk-session-id", SESSION_ID)
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert_eq!(
        response.bytes().await.unwrap(),
        Bytes::from_static(b"{\"id\":\"resp_test\",\"status\":\"completed\"}")
    );
    let seen = seen_rx.await.unwrap();
    assert!(seen.query.is_empty());
    assert_eq!(seen.body, body);
    assert!(header(&seen.headers, "x-milk-session-id").is_none());
    assert_eq!(
        header(&seen.headers, "authorization"),
        Some(b"Bearer test-managed-openai-key".as_slice())
    );
    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn capture_intent_and_immediate_outcome_are_operationally_honest() {
    let (encoding_tx, encoding_rx) = oneshot::channel();
    let encoding_tx = Arc::new(Mutex::new(Some(encoding_tx)));
    let (listener, upstream_address) = listen();
    let upstream = HttpServer::new(move || {
        let encoding_tx = Arc::clone(&encoding_tx);
        App::new().default_service(web::to(move |request: HttpRequest| {
            if let Some(encoding_tx) = encoding_tx.lock().unwrap().take() {
                encoding_tx
                    .send(
                        request
                            .headers()
                            .get("accept-encoding")
                            .map(|value| value.as_bytes())
                            .map(ToOwned::to_owned),
                    )
                    .expect("encoding receiver remains live");
            }
            async {
                HttpResponse::Ok()
                    .insert_header(("content-type", "application/json"))
                    .body(r#"{"choices":[{"message":{"role":"assistant","content":"ok"}}]}"#)
            }
        }))
    })
    .listen(listener)
    .unwrap()
    .run();
    let upstream = RunningServer::start(upstream, upstream_address);

    let mut gateway_config = config(4_096, 2);
    gateway_config.capture_mode = CaptureMode::WholeBodyAuthorized;
    gateway_config.capture_basis_points = 10_000;
    gateway_config.capture_policy_version = "test-authorized-v1".to_owned();
    gateway_config.capture_rights_state = "authorized".to_owned();
    let scope_id = config_scope(&gateway_config).scope_id;
    gateway_config
        .traffic_keys
        .push(traffic_key(SMOKE_KEY, scope_id, false));
    let scope = Scope { scope_id };
    let objects: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
    let object_probe = Arc::clone(&objects);
    let records = Records::start(
        objects,
        gateway_config.capture_queue_bytes,
        gateway_config.capture_record_bytes,
        scope,
        gateway_config.capture_basis_points,
    )
    .await
    .unwrap();
    let gateway = start_gateway_with_records(
        &format!("{}/v1/chat/completions", upstream.address),
        gateway_config,
        Some(records),
    );

    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .header("accept-encoding", "gzip, deflate")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-milk-capture-intent"], "selected");
    let trace_id = response.headers()["x-milk-trace-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(response.headers().get("content-encoding").is_none());
    assert_eq!(
        response.bytes().await.unwrap(),
        Bytes::from_static(
            b"{\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"ok\"}}]}"
        )
    );
    assert_eq!(encoding_rx.await.unwrap(), Some(b"identity".to_vec()));
    let outcome = client(false)
        .post(format!("{}/v1/milk/outcomes", gateway.address))
        .header("x-milk-key", OUTCOME_KEY)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"trace_id":"{trace_id}","outcome_version":1,"value":{{"kind":"accepted"}}}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(outcome.status(), reqwest::StatusCode::CREATED);

    let mut listed = object_probe.list(None);
    let trace_suffix = format!("/{trace_id}.json.zst");
    let mut trace_location = None;
    while let Some(object) = listed.next().await {
        let object = object.unwrap();
        if object.location.as_ref().ends_with(&trace_suffix) {
            trace_location = Some(object.location);
            break;
        }
    }
    let payload = object_probe
        .get(&trace_location.expect("captured trace object exists"))
        .await
        .unwrap()
        .bytes()
        .await
        .unwrap();
    let decoded = zstd::decode_all(Cursor::new(payload)).unwrap();
    let stored: StoredTraceProbe = serde_json::from_slice(&decoded).unwrap();
    assert_eq!(stored.schema_version, "milk.trace.v1");
    assert!(stored.catalog.capture_eligible);
    assert!(stored.catalog.capture_selected);
    assert!(stored.request.content_encoding.is_none());
    assert!(stored.response.content_encoding.is_none());

    let synthetic = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(SMOKE_KEY)
        .header("content-type", "application/json")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(synthetic.headers()["x-milk-capture-intent"], "not_selected");
    std::mem::drop(synthetic.bytes().await.unwrap());

    let not_selected = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "text/plain")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        not_selected.headers()["x-milk-capture-intent"],
        "not_selected"
    );
    std::mem::drop(not_selected.bytes().await.unwrap());

    let encoded = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(encoded.status(), reqwest::StatusCode::OK);
    assert_eq!(encoded.headers()["x-milk-capture-intent"], "not_selected");
    std::mem::drop(encoded.bytes().await.unwrap());

    let unavailable_trace = Uuid::now_v7();
    let unavailable = client(false)
        .post(format!("{}/v1/milk/outcomes", gateway.address))
        .header("x-milk-key", OUTCOME_KEY)
        .header("content-type", "application/json")
        .body(format!(
            r#"{{"trace_id":"{unavailable_trace}","outcome_version":1,"value":{{"kind":"accepted"}}}}"#
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unavailable.status().as_u16(), 425);
    assert_eq!(unavailable.headers()["retry-after"], "1");
    let error: LocalEnvelope = unavailable.json().await.unwrap();
    assert_eq!(error.error.code, "trace_unavailable");

    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn candidate_is_byte_transparent_and_isolates_credentials() {
    let baseline_count = Arc::new(AtomicUsize::new(0));
    let (baseline_listener, baseline_address) = listen();
    let baseline = {
        let count = Arc::clone(&baseline_count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    HttpResponse::Ok().finish()
                }
            }))
        })
        .listen(baseline_listener)
        .unwrap()
        .run()
    };
    let baseline = RunningServer::start(baseline, baseline_address.clone());

    let (seen_tx, seen_rx) = oneshot::channel();
    let seen_tx = Arc::new(Mutex::new(Some(seen_tx)));
    let (candidate_listener, candidate_address) = listen();
    let candidate = {
        let seen_tx = Arc::clone(&seen_tx);
        HttpServer::new(move || {
            let seen_tx = Arc::clone(&seen_tx);
            App::new().route(
                "/v1/chat/completions",
                web::post().to(move |request: HttpRequest, body: Bytes| {
                    let seen_tx = Arc::clone(&seen_tx);
                    async move {
                        let headers = request
                            .headers()
                            .iter()
                            .map(|(name, value)| {
                                (name.as_str().to_owned(), value.as_bytes().to_vec())
                            })
                            .collect();
                        seen_tx
                            .lock()
                            .unwrap()
                            .take()
                            .unwrap()
                            .send(SeenRequest {
                                query: request.query_string().to_owned(),
                                body,
                                headers,
                            })
                            .unwrap();
                        HttpResponse::Created()
                            .insert_header(("content-type", "application/json"))
                            .insert_header(("x-request-id", "candidate-request"))
                            .insert_header(("x-openai-internal", "remove-me"))
                            .insert_header(("x-milk-candidate-sha256", "spoofed"))
                            .body(Bytes::from_static(b"{ \"candidate\": true }\n"))
                    }
                }),
            )
        })
        .listen(candidate_listener)
        .unwrap()
        .run()
    };
    let candidate = RunningServer::start(candidate, candidate_address.clone());
    let gateway = start_gateway_with_route(
        &format!("{}/v1/chat/completions", baseline.address),
        &format!("{}/v1/chat/completions", candidate.address),
        3,
        1,
    );

    let body = Bytes::from_static(
        b"{ \"model\" : \"customer-model\", \"messages\" : [ { \"role\" : \"user\", \"content\" : \"hello\" } ] }\n",
    );
    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("openai-organization", "org-test")
        .header("openai-project", "project-test")
        .header("x-client-request-id", "logical-call")
        .header("content-type", "application/json")
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);
    assert_eq!(response.headers()["x-milk-route-target"], "candidate");
    assert_eq!(response.headers()["x-milk-route-revision"], "test-route-v1");
    assert_eq!(
        response.headers()["x-milk-candidate-sha256"],
        "33".repeat(32)
    );
    assert_eq!(
        response.headers()["x-milk-artifact-sha256"],
        "44".repeat(32)
    );
    assert_eq!(
        response.headers()["x-milk-deployment-sha256"],
        "55".repeat(32)
    );
    assert_eq!(response.headers()["x-request-id"], "candidate-request");
    assert!(response.headers().get("x-openai-internal").is_none());
    assert_eq!(
        response.bytes().await.unwrap(),
        Bytes::from_static(b"{ \"candidate\": true }\n")
    );

    let seen = seen_rx.await.unwrap();
    assert!(seen.query.is_empty());
    assert_eq!(seen.body, body);
    assert_eq!(
        header(&seen.headers, "authorization"),
        Some(format!("Bearer {CANDIDATE_KEY}").as_bytes())
    );
    assert!(header(&seen.headers, "openai-organization").is_none());
    assert!(header(&seen.headers, "openai-project").is_none());
    assert!(header(&seen.headers, "x-milk-key").is_none());
    assert_eq!(
        header(&seen.headers, "x-client-request-id"),
        Some(b"logical-call".as_slice())
    );
    assert_eq!(baseline_count.load(Ordering::SeqCst), 0);

    let beta = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("openai-beta", "assistants=v2")
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(beta.headers()["x-milk-route-target"], "openai");
    assert_eq!(baseline_count.load(Ordering::SeqCst), 1);

    gateway.stop().await;
    candidate.stop().await;
    baseline.stop().await;
}

#[actix_web::test]
async fn candidate_capacity_routes_baseline_and_recovers_after_stream_eof() {
    let baseline_count = Arc::new(AtomicUsize::new(0));
    let (baseline_listener, baseline_address) = listen();
    let baseline = {
        let count = Arc::clone(&baseline_count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    HttpResponse::Ok().body("baseline-capacity")
                }
            }))
        })
        .listen(baseline_listener)
        .unwrap()
        .run()
    };
    let baseline = RunningServer::start(baseline, baseline_address.clone());

    let gate = Arc::new(Notify::new());
    let candidate_count = Arc::new(AtomicUsize::new(0));
    let (candidate_listener, candidate_address) = listen();
    let candidate = {
        let gate = Arc::clone(&gate);
        let count = Arc::clone(&candidate_count);
        HttpServer::new(move || {
            let gate = Arc::clone(&gate);
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let gate = Arc::clone(&gate);
                let request_number = count.fetch_add(1, Ordering::SeqCst);
                async move {
                    if request_number == 0 {
                        let body = stream::unfold((0_u8, gate), |(step, gate)| async move {
                            match step {
                                0 => Some((
                                    Ok::<_, actix_web::Error>(Bytes::from_static(b"first")),
                                    (1, gate),
                                )),
                                1 => {
                                    gate.notified().await;
                                    Some((Ok(Bytes::from_static(b"-done")), (2, gate)))
                                }
                                _ => None,
                            }
                        });
                        HttpResponse::Ok().streaming(body)
                    } else {
                        HttpResponse::Ok().body("candidate-recovered")
                    }
                }
            }))
        })
        .listen(candidate_listener)
        .unwrap()
        .run()
    };
    let candidate = RunningServer::start(candidate, candidate_address.clone());
    let gateway = start_gateway_with_route(
        &format!("{}/v1/chat/completions", baseline.address),
        &format!("{}/v1/chat/completions", candidate.address),
        3,
        1,
    );
    let http = client(false);
    let url = format!("{}/v1/chat/completions", gateway.address);
    let request = || {
        http.post(&url)
            .bearer_auth(KEY)
            .header("content-type", "application/json")
            .body(r#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#)
    };

    let first = request().send().await.unwrap();
    assert_eq!(first.headers()["x-milk-route-target"], "candidate");
    let mut first_body = first.bytes_stream();
    assert_eq!(
        timeout(Duration::from_secs(1), first_body.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        Bytes::from_static(b"first")
    );

    let at_capacity = request().send().await.unwrap();
    assert_eq!(at_capacity.headers()["x-milk-route-target"], "openai");
    assert_eq!(at_capacity.text().await.unwrap(), "baseline-capacity");
    assert_eq!(candidate_count.load(Ordering::SeqCst), 1);
    assert_eq!(baseline_count.load(Ordering::SeqCst), 1);

    gate.notify_one();
    let mut completion = Vec::new();
    while let Some(chunk) = first_body.next().await {
        completion.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(completion, b"-done");
    drop(first_body);

    let recovered = request().send().await.unwrap();
    assert_eq!(recovered.headers()["x-milk-route-target"], "candidate");
    assert_eq!(recovered.text().await.unwrap(), "candidate-recovered");
    assert_eq!(candidate_count.load(Ordering::SeqCst), 2);
    assert_eq!(baseline_count.load(Ordering::SeqCst), 1);

    gateway.stop().await;
    candidate.stop().await;
    baseline.stop().await;
}

#[actix_web::test]
async fn candidate_transport_failure_falls_back_once_and_opens_sticky_fuse() {
    let baseline_count = Arc::new(AtomicUsize::new(0));
    let baseline_bodies = Arc::new(Mutex::new(Vec::<Bytes>::new()));
    let (baseline_listener, baseline_address) = listen();
    let baseline = {
        let count = Arc::clone(&baseline_count);
        let bodies = Arc::clone(&baseline_bodies);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            let bodies = Arc::clone(&bodies);
            App::new().default_service(web::to(move |body: Bytes| {
                let count = Arc::clone(&count);
                let bodies = Arc::clone(&bodies);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    bodies.lock().unwrap().push(body);
                    HttpResponse::Ok().body("baseline-after-fuse")
                }
            }))
        })
        .listen(baseline_listener)
        .unwrap()
        .run()
    };
    let baseline = RunningServer::start(baseline, baseline_address.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let candidate_url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let candidate_attempts = Arc::new(AtomicUsize::new(0));
    let attempts = Arc::clone(&candidate_attempts);
    let raw_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        attempts.fetch_add(1, Ordering::SeqCst);
        let mut buffer = [0_u8; 1_024];
        let _bytes_read = socket.read(&mut buffer).await.unwrap();
    });
    let gateway = start_gateway_with_route(
        &format!("{}/v1/chat/completions", baseline.address),
        &candidate_url,
        2,
        1,
    );
    let http = client(false);
    let url = format!("{}/v1/chat/completions", gateway.address);
    let request = || {
        http.post(&url)
            .bearer_auth(KEY)
            .header("content-type", "application/json")
            .body(r#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#)
    };

    let fallback = request().send().await.unwrap();
    assert_eq!(fallback.status(), reqwest::StatusCode::OK);
    assert_eq!(fallback.headers()["x-milk-route-target"], "openai");
    assert_eq!(fallback.text().await.unwrap(), "baseline-after-fuse");
    assert_eq!(baseline_count.load(Ordering::SeqCst), 1);
    assert_eq!(candidate_attempts.load(Ordering::SeqCst), 1);

    timeout(Duration::from_secs(1), raw_task)
        .await
        .unwrap()
        .unwrap();

    let later_call = request().send().await.unwrap();
    assert_eq!(later_call.status(), reqwest::StatusCode::OK);
    assert_eq!(later_call.headers()["x-milk-route-target"], "openai");
    assert_eq!(later_call.text().await.unwrap(), "baseline-after-fuse");
    assert_eq!(baseline_count.load(Ordering::SeqCst), 2);
    assert_eq!(candidate_attempts.load(Ordering::SeqCst), 1);
    assert_eq!(
        *baseline_bodies.lock().unwrap(),
        vec![
            Bytes::from_static(
                br#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#
            ),
            Bytes::from_static(
                br#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#
            ),
        ]
    );

    gateway.stop().await;
    baseline.stop().await;
}

#[actix_web::test]
async fn candidate_fallback_shares_one_total_upstream_deadline() {
    let baseline_count = Arc::new(AtomicUsize::new(0));
    let (baseline_listener, baseline_address) = listen();
    let baseline = {
        let count = Arc::clone(&baseline_count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(180)).await;
                    HttpResponse::Ok().body("too-late-baseline")
                }
            }))
        })
        .listen(baseline_listener)
        .unwrap()
        .run()
    };
    let baseline = RunningServer::start(baseline, baseline_address);

    let candidate_count = Arc::new(AtomicUsize::new(0));
    let (candidate_listener, candidate_address) = listen();
    let candidate = {
        let count = Arc::clone(&candidate_count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(180)).await;
                    HttpResponse::ServiceUnavailable().finish()
                }
            }))
        })
        .listen(candidate_listener)
        .unwrap()
        .run()
    };
    let candidate = RunningServer::start(candidate, candidate_address);

    let mut gateway_config = config(4_096, 2);
    gateway_config.connect_timeout_ms = 100;
    gateway_config.read_timeout_ms = 250;
    gateway_config.total_timeout_ms = 300;
    let gateway = start_gateway_with_route_config(
        &format!("{}/v1/chat/completions", baseline.address),
        &format!("{}/v1/chat/completions", candidate.address),
        gateway_config,
        1,
    );
    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .body(r#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert_eq!(response.headers()["x-milk-route-target"], "openai");
    let error: LocalEnvelope = response.json().await.unwrap();
    assert_eq!(error.error.code, "upstream_unavailable");
    assert_eq!(candidate_count.load(Ordering::SeqCst), 1);
    assert_eq!(baseline_count.load(Ordering::SeqCst), 1);

    gateway.stop().await;
    candidate.stop().await;
    baseline.stop().await;
}

#[actix_web::test]
async fn candidate_stream_transport_failure_opens_sticky_fuse() {
    let baseline_count = Arc::new(AtomicUsize::new(0));
    let (baseline_listener, baseline_address) = listen();
    let baseline = {
        let count = Arc::clone(&baseline_count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    HttpResponse::Ok().body("baseline-after-stream-fuse")
                }
            }))
        })
        .listen(baseline_listener)
        .unwrap()
        .run()
    };
    let baseline = RunningServer::start(baseline, baseline_address);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let candidate_url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let candidate_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 2_048];
        let _bytes_read = socket.read(&mut request).await.unwrap();
        socket
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{}",
            )
            .await
            .unwrap();
    });
    let gateway = start_gateway_with_route(
        &format!("{}/v1/chat/completions", baseline.address),
        &candidate_url,
        2,
        1,
    );
    let request = || {
        client(false)
            .post(format!("{}/v1/chat/completions", gateway.address))
            .bearer_auth(KEY)
            .header("content-type", "application/json")
            .body(r#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#)
    };

    let failed = request().send().await.unwrap();
    assert_eq!(failed.headers()["x-milk-route-target"], "candidate");
    assert!(failed.bytes().await.is_err());
    timeout(Duration::from_secs(1), candidate_task)
        .await
        .unwrap()
        .unwrap();

    let later = request().send().await.unwrap();
    assert_eq!(later.headers()["x-milk-route-target"], "openai");
    assert_eq!(later.text().await.unwrap(), "baseline-after-stream-fuse");
    assert_eq!(baseline_count.load(Ordering::SeqCst), 1);

    gateway.stop().await;
    baseline.stop().await;
}

#[actix_web::test]
async fn candidate_408_opens_sticky_fuse() {
    let (baseline_listener, baseline_address) = listen();
    let baseline = HttpServer::new(|| {
        App::new().default_service(web::to(|| async {
            HttpResponse::Ok().body("baseline-after-auth-failure")
        }))
    })
    .listen(baseline_listener)
    .unwrap()
    .run();
    let baseline = RunningServer::start(baseline, baseline_address);

    let attempts = Arc::new(AtomicUsize::new(0));
    let (candidate_listener, candidate_address) = listen();
    let candidate = {
        let attempts = Arc::clone(&attempts);
        HttpServer::new(move || {
            let attempts = Arc::clone(&attempts);
            App::new().default_service(web::to(move || {
                attempts.fetch_add(1, Ordering::SeqCst);
                async move { HttpResponse::RequestTimeout().finish() }
            }))
        })
        .listen(candidate_listener)
        .unwrap()
        .run()
    };
    let candidate = RunningServer::start(candidate, candidate_address);
    let gateway = start_gateway_with_route(
        &format!("{}/v1/chat/completions", baseline.address),
        &format!("{}/v1/chat/completions", candidate.address),
        3,
        1,
    );
    let http = client(false);
    let fallback = http
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .body(r#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(fallback.status(), reqwest::StatusCode::OK);
    assert_eq!(fallback.headers()["x-milk-route-target"], "openai");
    assert_eq!(
        fallback.text().await.unwrap(),
        "baseline-after-auth-failure"
    );

    let later = http
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .body(r#"{"model":"customer-model","messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(later.status(), reqwest::StatusCode::OK);
    assert_eq!(later.headers()["x-milk-route-target"], "openai");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    gateway.stop().await;
    candidate.stop().await;
    baseline.stop().await;
}

#[actix_web::test]
async fn redirect_and_transport_failure_never_make_a_second_attempt() {
    let target_count = Arc::new(AtomicUsize::new(0));
    let (target_listener, target_address) = listen();
    let target = {
        let count = Arc::clone(&target_count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    HttpResponse::Ok().finish()
                }
            }))
        })
        .listen(target_listener)
        .unwrap()
        .run()
    };
    let target = RunningServer::start(target, target_address);

    let (redirect_listener, redirect_address) = listen();
    let location = target.address.clone();
    let redirect = HttpServer::new(move || {
        let location = location.clone();
        App::new().default_service(web::to(move || {
            let location = location.clone();
            async move {
                HttpResponse::TemporaryRedirect()
                    .insert_header(("location", location))
                    .finish()
            }
        }))
    })
    .listen(redirect_listener)
    .unwrap()
    .run();
    let redirect = RunningServer::start(redirect, redirect_address);
    let gateway = start_gateway(
        &format!("{}/v1/chat/completions", redirect.address),
        1_024,
        2,
    );

    let response = client(true)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    assert!(response.headers().get("location").is_none());
    assert_eq!(target_count.load(Ordering::SeqCst), 0);
    gateway.stop().await;
    redirect.stop().await;
    target.stop().await;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_url = format!(
        "http://{}/v1/chat/completions",
        listener.local_addr().unwrap()
    );
    let accepts = Arc::new(AtomicUsize::new(0));
    let accept_count = Arc::clone(&accepts);
    let raw_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        accept_count.fetch_add(1, Ordering::SeqCst);
        let mut buffer = [0_u8; 1_024];
        let _bytes_read = socket.read(&mut buffer).await.unwrap();
    });
    let gateway = start_gateway(&upstream_url, 1_024, 2);
    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::BAD_GATEWAY);
    timeout(Duration::from_secs(1), raw_task)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(accepts.load(Ordering::SeqCst), 1);
    gateway.stop().await;
}

#[actix_web::test]
async fn sse_streams_before_completion_and_admission_stays_bounded() {
    let mut first_bytes = b"data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"".to_vec();
    first_bytes.push(0xf0);
    let first = Bytes::from(first_bytes);
    let mut second_bytes = vec![0x9f, 0xa7, 0xaa];
    second_bytes.extend_from_slice(
        b"\"}}]}}]}\n\ndata: {\"choices\":[],\"usage\":{\"total_tokens\":3}}\n\ndata: [DONE]\n\n",
    );
    let second = Bytes::from(second_bytes);
    let first_expected = first.clone();
    let expected = [first.as_ref(), second.as_ref()].concat();
    let gate = Arc::new(Notify::new());
    let upstream_count = Arc::new(AtomicUsize::new(0));
    let (listener, upstream_address) = listen();
    let upstream = {
        let gate = Arc::clone(&gate);
        let count = Arc::clone(&upstream_count);
        HttpServer::new(move || {
            let gate = Arc::clone(&gate);
            let count = Arc::clone(&count);
            let first = first.clone();
            let second = second.clone();
            App::new().default_service(web::to(move || {
                let gate = Arc::clone(&gate);
                let count = Arc::clone(&count);
                let first = first.clone();
                let second = second.clone();
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let body = stream::unfold((0_u8, gate, first, second), |state| async move {
                        let (step, gate, first, second) = state;
                        match step {
                            0 => Some((
                                Ok::<_, actix_web::Error>(first.clone()),
                                (1, gate, first, second),
                            )),
                            1 => {
                                gate.notified().await;
                                Some((Ok(second.clone()), (2, gate, first, second)))
                            }
                            _ => None,
                        }
                    });
                    HttpResponse::Ok()
                        .insert_header(("content-type", "text/event-stream"))
                        .streaming(body)
                }
            }))
        })
        .listen(listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address);
    let gateway = start_gateway(
        &format!("{}/v1/chat/completions", upstream.address),
        1_024,
        1,
    );

    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    let mut body = response.bytes_stream();
    let prefix = timeout(Duration::from_secs(1), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(prefix, first_expected);

    let rejected = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(rejected.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
    let error: LocalEnvelope = rejected.json().await.unwrap();
    assert_eq!(error.error.code, "gateway_over_capacity");
    assert_eq!(upstream_count.load(Ordering::SeqCst), 1);

    gate.notify_one();
    let mut actual = prefix.to_vec();
    while let Some(chunk) = body.next().await {
        actual.extend_from_slice(&chunk.unwrap());
    }
    assert_eq!(actual, expected);

    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn stalled_capture_consumer_cannot_delay_response_eof() {
    let first = Bytes::from_static(b"data: {\"delta\":\"");
    let second = Bytes::from_static(b"\x00\xff\"}\n\ndata: [DONE]\n\n");
    let expected = [first.as_ref(), second.as_ref()].concat();
    let (listener, upstream_address) = listen();
    let upstream = HttpServer::new(move || {
        let first = first.clone();
        let second = second.clone();
        App::new().default_service(web::to(move || {
            let body = stream::iter([Ok::<_, actix_web::Error>(first.clone()), Ok(second.clone())]);
            async move {
                HttpResponse::Ok()
                    .insert_header(("content-type", "text/event-stream"))
                    .streaming(body)
            }
        }))
    })
    .listen(listener)
    .unwrap()
    .run();
    let upstream = RunningServer::start(upstream, upstream_address);

    let mut gateway_config = config(1_024, 1);
    gateway_config.capture_mode = CaptureMode::WholeBodyAuthorized;
    gateway_config.capture_basis_points = 10_000;
    gateway_config.capture_response_bytes = 1_024;
    gateway_config.capture_record_bytes = 4_096;
    gateway_config.capture_queue_bytes = 8_192;
    gateway_config.capture_policy_version = "test-authorized-v1".to_owned();
    gateway_config.capture_rights_state = "authorized".to_owned();
    let records = Records::stalled_for_test(
        gateway_config.capture_queue_bytes,
        gateway_config.capture_record_bytes,
    )
    .unwrap();
    let queue_probe = records.clone();
    let gateway = start_gateway_with_records(
        &format!("{}/v1/chat/completions", upstream.address),
        gateway_config.clone(),
        Some(records),
    );

    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .header("content-type", "application/json")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .unwrap();
    let actual = timeout(Duration::from_secs(1), response.bytes())
        .await
        .expect("response EOF must not wait for capture work")
        .unwrap();
    assert_eq!(actual.as_ref(), expected);
    assert!(
        queue_probe.available_queue_bytes_for_test() < gateway_config.capture_queue_bytes,
        "EOF must enqueue a raw capture while the consumer is stalled"
    );

    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn oversized_request_never_reaches_upstream() {
    let count = Arc::new(AtomicUsize::new(0));
    let (listener, upstream_address) = listen();
    let upstream = {
        let count = Arc::clone(&count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    HttpResponse::Ok().finish()
                }
            }))
        })
        .listen(listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address);
    let gateway = start_gateway(&format!("{}/v1/chat/completions", upstream.address), 4, 1);
    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("12345")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::PAYLOAD_TOO_LARGE);
    let error: LocalEnvelope = response.json().await.unwrap();
    assert_eq!(error.error.code, "request_too_large");
    assert_eq!(count.load(Ordering::SeqCst), 0);
    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn slow_request_body_releases_admission_without_calling_upstream() {
    let count = Arc::new(AtomicUsize::new(0));
    let (listener, upstream_address) = listen();
    let upstream = {
        let count = Arc::clone(&count);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    HttpResponse::Ok().finish()
                }
            }))
        })
        .listen(listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address);
    let mut gateway_config = config(1_024, 1);
    gateway_config.request_body_timeout_ms = 50;
    let gateway = start_gateway_with_config(
        &format!("{}/v1/chat/completions", upstream.address),
        gateway_config,
    );

    let gateway_address = gateway.address.strip_prefix("http://").unwrap();
    let mut socket = tokio::net::TcpStream::connect(gateway_address)
        .await
        .unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {gateway_address}\r\nAuthorization: Bearer {KEY}\r\nContent-Length: 5\r\n\r\n1"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    let response = timeout(Duration::from_secs(1), async {
        let mut response = Vec::new();
        let mut chunk = [0_u8; 256];
        while !response.windows(2).any(|bytes| bytes == b"\r\n") {
            let read = socket.read(&mut chunk).await.unwrap();
            assert_ne!(read, 0, "connection closed before a status line arrived");
            response.extend_from_slice(&chunk[..read]);
        }
        response
    })
    .await
    .unwrap();
    let response = std::str::from_utf8(&response).unwrap();
    assert!(response.starts_with("HTTP/1.1 408"), "{response}");
    assert_eq!(count.load(Ordering::SeqCst), 0);
    drop(socket);

    let admitted = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), reqwest::StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 1);

    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn pre_header_disconnect_cancels_upstream_and_releases_admission() {
    struct DropProbe(Option<oneshot::Sender<()>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                sender.send(()).unwrap_or(());
            }
        }
    }

    let count = Arc::new(AtomicUsize::new(0));
    let (started_tx, started_rx) = oneshot::channel();
    let started_tx = Arc::new(Mutex::new(Some(started_tx)));
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let dropped_tx = Arc::new(Mutex::new(Some(dropped_tx)));
    let (listener, upstream_address) = listen();
    let upstream = {
        let count = Arc::clone(&count);
        let started_tx = Arc::clone(&started_tx);
        let dropped_tx = Arc::clone(&dropped_tx);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            let started_tx = Arc::clone(&started_tx);
            let dropped_tx = Arc::clone(&dropped_tx);
            App::new().default_service(web::to(move || {
                let request_number = count.fetch_add(1, Ordering::SeqCst);
                let started_tx = Arc::clone(&started_tx);
                let dropped_tx = Arc::clone(&dropped_tx);
                async move {
                    if request_number == 0 {
                        started_tx.lock().unwrap().take().unwrap().send(()).unwrap();
                        let _probe = DropProbe(dropped_tx.lock().unwrap().take());
                        std::future::pending::<()>().await;
                    }
                    HttpResponse::Ok().finish()
                }
            }))
        })
        .h1_allow_half_closed(false)
        .listen(listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address);
    let gateway = start_gateway(
        &format!("{}/v1/chat/completions", upstream.address),
        1_024,
        1,
    );

    let gateway_address = gateway.address.strip_prefix("http://").unwrap();
    let mut socket = tokio::net::TcpStream::connect(gateway_address)
        .await
        .unwrap();
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {gateway_address}\r\nAuthorization: Bearer {KEY}\r\nContent-Length: 2\r\n\r\n{{}}"
    );
    socket.write_all(request.as_bytes()).await.unwrap();
    timeout(Duration::from_secs(1), started_rx)
        .await
        .expect("first upstream request should start")
        .unwrap();
    drop(socket);

    let admitted = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(admitted.status(), reqwest::StatusCode::OK);
    assert_eq!(count.load(Ordering::SeqCst), 2);
    timeout(Duration::from_secs(1), dropped_rx)
        .await
        .expect("pre-header upstream request should be cancelled")
        .unwrap();

    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn downstream_disconnect_drops_the_upstream_stream() {
    struct DropProbe(Option<oneshot::Sender<()>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                sender.send(()).unwrap_or(());
            }
        }
    }

    let count = Arc::new(AtomicUsize::new(0));
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let dropped_tx = Arc::new(Mutex::new(Some(dropped_tx)));
    let (listener, upstream_address) = listen();
    let upstream = {
        let count = Arc::clone(&count);
        let dropped_tx = Arc::clone(&dropped_tx);
        HttpServer::new(move || {
            let count = Arc::clone(&count);
            let dropped_tx = Arc::clone(&dropped_tx);
            App::new().default_service(web::to(move || {
                let count = Arc::clone(&count);
                let dropped_tx = Arc::clone(&dropped_tx);
                async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    let probe = DropProbe(dropped_tx.lock().unwrap().take());
                    let body = stream::unfold((true, probe), |(first, probe)| async move {
                        if !first {
                            tokio::time::sleep(Duration::from_millis(10)).await;
                        }
                        Some((
                            Ok::<_, actix_web::Error>(Bytes::from_static(b"data: x\n\n")),
                            (false, probe),
                        ))
                    });
                    HttpResponse::Ok()
                        .insert_header(("content-type", "text/event-stream"))
                        .streaming(body)
                }
            }))
        })
        .listen(listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address);
    let gateway = start_gateway(
        &format!("{}/v1/chat/completions", upstream.address),
        1_024,
        1,
    );

    let response = client(false)
        .post(format!("{}/v1/chat/completions", gateway.address))
        .bearer_auth(KEY)
        .body("{}")
        .send()
        .await
        .unwrap();
    let mut body = response.bytes_stream();
    timeout(Duration::from_secs(1), body.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(body);

    timeout(Duration::from_secs(2), dropped_rx)
        .await
        .expect("upstream stream should be dropped after downstream disconnect")
        .unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 1);

    gateway.stop().await;
    upstream.stop().await;
}

#[actix_web::test]
async fn official_sdk_traces_persist_once_across_restarts() {
    #[derive(Deserialize)]
    struct SdkReceipt {
        content_retained: bool,
        succeeded: bool,
    }

    let test_directory = fs::canonicalize(std::env::temp_dir())
        .unwrap()
        .join(format!("milk-carton-capture-{}", Uuid::now_v7()));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&test_directory)
        .unwrap();
    let object_root = test_directory.join("objects");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&object_root)
        .unwrap();
    let loose_root = test_directory.join("loose");
    fs::DirBuilder::new()
        .mode(0o755)
        .create(&loose_root)
        .unwrap();
    assert!(crate::records::build_local(&loose_root).is_err());
    let linked_root = test_directory.join("linked");
    symlink(&object_root, &linked_root).unwrap();
    assert!(crate::records::build_local(&linked_root).is_err());
    fs::remove_file(&linked_root).unwrap();

    let (baseline_listener, baseline_address) = listen();
    let baseline = HttpServer::new(|| {
        App::new().route(
            "/v1/chat/completions",
            web::post().to(|request: HttpRequest| async move {
                assert_eq!(
                    request
                        .headers()
                        .get("authorization")
                        .and_then(|value| value.to_str().ok()),
                    Some("Bearer test-managed-openai-key")
                );
                HttpResponse::Ok().content_type("application/json").body(
                    r#"{"id":"capture-smoke","object":"chat.completion","created":1,"model":"capture-smoke-baseline","choices":[{"index":0,"message":{"role":"assistant","content":"Confirmed."},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":1,"total_tokens":11}}"#,
                )
            }),
        )
    })
    .listen(baseline_listener)
    .unwrap()
    .run();
    let baseline = RunningServer::start(baseline, baseline_address);

    let mut gateway_config = config(16_384, 1);
    gateway_config.max_active_body_bytes = 262_144;
    gateway_config.capture_mode = CaptureMode::WholeBodyAuthorized;
    gateway_config.capture_basis_points = 10_000;
    gateway_config.capture_response_bytes = 16_384;
    gateway_config.capture_record_bytes = 65_536;
    gateway_config.capture_queue_bytes = 131_072;
    gateway_config.capture_policy_version = "local-owner-v1".into();
    gateway_config.capture_rights_state = "owner_authorized".into();
    gateway_config.capture_retention_days = 30;
    gateway_config.stores = local_stores(&object_root);
    gateway_config.baseline = OpenAiCompatibleEndpoint {
        api_base_url: format!("{}/v1/", baseline.address),
        allow_loopback_http: true,
    };
    validate_config_identity(&gateway_config).unwrap();

    let records = start_records(
        &gateway_config,
        StoreAccessPlan::for_command(&super::Command::Serve),
    )
    .await
    .unwrap();
    let records_probe = records.clone();
    let (gateway_listener, gateway_address) = listen();
    let gateway = Gateway::with_route(
        &gateway_config,
        parse_openai_compatible_api_base_url(
            &gateway_config.baseline.api_base_url,
            gateway_config.baseline.allow_loopback_http,
        )
        .unwrap(),
        Some(records),
        RoutePolicy::baseline(),
        Some("test-managed-openai-key"),
        None,
    )
    .unwrap();
    let gateway = RunningServer::start(
        build_server(gateway_listener, gateway).unwrap(),
        gateway_address,
    );

    for _ in 0..3 {
        let output = timeout(Duration::from_secs(5), {
            let mut command = tokio::process::Command::new("node");
            command
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/tests/capture-sdk-smoke.mjs"
                ))
                .arg(&gateway.address)
                .kill_on_drop(true);
            command.output()
        })
        .await
        .expect("local SDK fixture should finish within five seconds")
        .expect("node should execute the local SDK fixture");
        assert!(
            output.status.success(),
            "local SDK fixture failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let sdk_receipt: SdkReceipt = serde_json::from_slice(&output.stdout).unwrap();
        assert!(sdk_receipt.succeeded);
        assert!(!sdk_receipt.content_retained);
    }
    timeout(Duration::from_secs(2), async {
        loop {
            if records_probe.health().traces_persisted == 3 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("captured trace should persist locally");
    gateway.stop().await;
    drop(records_probe);
    baseline.stop().await;
    assert!(fs::read_dir(&object_root).unwrap().next().is_some());

    fs::set_permissions(&test_directory, fs::Permissions::from_mode(0o700)).unwrap();
    fs::remove_dir_all(&test_directory).unwrap();
}

#[actix_web::test]
async fn official_node_sdk_is_chat_and_responses_compatible() {
    #[derive(Deserialize)]
    struct SmokeRequest {
        model: String,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SmokeReceipt {
        advanced_request: String,
        multimodal_request: String,
        multimodal_content: String,
        nonstream_content: String,
        responses_nonstream_text: String,
        responses_request: String,
        responses_stream_request: String,
        responses_stream_terminal: String,
        responses_stream_text: String,
        stream_text: String,
        missing_key_status: u16,
        rate_limit_status: u16,
        cancelled: bool,
    }

    struct DropProbe(Option<oneshot::Sender<()>>);

    impl Drop for DropProbe {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                sender.send(()).unwrap_or(());
            }
        }
    }

    let seen = Arc::new(Mutex::new(Vec::<SeenRequest>::new()));
    let stream_gate = Arc::new(Notify::new());
    let (dropped_tx, dropped_rx) = oneshot::channel();
    let dropped_tx = Arc::new(Mutex::new(Some(dropped_tx)));
    let (listener, upstream_address) = listen();
    let upstream = {
        let seen = Arc::clone(&seen);
        let stream_gate = Arc::clone(&stream_gate);
        let dropped_tx = Arc::clone(&dropped_tx);
        HttpServer::new(move || {
            let chat_seen = Arc::clone(&seen);
            let responses_seen = Arc::clone(&seen);
            let request_gate = Arc::clone(&stream_gate);
            let release_gate = Arc::clone(&stream_gate);
            let dropped_tx = Arc::clone(&dropped_tx);
            App::new()
                .route(
                    "/v1/chat/completions",
                    web::post().to(move |request: HttpRequest, body: Bytes| {
                        let seen = Arc::clone(&chat_seen);
                        let request_gate = Arc::clone(&request_gate);
                        let dropped_tx = Arc::clone(&dropped_tx);
                        async move {
                            let parsed: SmokeRequest = serde_json::from_slice(&body).unwrap();
                            let headers = request
                                .headers()
                                .iter()
                                .map(|(name, value)| {
                                    (name.as_str().to_owned(), value.as_bytes().to_vec())
                                })
                                .collect();
                            seen.lock().unwrap().push(SeenRequest {
                                query: request.query_string().to_owned(),
                                body,
                                headers,
                            });

                            match parsed.model.as_str() {
                                "sdk-nonstream" => HttpResponse::Ok()
                                    .insert_header(("content-type", "application/json"))
                                    .insert_header(("x-request-id", "req-nonstream"))
                                    .body(Bytes::from_static(
                                        br#"{"id":"chatcmpl-nonstream","object":"chat.completion","created":1,"model":"sdk-nonstream","choices":[{"index":0,"message":{"role":"assistant","content":"{\"ok\":true}"},"finish_reason":"stop","logprobs":null}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                                    )),
                                "sdk-multimodal" => HttpResponse::Ok()
                                    .insert_header(("content-type", "application/json"))
                                    .body(Bytes::from_static(
                                        br#"{"id":"chatcmpl-multimodal","object":"chat.completion","created":1,"model":"sdk-multimodal","choices":[{"index":0,"message":{"role":"assistant","content":"hello"},"finish_reason":"stop","logprobs":null}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#,
                                    )),
                                "sdk-stream" => {
                                    let body = stream::unfold(
                                        (0_u8, request_gate),
                                        |(step, gate)| async move {
                                            match step {
                                                0 => Some((
                                                    Ok::<_, actix_web::Error>(Bytes::from_static(
                                                        br#"data: {"id":"chatcmpl-stream","object":"chat.completion.chunk","created":1,"model":"sdk-stream","choices":[{"index":0,"delta":{"role":"assistant","content":"hel"},"finish_reason":null}]}

"#,
                                                    )),
                                                    (1, gate),
                                                )),
                                                1 => {
                                                    gate.notified().await;
                                                    Some((
                                                        Ok(Bytes::from_static(
                                                            br#"data: {"id":"chatcmpl-stream","object":"chat.completion.chunk","created":1,"model":"sdk-stream","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":null}]}

data: {"id":"chatcmpl-stream","object":"chat.completion.chunk","created":1,"model":"sdk-stream","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}

data: [DONE]

"#,
                                                        )),
                                                        (2, gate),
                                                    ))
                                                }
                                                _ => None,
                                            }
                                        },
                                    );
                                    HttpResponse::Ok()
                                        .insert_header(("content-type", "text/event-stream"))
                                        .streaming(body)
                                }
                                "sdk-rate-limit" => HttpResponse::TooManyRequests()
                                    .insert_header(("content-type", "application/json"))
                                    .insert_header(("x-request-id", "req-rate-limit"))
                                    .body(Bytes::from_static(
                                        br#"{"error":{"message":"Rate limited.","type":"rate_limit_error","param":null,"code":"rate_limit_exceeded"}}"#,
                                    )),
                                "sdk-cancel" => {
                                    let probe =
                                        DropProbe(dropped_tx.lock().unwrap().take());
                                    let body = stream::unfold(
                                        (true, probe),
                                        |(first, probe)| async move {
                                            let chunk = if first {
                                                Bytes::from_static(
                                                        br#"data: {"id":"chatcmpl-cancel","object":"chat.completion.chunk","created":1,"model":"sdk-cancel","choices":[{"index":0,"delta":{"role":"assistant","content":"first"},"finish_reason":null}]}

"#,
                                                    )
                                            } else {
                                                tokio::time::sleep(Duration::from_millis(10)).await;
                                                Bytes::from_static(b": heartbeat\n\n")
                                            };
                                            Some((
                                                Ok::<_, actix_web::Error>(chunk),
                                                (false, probe),
                                            ))
                                        },
                                    );
                                    HttpResponse::Ok()
                                        .insert_header(("content-type", "text/event-stream"))
                                        .streaming(body)
                                }
                                model => HttpResponse::BadRequest().body(model.to_owned()),
                            }
                        }
                    }),
                )
                .route(
                    "/v1/responses",
                    web::post().to(move |request: HttpRequest, body: Bytes| {
                        let seen = Arc::clone(&responses_seen);
                        async move {
                            let parsed: SmokeRequest = serde_json::from_slice(&body).unwrap();
                            let headers = request
                                .headers()
                                .iter()
                                .map(|(name, value)| {
                                    (name.as_str().to_owned(), value.as_bytes().to_vec())
                                })
                                .collect();
                            seen.lock().unwrap().push(SeenRequest {
                                query: request.query_string().to_owned(),
                                body,
                                headers,
                            });

                            match parsed.model.as_str() {
                                "sdk-responses-nonstream" => HttpResponse::Ok()
                                    .insert_header(("content-type", "application/json"))
                                    .body(Bytes::from_static(
                                        br#"{"id":"resp-sdk-nonstream","object":"response","created_at":1,"status":"completed","error":null,"incomplete_details":null,"instructions":null,"metadata":{},"model":"sdk-responses-nonstream","output":[{"id":"msg-sdk-nonstream","type":"message","status":"completed","role":"assistant","content":[{"type":"output_text","annotations":[],"logprobs":[],"text":"responses-ok"}]}],"parallel_tool_calls":true,"temperature":1.0,"tool_choice":"auto","tools":[],"top_p":1.0}"#,
                                    )),
                                "sdk-responses-stream" => HttpResponse::Ok()
                                    .insert_header(("content-type", "text/event-stream"))
                                    .body(Bytes::from_static(
                                        concat!(
                                            "event: response.output_text.delta\n",
                                            "data: {\"type\":\"response.output_text.delta\",\"content_index\":0,\"delta\":\"responses-stream-ok\",\"item_id\":\"msg-sdk-stream\",\"logprobs\":[],\"output_index\":0,\"sequence_number\":1}\n\n",
                                            "event: response.completed\n",
                                            "data: {\"type\":\"response.completed\",\"sequence_number\":2,\"response\":{\"id\":\"resp-sdk-stream\",\"object\":\"response\",\"created_at\":1,\"status\":\"completed\",\"error\":null,\"incomplete_details\":null,\"instructions\":null,\"metadata\":{},\"model\":\"sdk-responses-stream\",\"output\":[{\"id\":\"msg-sdk-stream\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"annotations\":[],\"logprobs\":[],\"text\":\"responses-stream-ok\"}]}],\"parallel_tool_calls\":true,\"temperature\":1.0,\"tool_choice\":\"auto\",\"tools\":[],\"top_p\":1.0}}\n\n",
                                        )
                                        .as_bytes(),
                                    )),
                                model => HttpResponse::BadRequest().body(model.to_owned()),
                            }
                        }
                    }),
                )
                .route(
                    "/release-stream",
                    web::post().to(move || {
                        let release_gate = Arc::clone(&release_gate);
                        async move {
                            release_gate.notify_one();
                            HttpResponse::NoContent().finish()
                        }
                    }),
                )
        })
        .listen(listener)
        .unwrap()
        .run()
    };
    let upstream = RunningServer::start(upstream, upstream_address);
    let mut gateway_config = config(4_096, 1);
    gateway_config.read_timeout_ms = 10_000;
    gateway_config.total_timeout_ms = 10_000;
    let gateway = start_gateway_with_config(
        &format!("{}/v1/chat/completions", upstream.address),
        gateway_config,
    );

    let mut command = tokio::process::Command::new("node");
    command
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/openai-sdk-smoke.mjs"
        ))
        .arg(&gateway.address)
        .arg(&upstream.address)
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(5), command.output())
        .await
        .expect("OpenAI SDK smoke should finish within five seconds")
        .expect("node should execute the OpenAI SDK smoke");
    assert!(
        output.status.success(),
        "OpenAI SDK smoke failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let receipt: SmokeReceipt = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(receipt.nonstream_content, r#"{"ok":true}"#);
    assert_eq!(receipt.multimodal_content, "hello");
    assert_eq!(receipt.stream_text, "hello");
    assert_eq!(receipt.responses_nonstream_text, "responses-ok");
    assert_eq!(receipt.responses_stream_text, "responses-stream-ok");
    assert_eq!(receipt.responses_stream_terminal, "response.completed");
    assert_eq!(receipt.missing_key_status, 401);
    assert_eq!(receipt.rate_limit_status, 429);
    assert!(receipt.cancelled);
    timeout(Duration::from_secs(2), dropped_rx)
        .await
        .expect("SDK cancellation should drop the upstream response body")
        .unwrap();

    {
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 7);
        let mut nonstream = 0;
        let mut multimodal = 0;
        let mut streamed = 0;
        let mut responses_nonstream = 0;
        let mut responses_stream = 0;
        let mut rate_limited = 0;
        let mut cancelled = 0;
        let mut missing_key = 0;
        for request in seen.iter() {
            let parsed: SmokeRequest = serde_json::from_slice(&request.body).unwrap();
            match parsed.model.as_str() {
                "sdk-nonstream" => nonstream += 1,
                "sdk-multimodal" => multimodal += 1,
                "sdk-stream" => streamed += 1,
                "sdk-responses-nonstream" => responses_nonstream += 1,
                "sdk-responses-stream" => responses_stream += 1,
                "sdk-rate-limit" => rate_limited += 1,
                "sdk-cancel" => cancelled += 1,
                "sdk-missing-key" => missing_key += 1,
                model => panic!("unexpected SDK smoke request model {model}"),
            }
            assert!(header(&request.headers, "x-milk-key").is_none());
        }
        assert_eq!(
            (
                nonstream,
                multimodal,
                streamed,
                responses_nonstream,
                responses_stream,
                rate_limited,
                cancelled,
                missing_key,
            ),
            (1, 1, 1, 1, 1, 1, 1, 0)
        );

        let advanced = seen
            .iter()
            .find(|request| request.body.as_ref() == receipt.advanced_request.as_bytes())
            .expect("advanced SDK request should reach upstream byte-for-byte");
        assert!(advanced.query.is_empty());
        assert_eq!(
            header(&advanced.headers, "authorization"),
            Some(b"Bearer test-managed-openai-key".as_slice())
        );

        seen.iter()
            .find(|request| request.body.as_ref() == receipt.multimodal_request.as_bytes())
            .expect("multimodal SDK request should reach upstream byte-for-byte");

        for expected in [
            receipt.responses_request.as_bytes(),
            receipt.responses_stream_request.as_bytes(),
        ] {
            let request = seen
                .iter()
                .find(|request| request.body.as_ref() == expected)
                .expect("Responses SDK request should reach upstream byte-for-byte");
            let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            assert_eq!(value["unknown_extension"]["keep"], true);
        }
    }

    gateway.stop().await;
    upstream.stop().await;
}

fn header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_slice())
}
