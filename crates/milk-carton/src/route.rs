use std::time::Instant;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, TimeDelta, Timelike, Utc};
use clap::ValueEnum;
use ring::{hmac, signature};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use url::{Host, Url};
use uuid::Uuid;

pub(crate) const ROUTE_SCHEMA_VERSION: &str = "milk.route.v4";
pub(crate) const OPERATOR_ROUTE_PROPOSAL_SCHEMA_VERSION: &str = "milk.unsigned-route-proposal.v1";
pub(crate) const OPERATOR_ROUTE_SCHEMA_VERSION: &str = "milk.route.v1";
pub(crate) const WINNER_ADMISSION_SCHEMA_VERSION: &str = "milk.winner-admission-receipt.v2";
const ROUTE_LIVE_SCHEMA_VERSION: &str = "milk.route-live.v1";
const BASELINE_ROUTE_REVISION: &str = "openai-baseline-v1";
pub(crate) const MAX_ROUTE_MANIFEST_BYTES: usize = 8 * 1_024;
pub(crate) const MAX_WINNER_ADMISSION_BYTES: usize = 8 * 1_024;
pub(crate) const ED25519_SIGNATURE_BYTES: usize = 64;
pub(crate) const MAX_ROUTE_LIVE_BYTES: usize = 1_024;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_MODEL_BYTES: usize = 256;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_PROVIDER_BYTES: usize = 64;
const MAX_EXECUTION_ID_BYTES: usize = 256;
const MAX_IMAGE_REFERENCE_BYTES: usize = 2_048;
const MAX_CAPABILITIES: usize = 8;
pub(crate) const CANDIDATE_CONTEXT_WINDOW_TOKENS: u32 = 4_096;
pub(crate) const CANDIDATE_MAX_INPUT_UTF8_BYTES: usize = 2_048;
pub(crate) const CANDIDATE_MAX_INPUT_MESSAGES: usize = 16;
pub(crate) const CANDIDATE_MAX_INPUT_REQUEST_BYTES: usize = 16_384;
pub(crate) const WINNER_CANARY_BASIS_POINTS: u16 = 100;
pub(crate) const WINNER_CANARY_VALID_FOR_SECONDS: u32 = 15 * 60;
pub(crate) const WINNER_ZERO_VALID_FOR_SECONDS: u32 = 60;
pub(crate) const WINNER_ROUTE_RUNWAY_SECONDS: u32 =
    WINNER_CANARY_VALID_FOR_SECONDS + WINNER_ZERO_VALID_FOR_SECONDS;
pub(crate) const MAX_WINNER_DEPLOYMENT_WALL_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const MAX_WINNER_DEPLOYMENT_COST_MICROUSD: u64 = 1_000_000_000;
pub(crate) const WINNER_PROVIDER: &str = "baseten";
const TEMPLATE_TOKENS_PER_MESSAGE: usize = 64;
const OUTPUT_AND_FIXED_RESERVE_TOKENS: usize = 1_024;
const _: () = assert!(
    CANDIDATE_MAX_INPUT_UTF8_BYTES
        + CANDIDATE_MAX_INPUT_MESSAGES * TEMPLATE_TOKENS_PER_MESSAGE
        + OUTPUT_AND_FIXED_RESERVE_TOKENS
        <= CANDIDATE_CONTEXT_WINDOW_TOKENS as usize
);
const MAX_ROUTE_VALIDITY_HOURS: i64 = 24;
const MAX_PUBLICATION_START_DELAY_MINUTES: i64 = 5;
const NON_PRODUCTION_MECHANICS_SCOPE_ID: u128 = 0xf7f88ff0_5947_440c_a661_e4e35f1d04e0;
const NON_PRODUCTION_MECHANICS_EVAL_SHA256: &str =
    "26b09c53937d80b07bc49f42beeca8562eaa4b303023d13033777da472c04499";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteStartupConfig {
    pub(crate) signing_public_key_hex: String,
    pub(crate) signing_key_id: String,
    pub(crate) allow_private_candidate_http: bool,
    pub(crate) authorized_provider_terms_sha256: Option<String>,
    pub(crate) authorized_student_branch_runtime_image_reference: Option<String>,
    pub(crate) authorized_admission_program_sha256: Option<String>,
    pub(crate) winner_authorization_not_after: Option<DateTime<Utc>>,
    pub(crate) winner_max_wall_seconds: Option<u64>,
    pub(crate) winner_max_cost_microusd: Option<u64>,
    pub(crate) candidate_max_in_flight: usize,
}

impl RouteStartupConfig {
    pub(crate) fn validate(&self, gateway_max_in_flight: usize) -> Result<()> {
        self.winner_deployment_authority()?.validate()?;
        self.validate_common(gateway_max_in_flight)
    }

    pub(crate) fn validate_common(&self, gateway_max_in_flight: usize) -> Result<()> {
        decode_lowercase_hex_32(&self.signing_public_key_hex, "route signing public key")?;
        if self.signing_key_id.is_empty() || self.signing_key_id.len() > MAX_KEY_ID_BYTES {
            bail!("route signing key ID is invalid");
        }
        let winner_fields = [
            self.authorized_provider_terms_sha256.is_some(),
            self.authorized_student_branch_runtime_image_reference
                .is_some(),
            self.authorized_admission_program_sha256.is_some(),
            self.winner_authorization_not_after.is_some(),
            self.winner_max_wall_seconds.is_some(),
            self.winner_max_cost_microusd.is_some(),
        ];
        if winner_fields.iter().any(|configured| *configured)
            && !winner_fields.iter().all(|configured| *configured)
        {
            bail!("legacy winner route authorization must be complete or omitted");
        }
        if gateway_max_in_flight < 2
            || self.candidate_max_in_flight == 0
            || self.candidate_max_in_flight >= gateway_max_in_flight
        {
            bail!("candidate_max_in_flight must reserve at least one baseline request slot");
        }
        Ok(())
    }

    pub(crate) fn winner_deployment_authority(&self) -> Result<WinnerDeploymentAuthority> {
        let authority = WinnerDeploymentAuthority {
            schema_version: "milk.winner-deployment-authority.v3".to_owned(),
            provider_policy: WinnerProviderPolicy {
                only: WINNER_PROVIDER.to_owned(),
            },
            provider_terms_sha256: self
                .authorized_provider_terms_sha256
                .clone()
                .context("legacy winner route authorization is not configured")?,
            student_branch_runtime_image_reference: self
                .authorized_student_branch_runtime_image_reference
                .clone()
                .context("legacy winner route authorization is not configured")?,
            admission_program_sha256: self
                .authorized_admission_program_sha256
                .clone()
                .context("legacy winner route authorization is not configured")?,
            authorization_not_after: self
                .winner_authorization_not_after
                .context("legacy winner route authorization is not configured")?,
            max_wall_seconds: self
                .winner_max_wall_seconds
                .context("legacy winner route authorization is not configured")?,
            max_cost_microusd: self
                .winner_max_cost_microusd
                .context("legacy winner route authorization is not configured")?,
            allow_private_candidate_http: self.allow_private_candidate_http,
            signing_public_key_hex: self.signing_public_key_hex.clone(),
            signing_key_id: self.signing_key_id.clone(),
            candidate_max_in_flight: self.candidate_max_in_flight,
            canary_candidate_basis_points: WINNER_CANARY_BASIS_POINTS,
            canary_valid_for_seconds: WINNER_CANARY_VALID_FOR_SECONDS,
            max_input_utf8_bytes: CANDIDATE_MAX_INPUT_UTF8_BYTES,
            max_input_messages: CANDIDATE_MAX_INPUT_MESSAGES,
            max_input_request_bytes: CANDIDATE_MAX_INPUT_REQUEST_BYTES,
            route_schema_version: ROUTE_SCHEMA_VERSION.to_owned(),
            winner_admission_schema_version: WINNER_ADMISSION_SCHEMA_VERSION.to_owned(),
        };
        authority.validate()?;
        Ok(authority)
    }

    pub(crate) fn has_winner_deployment_authority(&self) -> bool {
        self.authorized_provider_terms_sha256.is_some()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WinnerDeploymentAuthority {
    pub(crate) schema_version: String,
    pub(crate) provider_policy: WinnerProviderPolicy,
    pub(crate) provider_terms_sha256: String,
    pub(crate) student_branch_runtime_image_reference: String,
    pub(crate) admission_program_sha256: String,
    pub(crate) authorization_not_after: DateTime<Utc>,
    pub(crate) max_wall_seconds: u64,
    pub(crate) max_cost_microusd: u64,
    pub(crate) allow_private_candidate_http: bool,
    pub(crate) signing_public_key_hex: String,
    pub(crate) signing_key_id: String,
    pub(crate) candidate_max_in_flight: usize,
    pub(crate) canary_candidate_basis_points: u16,
    pub(crate) canary_valid_for_seconds: u32,
    pub(crate) max_input_utf8_bytes: usize,
    pub(crate) max_input_messages: usize,
    pub(crate) max_input_request_bytes: usize,
    pub(crate) route_schema_version: String,
    pub(crate) winner_admission_schema_version: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WinnerProviderPolicy {
    pub(crate) only: String,
}

impl WinnerDeploymentAuthority {
    pub(crate) fn validate(&self) -> Result<()> {
        decode_lowercase_hex_32(&self.signing_public_key_hex, "route signing public key")?;
        decode_lowercase_hex_32(
            &self.provider_terms_sha256,
            "authorized provider terms SHA-256",
        )?;
        validate_runtime_image_reference(&self.student_branch_runtime_image_reference)?;
        decode_lowercase_hex_32(
            &self.admission_program_sha256,
            "authorized admission program SHA-256",
        )?;
        if self.schema_version != "milk.winner-deployment-authority.v3"
            || self.provider_policy.only != WINNER_PROVIDER
            || self.authorization_not_after.nanosecond() != 0
            || !(60..=MAX_WINNER_DEPLOYMENT_WALL_SECONDS).contains(&self.max_wall_seconds)
            || !(1..=MAX_WINNER_DEPLOYMENT_COST_MICROUSD).contains(&self.max_cost_microusd)
            || self.signing_key_id.is_empty()
            || self.signing_key_id.len() > MAX_KEY_ID_BYTES
            || self.candidate_max_in_flight == 0
            || self.canary_candidate_basis_points != WINNER_CANARY_BASIS_POINTS
            || self.canary_valid_for_seconds != WINNER_CANARY_VALID_FOR_SECONDS
            || self.max_input_utf8_bytes != CANDIDATE_MAX_INPUT_UTF8_BYTES
            || self.max_input_messages != CANDIDATE_MAX_INPUT_MESSAGES
            || self.max_input_request_bytes != CANDIDATE_MAX_INPUT_REQUEST_BYTES
            || self.route_schema_version != ROUTE_SCHEMA_VERSION
            || self.winner_admission_schema_version != WINNER_ADMISSION_SCHEMA_VERSION
        {
            bail!("winner deployment authority is invalid");
        }
        Ok(())
    }

    pub(crate) fn provider_binding_sha256(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut digest = Sha256::new();
        digest.update(b"milk.winner-provider-binding.v1\0");
        digest.update(serde_json::to_vec(self)?);
        Ok(digest.finalize().into())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_field_names)]
pub(crate) struct RouteScope {
    pub(crate) scope_id: Uuid,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteLivePointerWire {
    schema_version: String,
    scope: RouteScope,
    route_revision: String,
    previous_route_revision: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RouteLivePointer {
    pub(crate) scope: RouteScope,
    pub(crate) route_revision: [u8; 32],
    pub(crate) previous_route_revision: Option<[u8; 32]>,
}

impl RouteLivePointer {
    pub(crate) fn new(
        scope: RouteScope,
        route_revision: [u8; 32],
        previous_route_revision: Option<[u8; 32]>,
    ) -> Result<Self> {
        if previous_route_revision == Some(route_revision) {
            bail!("live route pointer cannot select its previous revision");
        }
        Ok(Self {
            scope,
            route_revision,
            previous_route_revision,
        })
    }

    pub(crate) fn parse(expected_scope: &RouteScope, bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_ROUTE_LIVE_BYTES {
            bail!("live route pointer exceeds {MAX_ROUTE_LIVE_BYTES} bytes");
        }
        let wire: RouteLivePointerWire =
            serde_json::from_slice(bytes).context("live route pointer is not strict typed JSON")?;
        if serde_json::to_vec(&wire)? != bytes {
            bail!("live route pointer is not canonical JSON");
        }
        if wire.schema_version != ROUTE_LIVE_SCHEMA_VERSION {
            bail!("live route pointer has an unsupported schema version");
        }
        if &wire.scope != expected_scope {
            bail!("live route pointer scope does not match startup configuration");
        }
        Self::new(
            wire.scope,
            decode_lowercase_hex_32(&wire.route_revision, "live route revision")?,
            wire.previous_route_revision
                .as_deref()
                .map(|revision| decode_lowercase_hex_32(revision, "previous live route revision"))
                .transpose()?,
        )
    }

    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&RouteLivePointerWire {
            schema_version: ROUTE_LIVE_SCHEMA_VERSION.to_owned(),
            scope: self.scope.clone(),
            route_revision: hex_digest(&self.route_revision),
            previous_route_revision: self.previous_route_revision.map(|value| hex_digest(&value)),
        })?)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum RouteCapability {
    Stream,
    Responses,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WinnerVariant {
    Bf16,
    DynamicFp8,
    StaticFp8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WinnerAdmissionReceipt {
    pub(crate) schema_version: String,
    pub(crate) provider: String,
    pub(crate) student_job_id: String,
    pub(crate) student_variant: WinnerVariant,
    pub(crate) model_manifest_sha256: String,
    pub(crate) model_alias: String,
    pub(crate) model_alias_sha256: String,
    pub(crate) candidate_api_key_sha256: String,
    pub(crate) student_branch_runtime_image_reference: String,
    pub(crate) admission_program_sha256: String,
    pub(crate) execution_id: String,
    pub(crate) execution_name: String,
    pub(crate) api_base_url: String,
    pub(crate) models_response_sha256: String,
    pub(crate) chat_request_sha256: String,
    pub(crate) chat_response_sha256: String,
    pub(crate) launch_started_at: DateTime<Utc>,
    pub(crate) ready_at: DateTime<Utc>,
    pub(crate) admitted_at: DateTime<Utc>,
    pub(crate) service_not_after: DateTime<Utc>,
}

impl WinnerAdmissionReceipt {
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_WINNER_ADMISSION_BYTES {
            bail!("winner admission exceeds {MAX_WINNER_ADMISSION_BYTES} bytes");
        }
        let body = bytes
            .strip_suffix(b"\n")
            .context("winner admission must be canonical compact JSON plus one LF")?;
        let receipt: Self =
            serde_json::from_slice(body).context("winner admission is not strict typed JSON")?;
        if serde_json::to_vec(&receipt)? != body {
            bail!("winner admission must be canonical compact JSON plus one LF");
        }
        Ok(receipt)
    }

    pub(crate) fn to_canonical_json_line(&self) -> Result<Vec<u8>> {
        let mut bytes = serde_json::to_vec(self)?;
        bytes.push(b'\n');
        if bytes.len() > MAX_WINNER_ADMISSION_BYTES {
            bail!("winner admission exceeds {MAX_WINNER_ADMISSION_BYTES} bytes");
        }
        Ok(bytes)
    }

    pub(crate) fn validate_for_authority(
        &self,
        authority: &WinnerDeploymentAuthority,
    ) -> Result<Url> {
        authority.validate()?;
        if self.schema_version != WINNER_ADMISSION_SCHEMA_VERSION {
            bail!("winner admission receipt has an unsupported schema version");
        }
        if !valid_provider(&self.provider) || self.provider != authority.provider_policy.only {
            bail!("winner admission provider is not authorized");
        }
        if !valid_model_alias(&self.model_alias) {
            bail!("winner admission model alias is invalid");
        }
        for (value, name) in [
            (&self.student_job_id, "winner admission student job ID"),
            (
                &self.model_manifest_sha256,
                "winner admission model manifest SHA-256",
            ),
            (
                &self.model_alias_sha256,
                "winner admission model alias SHA-256",
            ),
            (
                &self.candidate_api_key_sha256,
                "winner admission candidate API key SHA-256",
            ),
            (
                &self.admission_program_sha256,
                "winner admission program SHA-256",
            ),
            (
                &self.models_response_sha256,
                "winner admission models response SHA-256",
            ),
            (
                &self.chat_request_sha256,
                "winner admission chat request SHA-256",
            ),
            (
                &self.chat_response_sha256,
                "winner admission chat response SHA-256",
            ),
        ] {
            decode_lowercase_hex_32(value, name)?;
        }
        let model_alias_sha256: [u8; 32] = Sha256::digest(self.model_alias.as_bytes()).into();
        if self.model_alias_sha256 != hex_digest(&model_alias_sha256) {
            bail!("winner admission model alias digest differs");
        }
        validate_runtime_image_reference(&self.student_branch_runtime_image_reference)?;
        if self.student_branch_runtime_image_reference
            != authority.student_branch_runtime_image_reference
        {
            bail!("winner admission runtime image is not authorized");
        }
        if self.admission_program_sha256 != authority.admission_program_sha256 {
            bail!("winner admission program is not authorized");
        }
        if !valid_bounded_ascii(&self.execution_id, MAX_EXECUTION_ID_BYTES)
            || !valid_bounded_ascii(&self.execution_name, MAX_EXECUTION_ID_BYTES)
        {
            bail!("winner admission execution identity is invalid");
        }
        let maximum_interval = TimeDelta::seconds(
            i64::try_from(authority.max_wall_seconds)
                .context("winner deployment wall authority is out of range")?,
        );
        if self.launch_started_at > self.ready_at
            || self.ready_at > self.admitted_at
            || self.admitted_at >= self.service_not_after
            || self.service_not_after > authority.authorization_not_after
            || self.admitted_at - self.launch_started_at > maximum_interval
            || self.service_not_after - self.admitted_at
                < TimeDelta::seconds(i64::from(WINNER_ROUTE_RUNWAY_SECONDS))
        {
            bail!("winner admission service interval is invalid");
        }
        validate_candidate_api_base_url(&self.api_base_url, authority.allow_private_candidate_http)
    }

    pub(crate) fn deployment_sha256(&self) -> Result<[u8; 32]> {
        let mut deployment = Sha256::new();
        deployment.update(b"milk.student-deployment.v2\0");
        deployment.update(serde_json::to_vec(self)?);
        Ok(deployment.finalize().into())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RouteManifest {
    schema_version: String,
    scope: RouteScope,
    cohort_sha256: String,
    student_job_id: String,
    student_result_sha256: String,
    model_manifest_sha256: String,
    dev_receipt_sha256: String,
    winner_admission: WinnerAdmissionReceipt,
    winner_provider_binding_sha256: String,
    provider_terms_sha256: String,
    candidate_basis_points: u16,
    previous_route_revision: Option<String>,
    route_secret_sha256: String,
    supported_capabilities: Vec<RouteCapability>,
    reasoning_effort: Option<CandidateReasoningEffort>,
    max_input_utf8_bytes: usize,
    max_input_messages: usize,
    max_input_request_bytes: usize,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    signing_key_id: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorRouteCandidate {
    eval_sha256: String,
    candidate_id: String,
    api_base_url: String,
    model: String,
    candidate_api_key_sha256: String,
    supported_capabilities: Vec<RouteCapability>,
    reasoning_effort: Option<CandidateReasoningEffort>,
    max_input_utf8_bytes: usize,
    max_input_messages: usize,
    max_input_request_bytes: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorRouteProposal {
    api_base_url: String,
    candidate_basis_points: u16,
    candidate_id: String,
    eval_sha256: String,
    model: String,
    schema_version: String,
    scope_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorRouteManifest {
    schema_version: String,
    scope: RouteScope,
    proposal_sha256: String,
    candidate: Option<OperatorRouteCandidate>,
    candidate_basis_points: u16,
    previous_route_revision: Option<String>,
    route_secret_sha256: Option<String>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
    signing_key_id: String,
}

#[derive(Clone, Debug)]
struct RuntimeRouteCandidate {
    model: String,
    candidate_api_key_sha256: String,
    supported_capabilities: Vec<RouteCapability>,
    reasoning_effort: Option<CandidateReasoningEffort>,
    max_input_utf8_bytes: usize,
    max_input_messages: usize,
    max_input_request_bytes: usize,
    candidate_sha256: String,
    artifact_sha256: String,
}

#[derive(Clone, Debug)]
struct RuntimeRouteManifest {
    candidate: Option<RuntimeRouteCandidate>,
    candidate_basis_points: u16,
    route_secret_sha256: Option<String>,
    not_before: DateTime<Utc>,
    not_after: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RoutePublicationSource {
    StudentWinner,
    OperatorProposal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedRouteWinner {
    pub(crate) student_job_id: [u8; 32],
    pub(crate) student_result_sha256: [u8; 32],
    pub(crate) model_manifest_sha256: [u8; 32],
    pub(crate) dev_receipt_sha256: [u8; 32],
    pub(crate) cohort_sha256: [u8; 32],
    pub(crate) student_variant: WinnerVariant,
    pub(crate) student_branch_runtime_image_reference: String,
}

struct ParsedRouteManifest {
    manifest: RuntimeRouteManifest,
    endpoint: Option<Url>,
    cohort_sha256: [u8; 32],
    deployment_sha256: [u8; 32],
    revision: [u8; 32],
    publication: RoutePublication,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RoutePublication {
    pub(crate) source: RoutePublicationSource,
    pub(crate) has_candidate: bool,
    pub(crate) revision: [u8; 32],
    pub(crate) cohort_sha256: [u8; 32],
    pub(crate) student_job_id: [u8; 32],
    pub(crate) student_result_sha256: [u8; 32],
    pub(crate) model_manifest_sha256: [u8; 32],
    pub(crate) dev_receipt_sha256: [u8; 32],
    pub(crate) deployment_sha256: [u8; 32],
    pub(crate) winner_provider_binding_sha256: [u8; 32],
    pub(crate) student_variant: WinnerVariant,
    pub(crate) student_branch_runtime_image_reference: String,
    pub(crate) provider_terms_sha256: [u8; 32],
    pub(crate) candidate_api_base_url: String,
    pub(crate) logical_model_alias: String,
    pub(crate) candidate_basis_points: u16,
    pub(crate) reasoning_effort: Option<CandidateReasoningEffort>,
    pub(crate) previous_route_revision: Option<[u8; 32]>,
    pub(crate) route_secret_sha256: [u8; 32],
    pub(crate) max_input_utf8_bytes: usize,
    pub(crate) max_input_messages: usize,
    pub(crate) max_input_request_bytes: usize,
    pub(crate) not_after: DateTime<Utc>,
}

impl RoutePublication {
    pub(crate) fn parse_for_publication(
        config: &RouteStartupConfig,
        expected_scope: &RouteScope,
        manifest_bytes: &[u8],
        signature_bytes: Option<&[u8]>,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        Self::parse(
            config,
            expected_scope,
            manifest_bytes,
            signature_bytes,
            Some(now),
        )
    }

    pub(crate) fn parse_archived(
        config: &RouteStartupConfig,
        expected_scope: &RouteScope,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<Self> {
        Self::parse(
            config,
            expected_scope,
            manifest_bytes,
            Some(signature_bytes),
            None,
        )
    }

    fn parse(
        config: &RouteStartupConfig,
        expected_scope: &RouteScope,
        manifest_bytes: &[u8],
        signature_bytes: Option<&[u8]>,
        now: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        decode_lowercase_hex_32(&config.signing_public_key_hex, "route signing public key")?;
        if let Some(signature_bytes) = signature_bytes {
            verify_signature(config, manifest_bytes, signature_bytes)?;
        }
        let ParsedRouteManifest {
            manifest,
            publication,
            ..
        } = parse_manifest(config, expected_scope, manifest_bytes)?;
        if let Some(now) = now
            && (manifest.not_after <= now
                || manifest.not_after > now + chrono::TimeDelta::hours(MAX_ROUTE_VALIDITY_HOURS)
                || manifest.not_before
                    > now + chrono::TimeDelta::minutes(MAX_PUBLICATION_START_DELAY_MINUTES))
        {
            bail!(
                "route publication validity must start within five minutes and end within 24 hours"
            );
        }
        Ok(publication)
    }

    pub(crate) fn revision_hex(&self) -> String {
        hex_digest(&self.revision)
    }

    pub(crate) const fn is_operator_proposal(&self) -> bool {
        matches!(self.source, RoutePublicationSource::OperatorProposal)
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_route_manifest(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    winner: &VerifiedRouteWinner,
    winner_admission_bytes: &[u8],
    route_secret_hex: &str,
    candidate_basis_points: u16,
    reasoning_effort: Option<CandidateReasoningEffort>,
    previous: Option<&RoutePublication>,
    now: DateTime<Utc>,
    valid_for_seconds: u32,
) -> Result<(Vec<u8>, RoutePublication)> {
    if !(60..=u32::try_from(MAX_ROUTE_VALIDITY_HOURS * 60 * 60)?).contains(&valid_for_seconds) {
        bail!("route validity must be in 60..=86400 seconds");
    }
    let winner_admission = WinnerAdmissionReceipt::parse(winner_admission_bytes)?;
    if winner_admission.student_job_id != hex_digest(&winner.student_job_id)
        || winner_admission.model_manifest_sha256 != hex_digest(&winner.model_manifest_sha256)
        || winner_admission.student_variant != winner.student_variant
        || winner_admission.student_branch_runtime_image_reference
            != winner.student_branch_runtime_image_reference
    {
        bail!("winner admission differs from the verified stored winner");
    }
    let route_secret = decode_lowercase_hex_32(route_secret_hex, "route secret")?;
    let route_secret_sha256: [u8; 32] = Sha256::digest(route_secret).into();
    let not_before = now
        .with_nanosecond(0)
        .context("route preparation time is outside the supported range")?
        .max(winner_admission.admitted_at);
    let not_after = not_before
        .checked_add_signed(TimeDelta::seconds(i64::from(valid_for_seconds)))
        .context("route validity overflow")?;
    if not_after > winner_admission.service_not_after {
        bail!("requested route validity exceeds the admitted winner service interval");
    }
    let winner_authority = config.winner_deployment_authority()?;
    let manifest = serde_json::to_vec(&RouteManifest {
        schema_version: ROUTE_SCHEMA_VERSION.to_owned(),
        scope: scope.clone(),
        cohort_sha256: hex_digest(&winner.cohort_sha256),
        student_job_id: hex_digest(&winner.student_job_id),
        student_result_sha256: hex_digest(&winner.student_result_sha256),
        model_manifest_sha256: hex_digest(&winner.model_manifest_sha256),
        dev_receipt_sha256: hex_digest(&winner.dev_receipt_sha256),
        winner_admission,
        winner_provider_binding_sha256: hex_digest(&winner_authority.provider_binding_sha256()?),
        provider_terms_sha256: winner_authority.provider_terms_sha256,
        candidate_basis_points,
        previous_route_revision: previous.map(RoutePublication::revision_hex),
        route_secret_sha256: hex_digest(&route_secret_sha256),
        supported_capabilities: vec![RouteCapability::Stream],
        reasoning_effort,
        max_input_utf8_bytes: CANDIDATE_MAX_INPUT_UTF8_BYTES,
        max_input_messages: CANDIDATE_MAX_INPUT_MESSAGES,
        max_input_request_bytes: CANDIDATE_MAX_INPUT_REQUEST_BYTES,
        not_before,
        not_after,
        signing_key_id: config.signing_key_id.clone(),
    })?;
    let publication = RoutePublication::parse_for_publication(config, scope, &manifest, None, now)?;
    Ok((manifest, publication))
}

pub(crate) fn prepare_operator_route_manifest(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    proposal_bytes: &[u8],
    route_secret_hex: Option<&str>,
    candidate_api_key: Option<&str>,
    previous: Option<&RoutePublication>,
    now: DateTime<Utc>,
) -> Result<(Vec<u8>, RoutePublication)> {
    if proposal_bytes.len() > MAX_ROUTE_MANIFEST_BYTES {
        bail!("route proposal exceeds {MAX_ROUTE_MANIFEST_BYTES} bytes");
    }
    let proposal: OperatorRouteProposal = serde_json::from_slice(proposal_bytes)
        .context("route proposal is not strict typed JSON")?;
    let mut canonical_proposal = serde_json::to_vec(&serde_json::to_value(&proposal)?)?;
    canonical_proposal.push(b'\n');
    if canonical_proposal != proposal_bytes {
        bail!("route proposal must be canonical key-sorted compact JSON plus one LF");
    }
    if proposal.schema_version != OPERATOR_ROUTE_PROPOSAL_SCHEMA_VERSION {
        bail!("route proposal has an unsupported schema version");
    }
    if proposal.scope_id != scope.scope_id {
        bail!("route proposal scope does not match startup configuration");
    }
    if proposal.candidate_basis_points > 10_000 {
        bail!("candidate_basis_points cannot exceed 10000");
    }
    decode_lowercase_hex_32(&proposal.eval_sha256, "route proposal eval SHA-256")?;
    reject_non_production_mechanics_route(proposal.scope_id, Some(&proposal.eval_sha256))?;
    if !valid_bounded_ascii(&proposal.candidate_id, MAX_EXECUTION_ID_BYTES)
        || !valid_model_alias(&proposal.model)
    {
        bail!("route proposal candidate identity is invalid");
    }
    validate_candidate_api_base_url(&proposal.api_base_url, config.allow_private_candidate_http)?;
    let candidate = if proposal.candidate_basis_points == 0 {
        None
    } else {
        let candidate_api_key =
            candidate_api_key.context("candidate route requires its API key")?;
        if candidate_api_key.is_empty() {
            bail!("candidate API key cannot be empty");
        }
        Some(OperatorRouteCandidate {
            eval_sha256: proposal.eval_sha256.clone(),
            candidate_id: proposal.candidate_id.clone(),
            api_base_url: proposal.api_base_url.clone(),
            model: proposal.model.clone(),
            candidate_api_key_sha256: hex_digest(
                &Sha256::digest(candidate_api_key.as_bytes()).into(),
            ),
            supported_capabilities: vec![RouteCapability::Stream],
            reasoning_effort: None,
            max_input_utf8_bytes: CANDIDATE_MAX_INPUT_UTF8_BYTES,
            max_input_messages: CANDIDATE_MAX_INPUT_MESSAGES,
            max_input_request_bytes: CANDIDATE_MAX_INPUT_REQUEST_BYTES,
        })
    };
    let route_secret_sha256 = if candidate.is_some() {
        let value =
            route_secret_hex.context("candidate route requires the operator route secret")?;
        let secret = decode_lowercase_hex_32(value, "route secret")?;
        Some(hex_digest(&Sha256::digest(secret).into()))
    } else {
        None
    };
    let valid_for_seconds = if candidate.is_some() {
        WINNER_CANARY_VALID_FOR_SECONDS
    } else {
        WINNER_ZERO_VALID_FOR_SECONDS
    };
    let not_before = now
        .with_nanosecond(0)
        .context("route preparation time is outside the supported range")?;
    let not_after = not_before
        .checked_add_signed(TimeDelta::seconds(i64::from(valid_for_seconds)))
        .context("route validity overflow")?;
    let manifest = serde_json::to_vec(&OperatorRouteManifest {
        schema_version: OPERATOR_ROUTE_SCHEMA_VERSION.to_owned(),
        scope: scope.clone(),
        proposal_sha256: hex_digest(&Sha256::digest(proposal_bytes).into()),
        candidate,
        candidate_basis_points: proposal.candidate_basis_points,
        previous_route_revision: previous.map(RoutePublication::revision_hex),
        route_secret_sha256,
        not_before,
        not_after,
        signing_key_id: config.signing_key_id.clone(),
    })?;
    let publication = RoutePublication::parse_for_publication(config, scope, &manifest, None, now)?;
    Ok((manifest, publication))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub(crate) enum WinnerRoutePhase {
    Canary,
    Zero,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WinnerRouteAdvanceAction {
    Prepare,
    Observe,
    Done,
}

#[derive(Debug)]
pub(crate) struct WinnerRouteAdvance {
    pub(crate) action: WinnerRouteAdvanceAction,
    pub(crate) manifest: Option<Vec<u8>>,
    pub(crate) publication: RoutePublication,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn advance_winner_route(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    winner: &VerifiedRouteWinner,
    winner_admission_bytes: &[u8],
    route_secret_hex: &str,
    phase: WinnerRoutePhase,
    live: Option<&RoutePublication>,
    live_previous: Option<&RoutePublication>,
    now: DateTime<Utc>,
) -> Result<WinnerRouteAdvance> {
    let Some(live) = live else {
        if live_previous.is_some() {
            bail!("live route predecessor exists without a live route");
        }
        if phase == WinnerRoutePhase::Zero {
            bail!("zero route requires an exact live canary");
        }
        let (manifest, publication) = prepare_route_manifest(
            config,
            scope,
            winner,
            winner_admission_bytes,
            route_secret_hex,
            WINNER_CANARY_BASIS_POINTS,
            None,
            None,
            now,
            WINNER_CANARY_VALID_FOR_SECONDS,
        )?;
        return Ok(WinnerRouteAdvance {
            action: WinnerRouteAdvanceAction::Prepare,
            manifest: Some(manifest),
            publication,
        });
    };

    if live.student_job_id != winner.student_job_id {
        bail!("live route belongs to a different student job");
    }

    match live.candidate_basis_points {
        WINNER_CANARY_BASIS_POINTS => {
            if live_previous.is_some() {
                bail!("live canary unexpectedly has a predecessor");
            }
            require_exact_winner_route(
                config,
                scope,
                winner,
                winner_admission_bytes,
                route_secret_hex,
                live,
                None,
                WINNER_CANARY_BASIS_POINTS,
                WINNER_CANARY_VALID_FOR_SECONDS,
            )?;
            if phase == WinnerRoutePhase::Canary {
                return Ok(WinnerRouteAdvance {
                    action: WinnerRouteAdvanceAction::Observe,
                    manifest: None,
                    publication: live.clone(),
                });
            }
            let (manifest, publication) = prepare_route_manifest(
                config,
                scope,
                winner,
                winner_admission_bytes,
                route_secret_hex,
                0,
                None,
                Some(live),
                now,
                WINNER_ZERO_VALID_FOR_SECONDS,
            )?;
            Ok(WinnerRouteAdvance {
                action: WinnerRouteAdvanceAction::Prepare,
                manifest: Some(manifest),
                publication,
            })
        }
        0 => {
            let previous = live_previous.context("live zero route is missing its canary")?;
            if previous.student_job_id != winner.student_job_id {
                bail!("live route predecessor belongs to a different student job");
            }
            require_exact_winner_route(
                config,
                scope,
                winner,
                winner_admission_bytes,
                route_secret_hex,
                previous,
                None,
                WINNER_CANARY_BASIS_POINTS,
                WINNER_CANARY_VALID_FOR_SECONDS,
            )?;
            require_exact_winner_route(
                config,
                scope,
                winner,
                winner_admission_bytes,
                route_secret_hex,
                live,
                Some(previous),
                0,
                WINNER_ZERO_VALID_FOR_SECONDS,
            )?;
            Ok(WinnerRouteAdvance {
                action: WinnerRouteAdvanceAction::Done,
                manifest: None,
                publication: live.clone(),
            })
        }
        _ => bail!("live route is not the exact winner canary or zero route"),
    }
}

#[allow(clippy::too_many_arguments)]
fn require_exact_winner_route(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    winner: &VerifiedRouteWinner,
    winner_admission_bytes: &[u8],
    route_secret_hex: &str,
    actual: &RoutePublication,
    previous: Option<&RoutePublication>,
    candidate_basis_points: u16,
    valid_for_seconds: u32,
) -> Result<()> {
    let prepared_at = actual
        .not_after
        .checked_sub_signed(TimeDelta::seconds(i64::from(valid_for_seconds)))
        .context("live route validity start is outside the supported range")?;
    let (_, expected) = prepare_route_manifest(
        config,
        scope,
        winner,
        winner_admission_bytes,
        route_secret_hex,
        candidate_basis_points,
        None,
        previous,
        prepared_at,
        valid_for_seconds,
    )?;
    if actual != &expected {
        bail!("live route is not the exact winner canary or zero route");
    }
    Ok(())
}

pub(crate) struct RoutePolicy {
    revision: String,
    state: RouteState,
}

enum RouteState {
    Dormant(BaselineReason),
    Active(Box<ActiveRoute>),
}

struct ActiveRoute {
    manifest: RuntimeRouteManifest,
    endpoint: Url,
    cohort_sha256: [u8; 32],
    deployment_sha256: String,
    expires_at: Instant,
    hmac_key: hmac::Key,
    max_in_flight: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteTarget {
    Baseline,
    Candidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BaselineReason {
    PolicyAbsent,
    PolicyZero,
    PolicyExpired,
    PolicyNotYetValid,
    RouteSecretMissing,
    CandidateCredentialMissing,
    UnsupportedContentType,
    ContentEncoding,
    QueryString,
    UnsupportedRequest,
    ModelMismatch,
    UnsupportedCapability,
    ReasoningEffortMismatch,
    NotSampled,
}

impl BaselineReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyAbsent => "policy_absent",
            Self::PolicyZero => "policy_zero",
            Self::PolicyExpired => "policy_expired",
            Self::PolicyNotYetValid => "policy_not_yet_valid",
            Self::RouteSecretMissing => "route_secret_missing",
            Self::CandidateCredentialMissing => "candidate_credential_missing",
            Self::UnsupportedContentType => "unsupported_content_type",
            Self::ContentEncoding => "content_encoding",
            Self::QueryString => "query_string",
            Self::UnsupportedRequest => "unsupported_request",
            Self::ModelMismatch => "model_mismatch",
            Self::UnsupportedCapability => "unsupported_capability",
            Self::ReasoningEffortMismatch => "reasoning_effort_mismatch",
            Self::NotSampled => "not_sampled",
        }
    }
}

pub(crate) struct RouteRequest<'a> {
    pub(crate) endpoint: RouteEndpoint,
    pub(crate) body: &'a [u8],
    pub(crate) content_type: Option<&'a [u8]>,
    pub(crate) has_multiple_content_types: bool,
    pub(crate) has_content_encoding: bool,
    pub(crate) has_openai_beta: bool,
    pub(crate) query: &'a str,
    pub(crate) routing_cohort: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RouteEndpoint {
    ChatCompletions,
    Responses,
}

impl RouteEndpoint {
    pub(crate) const fn relative_path(self) -> &'static str {
        match self {
            Self::ChatCompletions => "chat/completions",
            Self::Responses => "responses",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CandidateRoute<'a> {
    pub(crate) endpoint: &'a Url,
    pub(crate) candidate_sha256: &'a str,
    pub(crate) artifact_sha256: &'a str,
    pub(crate) deployment_sha256: &'a str,
    pub(crate) candidate_api_key_sha256: &'a str,
    pub(crate) max_in_flight: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct RouteDecision<'a> {
    pub(crate) target: RouteTarget,
    pub(crate) route_revision: &'a str,
    pub(crate) candidate: Option<CandidateRoute<'a>>,
    pub(crate) baseline_reason: Option<BaselineReason>,
}

#[derive(Deserialize)]
struct CandidateChat<'a> {
    model: &'a str,
    #[serde(borrow)]
    messages: &'a RawValue,
    #[serde(borrow)]
    stream: Option<&'a RawValue>,
    reasoning_effort: Option<CandidateReasoningEffort>,
}

#[derive(Deserialize)]
struct CandidateResponses<'a> {
    model: &'a str,
    #[serde(borrow)]
    input: Option<&'a RawValue>,
    #[serde(borrow)]
    stream: Option<&'a RawValue>,
    reasoning: Option<CandidateResponsesReasoning>,
}

#[derive(Deserialize)]
struct CandidateResponsesReasoning {
    effort: Option<CandidateReasoningEffort>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub(crate) enum CandidateReasoningEffort {
    Low,
    Medium,
    High,
    Max,
}

struct CandidateRequestMetadata<'a> {
    model: &'a str,
    input: Option<&'a RawValue>,
    stream: Option<&'a RawValue>,
    reasoning_effort: Option<CandidateReasoningEffort>,
}

impl RoutePolicy {
    pub(crate) fn baseline() -> Self {
        Self {
            revision: BASELINE_ROUTE_REVISION.to_owned(),
            state: RouteState::Dormant(BaselineReason::PolicyAbsent),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_signed_bytes(
        config: &RouteStartupConfig,
        expected_scope: &RouteScope,
        route_secret_hex: Option<&str>,
        candidate_api_key: Option<&str>,
        gateway_max_in_flight: usize,
        wall_now: DateTime<Utc>,
        monotonic_now: Instant,
        manifest_bytes: &[u8],
        signature_bytes: &[u8],
    ) -> Result<Self> {
        verify_signature(config, manifest_bytes, signature_bytes)?;
        let ParsedRouteManifest {
            manifest,
            endpoint,
            cohort_sha256,
            deployment_sha256,
            revision,
            publication,
        } = parse_manifest(config, expected_scope, manifest_bytes)?;
        if publication.is_operator_proposal() {
            config.validate_common(gateway_max_in_flight)?;
        } else {
            config.validate(gateway_max_in_flight)?;
        }

        let route_secret = route_secret_hex
            .map(|value| decode_lowercase_hex_32(value, "route secret"))
            .transpose()?;
        if let (Some(route_secret), Some(expected)) =
            (route_secret, manifest.route_secret_sha256.as_deref())
        {
            let expected_route_secret_sha256 =
                decode_lowercase_hex_32(expected, "route secret SHA-256")?;
            let actual_route_secret_sha256: [u8; 32] = Sha256::digest(route_secret).into();
            if actual_route_secret_sha256 != expected_route_secret_sha256 {
                bail!("route secret does not match the signed manifest");
            }
        }

        let dormant = if wall_now >= manifest.not_after {
            Some(BaselineReason::PolicyExpired)
        } else if wall_now < manifest.not_before {
            Some(BaselineReason::PolicyNotYetValid)
        } else if manifest.candidate_basis_points == 0 {
            Some(BaselineReason::PolicyZero)
        } else if route_secret_hex.is_none() {
            Some(BaselineReason::RouteSecretMissing)
        } else if candidate_api_key.is_none() {
            Some(BaselineReason::CandidateCredentialMissing)
        } else {
            None
        };
        if let Some(reason) = dormant {
            return Ok(Self {
                revision: hex_digest(&revision),
                state: RouteState::Dormant(reason),
            });
        }

        let route_secret = route_secret.context("active route secret is missing")?;
        let candidate_api_key = candidate_api_key.context("active candidate API key is missing")?;
        let candidate = manifest
            .candidate
            .as_ref()
            .context("active route is missing its candidate")?;
        let expected_candidate_api_key_sha256 = decode_lowercase_hex_32(
            &candidate.candidate_api_key_sha256,
            "winner admission candidate API key SHA-256",
        )?;
        let observed_candidate_api_key_sha256: [u8; 32] =
            Sha256::digest(candidate_api_key.as_bytes()).into();
        if observed_candidate_api_key_sha256 != expected_candidate_api_key_sha256 {
            bail!("candidate API key differs from the admitted credential");
        }
        let expires_after = (manifest.not_after - wall_now)
            .to_std()
            .context("route expiry is outside the monotonic clock range")?;
        let expires_at = monotonic_now
            .checked_add(expires_after)
            .context("route expiry overflows the monotonic clock")?;

        Ok(Self {
            revision: hex_digest(&revision),
            state: RouteState::Active(Box::new(ActiveRoute {
                manifest,
                endpoint: endpoint.context("active route is missing its candidate endpoint")?,
                cohort_sha256,
                deployment_sha256: hex_digest(&deployment_sha256),
                expires_at,
                hmac_key: hmac::Key::new(hmac::HMAC_SHA256, &route_secret),
                max_in_flight: config.candidate_max_in_flight,
            })),
        })
    }

    pub(crate) fn revision(&self) -> &str {
        &self.revision
    }

    pub(crate) fn candidate(&self) -> Option<CandidateRoute<'_>> {
        match &self.state {
            RouteState::Dormant(_) => None,
            RouteState::Active(active) => Some(active.candidate()),
        }
    }

    #[cfg(test)]
    pub(crate) fn active_for_test(
        endpoint: Url,
        max_in_flight: usize,
        candidate_api_key: &str,
    ) -> Self {
        Self::active_with_reasoning_for_test(endpoint, max_in_flight, candidate_api_key, None)
    }

    #[cfg(test)]
    fn active_with_reasoning_for_test(
        endpoint: Url,
        max_in_flight: usize,
        candidate_api_key: &str,
        reasoning_effort: Option<CandidateReasoningEffort>,
    ) -> Self {
        let now = Utc::now();
        let route_secret = [9_u8; 32];
        Self {
            revision: "test-route-v1".to_owned(),
            state: RouteState::Active(Box::new(ActiveRoute {
                manifest: RuntimeRouteManifest {
                    candidate: Some(RuntimeRouteCandidate {
                        model: "customer-model".to_owned(),
                        candidate_api_key_sha256: hex_digest(
                            &Sha256::digest(candidate_api_key.as_bytes()).into(),
                        ),
                        supported_capabilities: vec![
                            RouteCapability::Stream,
                            RouteCapability::Responses,
                        ],
                        reasoning_effort,
                        max_input_utf8_bytes: CANDIDATE_MAX_INPUT_UTF8_BYTES,
                        max_input_messages: CANDIDATE_MAX_INPUT_MESSAGES,
                        max_input_request_bytes: CANDIDATE_MAX_INPUT_REQUEST_BYTES,
                        candidate_sha256: "33".repeat(32),
                        artifact_sha256: "44".repeat(32),
                    }),
                    candidate_basis_points: 10_000,
                    route_secret_sha256: Some(hex_digest(&Sha256::digest(route_secret).into())),
                    not_before: now - chrono::TimeDelta::hours(1),
                    not_after: now + chrono::TimeDelta::hours(1),
                },
                endpoint,
                cohort_sha256: [0x22; 32],
                deployment_sha256: "55".repeat(32),
                expires_at: Instant::now() + std::time::Duration::from_hours(1),
                hmac_key: hmac::Key::new(hmac::HMAC_SHA256, &route_secret),
                max_in_flight,
            })),
        }
    }

    pub(crate) fn decide<'a>(
        &'a self,
        request: &RouteRequest<'_>,
        monotonic_now: Instant,
    ) -> RouteDecision<'a> {
        let active = match &self.state {
            RouteState::Dormant(reason) => return self.baseline_decision(*reason),
            RouteState::Active(active) => active,
        };
        if monotonic_now >= active.expires_at {
            return self.baseline_decision(BaselineReason::PolicyExpired);
        }
        let Some(candidate) = active.manifest.candidate.as_ref() else {
            return self.baseline_decision(BaselineReason::PolicyZero);
        };
        if request.has_multiple_content_types || !is_json_content_type(request.content_type) {
            return self.baseline_decision(BaselineReason::UnsupportedContentType);
        }
        if request.has_content_encoding {
            return self.baseline_decision(BaselineReason::ContentEncoding);
        }
        if request.has_openai_beta {
            return self.baseline_decision(BaselineReason::UnsupportedCapability);
        }
        if !request.query.is_empty() {
            return self.baseline_decision(BaselineReason::QueryString);
        }
        if request.body.len() > candidate.max_input_request_bytes {
            return self.baseline_decision(BaselineReason::UnsupportedCapability);
        }

        if request.endpoint == RouteEndpoint::Responses
            && !candidate
                .supported_capabilities
                .contains(&RouteCapability::Responses)
        {
            return self.baseline_decision(BaselineReason::UnsupportedCapability);
        }
        let Some(parsed) = parse_candidate_request(request.endpoint, request.body) else {
            return self.baseline_decision(BaselineReason::UnsupportedRequest);
        };
        if parsed.model != candidate.model {
            return self.baseline_decision(BaselineReason::ModelMismatch);
        }
        if parsed.reasoning_effort != candidate.reasoning_effort {
            return self.baseline_decision(BaselineReason::ReasoningEffortMismatch);
        }
        if let Some(input) = parsed.input {
            let Some(items) = candidate_input_items(input) else {
                return self.baseline_decision(BaselineReason::UnsupportedRequest);
            };
            if items > candidate.max_input_messages
                || input.get().len() > candidate.max_input_utf8_bytes
            {
                return self.baseline_decision(BaselineReason::UnsupportedCapability);
            }
        }
        let streaming = match parsed.stream.map(|value| value.get().trim()) {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return self.baseline_decision(BaselineReason::UnsupportedRequest),
        };
        if streaming
            && !candidate
                .supported_capabilities
                .contains(&RouteCapability::Stream)
        {
            return self.baseline_decision(BaselineReason::UnsupportedCapability);
        }
        let sample = sticky_sample(
            &active.hmac_key,
            &active.cohort_sha256,
            request.routing_cohort,
        );
        if !selected(sample, active.manifest.candidate_basis_points) {
            return self.baseline_decision(BaselineReason::NotSampled);
        }

        RouteDecision {
            target: RouteTarget::Candidate,
            route_revision: &self.revision,
            candidate: Some(active.candidate()),
            baseline_reason: None,
        }
    }

    fn baseline_decision(&self, reason: BaselineReason) -> RouteDecision<'_> {
        RouteDecision {
            target: RouteTarget::Baseline,
            route_revision: &self.revision,
            candidate: None,
            baseline_reason: Some(reason),
        }
    }
}

fn parse_candidate_request(
    endpoint: RouteEndpoint,
    body: &[u8],
) -> Option<CandidateRequestMetadata<'_>> {
    match endpoint {
        RouteEndpoint::ChatCompletions => {
            let parsed = serde_json::from_slice::<CandidateChat<'_>>(body).ok()?;
            Some(CandidateRequestMetadata {
                model: parsed.model,
                input: Some(parsed.messages),
                stream: parsed.stream,
                reasoning_effort: parsed.reasoning_effort,
            })
        }
        RouteEndpoint::Responses => {
            let parsed = serde_json::from_slice::<CandidateResponses<'_>>(body).ok()?;
            Some(CandidateRequestMetadata {
                model: parsed.model,
                input: parsed.input,
                stream: parsed.stream,
                reasoning_effort: parsed.reasoning.and_then(|reasoning| reasoning.effort),
            })
        }
    }
}

fn candidate_input_items(input: &RawValue) -> Option<usize> {
    let raw = input.get().trim_start();
    if raw.starts_with('[') {
        serde_json::from_str::<Vec<&RawValue>>(raw)
            .ok()
            .map(|items| items.len())
    } else if raw.starts_with('"') || raw.starts_with('{') {
        Some(1)
    } else {
        None
    }
}

impl ActiveRoute {
    fn candidate(&self) -> CandidateRoute<'_> {
        let candidate = self
            .manifest
            .candidate
            .as_ref()
            .expect("active route has a candidate");
        CandidateRoute {
            endpoint: &self.endpoint,
            candidate_sha256: &candidate.candidate_sha256,
            artifact_sha256: &candidate.artifact_sha256,
            deployment_sha256: &self.deployment_sha256,
            candidate_api_key_sha256: &candidate.candidate_api_key_sha256,
            max_in_flight: self.max_in_flight,
        }
    }
}

fn verify_signature(
    config: &RouteStartupConfig,
    manifest_bytes: &[u8],
    signature_bytes: &[u8],
) -> Result<()> {
    if manifest_bytes.len() > MAX_ROUTE_MANIFEST_BYTES {
        bail!("route manifest exceeds {MAX_ROUTE_MANIFEST_BYTES} bytes");
    }
    if signature_bytes.len() != ED25519_SIGNATURE_BYTES {
        bail!("route signature must contain exactly {ED25519_SIGNATURE_BYTES} raw bytes");
    }
    let public_key =
        decode_lowercase_hex_32(&config.signing_public_key_hex, "route signing public key")?;
    signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(manifest_bytes, signature_bytes)
        .map_err(|_| anyhow::anyhow!("route signature verification failed"))
}

fn parse_manifest(
    config: &RouteStartupConfig,
    expected_scope: &RouteScope,
    manifest_bytes: &[u8],
) -> Result<ParsedRouteManifest> {
    if manifest_bytes.len() > MAX_ROUTE_MANIFEST_BYTES {
        bail!("route manifest exceeds {MAX_ROUTE_MANIFEST_BYTES} bytes");
    }
    #[derive(Deserialize)]
    struct ManifestSchema<'a> {
        schema_version: &'a str,
    }
    let schema: ManifestSchema<'_> = serde_json::from_slice(manifest_bytes)
        .context("route manifest is not strict typed JSON")?;
    match schema.schema_version {
        ROUTE_SCHEMA_VERSION => parse_student_manifest(config, expected_scope, manifest_bytes),
        OPERATOR_ROUTE_SCHEMA_VERSION => {
            parse_operator_manifest(config, expected_scope, manifest_bytes)
        }
        _ => bail!("route manifest has an unsupported schema version"),
    }
}

fn parse_student_manifest(
    config: &RouteStartupConfig,
    expected_scope: &RouteScope,
    manifest_bytes: &[u8],
) -> Result<ParsedRouteManifest> {
    let manifest: RouteManifest = serde_json::from_slice(manifest_bytes)
        .context("student route manifest is not strict typed JSON")?;
    if serde_json::to_vec(&manifest)? != manifest_bytes {
        bail!("route manifest is not canonical JSON");
    }
    let (endpoint, cohort_sha256, deployment_sha256) =
        validate_manifest(config, expected_scope, &manifest)?;
    let revision = Sha256::digest(manifest_bytes).into();
    let candidate_sha256 = decode_lowercase_hex_32(&manifest.student_job_id, "student job ID")?;
    let artifact_sha256 =
        decode_lowercase_hex_32(&manifest.model_manifest_sha256, "model manifest SHA-256")?;
    let publication = RoutePublication {
        source: RoutePublicationSource::StudentWinner,
        has_candidate: true,
        revision,
        cohort_sha256,
        student_job_id: candidate_sha256,
        student_result_sha256: decode_lowercase_hex_32(
            &manifest.student_result_sha256,
            "student result SHA-256",
        )?,
        model_manifest_sha256: artifact_sha256,
        dev_receipt_sha256: decode_lowercase_hex_32(
            &manifest.dev_receipt_sha256,
            "DEV receipt SHA-256",
        )?,
        deployment_sha256,
        winner_provider_binding_sha256: decode_lowercase_hex_32(
            &manifest.winner_provider_binding_sha256,
            "winner provider binding SHA-256",
        )?,
        student_variant: manifest.winner_admission.student_variant,
        student_branch_runtime_image_reference: manifest
            .winner_admission
            .student_branch_runtime_image_reference
            .clone(),
        provider_terms_sha256: decode_lowercase_hex_32(
            &manifest.provider_terms_sha256,
            "provider terms SHA-256",
        )?,
        candidate_api_base_url: manifest.winner_admission.api_base_url.clone(),
        logical_model_alias: manifest.winner_admission.model_alias.clone(),
        candidate_basis_points: manifest.candidate_basis_points,
        reasoning_effort: manifest.reasoning_effort,
        previous_route_revision: manifest
            .previous_route_revision
            .as_deref()
            .map(|value| decode_lowercase_hex_32(value, "previous route revision"))
            .transpose()?,
        route_secret_sha256: decode_lowercase_hex_32(
            &manifest.route_secret_sha256,
            "route secret SHA-256",
        )?,
        max_input_utf8_bytes: manifest.max_input_utf8_bytes,
        max_input_messages: manifest.max_input_messages,
        max_input_request_bytes: manifest.max_input_request_bytes,
        not_after: manifest.not_after,
    };
    let runtime = RuntimeRouteManifest {
        candidate: Some(RuntimeRouteCandidate {
            model: manifest.winner_admission.model_alias.clone(),
            candidate_api_key_sha256: manifest.winner_admission.candidate_api_key_sha256.clone(),
            supported_capabilities: manifest.supported_capabilities.clone(),
            reasoning_effort: manifest.reasoning_effort,
            max_input_utf8_bytes: manifest.max_input_utf8_bytes,
            max_input_messages: manifest.max_input_messages,
            max_input_request_bytes: manifest.max_input_request_bytes,
            candidate_sha256: hex_digest(&candidate_sha256),
            artifact_sha256: hex_digest(&artifact_sha256),
        }),
        candidate_basis_points: manifest.candidate_basis_points,
        route_secret_sha256: Some(manifest.route_secret_sha256),
        not_before: manifest.not_before,
        not_after: manifest.not_after,
    };
    Ok(ParsedRouteManifest {
        manifest: runtime,
        endpoint: Some(endpoint),
        cohort_sha256,
        deployment_sha256,
        revision,
        publication,
    })
}

fn parse_operator_manifest(
    config: &RouteStartupConfig,
    expected_scope: &RouteScope,
    manifest_bytes: &[u8],
) -> Result<ParsedRouteManifest> {
    let manifest: OperatorRouteManifest = serde_json::from_slice(manifest_bytes)
        .context("operator route manifest is not strict typed JSON")?;
    if serde_json::to_vec(&manifest)? != manifest_bytes {
        bail!("route manifest is not canonical JSON");
    }
    let endpoint = validate_operator_manifest(config, expected_scope, &manifest)?;
    let revision = Sha256::digest(manifest_bytes).into();
    let proposal_sha256 =
        decode_lowercase_hex_32(&manifest.proposal_sha256, "route proposal SHA-256")?;
    let previous_route_revision = manifest
        .previous_route_revision
        .as_deref()
        .map(|value| decode_lowercase_hex_32(value, "previous route revision"))
        .transpose()?;
    let route_secret_sha256 = manifest
        .route_secret_sha256
        .as_deref()
        .map(|value| decode_lowercase_hex_32(value, "route secret SHA-256"))
        .transpose()?;
    let (candidate, candidate_sha256, artifact_sha256, deployment_sha256) =
        if let Some(candidate) = &manifest.candidate {
            let candidate_bytes = serde_json::to_vec(candidate)?;
            let candidate_sha256: [u8; 32] = Sha256::digest(&candidate_bytes).into();
            let artifact_sha256: [u8; 32] = Sha256::digest(
                [
                    b"milk.route-model.v1\0".as_slice(),
                    candidate.model.as_bytes(),
                ]
                .concat(),
            )
            .into();
            let deployment_sha256: [u8; 32] = Sha256::digest(
                [
                    b"milk.route-deployment.v1\0".as_slice(),
                    candidate.api_base_url.as_bytes(),
                ]
                .concat(),
            )
            .into();
            (
                Some(RuntimeRouteCandidate {
                    model: candidate.model.clone(),
                    candidate_api_key_sha256: candidate.candidate_api_key_sha256.clone(),
                    supported_capabilities: candidate.supported_capabilities.clone(),
                    reasoning_effort: candidate.reasoning_effort,
                    max_input_utf8_bytes: candidate.max_input_utf8_bytes,
                    max_input_messages: candidate.max_input_messages,
                    max_input_request_bytes: candidate.max_input_request_bytes,
                    candidate_sha256: hex_digest(&candidate_sha256),
                    artifact_sha256: hex_digest(&artifact_sha256),
                }),
                candidate_sha256,
                artifact_sha256,
                deployment_sha256,
            )
        } else {
            (None, [0; 32], [0; 32], [0; 32])
        };
    let cohort_sha256 = if candidate.is_some() {
        candidate_sha256
    } else {
        proposal_sha256
    };
    let publication = RoutePublication {
        source: RoutePublicationSource::OperatorProposal,
        has_candidate: candidate.is_some(),
        revision,
        cohort_sha256,
        student_job_id: candidate_sha256,
        student_result_sha256: proposal_sha256,
        model_manifest_sha256: artifact_sha256,
        dev_receipt_sha256: [0; 32],
        deployment_sha256,
        winner_provider_binding_sha256: [0; 32],
        student_variant: WinnerVariant::Bf16,
        student_branch_runtime_image_reference: String::new(),
        provider_terms_sha256: [0; 32],
        candidate_api_base_url: manifest
            .candidate
            .as_ref()
            .map(|value| value.api_base_url.clone())
            .unwrap_or_default(),
        logical_model_alias: manifest
            .candidate
            .as_ref()
            .map(|value| value.model.clone())
            .unwrap_or_default(),
        candidate_basis_points: manifest.candidate_basis_points,
        reasoning_effort: manifest
            .candidate
            .as_ref()
            .and_then(|value| value.reasoning_effort),
        previous_route_revision,
        route_secret_sha256: route_secret_sha256.unwrap_or([0; 32]),
        max_input_utf8_bytes: manifest
            .candidate
            .as_ref()
            .map_or(0, |value| value.max_input_utf8_bytes),
        max_input_messages: manifest
            .candidate
            .as_ref()
            .map_or(0, |value| value.max_input_messages),
        max_input_request_bytes: manifest
            .candidate
            .as_ref()
            .map_or(0, |value| value.max_input_request_bytes),
        not_after: manifest.not_after,
    };
    Ok(ParsedRouteManifest {
        manifest: RuntimeRouteManifest {
            candidate,
            candidate_basis_points: manifest.candidate_basis_points,
            route_secret_sha256: manifest.route_secret_sha256,
            not_before: manifest.not_before,
            not_after: manifest.not_after,
        },
        endpoint,
        cohort_sha256,
        deployment_sha256,
        revision,
        publication,
    })
}

fn validate_operator_manifest(
    config: &RouteStartupConfig,
    expected_scope: &RouteScope,
    manifest: &OperatorRouteManifest,
) -> Result<Option<Url>> {
    if manifest.schema_version != OPERATOR_ROUTE_SCHEMA_VERSION {
        bail!("operator route manifest has an unsupported schema version");
    }
    if &manifest.scope != expected_scope {
        bail!("operator route manifest scope does not match startup configuration");
    }
    reject_non_production_mechanics_route(
        manifest.scope.scope_id,
        manifest
            .candidate
            .as_ref()
            .map(|candidate| candidate.eval_sha256.as_str()),
    )?;
    if config.signing_key_id.is_empty()
        || config.signing_key_id.len() > MAX_KEY_ID_BYTES
        || manifest.signing_key_id != config.signing_key_id
    {
        bail!("operator route manifest signing key ID does not match startup configuration");
    }
    if manifest.not_before >= manifest.not_after
        || manifest.not_after - manifest.not_before > TimeDelta::hours(MAX_ROUTE_VALIDITY_HOURS)
    {
        bail!("operator route validity must be positive and no longer than 24 hours");
    }
    decode_lowercase_hex_32(&manifest.proposal_sha256, "route proposal SHA-256")?;
    if let Some(revision) = &manifest.previous_route_revision {
        decode_lowercase_hex_32(revision, "previous route revision")?;
    }
    match (&manifest.candidate, manifest.candidate_basis_points) {
        (None, 0) => {
            if manifest.route_secret_sha256.is_some() {
                bail!("baseline-only route cannot contain a route secret digest");
            }
            Ok(None)
        }
        (Some(candidate), 1..=10_000) => {
            let route_secret = manifest
                .route_secret_sha256
                .as_deref()
                .context("candidate route requires a route secret digest")?;
            decode_lowercase_hex_32(route_secret, "route secret SHA-256")?;
            validate_operator_candidate(config, candidate).map(Some)
        }
        (None, _) => bail!("baseline-only route must use zero candidate basis points"),
        (Some(_), 0) => bail!("zero-basis-point route must not contain a candidate"),
        (Some(_), _) => bail!("candidate_basis_points cannot exceed 10000"),
    }
}

fn reject_non_production_mechanics_route(scope_id: Uuid, eval_sha256: Option<&str>) -> Result<()> {
    if scope_id.as_u128() == NON_PRODUCTION_MECHANICS_SCOPE_ID {
        bail!("non-production mechanics scope is not route-admissible");
    }
    if eval_sha256.is_some_and(|value| value == NON_PRODUCTION_MECHANICS_EVAL_SHA256) {
        bail!("non-production mechanics eval is not route-admissible");
    }
    Ok(())
}

fn validate_operator_candidate(
    config: &RouteStartupConfig,
    candidate: &OperatorRouteCandidate,
) -> Result<Url> {
    decode_lowercase_hex_32(&candidate.eval_sha256, "route proposal eval SHA-256")?;
    if !valid_bounded_ascii(&candidate.candidate_id, MAX_EXECUTION_ID_BYTES) {
        bail!("operator route candidate ID is invalid");
    }
    if !valid_model_alias(&candidate.model) {
        bail!("operator route candidate model is invalid");
    }
    decode_lowercase_hex_32(
        &candidate.candidate_api_key_sha256,
        "candidate API key SHA-256",
    )?;
    if candidate.supported_capabilities.len() > MAX_CAPABILITIES {
        bail!("operator route candidate has too many supported capabilities");
    }
    for (index, capability) in candidate.supported_capabilities.iter().enumerate() {
        if candidate.supported_capabilities[..index].contains(capability) {
            bail!("operator route candidate contains a duplicate capability");
        }
    }
    if candidate.max_input_utf8_bytes != CANDIDATE_MAX_INPUT_UTF8_BYTES
        || candidate.max_input_messages != CANDIDATE_MAX_INPUT_MESSAGES
        || candidate.max_input_request_bytes != CANDIDATE_MAX_INPUT_REQUEST_BYTES
    {
        bail!("operator route candidate input bounds are unsupported");
    }
    validate_candidate_api_base_url(&candidate.api_base_url, config.allow_private_candidate_http)
}

fn validate_manifest(
    config: &RouteStartupConfig,
    expected_scope: &RouteScope,
    manifest: &RouteManifest,
) -> Result<(Url, [u8; 32], [u8; 32])> {
    if manifest.schema_version != ROUTE_SCHEMA_VERSION {
        bail!("route manifest has an unsupported schema version");
    }
    if &manifest.scope != expected_scope {
        bail!("route manifest scope does not match startup configuration");
    }
    if config.signing_key_id.is_empty()
        || config.signing_key_id.len() > MAX_KEY_ID_BYTES
        || manifest.signing_key_id != config.signing_key_id
    {
        bail!("route manifest signing key ID does not match startup configuration");
    }
    if manifest.not_before >= manifest.not_after
        || manifest.not_after - manifest.not_before
            > chrono::TimeDelta::hours(MAX_ROUTE_VALIDITY_HOURS)
    {
        bail!("route manifest validity interval must be positive and no longer than 24 hours");
    }
    if manifest.candidate_basis_points > 10_000 {
        bail!("candidate_basis_points cannot exceed 10000");
    }
    if manifest.candidate_basis_points == 0 && manifest.previous_route_revision.is_none() {
        bail!("zero-basis-point route requires a previous route revision");
    }
    if manifest.supported_capabilities.len() > MAX_CAPABILITIES {
        bail!("route manifest has too many supported capabilities");
    }
    if manifest.max_input_utf8_bytes != CANDIDATE_MAX_INPUT_UTF8_BYTES
        || manifest.max_input_messages != CANDIDATE_MAX_INPUT_MESSAGES
        || manifest.max_input_request_bytes != CANDIDATE_MAX_INPUT_REQUEST_BYTES
    {
        bail!("route manifest candidate input bounds are unsupported");
    }
    for (index, capability) in manifest.supported_capabilities.iter().enumerate() {
        if manifest.supported_capabilities[..index].contains(capability) {
            bail!("route manifest contains a duplicate capability");
        }
    }

    let cohort_sha256 = decode_lowercase_hex_32(&manifest.cohort_sha256, "cohort SHA-256")?;
    for (value, name) in [
        (&manifest.student_job_id, "student job ID"),
        (&manifest.student_result_sha256, "student result SHA-256"),
        (&manifest.model_manifest_sha256, "model manifest SHA-256"),
        (&manifest.dev_receipt_sha256, "DEV receipt SHA-256"),
        (&manifest.provider_terms_sha256, "provider terms SHA-256"),
        (
            &manifest.winner_provider_binding_sha256,
            "winner provider binding SHA-256",
        ),
        (&manifest.route_secret_sha256, "route secret SHA-256"),
    ] {
        decode_lowercase_hex_32(value, name)?;
    }
    if let Some(revision) = &manifest.previous_route_revision {
        decode_lowercase_hex_32(revision, "previous route revision")?;
    }
    let winner_authority = config.winner_deployment_authority()?;
    let authorized_terms = decode_lowercase_hex_32(
        &winner_authority.provider_terms_sha256,
        "authorized provider terms SHA-256",
    )?;
    let manifest_terms =
        decode_lowercase_hex_32(&manifest.provider_terms_sha256, "provider terms SHA-256")?;
    if authorized_terms != manifest_terms {
        bail!("route manifest provider terms do not match startup authorization");
    }
    let authorized_winner_binding = winner_authority.provider_binding_sha256()?;
    if manifest.winner_provider_binding_sha256 != hex_digest(&authorized_winner_binding) {
        bail!("route manifest winner provider binding does not match startup authorization");
    }

    let (endpoint, deployment_sha256) = validate_winner_admission(config, manifest)?;
    Ok((endpoint, cohort_sha256, deployment_sha256))
}

fn validate_winner_admission(
    config: &RouteStartupConfig,
    manifest: &RouteManifest,
) -> Result<(Url, [u8; 32])> {
    let receipt = &manifest.winner_admission;
    let authority = config.winner_deployment_authority()?;
    let endpoint = receipt.validate_for_authority(&authority)?;
    if receipt.student_job_id != manifest.student_job_id
        || receipt.model_manifest_sha256 != manifest.model_manifest_sha256
    {
        bail!("winner admission receipt differs from the routed student winner");
    }
    if manifest.not_before < receipt.admitted_at || manifest.not_after > receipt.service_not_after {
        bail!("route validity exceeds the admitted winner service interval");
    }
    Ok((endpoint, receipt.deployment_sha256()?))
}

pub(crate) fn validate_runtime_image_reference(value: &str) -> Result<()> {
    runtime_image_digest(value)?;
    Ok(())
}

pub(crate) fn validate_distinct_runtime_image_references(left: &str, right: &str) -> Result<()> {
    if runtime_image_digest(left)? == runtime_image_digest(right)? {
        bail!("runtime images must use distinct SHA-256 digests");
    }
    Ok(())
}

fn runtime_image_digest(value: &str) -> Result<&str> {
    let Some((name, digest)) = value.rsplit_once("@sha256:") else {
        bail!("runtime image reference must use an immutable SHA-256 digest");
    };
    if value.len() > MAX_IMAGE_REFERENCE_BYTES
        || name.is_empty()
        || name.contains('@')
        || name
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
    {
        bail!("runtime image reference is invalid");
    }
    decode_lowercase_hex_32(digest, "runtime image digest")?;
    Ok(digest)
}

fn valid_provider(value: &str) -> bool {
    (1..=MAX_PROVIDER_BYTES).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'_')
        })
}

fn valid_model_alias(value: &str) -> bool {
    (1..=MAX_MODEL_BYTES).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'/' | b':' | b'_')
        })
}

fn valid_bounded_ascii(value: &str, maximum: usize) -> bool {
    (1..=maximum).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub(crate) fn validate_candidate_api_base_url(
    value: &str,
    allow_private_candidate_http: bool,
) -> Result<Url> {
    if value.is_empty() || value.len() > MAX_ENDPOINT_BYTES {
        bail!("candidate API base URL must contain 1..={MAX_ENDPOINT_BYTES} bytes");
    }
    let endpoint = Url::parse(value).context("candidate API base URL is not a valid URL")?;
    let local_http = endpoint.scheme() == "http"
        && endpoint.as_str() == value
        && endpoint.path() == "/v1/"
        && match endpoint.host() {
            Some(Host::Ipv4(address)) => {
                address.is_loopback() || (allow_private_candidate_http && address.is_private())
            }
            Some(Host::Ipv6(address)) => address.is_loopback(),
            _ => false,
        };
    let standard_endpoint = endpoint.scheme() == "https"
        && endpoint.as_str() == value
        && endpoint.path().ends_with("/v1/");
    if (!standard_endpoint && !local_http)
        || endpoint.host_str().is_none()
        || !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.query().is_some()
        || endpoint.fragment().is_some()
    {
        bail!(
            "candidate API base URL must be credential-free HTTPS ending in /v1/, or authorized literal-IP HTTP at the exact root path"
        );
    }
    Ok(endpoint)
}

fn sticky_sample(key: &hmac::Key, cohort_sha256: &[u8; 32], routing_cohort: &[u8]) -> u64 {
    let mut context = hmac::Context::with_key(key);
    context.update(cohort_sha256);
    context.update(routing_cohort);
    let tag = context.sign();
    let bytes = tag.as_ref();
    u64::from_be_bytes(bytes[..8].try_into().expect("HMAC-SHA256 is 32 bytes"))
}

fn selected(sample: u64, basis_points: u16) -> bool {
    let threshold = u128::from(basis_points) * (1_u128 << u64::BITS) / 10_000;
    u128::from(sample) < threshold
}

fn is_json_content_type(value: Option<&[u8]>) -> bool {
    value
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
}

fn decode_lowercase_hex_32(value: &str, name: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{name} must be exactly 64 lowercase hexadecimal characters");
    }
    let mut decoded = [0_u8; 32];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .with_context(|| format!("{name} contains non-hexadecimal characters"))?;
    }
    Ok(decoded)
}

fn hex_digest(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(test)]
mod tests {
    use ring::signature::{Ed25519KeyPair, KeyPair};

    use super::*;

    const SIGNING_SEED: [u8; 32] = [7; 32];
    const ROUTE_SECRET: [u8; 32] = [9; 32];
    const CANDIDATE_API_KEY: &str = "candidate-test-secret";
    const ACTIVE_NOW: &str = "2026-08-25T12:00:00Z";
    const ACTIVE_NOT_BEFORE: &str = "2026-08-25T00:00:00Z";
    const ACTIVE_NOT_AFTER: &str = "2026-08-26T00:00:00Z";

    struct Fixture {
        config: RouteStartupConfig,
        scope: RouteScope,
        secret_hex: String,
        manifest: Vec<u8>,
        signature: Vec<u8>,
    }

    impl Fixture {
        fn active(basis_points: u16, capabilities: &str) -> Self {
            Self::new(
                basis_points,
                capabilities,
                ACTIVE_NOT_BEFORE,
                ACTIVE_NOT_AFTER,
            )
        }

        fn new(basis_points: u16, capabilities: &str, not_before: &str, not_after: &str) -> Self {
            let previous = repeated_digest(0x88);
            Self::new_with_previous(
                basis_points,
                capabilities,
                not_before,
                not_after,
                (basis_points == 0).then_some(previous.as_str()),
            )
        }

        fn new_with_previous(
            basis_points: u16,
            capabilities: &str,
            not_before: &str,
            not_after: &str,
            previous_revision: Option<&str>,
        ) -> Self {
            let scope = RouteScope {
                scope_id: "11111111-1111-4111-8111-111111111111".parse().unwrap(),
            };
            let secret_hex = hex_bytes(&ROUTE_SECRET);
            let route_secret_sha256: [u8; 32] = Sha256::digest(ROUTE_SECRET).into();
            let student_branch_runtime_image_reference = format!(
                "ghcr.io/milkinfrastructure/milk-student-branch@sha256:{}",
                repeated_digest(0x91)
            );
            let admission_program_sha256 = repeated_digest(0x92);
            let not_before: DateTime<Utc> = not_before.parse().unwrap();
            let not_after: DateTime<Utc> = not_after.parse().unwrap();
            let key_pair = signing_key();
            let config = RouteStartupConfig {
                signing_public_key_hex: hex_bytes(key_pair.public_key().as_ref()),
                signing_key_id: "route-key-v1".to_owned(),
                allow_private_candidate_http: false,
                authorized_provider_terms_sha256: Some(repeated_digest(0x66)),
                authorized_student_branch_runtime_image_reference: Some(
                    student_branch_runtime_image_reference.clone(),
                ),
                authorized_admission_program_sha256: Some(admission_program_sha256.clone()),
                winner_authorization_not_after: Some(not_after),
                winner_max_wall_seconds: Some(MAX_WINNER_DEPLOYMENT_WALL_SECONDS),
                winner_max_cost_microusd: Some(MAX_WINNER_DEPLOYMENT_COST_MICROUSD),
                candidate_max_in_flight: 2,
            };
            let manifest = serde_json::to_vec(&RouteManifest {
                schema_version: ROUTE_SCHEMA_VERSION.to_owned(),
                scope: scope.clone(),
                cohort_sha256: repeated_digest(0x22),
                student_job_id: repeated_digest(0x33),
                student_result_sha256: repeated_digest(0x88),
                model_manifest_sha256: repeated_digest(0x44),
                dev_receipt_sha256: repeated_digest(0x77),
                winner_admission: WinnerAdmissionReceipt {
                    schema_version: WINNER_ADMISSION_SCHEMA_VERSION.to_owned(),
                    provider: WINNER_PROVIDER.to_owned(),
                    student_job_id: repeated_digest(0x33),
                    student_variant: WinnerVariant::StaticFp8,
                    model_manifest_sha256: repeated_digest(0x44),
                    model_alias: "customer-model".to_owned(),
                    model_alias_sha256: hex_digest(&Sha256::digest(b"customer-model").into()),
                    candidate_api_key_sha256: hex_digest(
                        &Sha256::digest(b"candidate-test-secret").into(),
                    ),
                    student_branch_runtime_image_reference: student_branch_runtime_image_reference
                        .clone(),
                    admission_program_sha256: admission_program_sha256.clone(),
                    execution_id: "sb-0123456789".to_owned(),
                    execution_name: "winner-test".to_owned(),
                    api_base_url: "https://candidate.example/v1/".to_owned(),
                    models_response_sha256: repeated_digest(0x93),
                    chat_request_sha256: repeated_digest(0x94),
                    chat_response_sha256: repeated_digest(0x95),
                    launch_started_at: not_before,
                    ready_at: not_before,
                    admitted_at: not_before,
                    service_not_after: not_after,
                },
                winner_provider_binding_sha256: hex_digest(
                    &config
                        .winner_deployment_authority()
                        .unwrap()
                        .provider_binding_sha256()
                        .unwrap(),
                ),
                provider_terms_sha256: repeated_digest(0x66),
                candidate_basis_points: basis_points,
                previous_route_revision: previous_revision.map(str::to_owned),
                route_secret_sha256: hex_digest(&route_secret_sha256),
                supported_capabilities: serde_json::from_str(capabilities).unwrap(),
                reasoning_effort: None,
                max_input_utf8_bytes: CANDIDATE_MAX_INPUT_UTF8_BYTES,
                max_input_messages: CANDIDATE_MAX_INPUT_MESSAGES,
                max_input_request_bytes: CANDIDATE_MAX_INPUT_REQUEST_BYTES,
                not_before,
                not_after,
                signing_key_id: "route-key-v1".to_owned(),
            })
            .unwrap();
            let signature = key_pair.sign(&manifest).as_ref().to_vec();
            Self {
                config,
                scope,
                secret_hex,
                manifest,
                signature,
            }
        }

        fn policy(&self) -> RoutePolicy {
            self.policy_with(Some(&self.secret_hex), Some(CANDIDATE_API_KEY))
        }

        fn policy_with(
            &self,
            secret: Option<&str>,
            candidate_api_key: Option<&str>,
        ) -> RoutePolicy {
            RoutePolicy::from_signed_bytes(
                &self.config,
                &self.scope,
                secret,
                candidate_api_key,
                8,
                ACTIVE_NOW.parse().unwrap(),
                Instant::now(),
                &self.manifest,
                &self.signature,
            )
            .unwrap()
        }
    }

    fn verified_winner(fixture: &Fixture) -> (VerifiedRouteWinner, Vec<u8>) {
        let source: RouteManifest = serde_json::from_slice(&fixture.manifest).unwrap();
        let admission = source.winner_admission.to_canonical_json_line().unwrap();
        let winner = VerifiedRouteWinner {
            student_job_id: decode_lowercase_hex_32(&source.student_job_id, "student").unwrap(),
            student_result_sha256: decode_lowercase_hex_32(&source.student_result_sha256, "result")
                .unwrap(),
            model_manifest_sha256: decode_lowercase_hex_32(&source.model_manifest_sha256, "model")
                .unwrap(),
            dev_receipt_sha256: decode_lowercase_hex_32(&source.dev_receipt_sha256, "DEV").unwrap(),
            cohort_sha256: decode_lowercase_hex_32(&source.cohort_sha256, "cohort").unwrap(),
            student_variant: source.winner_admission.student_variant,
            student_branch_runtime_image_reference: source
                .winner_admission
                .student_branch_runtime_image_reference,
        };
        (winner, admission)
    }

    #[test]
    fn prepare_route_builds_verified_canary_and_exact_rollback() {
        let fixture = Fixture::active(100, r#"["stream"]"#);
        let (winner, admission) = verified_winner(&fixture);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        let (canary_bytes, canary) = prepare_route_manifest(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            100,
            None,
            None,
            now,
            900,
        )
        .unwrap();
        let canary_wire: RouteManifest = serde_json::from_slice(&canary_bytes).unwrap();
        assert_eq!(serde_json::to_vec(&canary_wire).unwrap(), canary_bytes);
        assert_eq!(canary.candidate_basis_points, 100);
        assert_eq!(canary.previous_route_revision, None);
        assert_eq!(canary.student_job_id, winner.student_job_id);
        assert_eq!(canary.student_result_sha256, winner.student_result_sha256);
        assert_eq!(canary.model_manifest_sha256, winner.model_manifest_sha256);
        assert_eq!(canary.dev_receipt_sha256, winner.dev_receipt_sha256);
        assert_eq!(canary.cohort_sha256, winner.cohort_sha256);
        assert_eq!(canary.student_variant, winner.student_variant);
        assert_eq!(
            canary_wire.supported_capabilities,
            [RouteCapability::Stream]
        );
        assert_eq!(
            canary_wire.max_input_utf8_bytes,
            CANDIDATE_MAX_INPUT_UTF8_BYTES
        );
        assert_eq!(canary_wire.max_input_messages, CANDIDATE_MAX_INPUT_MESSAGES);
        assert_eq!(
            canary_wire.max_input_request_bytes,
            CANDIDATE_MAX_INPUT_REQUEST_BYTES
        );
        assert_eq!(canary_wire.not_before, now);
        assert_eq!(canary_wire.not_after, now + TimeDelta::seconds(900));

        let rollback_now = now + TimeDelta::seconds(60);
        let (rollback_bytes, rollback) = prepare_route_manifest(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            0,
            None,
            Some(&canary),
            rollback_now,
            300,
        )
        .unwrap();
        let rollback_wire: RouteManifest = serde_json::from_slice(&rollback_bytes).unwrap();
        assert_eq!(rollback.candidate_basis_points, 0);
        assert_eq!(rollback.previous_route_revision, Some(canary.revision));
        assert_eq!(
            rollback_wire.previous_route_revision,
            Some(canary.revision_hex())
        );
        assert_eq!(rollback.deployment_sha256, canary.deployment_sha256);
        assert_eq!(rollback.student_job_id, canary.student_job_id);
        assert_eq!(rollback.student_result_sha256, canary.student_result_sha256);
        assert_eq!(rollback.model_manifest_sha256, canary.model_manifest_sha256);
        assert_eq!(rollback.dev_receipt_sha256, canary.dev_receipt_sha256);
        assert_eq!(rollback.cohort_sha256, canary.cohort_sha256);
        assert_eq!(rollback.route_secret_sha256, canary.route_secret_sha256);

        assert!(
            prepare_route_manifest(
                &fixture.config,
                &fixture.scope,
                &winner,
                admission.strip_suffix(b"\n").unwrap(),
                &fixture.secret_hex,
                100,
                None,
                None,
                now,
                900,
            )
            .is_err()
        );
        assert!(
            prepare_route_manifest(
                &fixture.config,
                &fixture.scope,
                &winner,
                &admission,
                &fixture.secret_hex,
                0,
                None,
                None,
                now,
                900,
            )
            .is_err()
        );
        let mut wrong_runtime_winner = winner.clone();
        wrong_runtime_winner.student_branch_runtime_image_reference = format!(
            "ghcr.io/milkinfrastructure/milk-student-branch@sha256:{}",
            "a".repeat(64)
        );
        assert!(
            prepare_route_manifest(
                &fixture.config,
                &fixture.scope,
                &wrong_runtime_winner,
                &admission,
                &fixture.secret_hex,
                100,
                None,
                None,
                now,
                900,
            )
            .is_err()
        );
    }

    #[test]
    fn unsigned_harness_proposal_routes_chat_and_keeps_responses_on_baseline() {
        let fixture = Fixture::active(10_000, r#"["stream"]"#);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        let generic_config: RouteStartupConfig = serde_json::from_value(serde_json::json!({
            "allow_private_candidate_http": fixture.config.allow_private_candidate_http,
            "candidate_max_in_flight": fixture.config.candidate_max_in_flight,
            "signing_key_id": fixture.config.signing_key_id.clone(),
            "signing_public_key_hex": fixture.config.signing_public_key_hex.clone(),
        }))
        .unwrap();
        generic_config.validate_common(8).unwrap();
        assert!(generic_config.winner_deployment_authority().is_err());
        let proposal = format!(
            concat!(
                "{{\"api_base_url\":\"https://candidate.example/v1/\",",
                "\"candidate_basis_points\":10000,",
                "\"candidate_id\":\"candidate-2026-08-29\",",
                "\"eval_sha256\":\"{}\",",
                "\"model\":\"customer-model\",",
                "\"schema_version\":\"milk.unsigned-route-proposal.v1\",",
                "\"scope_id\":\"{}\"}}\n"
            ),
            repeated_digest(0xa1),
            fixture.scope.scope_id,
        )
        .into_bytes();
        let (manifest_bytes, publication) = prepare_operator_route_manifest(
            &generic_config,
            &fixture.scope,
            &proposal,
            Some(&fixture.secret_hex),
            Some(CANDIDATE_API_KEY),
            None,
            now,
        )
        .unwrap();
        assert!(publication.is_operator_proposal());
        assert!(publication.has_candidate);

        let mut missing_lf = proposal.clone();
        assert_eq!(missing_lf.pop(), Some(b'\n'));
        assert!(
            prepare_operator_route_manifest(
                &generic_config,
                &fixture.scope,
                &missing_lf,
                Some(&fixture.secret_hex),
                Some(CANDIDATE_API_KEY),
                None,
                now,
            )
            .unwrap_err()
            .to_string()
            .contains("canonical key-sorted compact JSON plus one LF")
        );
        let unknown_field = String::from_utf8(proposal.clone())
            .unwrap()
            .replace("}\n", ",\"signature\":null}\n")
            .into_bytes();
        assert!(
            prepare_operator_route_manifest(
                &generic_config,
                &fixture.scope,
                &unknown_field,
                Some(&fixture.secret_hex),
                Some(CANDIDATE_API_KEY),
                None,
                now,
            )
            .unwrap_err()
            .to_string()
            .contains("strict typed JSON")
        );
        let manifest: OperatorRouteManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert_eq!(manifest.schema_version, OPERATOR_ROUTE_SCHEMA_VERSION);
        assert_eq!(manifest.previous_route_revision, None);
        assert_eq!(
            manifest.candidate.unwrap().supported_capabilities,
            [RouteCapability::Stream]
        );

        let signature = signing_key().sign(&manifest_bytes);
        let policy = RoutePolicy::from_signed_bytes(
            &generic_config,
            &fixture.scope,
            Some(&fixture.secret_hex),
            Some(CANDIDATE_API_KEY),
            8,
            now,
            Instant::now(),
            &manifest_bytes,
            signature.as_ref(),
        )
        .unwrap();
        let chat = br#"{"model":"customer-model","messages":[{"role":"user","content":"hi"}]}"#;
        assert_eq!(
            policy
                .decide(&request(chat, b"session"), Instant::now())
                .target,
            RouteTarget::Candidate
        );
        let responses = br#"{"model":"customer-model","input":"hi"}"#;
        assert_eq!(
            policy
                .decide(&responses_request(responses, b"session"), Instant::now())
                .target,
            RouteTarget::Baseline
        );
    }

    #[test]
    fn unsigned_harness_zero_proposal_emits_signed_baseline_without_candidate() {
        let fixture = Fixture::active(10_000, r#"["stream"]"#);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        let proposal = format!(
            concat!(
                "{{\"api_base_url\":\"https://candidate.example/v1/\",",
                "\"candidate_basis_points\":0,",
                "\"candidate_id\":\"candidate-2026-08-29\",",
                "\"eval_sha256\":\"{}\",",
                "\"model\":\"customer-model\",",
                "\"schema_version\":\"milk.unsigned-route-proposal.v1\",",
                "\"scope_id\":\"{}\"}}\n"
            ),
            repeated_digest(0xa2),
            fixture.scope.scope_id,
        )
        .into_bytes();
        let (manifest_bytes, publication) = prepare_operator_route_manifest(
            &fixture.config,
            &fixture.scope,
            &proposal,
            None,
            None,
            None,
            now,
        )
        .unwrap();
        assert!(publication.is_operator_proposal());
        assert!(!publication.has_candidate);
        assert_eq!(publication.candidate_basis_points, 0);
        let manifest: OperatorRouteManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        assert!(manifest.candidate.is_none());
        assert!(manifest.route_secret_sha256.is_none());
        assert!(manifest.previous_route_revision.is_none());

        let signature = signing_key().sign(&manifest_bytes);
        let policy = RoutePolicy::from_signed_bytes(
            &fixture.config,
            &fixture.scope,
            None,
            None,
            8,
            now,
            Instant::now(),
            &manifest_bytes,
            signature.as_ref(),
        )
        .unwrap();
        assert_baseline(
            policy.decide(
                &request(br#"{"model":"customer-model","messages":[]}"#, b"session"),
                Instant::now(),
            ),
            BaselineReason::PolicyZero,
        );
    }

    #[test]
    fn non_production_mechanics_identities_cannot_prepare_or_publish_operator_routes() {
        let fixture = Fixture::active(10_000, r#"["stream"]"#);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        let mechanics_scope = RouteScope {
            scope_id: "f7f88ff0-5947-440c-a661-e4e35f1d04e0".parse().unwrap(),
        };
        let proposal = |scope: &RouteScope, eval_sha256: &str| {
            format!(
                concat!(
                    "{{\"api_base_url\":\"https://candidate.example/v1/\",",
                    "\"candidate_basis_points\":100,",
                    "\"candidate_id\":\"candidate-2026-08-29\",",
                    "\"eval_sha256\":\"{}\",",
                    "\"model\":\"customer-model\",",
                    "\"schema_version\":\"milk.unsigned-route-proposal.v1\",",
                    "\"scope_id\":\"{}\"}}\n"
                ),
                eval_sha256, scope.scope_id,
            )
            .into_bytes()
        };

        let blocked_scope = prepare_operator_route_manifest(
            &fixture.config,
            &mechanics_scope,
            &proposal(&mechanics_scope, &repeated_digest(0xa3)),
            None,
            None,
            None,
            now,
        )
        .unwrap_err();
        assert!(
            blocked_scope
                .to_string()
                .contains("mechanics scope is not route-admissible")
        );

        let blocked_eval = prepare_operator_route_manifest(
            &fixture.config,
            &fixture.scope,
            &proposal(&fixture.scope, NON_PRODUCTION_MECHANICS_EVAL_SHA256),
            None,
            None,
            None,
            now,
        )
        .unwrap_err();
        assert!(
            blocked_eval
                .to_string()
                .contains("mechanics eval is not route-admissible")
        );

        let mut unrelated_eval = NON_PRODUCTION_MECHANICS_EVAL_SHA256.to_owned();
        unrelated_eval.replace_range(63..64, "8");
        prepare_operator_route_manifest(
            &fixture.config,
            &fixture.scope,
            &proposal(&fixture.scope, &unrelated_eval),
            Some(&fixture.secret_hex),
            Some(CANDIDATE_API_KEY),
            None,
            now,
        )
        .unwrap();

        let (manifest_bytes, _) = prepare_operator_route_manifest(
            &fixture.config,
            &fixture.scope,
            &proposal(&fixture.scope, &repeated_digest(0xa4)),
            Some(&fixture.secret_hex),
            Some(CANDIDATE_API_KEY),
            None,
            now,
        )
        .unwrap();
        let mut manifest: OperatorRouteManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        manifest.candidate.as_mut().unwrap().eval_sha256 =
            NON_PRODUCTION_MECHANICS_EVAL_SHA256.to_owned();
        let blocked_manifest = serde_json::to_vec(&manifest).unwrap();
        let signature = signing_key().sign(&blocked_manifest);
        let error = RoutePublication::parse_for_publication(
            &fixture.config,
            &fixture.scope,
            &blocked_manifest,
            Some(signature.as_ref()),
            now,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("mechanics eval is not route-admissible")
        );
    }

    #[test]
    fn advance_route_adopts_canary_without_extending_after_lost_response() {
        let fixture = Fixture::active(WINNER_CANARY_BASIS_POINTS, r#"["stream"]"#);
        let (winner, admission) = verified_winner(&fixture);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        let prepared = advance_winner_route(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            WinnerRoutePhase::Canary,
            None,
            None,
            now,
        )
        .unwrap();
        assert_eq!(prepared.action, WinnerRouteAdvanceAction::Prepare);
        assert!(prepared.manifest.is_some());
        let canary = prepared.publication;

        let adopted = advance_winner_route(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            WinnerRoutePhase::Canary,
            Some(&canary),
            None,
            now + TimeDelta::seconds(30),
        )
        .unwrap();
        assert_eq!(adopted.action, WinnerRouteAdvanceAction::Observe);
        assert!(adopted.manifest.is_none());
        assert_eq!(adopted.publication, canary);
        assert_eq!(
            adopted.publication.not_after,
            now + TimeDelta::seconds(i64::from(WINNER_CANARY_VALID_FOR_SECONDS))
        );
    }

    #[test]
    fn advance_route_prepares_sixty_second_zero_from_expired_canary() {
        let fixture = Fixture::active(WINNER_CANARY_BASIS_POINTS, r#"["stream"]"#);
        let (winner, admission) = verified_winner(&fixture);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        let canary = advance_winner_route(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            WinnerRoutePhase::Canary,
            None,
            None,
            now,
        )
        .unwrap()
        .publication;

        let zero = advance_winner_route(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            WinnerRoutePhase::Zero,
            Some(&canary),
            None,
            canary.not_after,
        )
        .unwrap();
        assert_eq!(zero.action, WinnerRouteAdvanceAction::Prepare);
        assert!(zero.manifest.is_some());
        assert_eq!(zero.publication.candidate_basis_points, 0);
        assert_eq!(
            zero.publication.previous_route_revision,
            Some(canary.revision)
        );
        assert_eq!(
            zero.publication.not_after,
            canary.not_after + TimeDelta::seconds(i64::from(WINNER_ZERO_VALID_FOR_SECONDS))
        );
    }

    #[test]
    fn advance_route_adopts_zero_after_lost_response() {
        let fixture = Fixture::active(WINNER_CANARY_BASIS_POINTS, r#"["stream"]"#);
        let (winner, admission) = verified_winner(&fixture);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        let canary = advance_winner_route(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            WinnerRoutePhase::Canary,
            None,
            None,
            now,
        )
        .unwrap()
        .publication;
        let zero = advance_winner_route(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            WinnerRoutePhase::Zero,
            Some(&canary),
            None,
            canary.not_after,
        )
        .unwrap()
        .publication;

        for phase in [WinnerRoutePhase::Zero, WinnerRoutePhase::Canary] {
            let adopted = advance_winner_route(
                &fixture.config,
                &fixture.scope,
                &winner,
                &admission,
                &fixture.secret_hex,
                phase,
                Some(&zero),
                Some(&canary),
                zero.not_after,
            )
            .unwrap();
            assert_eq!(adopted.action, WinnerRouteAdvanceAction::Done);
            assert!(adopted.manifest.is_none());
            assert_eq!(adopted.publication, zero);
        }
    }

    #[test]
    fn advance_route_rejects_missing_canary_other_student_and_other_state() {
        let fixture = Fixture::active(WINNER_CANARY_BASIS_POINTS, r#"["stream"]"#);
        let (winner, admission) = verified_winner(&fixture);
        let now: DateTime<Utc> = ACTIVE_NOW.parse().unwrap();
        assert!(
            advance_winner_route(
                &fixture.config,
                &fixture.scope,
                &winner,
                &admission,
                &fixture.secret_hex,
                WinnerRoutePhase::Zero,
                None,
                None,
                now,
            )
            .is_err()
        );
        let canary = advance_winner_route(
            &fixture.config,
            &fixture.scope,
            &winner,
            &admission,
            &fixture.secret_hex,
            WinnerRoutePhase::Canary,
            None,
            None,
            now,
        )
        .unwrap()
        .publication;
        let mut other_student = canary.clone();
        other_student.student_job_id = [0xaa; 32];
        assert!(
            advance_winner_route(
                &fixture.config,
                &fixture.scope,
                &winner,
                &admission,
                &fixture.secret_hex,
                WinnerRoutePhase::Canary,
                Some(&other_student),
                None,
                now,
            )
            .is_err()
        );
        let mut other_state = canary;
        other_state.candidate_basis_points = 200;
        assert!(
            advance_winner_route(
                &fixture.config,
                &fixture.scope,
                &winner,
                &admission,
                &fixture.secret_hex,
                WinnerRoutePhase::Canary,
                Some(&other_state),
                None,
                now,
            )
            .is_err()
        );
    }

    #[test]
    fn winner_admission_requires_canary_and_zero_runway() {
        let fixture = Fixture::active(WINNER_CANARY_BASIS_POINTS, r#"["stream"]"#);
        let source: RouteManifest = serde_json::from_slice(&fixture.manifest).unwrap();
        let authority = fixture.config.winner_deployment_authority().unwrap();
        let mut admission = source.winner_admission;
        admission.service_not_after =
            admission.admitted_at + TimeDelta::seconds(i64::from(WINNER_ROUTE_RUNWAY_SECONDS - 1));
        assert!(admission.validate_for_authority(&authority).is_err());
        admission.service_not_after =
            admission.admitted_at + TimeDelta::seconds(i64::from(WINNER_ROUTE_RUNWAY_SECONDS));
        assert!(admission.validate_for_authority(&authority).is_ok());
    }

    #[test]
    fn winner_authority_is_exactly_baseten_only_v3() {
        let fixture = Fixture::active(WINNER_CANARY_BASIS_POINTS, r#"["stream"]"#);
        let authority = fixture.config.winner_deployment_authority().unwrap();
        let encoded = serde_json::to_string(&authority).unwrap();
        assert!(encoded.starts_with(
            r#"{"schema_version":"milk.winner-deployment-authority.v3","provider_policy":{"only":"baseten"},"provider_terms_sha256":"#
        ));
        assert!(!encoded.contains("primary"));
        assert!(!encoded.contains("fallback"));

        let mut obsolete = authority;
        obsolete.schema_version = "milk.winner-deployment-authority.v2".to_owned();
        assert!(obsolete.validate().is_err());
    }

    #[test]
    fn live_pointer_is_typed_canonical_and_scope_bound() {
        let fixture = Fixture::active(10_000, "[]");
        let pointer =
            RouteLivePointer::new(fixture.scope.clone(), [0xaa; 32], Some([0xbb; 32])).unwrap();
        let bytes = pointer.to_bytes().unwrap();
        assert!(bytes.len() <= MAX_ROUTE_LIVE_BYTES);
        assert_eq!(
            RouteLivePointer::parse(&fixture.scope, &bytes).unwrap(),
            pointer
        );

        let mut noncanonical = bytes.clone();
        noncanonical.push(b'\n');
        assert!(RouteLivePointer::parse(&fixture.scope, &noncanonical).is_err());

        let mut wrong_scope = fixture.scope.clone();
        wrong_scope.scope_id = Uuid::new_v4();
        assert!(RouteLivePointer::parse(&wrong_scope, &bytes).is_err());
        assert!(RouteLivePointer::new(fixture.scope, [0xaa; 32], Some([0xaa; 32])).is_err());
    }

    #[test]
    fn signed_policy_routes_known_endpoints_without_rejecting_optional_fields() {
        let fixture = Fixture::active(10_000, r#"["stream"]"#);
        let policy = fixture.policy();
        let monotonic_now = Instant::now();
        let valid_body = br#"{"model":"customer-model","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
        let valid = request(valid_body, b"tenant-42");
        let decision = policy.decide(&valid, monotonic_now);
        assert_eq!(decision.target, RouteTarget::Candidate);
        assert_eq!(decision.route_revision, policy.revision());
        assert_eq!(decision.baseline_reason, None);
        let candidate = decision.candidate.unwrap();
        assert_eq!(candidate.endpoint.as_str(), "https://candidate.example/v1/");
        assert_eq!(candidate.candidate_sha256, repeated_digest(0x33));
        assert_eq!(candidate.artifact_sha256, repeated_digest(0x44));
        let manifest: RouteManifest = serde_json::from_slice(&fixture.manifest).unwrap();
        assert_eq!(
            candidate.deployment_sha256,
            hex_digest(&manifest.winner_admission.deployment_sha256().unwrap())
        );
        assert_eq!(candidate.max_in_flight, 2);
        assert_eq!(policy.candidate().unwrap().max_in_flight, 2);

        let with_tools = request(
            br#"{"model":"customer-model","messages":[],"tools":[]}"#,
            b"tenant-42",
        );
        assert_eq!(
            policy.decide(&with_tools, monotonic_now).target,
            RouteTarget::Candidate
        );
        for supported_body in [
            br#"{"model":"customer-model","messages":[],"response_format":{"type":"json_object"}}"#.as_slice(),
            br#"{"model":"customer-model","messages":[],"modalities":["text"]}"#.as_slice(),
            br#"{"model":"customer-model","messages":[],"tool_choice":"none"}"#.as_slice(),
            br#"{"model":"customer-model","messages":[],"unknown_extension":true}"#.as_slice(),
            br#"{"model":"customer-model","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA=="}}]}]}"#.as_slice(),
            br#"{"model":"customer-model","messages":[{"role":"user","content":[{"type":"input_audio","input_audio":{"data":"AA==","format":"wav"}}]}]}"#.as_slice(),
            br#"{"model":"customer-model","messages":[{"role":"user","content":[{"type":"file","file":{"file_id":"file-1"}}]}]}"#.as_slice(),
        ] {
            assert_eq!(
                policy
                    .decide(&request(supported_body, b"tenant-42"), monotonic_now)
                    .target,
                RouteTarget::Candidate
            );
        }
        let text_parts = request(
            br#"{"model":"customer-model","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}"#,
            b"tenant-42",
        );
        assert_eq!(
            policy.decide(&text_parts, monotonic_now).target,
            RouteTarget::Candidate
        );
        let wrong_model = request(br#"{"model":"another-model","messages":[]}"#, b"tenant-42");
        assert_baseline(
            policy.decide(&wrong_model, monotonic_now),
            BaselineReason::ModelMismatch,
        );
    }

    #[test]
    fn reasoning_effort_routes_only_when_it_matches_signed_policy() {
        let policy = RoutePolicy::active_with_reasoning_for_test(
            Url::parse("https://candidate.example/v1/").unwrap(),
            2,
            CANDIDATE_API_KEY,
            Some(CandidateReasoningEffort::High),
        );
        let matching = request(
            br#"{"model":"customer-model","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"high"}"#,
            b"tenant-42",
        );
        assert_eq!(
            policy.decide(&matching, Instant::now()).target,
            RouteTarget::Candidate
        );
        for body in [
            br#"{"model":"customer-model","messages":[{"role":"user","content":"hi"}]}"#.as_slice(),
            br#"{"model":"customer-model","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"low"}"#.as_slice(),
        ] {
            assert_baseline(
                policy.decide(&request(body, b"tenant-42"), Instant::now()),
                BaselineReason::ReasoningEffortMismatch,
            );
        }
        assert_baseline(
            policy.decide(
                &request(
                    br#"{"model":"customer-model","messages":[{"role":"user","content":"hi"}],"reasoning_effort":"extreme"}"#,
                    b"tenant-42",
                ),
                Instant::now(),
            ),
            BaselineReason::UnsupportedRequest,
        );
    }

    #[test]
    fn responses_routing_is_endpoint_aware_and_preserves_optional_fields() {
        let policy = RoutePolicy::active_for_test(
            Url::parse("https://candidate.example/v1/").unwrap(),
            2,
            CANDIDATE_API_KEY,
        );
        let body = br#"{"model":"customer-model","input":[{"role":"user","content":"hi"}],"conversation":"conv_123","stream":true,"tools":[{"type":"function","name":"lookup","parameters":{"type":"object"}}],"unknown_extension":{"enabled":true}}"#;
        let request = responses_request(body, b"session-hmac");
        assert_eq!(
            policy.decide(&request, Instant::now()).target,
            RouteTarget::Candidate
        );

        let mut fixture = Fixture::active(10_000, r#"["stream"]"#);
        let mut manifest: RouteManifest = serde_json::from_slice(&fixture.manifest).unwrap();
        manifest
            .supported_capabilities
            .retain(|capability| *capability != RouteCapability::Responses);
        fixture.manifest = serde_json::to_vec(&manifest).unwrap();
        fixture.signature = signing_key().sign(&fixture.manifest).as_ref().to_vec();
        assert_baseline(
            fixture.policy().decide(&request, Instant::now()),
            BaselineReason::UnsupportedCapability,
        );
    }

    #[test]
    fn candidate_input_bounds_count_items_and_raw_bytes() {
        let fixture = Fixture::active(10_000, "[]");
        let policy = fixture.policy();
        let monotonic_now = Instant::now();
        let body = |contents: Vec<String>| {
            let messages = contents
                .into_iter()
                .map(|content| serde_json::json!({"role": "user", "content": content}))
                .collect::<Vec<_>>();
            serde_json::to_vec(
                &serde_json::json!({"model": "customer-model", "messages": messages}),
            )
            .unwrap()
        };

        let sixteen_messages = body(vec!["x".to_owned(); CANDIDATE_MAX_INPUT_MESSAGES]);
        assert_eq!(
            policy
                .decide(&request(&sixteen_messages, b"tenant-42"), monotonic_now)
                .target,
            RouteTarget::Candidate
        );
        let seventeen_messages = body(vec!["x".to_owned(); CANDIDATE_MAX_INPUT_MESSAGES + 1]);
        assert_baseline(
            policy.decide(&request(&seventeen_messages, b"tenant-42"), monotonic_now),
            BaselineReason::UnsupportedCapability,
        );

        let mut exact_request_bytes = body(vec!["x".to_owned()]);
        exact_request_bytes.resize(CANDIDATE_MAX_INPUT_REQUEST_BYTES, b' ');
        assert_eq!(
            policy
                .decide(&request(&exact_request_bytes, b"tenant-42"), monotonic_now,)
                .target,
            RouteTarget::Candidate
        );
        exact_request_bytes.push(b' ');
        assert_baseline(
            policy.decide(&request(&exact_request_bytes, b"tenant-42"), monotonic_now),
            BaselineReason::UnsupportedCapability,
        );

        let oversized_input = body(vec!["x".repeat(CANDIDATE_MAX_INPUT_UTF8_BYTES + 1)]);
        assert_baseline(
            policy.decide(&request(&oversized_input, b"tenant-42"), monotonic_now),
            BaselineReason::UnsupportedCapability,
        );
    }

    #[test]
    fn signature_scope_origin_terms_and_secret_are_bound() {
        let fixture = Fixture::active(10_000, "[]");
        let mut tampered = fixture.manifest.clone();
        let last = tampered.len() - 2;
        tampered[last] ^= 1;
        assert!(
            RoutePolicy::from_signed_bytes(
                &fixture.config,
                &fixture.scope,
                Some(&fixture.secret_hex),
                Some(CANDIDATE_API_KEY),
                8,
                ACTIVE_NOW.parse().unwrap(),
                Instant::now(),
                &tampered,
                &fixture.signature,
            )
            .err()
            .unwrap()
            .to_string()
            .contains("signature verification")
        );

        let mut unknown = String::from_utf8(fixture.manifest.clone()).unwrap();
        unknown.insert_str(1, r#""unknown":true,"#);
        let unknown = unknown.into_bytes();
        let unknown_signature = signing_key().sign(&unknown);
        assert!(
            RoutePolicy::from_signed_bytes(
                &fixture.config,
                &fixture.scope,
                Some(&fixture.secret_hex),
                Some(CANDIDATE_API_KEY),
                8,
                ACTIVE_NOW.parse().unwrap(),
                Instant::now(),
                &unknown,
                unknown_signature.as_ref(),
            )
            .err()
            .unwrap()
            .to_string()
            .contains("strict typed JSON")
        );

        let mut wrong_scope = fixture.scope.clone();
        wrong_scope.scope_id = Uuid::new_v4();
        assert!(load_bytes(&fixture, &fixture.config, &wrong_scope, &fixture.secret_hex).is_err());
        let mut wrong_eval = fixture.scope.clone();
        wrong_eval.scope_id = Uuid::new_v4();
        assert!(load_bytes(&fixture, &fixture.config, &wrong_eval, &fixture.secret_hex).is_err());

        let mut wrong_terms = fixture.config.clone();
        wrong_terms.authorized_provider_terms_sha256 = Some(repeated_digest(0xaa));
        assert!(load_bytes(&fixture, &wrong_terms, &fixture.scope, &fixture.secret_hex).is_err());

        let wrong_secret = hex_bytes(&[1; 32]);
        assert!(load_bytes(&fixture, &fixture.config, &fixture.scope, &wrong_secret).is_err());
        for (expected, unsupported) in [
            (
                "\"max_input_utf8_bytes\":2048",
                "\"max_input_utf8_bytes\":2049",
            ),
            ("\"max_input_messages\":16", "\"max_input_messages\":17"),
            (
                "\"max_input_request_bytes\":16384",
                "\"max_input_request_bytes\":16385",
            ),
        ] {
            let manifest = String::from_utf8(fixture.manifest.clone())
                .unwrap()
                .replacen(expected, unsupported, 1)
                .into_bytes();
            let signature = signing_key().sign(&manifest);
            assert!(
                RoutePolicy::from_signed_bytes(
                    &fixture.config,
                    &fixture.scope,
                    Some(&fixture.secret_hex),
                    Some(CANDIDATE_API_KEY),
                    8,
                    ACTIVE_NOW.parse().unwrap(),
                    Instant::now(),
                    &manifest,
                    signature.as_ref(),
                )
                .is_err()
            );
        }
        let mut no_baseline_capacity = fixture.config.clone();
        no_baseline_capacity.candidate_max_in_flight = 8;
        assert!(
            load_bytes(
                &fixture,
                &no_baseline_capacity,
                &fixture.scope,
                &fixture.secret_hex,
            )
            .is_err()
        );
        assert!(
            RoutePolicy::from_signed_bytes(
                &fixture.config,
                &fixture.scope,
                Some(&fixture.secret_hex),
                Some(CANDIDATE_API_KEY),
                8,
                ACTIVE_NOW.parse().unwrap(),
                Instant::now(),
                &fixture.manifest,
                &fixture.signature[..63],
            )
            .is_err()
        );
    }

    #[test]
    fn signed_route_binds_the_exact_authorized_winner_admission() {
        let fixture = Fixture::active(100, r#"["stream"]"#);
        let publication = RoutePublication::parse_for_publication(
            &fixture.config,
            &fixture.scope,
            &fixture.manifest,
            Some(&fixture.signature),
            ACTIVE_NOW.parse().unwrap(),
        )
        .unwrap();
        let manifest: RouteManifest = serde_json::from_slice(&fixture.manifest).unwrap();
        assert_eq!(publication.student_variant, WinnerVariant::StaticFp8);
        assert_eq!(
            publication.candidate_api_base_url,
            manifest.winner_admission.api_base_url
        );
        assert_eq!(
            publication.logical_model_alias,
            manifest.winner_admission.model_alias
        );
        assert_eq!(
            publication.deployment_sha256,
            manifest.winner_admission.deployment_sha256().unwrap()
        );
        assert!(!String::from_utf8_lossy(&fixture.manifest).contains("\"deployment_sha256\""));

        let mut unsupported_manifest: RouteManifest =
            serde_json::from_slice(&fixture.manifest).unwrap();
        unsupported_manifest.winner_admission.provider = "runpod".to_owned();
        let unsupported_manifest = serde_json::to_vec(&unsupported_manifest).unwrap();
        let unsupported_signature = signing_key().sign(&unsupported_manifest);
        assert!(
            RoutePublication::parse_for_publication(
                &fixture.config,
                &fixture.scope,
                &unsupported_manifest,
                Some(unsupported_signature.as_ref()),
                ACTIVE_NOW.parse().unwrap(),
            )
            .is_err()
        );

        let mut wrong_authority = fixture.config.clone();
        *wrong_authority.winner_max_cost_microusd.as_mut().unwrap() -= 1;
        assert!(
            RoutePublication::parse_for_publication(
                &wrong_authority,
                &fixture.scope,
                &fixture.manifest,
                Some(&fixture.signature),
                ACTIVE_NOW.parse().unwrap(),
            )
            .is_err()
        );

        let mut wrong_image = fixture.config.clone();
        wrong_image.authorized_student_branch_runtime_image_reference = Some(format!(
            "ghcr.io/milkinfrastructure/milk-student-branch@sha256:{}",
            repeated_digest(0xaa)
        ));
        assert!(
            RoutePublication::parse_for_publication(
                &wrong_image,
                &fixture.scope,
                &fixture.manifest,
                Some(&fixture.signature),
                ACTIVE_NOW.parse().unwrap(),
            )
            .is_err()
        );

        let mut wrong_program = fixture.config.clone();
        wrong_program.authorized_admission_program_sha256 = Some(repeated_digest(0xaa));
        assert!(
            RoutePublication::parse_for_publication(
                &wrong_program,
                &fixture.scope,
                &fixture.manifest,
                Some(&fixture.signature),
                ACTIVE_NOW.parse().unwrap(),
            )
            .is_err()
        );

        for mutation in ["student", "alias", "interval"] {
            let mut manifest: RouteManifest = serde_json::from_slice(&fixture.manifest).unwrap();
            match mutation {
                "student" => manifest.winner_admission.student_job_id = repeated_digest(0xaa),
                "alias" => manifest.winner_admission.model_alias_sha256 = repeated_digest(0xaa),
                "interval" => {
                    manifest.winner_admission.admitted_at =
                        manifest.not_before + chrono::TimeDelta::seconds(1);
                }
                _ => unreachable!(),
            }
            let manifest = serde_json::to_vec(&manifest).unwrap();
            let signature = signing_key().sign(&manifest);
            assert!(
                RoutePublication::parse_for_publication(
                    &fixture.config,
                    &fixture.scope,
                    &manifest,
                    Some(signature.as_ref()),
                    ACTIVE_NOW.parse().unwrap(),
                )
                .is_err(),
                "{mutation}"
            );
        }
    }

    #[test]
    fn inactive_policies_are_permanently_dormant_for_the_process() {
        let invalid = request(b"not-json", b"tenant-42");
        let baseline = RoutePolicy::baseline();
        assert_eq!(baseline.revision(), BASELINE_ROUTE_REVISION);
        assert_baseline(
            baseline.decide(&invalid, Instant::now()),
            BaselineReason::PolicyAbsent,
        );

        let zero_fixture = Fixture::active(0, "[]");
        let zero = zero_fixture.policy_with(None, None);
        assert!(zero.candidate().is_none());
        assert_baseline(
            zero.decide(&invalid, Instant::now()),
            BaselineReason::PolicyZero,
        );
        assert!(
            load_bytes(
                &zero_fixture,
                &zero_fixture.config,
                &zero_fixture.scope,
                &hex_bytes(&[1; 32]),
            )
            .is_err()
        );
        let mut rollback_config = zero_fixture.config.clone();
        rollback_config.candidate_max_in_flight = 8;
        assert!(
            RoutePolicy::from_signed_bytes(
                &rollback_config,
                &zero_fixture.scope,
                None,
                None,
                8,
                ACTIVE_NOW.parse().unwrap(),
                Instant::now(),
                &zero_fixture.manifest,
                &zero_fixture.signature,
            )
            .is_err()
        );

        let expired = Fixture::new(10_000, "[]", "2026-08-23T00:00:00Z", "2026-08-24T00:00:00Z")
            .policy_with(None, None);
        assert_baseline(
            expired.decide(&invalid, Instant::now()),
            BaselineReason::PolicyExpired,
        );

        let future = Fixture::new(10_000, "[]", "2026-08-27T00:00:00Z", "2026-08-28T00:00:00Z")
            .policy_with(None, None);
        assert_baseline(
            future.decide(&invalid, Instant::now()),
            BaselineReason::PolicyNotYetValid,
        );

        let missing_secret =
            Fixture::active(10_000, "[]").policy_with(None, Some(CANDIDATE_API_KEY));
        assert_baseline(
            missing_secret.decide(&invalid, Instant::now()),
            BaselineReason::RouteSecretMissing,
        );
        let fixture = Fixture::active(10_000, "[]");
        let missing_credential = fixture.policy_with(Some(&fixture.secret_hex), None);
        assert_baseline(
            missing_credential.decide(&invalid, Instant::now()),
            BaselineReason::CandidateCredentialMissing,
        );
        assert!(
            RoutePolicy::from_signed_bytes(
                &fixture.config,
                &fixture.scope,
                Some(&fixture.secret_hex),
                Some("wrong-candidate-key"),
                8,
                ACTIVE_NOW.parse().unwrap(),
                Instant::now(),
                &fixture.manifest,
                &fixture.signature,
            )
            .err()
            .unwrap()
            .to_string()
            .contains("admitted credential")
        );
    }

    #[test]
    fn publication_and_startup_enforce_the_24_hour_validity_ceiling() {
        let rollback_revision = repeated_digest(0x88);
        let zero = Fixture::new_with_previous(
            0,
            "[]",
            ACTIVE_NOT_BEFORE,
            ACTIVE_NOT_AFTER,
            Some(&rollback_revision),
        );
        let publication = RoutePublication::parse_for_publication(
            &zero.config,
            &zero.scope,
            &zero.manifest,
            Some(&zero.signature),
            ACTIVE_NOW.parse().unwrap(),
        )
        .unwrap();
        assert_eq!(publication.candidate_basis_points, 0);
        assert_eq!(publication.cohort_sha256, [0x22; 32]);
        assert_eq!(publication.previous_route_revision, Some([0x88; 32]));
        let route_secret_sha256: [u8; 32] = Sha256::digest(ROUTE_SECRET).into();
        assert_eq!(publication.route_secret_sha256, route_secret_sha256);
        assert!(
            RoutePublication::parse_archived(
                &zero.config,
                &zero.scope,
                &zero.manifest,
                &zero.signature,
            )
            .is_ok()
        );
        let mut bad_signature = zero.signature.clone();
        bad_signature[0] ^= 1;
        assert!(
            RoutePublication::parse_archived(
                &zero.config,
                &zero.scope,
                &zero.manifest,
                &bad_signature,
            )
            .is_err()
        );

        let nonzero_previous = Fixture::new_with_previous(
            100,
            "[]",
            ACTIVE_NOT_BEFORE,
            ACTIVE_NOT_AFTER,
            Some(&rollback_revision),
        );
        assert!(
            RoutePublication::parse_for_publication(
                &nonzero_previous.config,
                &nonzero_previous.scope,
                &nonzero_previous.manifest,
                Some(&nonzero_previous.signature),
                ACTIVE_NOW.parse().unwrap(),
            )
            .is_ok()
        );

        let too_long = Fixture::new(0, "[]", "2026-08-25T00:00:00Z", "2026-08-26T00:00:01Z");
        assert!(
            RoutePolicy::from_signed_bytes(
                &too_long.config,
                &too_long.scope,
                None,
                None,
                8,
                ACTIVE_NOW.parse().unwrap(),
                Instant::now(),
                &too_long.manifest,
                &too_long.signature,
            )
            .is_err()
        );
    }

    #[test]
    fn sticky_hash_math_is_exact() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &ROUTE_SECRET);
        let experiment = [0x22; 32];
        let sample = sticky_sample(&key, &experiment, b"tenant-42");
        assert_eq!(sample, 1_037_516_788_915_898_171);
        assert!(!selected(sample, 562));
        assert!(selected(sample, 563));
        let one_basis_point = ((1_u128 << u64::BITS) / 10_000) as u64;
        assert!(selected(one_basis_point - 1, 1));
        assert!(!selected(one_basis_point, 1));
        assert!(!selected(u64::MAX, 0));
        assert!(selected(u64::MAX, 10_000));
    }

    #[test]
    fn candidate_api_base_requires_explicit_private_http_authorization() {
        assert!(validate_candidate_api_base_url("https://candidate.example/v1/", false).is_ok());
        assert!(validate_candidate_api_base_url("http://127.0.0.1:8081/v1/", false).is_ok());
        assert!(validate_candidate_api_base_url("http://[::1]:8081/v1/", false).is_ok());
        assert!(
            validate_candidate_api_base_url(
                "https://model-a1b2c3.api.baseten.co/environments/production/sync/v1/",
                false,
            )
            .is_ok()
        );
        for private in [
            "http://10.0.0.1:8080/v1/",
            "http://10.255.255.254:8080/v1/",
            "http://172.16.0.1:8080/v1/",
            "http://172.31.255.254:8080/v1/",
            "http://192.168.0.1:8080/v1/",
            "http://192.168.255.254:8080/v1/",
        ] {
            assert!(
                validate_candidate_api_base_url(private, false).is_err(),
                "{private}"
            );
            assert!(
                validate_candidate_api_base_url(private, true).is_ok(),
                "{private}"
            );
        }
        for invalid in [
            "http://candidate.example/v1/",
            "http://localhost:8081/v1/",
            "http://172.15.255.255:8080/v1/",
            "http://172.32.0.1:8080/v1/",
            "http://192.167.255.255:8080/v1/",
            "http://192.169.0.1:8080/v1/",
            "http://169.254.169.254/v1/",
            "http://100.64.0.1/v1/",
            "http://8.8.8.8/v1/",
            "http://[fd00::1]/v1/",
            "http://0x0a000001/v1/",
            "http://user:pass@10.0.0.1/v1/",
            "http://127.0.0.1:8081/v1/models",
            "http://127.0.0.1:8081/v1/?debug=1",
            "http://10.0.0.1/v1/#fragment",
            "https://candidate.example/v1-extra/",
        ] {
            assert!(
                validate_candidate_api_base_url(invalid, true).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn signed_route_requires_startup_opt_in_for_private_http() {
        let mut fixture = Fixture::active(10_000, r#"["stream"]"#);
        let private = "http://10.0.0.8:8080/v1/";
        fixture.manifest = String::from_utf8(fixture.manifest)
            .unwrap()
            .replace("https://candidate.example/v1/", private)
            .into_bytes();
        fixture.signature = signing_key().sign(&fixture.manifest).as_ref().to_vec();
        assert!(
            load_bytes(
                &fixture,
                &fixture.config,
                &fixture.scope,
                &fixture.secret_hex,
            )
            .is_err()
        );
        fixture.config.allow_private_candidate_http = true;
        let mut manifest: RouteManifest = serde_json::from_slice(&fixture.manifest).unwrap();
        manifest.winner_provider_binding_sha256 = hex_digest(
            &fixture
                .config
                .winner_deployment_authority()
                .unwrap()
                .provider_binding_sha256()
                .unwrap(),
        );
        fixture.manifest = serde_json::to_vec(&manifest).unwrap();
        fixture.signature = signing_key().sign(&fixture.manifest).as_ref().to_vec();
        assert_eq!(
            fixture.policy().candidate().unwrap().endpoint.as_str(),
            private
        );
    }

    fn request<'a>(body: &'a [u8], routing_cohort: &'a [u8]) -> RouteRequest<'a> {
        RouteRequest {
            endpoint: RouteEndpoint::ChatCompletions,
            body,
            content_type: Some(b"Application/JSON; charset=utf-8"),
            has_multiple_content_types: false,
            has_content_encoding: false,
            has_openai_beta: false,
            query: "",
            routing_cohort,
        }
    }

    fn responses_request<'a>(body: &'a [u8], routing_cohort: &'a [u8]) -> RouteRequest<'a> {
        RouteRequest {
            endpoint: RouteEndpoint::Responses,
            ..request(body, routing_cohort)
        }
    }

    fn assert_baseline(decision: RouteDecision<'_>, reason: BaselineReason) {
        assert_eq!(decision.target, RouteTarget::Baseline);
        assert_eq!(decision.baseline_reason, Some(reason));
        assert!(decision.candidate.is_none());
    }

    fn load_bytes(
        fixture: &Fixture,
        config: &RouteStartupConfig,
        scope: &RouteScope,
        secret: &str,
    ) -> Result<RoutePolicy> {
        RoutePolicy::from_signed_bytes(
            config,
            scope,
            Some(secret),
            Some(CANDIDATE_API_KEY),
            8,
            ACTIVE_NOW.parse().unwrap(),
            Instant::now(),
            &fixture.manifest,
            &fixture.signature,
        )
    }

    fn signing_key() -> Ed25519KeyPair {
        Ed25519KeyPair::from_seed_unchecked(&SIGNING_SEED).unwrap()
    }

    fn repeated_digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn hex_bytes(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }
}
