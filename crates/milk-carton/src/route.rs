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

pub(crate) const OPERATOR_ROUTE_PROPOSAL_SCHEMA_VERSION: &str = "milk.unsigned-route-proposal.v3";
pub(crate) const OPERATOR_ROUTE_SCHEMA_VERSION: &str = "milk.route.v1";
const ROUTE_LIVE_SCHEMA_VERSION: &str = "milk.route-live.v1";
const BASELINE_ROUTE_REVISION: &str = "openai-baseline-v1";
pub(crate) const MAX_ROUTE_MANIFEST_BYTES: usize = 8 * 1_024;
pub(crate) const ED25519_SIGNATURE_BYTES: usize = 64;
pub(crate) const MAX_ROUTE_LIVE_BYTES: usize = 1_024;
const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_MODEL_BYTES: usize = 256;
const MAX_KEY_ID_BYTES: usize = 128;
const MAX_EXECUTION_ID_BYTES: usize = 256;
const MAX_IMAGE_REFERENCE_BYTES: usize = 2_048;
const MAX_CAPABILITIES: usize = 8;
pub(crate) const CANDIDATE_CONTEXT_WINDOW_TOKENS: u32 = 4_096;
pub(crate) const CANDIDATE_MAX_INPUT_UTF8_BYTES: usize = 2_048;
pub(crate) const CANDIDATE_MAX_INPUT_MESSAGES: usize = 16;
pub(crate) const CANDIDATE_MAX_INPUT_REQUEST_BYTES: usize = 16_384;
const OPERATOR_CANDIDATE_VALID_FOR_SECONDS: u32 = 15 * 60;
const OPERATOR_ZERO_VALID_FOR_SECONDS: u32 = 60;
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
const MAX_HARNESS_CANDIDATE_BASIS_POINTS: u16 = 1_000;
const HARNESS_CODE_VERSION: &str = "milk.harness-run-once.v4";
const HARNESS_TAXONOMY_VERSION: &str = "milk.semantic-taxonomy.v1";

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RouteStartupConfig {
    pub(crate) signing_public_key_hex: String,
    pub(crate) signing_key_id: String,
    pub(crate) allow_private_candidate_http: bool,
    pub(crate) candidate_max_in_flight: usize,
}

impl RouteStartupConfig {
    pub(crate) fn validate_common(&self, gateway_max_in_flight: usize) -> Result<()> {
        decode_lowercase_hex_32(&self.signing_public_key_hex, "route signing public key")?;
        if self.signing_key_id.is_empty() || self.signing_key_id.len() > MAX_KEY_ID_BYTES {
            bail!("route signing key ID is invalid");
        }
        if gateway_max_in_flight < 2
            || self.candidate_max_in_flight == 0
            || self.candidate_max_in_flight >= gateway_max_in_flight
        {
            bail!("candidate_max_in_flight must reserve at least one baseline request slot");
        }
        Ok(())
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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HarnessProfile {
    Mechanics,
    Production,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessTeacherBinding {
    pub(crate) api_url: String,
    pub(crate) model: String,
    pub(crate) reasoning_effort: String,
    pub(crate) timeout_seconds: u64,
    pub(crate) max_input_tokens: u64,
    pub(crate) max_output_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessScoreTargetBinding {
    pub(crate) api_url: String,
    pub(crate) model: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessCandidateScoreBinding {
    pub(crate) incumbent: HarnessScoreTargetBinding,
    pub(crate) candidate: HarnessScoreTargetBinding,
    pub(crate) held_out_cases: u64,
    pub(crate) timeout_seconds: u64,
    pub(crate) minimum_request_interval_ms: u64,
    pub(crate) max_calls_per_run: u64,
    pub(crate) max_input_tokens_per_call: u64,
    pub(crate) max_output_tokens_per_call: u64,
    pub(crate) max_total_tokens_per_run: u64,
    pub(crate) case_reference_similarity_basis_points: u16,
    pub(crate) minimum_candidate_reference_pass_basis_points: u16,
    pub(crate) minimum_reference_pass_delta_basis_points: i16,
    pub(crate) maximum_candidate_error_basis_points: u16,
    pub(crate) maximum_candidate_p95_latency_ms: u64,
    pub(crate) minimum_fallback_reference_pass_basis_points: u16,
    pub(crate) maximum_fallback_error_basis_points: u16,
    pub(crate) maximum_fallback_p95_latency_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessPromptDigests {
    pub(crate) classifier: String,
    pub(crate) eval_generation: String,
    pub(crate) eval_validation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessJobIds {
    pub(crate) classifier: String,
    pub(crate) eval_generation: String,
    pub(crate) eval_validation: String,
    pub(crate) candidate_score: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HarnessTeacherResultDigests {
    pub(crate) classifier: String,
    pub(crate) eval_generation: String,
    pub(crate) eval_validation: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorRouteProvenance {
    pub(crate) harness_revision: String,
    pub(crate) config_sha256: String,
    pub(crate) taxonomy_version: String,
    pub(crate) prompt_sha256s: HarnessPromptDigests,
    pub(crate) teacher: HarnessTeacherBinding,
    pub(crate) candidate_score: HarnessCandidateScoreBinding,
    pub(crate) job_ids: HarnessJobIds,
    pub(crate) teacher_result_sha256s: HarnessTeacherResultDigests,
    pub(crate) provider_tokens: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorRouteProposal {
    pub(crate) schema_version: String,
    pub(crate) scope_id: Uuid,
    pub(crate) profile: HarnessProfile,
    pub(crate) series_id: String,
    pub(crate) code_version: String,
    pub(crate) source_manifest_sha256: String,
    pub(crate) summary_sha256: String,
    pub(crate) readiness_sha256: String,
    pub(crate) eval_sha256: String,
    pub(crate) eval_validation_sha256: String,
    pub(crate) candidate_score_sha256: String,
    pub(crate) candidate_id: String,
    pub(crate) api_base_url: String,
    pub(crate) model: String,
    pub(crate) candidate_basis_points: u16,
    pub(crate) provenance: OperatorRouteProvenance,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorRouteManifest {
    schema_version: String,
    scope: RouteScope,
    proposal_sha256: String,
    profile: HarnessProfile,
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
    pub(crate) has_candidate: bool,
    pub(crate) revision: [u8; 32],
    pub(crate) cohort_sha256: [u8; 32],
    pub(crate) proposal_sha256: [u8; 32],
    pub(crate) candidate_api_key_sha256: Option<[u8; 32]>,
    pub(crate) candidate_basis_points: u16,
    pub(crate) previous_route_revision: Option<[u8; 32]>,
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

    pub(crate) const fn operator_proposal_sha256(&self) -> [u8; 32] {
        self.proposal_sha256
    }
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
    prepare_operator_route_manifest_inner(
        config,
        scope,
        proposal_bytes,
        route_secret_hex,
        candidate_api_key,
        previous,
        now,
        false,
    )
}

pub(crate) fn prepare_operator_zero_route_manifest(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    proposal_bytes: &[u8],
    previous: &RoutePublication,
    now: DateTime<Utc>,
) -> Result<(Vec<u8>, RoutePublication)> {
    prepare_operator_route_manifest_inner(
        config,
        scope,
        proposal_bytes,
        None,
        None,
        Some(previous),
        now,
        true,
    )
}

#[allow(clippy::too_many_arguments)]
fn prepare_operator_route_manifest_inner(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    proposal_bytes: &[u8],
    route_secret_hex: Option<&str>,
    candidate_api_key: Option<&str>,
    previous: Option<&RoutePublication>,
    now: DateTime<Utc>,
    zero: bool,
) -> Result<(Vec<u8>, RoutePublication)> {
    let proposal = parse_operator_route_proposal(config, scope, proposal_bytes)?;
    let proposal_sha256: [u8; 32] = Sha256::digest(proposal_bytes).into();
    if zero {
        let previous = previous.context("operator zero route requires a live predecessor")?;
        if proposal.candidate_basis_points == 0
            || !previous.has_candidate
            || previous.candidate_basis_points == 0
            || previous.proposal_sha256 != proposal_sha256
        {
            bail!("operator zero route requires the live candidate route for this exact proposal");
        }
    }
    let candidate_basis_points = if zero {
        0
    } else {
        proposal.candidate_basis_points
    };
    let candidate = if candidate_basis_points == 0 {
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
        OPERATOR_CANDIDATE_VALID_FOR_SECONDS
    } else {
        OPERATOR_ZERO_VALID_FOR_SECONDS
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
        proposal_sha256: hex_digest(&proposal_sha256),
        profile: proposal.profile,
        candidate,
        candidate_basis_points,
        previous_route_revision: previous.map(RoutePublication::revision_hex),
        route_secret_sha256,
        not_before,
        not_after,
        signing_key_id: config.signing_key_id.clone(),
    })?;
    let publication = RoutePublication::parse_for_publication(config, scope, &manifest, None, now)?;
    Ok((manifest, publication))
}

pub(crate) fn parse_operator_route_proposal(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    proposal_bytes: &[u8],
) -> Result<OperatorRouteProposal> {
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
    if proposal.candidate_basis_points > MAX_HARNESS_CANDIDATE_BASIS_POINTS {
        bail!("candidate_basis_points cannot exceed 1000");
    }
    for (value, description) in [
        (&proposal.source_manifest_sha256, "source manifest SHA-256"),
        (&proposal.summary_sha256, "summary SHA-256"),
        (&proposal.readiness_sha256, "readiness SHA-256"),
        (&proposal.eval_sha256, "eval SHA-256"),
        (&proposal.eval_validation_sha256, "eval validation SHA-256"),
        (&proposal.candidate_score_sha256, "candidate score SHA-256"),
        (&proposal.provenance.config_sha256, "harness config SHA-256"),
        (
            &proposal.provenance.prompt_sha256s.classifier,
            "classifier prompt SHA-256",
        ),
        (
            &proposal.provenance.prompt_sha256s.eval_generation,
            "eval generation prompt SHA-256",
        ),
        (
            &proposal.provenance.prompt_sha256s.eval_validation,
            "eval validation prompt SHA-256",
        ),
        (&proposal.provenance.job_ids.classifier, "classifier job ID"),
        (
            &proposal.provenance.job_ids.eval_generation,
            "eval generation job ID",
        ),
        (
            &proposal.provenance.job_ids.eval_validation,
            "eval validation job ID",
        ),
        (
            &proposal.provenance.job_ids.candidate_score,
            "candidate score job ID",
        ),
        (
            &proposal.provenance.teacher_result_sha256s.classifier,
            "classifier result SHA-256",
        ),
        (
            &proposal.provenance.teacher_result_sha256s.eval_generation,
            "eval generation result SHA-256",
        ),
        (
            &proposal.provenance.teacher_result_sha256s.eval_validation,
            "eval validation result SHA-256",
        ),
    ] {
        decode_lowercase_hex_32(value, description)?;
    }
    if proposal.profile != HarnessProfile::Production {
        bail!("candidate proposals require production-qualified evidence");
    }
    if !valid_harness_identifier(&proposal.series_id)
        || !valid_harness_identifier(&proposal.candidate_id)
        || !valid_model_alias(&proposal.model)
        || proposal.code_version != HARNESS_CODE_VERSION
        || proposal.provenance.taxonomy_version != HARNESS_TAXONOMY_VERSION
        || proposal.provenance.harness_revision.len() != 40
        || !proposal
            .provenance
            .harness_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("route proposal harness identity is invalid");
    }
    validate_candidate_api_base_url(&proposal.api_base_url, config.allow_private_candidate_http)?;
    Ok(proposal)
}

pub(crate) fn verify_operator_manifest_proposal_binding(
    config: &RouteStartupConfig,
    scope: &RouteScope,
    manifest_bytes: &[u8],
    proposal_bytes: &[u8],
) -> Result<()> {
    let proposal = parse_operator_route_proposal(config, scope, proposal_bytes)?;
    let manifest: OperatorRouteManifest = serde_json::from_slice(manifest_bytes)
        .context("operator route manifest is not strict typed JSON")?;
    if serde_json::to_vec(&manifest)? != manifest_bytes {
        bail!("route manifest is not canonical JSON");
    }
    validate_operator_manifest(config, scope, &manifest)?;
    if manifest.profile != proposal.profile {
        bail!("signed route profile differs from its stored proposal");
    }
    let proposal_sha256: [u8; 32] = Sha256::digest(proposal_bytes).into();
    if manifest.proposal_sha256 != hex_digest(&proposal_sha256) {
        bail!("signed route does not reference the exact stored proposal");
    }

    let expected_validity = if let Some(candidate) = &manifest.candidate {
        if manifest.candidate_basis_points != proposal.candidate_basis_points
            || proposal.candidate_basis_points == 0
            || candidate.eval_sha256 != proposal.eval_sha256
            || candidate.candidate_id != proposal.candidate_id
            || candidate.api_base_url != proposal.api_base_url
            || candidate.model != proposal.model
            || candidate.supported_capabilities != [RouteCapability::Stream]
            || candidate.reasoning_effort.is_some()
        {
            bail!("signed candidate route differs from its stored proposal");
        }
        OPERATOR_CANDIDATE_VALID_FOR_SECONDS
    } else {
        if proposal.candidate_basis_points == 0
            || manifest.candidate_basis_points != 0
            || manifest.previous_route_revision.is_none()
        {
            bail!("signed zero route differs from its candidate proposal lineage");
        }
        OPERATOR_ZERO_VALID_FOR_SECONDS
    };
    if manifest.not_before.nanosecond() != 0
        || manifest.not_after.nanosecond() != 0
        || manifest.not_after - manifest.not_before
            != TimeDelta::seconds(i64::from(expected_validity))
    {
        bail!("signed operator route validity differs from the bounded prepared route");
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
            publication: _,
        } = parse_manifest(config, expected_scope, manifest_bytes)?;
        config.validate_common(gateway_max_in_flight)?;

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
            "candidate API key SHA-256",
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
    parse_operator_manifest(config, expected_scope, manifest_bytes)
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
    if let Some(value) = manifest.route_secret_sha256.as_deref() {
        decode_lowercase_hex_32(value, "route secret SHA-256")?;
    }
    let (candidate, candidate_sha256, deployment_sha256, candidate_api_key_sha256) =
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
                deployment_sha256,
                Some(decode_lowercase_hex_32(
                    &candidate.candidate_api_key_sha256,
                    "candidate API key SHA-256",
                )?),
            )
        } else {
            (None, [0; 32], [0; 32], None)
        };
    let cohort_sha256 = if candidate.is_some() {
        candidate_sha256
    } else {
        proposal_sha256
    };
    let publication = RoutePublication {
        has_candidate: candidate.is_some(),
        revision,
        cohort_sha256,
        proposal_sha256,
        candidate_api_key_sha256,
        candidate_basis_points: manifest.candidate_basis_points,
        previous_route_revision,
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
            if manifest.profile != HarnessProfile::Production {
                bail!("candidate routes require production-qualified evidence");
            }
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

fn valid_harness_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
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
