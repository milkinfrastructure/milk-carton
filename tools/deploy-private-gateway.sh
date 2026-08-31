#!/bin/sh
set -eu
umask 077

exec 3<&0
exec python3 - "$0" "$@" 3<&3 <<'PY'
import copy
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path


DEPLOYMENT_TARGETS = {
    "production": ("milk-carton", "milk-carton-milkcarton", "carton.milkinfrastructure.com"),
    "mechanics": (
        "milk-carton-mechanics",
        "milk-carton-mechanics-milkcarton",
        "mechanics-carton.milkinfrastructure.com",
    ),
}
WORKER, APPLICATION_NAME, EXPECTED_HOSTNAME = DEPLOYMENT_TARGETS["production"]
SOURCE_REPOSITORY = "https://github.com/milkinfrastructure/milk-carton"
GHCR_REPOSITORY = "ghcr.io/milkinfrastructure/milk-carton"
REGISTRY = "registry.cloudflare.com"
WRANGLER_VERSION = "4.126.0"
MAIN_SENTINEL = ".milk-private-deploy-script-required"
IMAGE_SENTINEL = "registry.invalid/milk-carton:admitted-image-required"
CUSTOM_DOMAIN_SENTINEL = "MILK_CARTON_CUSTOM_DOMAIN_REQUIRED"
BUILDKIT_IMAGE = "moby/buildkit@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e"
DOCKERFILE_FRONTEND = "docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
SLSA_V1 = "https://slsa.dev/provenance/v1"
SPDX = "https://spdx.dev/Document"
SHA256 = re.compile(r"[0-9a-f]{64}")
SHA1 = re.compile(r"[0-9a-f]{40}")
ACCOUNT_ID = re.compile(r"[0-9a-f]{32}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
RFC3339 = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
TAG = re.compile(r"[a-z0-9_][a-z0-9._-]{0,127}")
REPOSITORY = re.compile(r"[a-z0-9]+(?:[._-][a-z0-9]+)*(?:/[a-z0-9]+(?:[._-][a-z0-9]+)*)*")
COHORT_ID = re.compile(r"[A-Za-z0-9._~-]{1,128}")
HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
PRODUCTION_PROOF = {
    "baseline_requests": 322,
    "candidate_requests": 2,
    "generated_concurrency": 1,
    "generated_health_timeout_ms": 30000,
    "generated_minimum_request_interval_ms": 4250,
    "generated_mechanics_requests": 320,
    "generated_reasoning_effort": "low",
    "generated_request_timeout_ms": 60000,
    "max_sdk_requests": 324,
    "model": "zai-org/GLM-5.3-Flash",
    "saturation_max_completion_tokens": 3840,
    "short_max_completion_tokens": 256,
}
PRODUCTION_PROOF_SHA256 = "d9fb8b4daa1754acdbadc3b4028601434b79bf9c2096343c7a790df838bbcc66"
if hashlib.sha256(json.dumps(
    PRODUCTION_PROOF, sort_keys=True, separators=(",", ":"),
).encode()).hexdigest() != PRODUCTION_PROOF_SHA256:
    raise RuntimeError("production proof contract SHA-256 is stale")
OFFICIAL_OPENAI_SDK_BASELINE_FIELDS = {
    "authenticated", "baseline_request_count", "candidate_request_count",
    "choice_count", "content_retained", "endpoint_sha256", "finish_reason",
    "http_status", "max_completion_tokens", "model", "proof_contract_sha256",
    "proof_step", "request_sha256", "response_bytes", "response_sha256",
    "schema_version", "sdk", "sdk_request_count", "sdk_version", "succeeded",
    "traffic_cohort_sha256", "traffic_key_sha256",
}
CURRENT_DEPLOYMENT_FIELDS = {
    "schema_version", "operation_id", "worker_version_id", "application_name",
    "application_id", "application_version", "image", "gateway_config_sha256",
    "official_openai_sdk_baseline_receipt_sha256", "proof_contract_sha256",
    "rollout", "accepted",
}
POLL_ATTEMPTS = 20
POLL_INTERVAL_SECONDS = 15
MAX_JSON = 1024 * 1024
BOOTSTRAP_REQUIRED_SECRET_NAMES = {
    "MILK_CARTON_CONFIG_JSON",
    "MILK_CARTON_CONTAINER_ADMIN_KEY",
    "MILK_CARTON_OPENAI_API_KEY",
    "MILK_CAPTURE_SAMPLING_KEY_HEX",
    "MILK_CAPTURE_SAMPLING_KEY_VERSION",
    "MILK_CAPTURE_STORE_ACCESS_KEY_ID",
    "MILK_CAPTURE_STORE_SECRET_ACCESS_KEY",
    "MILK_ROUTE_STORE_ACCESS_KEY_ID",
    "MILK_ROUTE_STORE_SECRET_ACCESS_KEY",
}
BOOTSTRAP_OPTIONAL_SECRET_NAMES = {
    "MILK_CARTON_ROUTE_SECRET_HEX",
    "MILK_CAPTURE_STORE_SESSION_TOKEN",
    "MILK_ROUTE_STORE_SESSION_TOKEN",
}
BOOTSTRAP_CLEANUP_ATTEMPTS = 6
BOOTSTRAP_CLEANUP_ABSENCE_PROOFS = 3
BOOTSTRAP_CLEANUP_INTERVAL_SECONDS = 5


class DeployFailure(Exception):
    pass


class ContractFailure(DeployFailure):
    pass


class CommandFailure(DeployFailure):
    def __init__(self, action):
        super().__init__(action)
        self.action = action


class Interrupted(DeployFailure):
    pass


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def clear_sensitive_bytes(value):
    if value is not None:
        value[:] = b"\0" * len(value)


def validate_api_base_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise DeployFailure("API base URL is invalid") from error
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or HOSTNAME.fullmatch(hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.netloc != hostname
        or parsed.path != "/v1"
        or parsed.query
        or parsed.fragment
    ):
        raise DeployFailure("API base URL must be a lowercase HTTPS domain ending in /v1")
    return value, hostname, f"https://{hostname}/healthz"


def utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def within(path, parent):
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def require_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise ContractFailure(f"invalid {label}")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ContractFailure("duplicate JSON key")
        value[key] = item
    return value


def parse_json(raw, label, maximum=MAX_JSON):
    if len(raw) > maximum:
        raise ContractFailure(f"oversized {label}")
    try:
        return json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ContractFailure(f"invalid {label}") from error


def read_regular(path, label, maximum=MAX_JSON):
    if path.is_symlink() or not path.is_file():
        raise ContractFailure(f"missing {label}")
    raw = path.read_bytes()
    if len(raw) > maximum:
        raise ContractFailure(f"oversized {label}")
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def validate_wrangler_oauth(command, config, environment, account_id):
    try:
        version = subprocess.run(
            [command, "--version"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            check=False, timeout=60,
        )
        versions = re.findall(
            r"(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])",
            version.stdout.decode("utf-8", errors="strict"),
        )
        if version.returncode != 0 or versions != [WRANGLER_VERSION]:
            raise ContractFailure("Wrangler is not pinned to 4.126.0")
        whoami = subprocess.run(
            [command, "whoami", "--json", "--config", str(config)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, check=False, timeout=60,
        )
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise DeployFailure("Wrangler OAuth preflight failed") from error
    if whoami.returncode != 0:
        raise DeployFailure("Wrangler OAuth preflight failed")
    value = parse_json(whoami.stdout, "Wrangler whoami response")
    accounts = value.get("accounts") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("loggedIn") is not True
        or not isinstance(accounts, list)
    ):
        raise DeployFailure("Wrangler OAuth session is not logged in")
    if not any(
        isinstance(account, dict) and account.get("id") == account_id
        for account in accounts
    ):
        raise DeployFailure("Wrangler OAuth account does not match CLOUDFLARE_ACCOUNT_ID")
    return {
        "schema_version": "milk.wrangler-oauth-preflight.v1",
        "command": "wrangler whoami --json",
        "wrangler_version": WRANGLER_VERSION,
        "logged_in": True,
        "account_match": True,
        "content_retained": False,
    }


def validate_deployment_baseline_binding(current_raw, baseline_raw, expected_sha256):
    current = parse_json(current_raw, "current deployment", 65536)
    baseline = parse_json(baseline_raw, "official OpenAI SDK baseline", 65536)
    require_keys(current, CURRENT_DEPLOYMENT_FIELDS, "current deployment")
    require_keys(
        baseline,
        OFFICIAL_OPENAI_SDK_BASELINE_FIELDS,
        "official OpenAI SDK baseline",
    )
    if (
        current_raw != canonical_json(current)
        or baseline_raw != canonical_json(baseline)
        or SHA256.fullmatch(expected_sha256 or "") is None
        or current["schema_version"] != "milk.private-gateway-current-deployment.v2"
        or baseline["schema_version"] != "milk.official-openai-sdk-smoke.v2"
        or baseline["proof_step"] != "deployment_baseline"
        or digest(baseline_raw) != expected_sha256
        or current["official_openai_sdk_baseline_receipt_sha256"] != expected_sha256
        or current["proof_contract_sha256"] != PRODUCTION_PROOF_SHA256
        or baseline["proof_contract_sha256"] != current["proof_contract_sha256"]
    ):
        raise ContractFailure("current deployment baseline binding is invalid")


def validate_release(directory):
    release_raw = read_regular(directory / "release.json", "release", 65536)
    admission_raw = read_regular(directory / "admission.json", "admission", 262144)
    index_raw = read_regular(directory / "index.json", "index")
    manifest_raw = read_regular(directory / "amd64-manifest.json", "amd64 manifest")
    config_raw = read_regular(directory / "config.json", "image config")
    build_log_raw = read_regular(directory / "build-log.json", "build log", 65536)
    ops_log_raw = read_regular(directory / "ops-log-reference.json", "ops-log reference", 65536)
    release = parse_json(release_raw, "release")
    admission = parse_json(admission_raw, "admission")
    index = parse_json(index_raw, "index")
    manifest = parse_json(manifest_raw, "amd64 manifest")
    config = parse_json(config_raw, "image config")
    build_log = parse_json(build_log_raw, "build log", 65536)
    ops_log = parse_json(ops_log_raw, "ops-log reference", 65536)
    if release_raw != canonical_json(release) or admission_raw != canonical_json(admission):
        raise ContractFailure("release evidence is not canonical")

    require_keys(release, {
        "schema_version", "source_commit", "source_date_epoch", "source_repository",
        "buildkit_image_reference", "dockerfile_frontend_reference", "build_authority",
        "platform", "image", "ops_log_reference_sha256", "started_at", "completed_at",
    }, "release")
    require_keys(release["image"], {
        "admission_sha256", "artifact", "image_reference",
    }, "release image")
    require_keys(admission, {
        "schema_version", "artifact", "repository", "image_reference",
        "source_repository", "source_commit", "source_context_method",
        "source_context_sha256", "gateway_image_reference", "index_sha256",
        "amd64_manifest_sha256", "config_sha256", "attestation_manifest_sha256",
        "attestations", "platform", "visibility", "builder",
    }, "admission")
    require_keys(admission["builder"], {
        "authority", "driver", "endpoint_kind", "buildkit_image_reference",
        "buildkit_version", "dockerfile_frontend_reference", "provenance_mode",
        "provenance_version", "sbom",
    }, "builder admission")

    if (
        release["schema_version"] != "milk.private-gateway-release.v1"
        or admission["schema_version"] != "milk.private-image-admission.v1"
        or release["source_repository"] != SOURCE_REPOSITORY
        or admission["source_repository"] != SOURCE_REPOSITORY
        or release["source_commit"] != admission["source_commit"]
        or SHA1.fullmatch(release["source_commit"] or "") is None
        or release["platform"] != "linux/amd64"
        or admission["platform"] != "linux/amd64"
        or release["build_authority"] != "local-socket"
        or release["buildkit_image_reference"] != BUILDKIT_IMAGE
        or release["dockerfile_frontend_reference"] != DOCKERFILE_FRONTEND
        or release["image"]["artifact"] != "gateway"
        or admission["artifact"] != "gateway"
        or admission["repository"] != GHCR_REPOSITORY
        or admission["visibility"] != "private"
        or admission["source_context_method"] != "git-archive-tar-v1"
        or admission["gateway_image_reference"] is not None
    ):
        raise ContractFailure("release identity is invalid")
    if (
        SHA256.fullmatch(release["ops_log_reference_sha256"] or "") is None
        or release["ops_log_reference_sha256"] != digest(ops_log_raw)
        or ops_log != {
            "schema_version": "milk.private-ops-log-reference.v1",
            "authority": "private-release-evidence",
            "reference": "build-log.json",
            "receipt_sha256": digest(build_log_raw),
            "immutable": True,
            "content_retained": False,
        }
        or build_log.get("schema_version") != "milk.content-free-build-log.v1"
        or build_log.get("content_retained") is not False
    ):
        raise ContractFailure("release ops-log reference is invalid")
    if (
        not isinstance(release["source_date_epoch"], int)
        or isinstance(release["source_date_epoch"], bool)
        or release["source_date_epoch"] <= 0
        or RFC3339.fullmatch(release["started_at"] or "") is None
        or RFC3339.fullmatch(release["completed_at"] or "") is None
        or release["completed_at"] < release["started_at"]
    ):
        raise ContractFailure("release timing is invalid")

    for key in (
        "source_context_sha256", "index_sha256", "amd64_manifest_sha256",
        "config_sha256", "attestation_manifest_sha256",
    ):
        if SHA256.fullmatch(admission[key] or "") is None:
            raise ContractFailure(f"invalid admission {key}")
    image_reference = f"{GHCR_REPOSITORY}@sha256:{admission['index_sha256']}"
    if (
        admission["image_reference"] != image_reference
        or release["image"]["image_reference"] != image_reference
        or release["image"]["admission_sha256"] != digest(admission_raw)
        or digest(index_raw) != admission["index_sha256"]
        or digest(manifest_raw) != admission["amd64_manifest_sha256"]
        or digest(config_raw) != admission["config_sha256"]
    ):
        raise ContractFailure("release content digest is invalid")

    builder = admission["builder"]
    if builder != {
        "authority": "local-socket",
        "driver": "docker-container",
        "endpoint_kind": "local-socket",
        "buildkit_image_reference": BUILDKIT_IMAGE,
        "buildkit_version": "v0.23.2",
        "dockerfile_frontend_reference": DOCKERFILE_FRONTEND,
        "provenance_mode": "max",
        "provenance_version": "v1",
        "sbom": True,
    }:
        raise ContractFailure("builder admission is invalid")
    attestations = admission["attestations"]
    if not isinstance(attestations, list) or len(attestations) != 2:
        raise ContractFailure("attestation admission is invalid")
    predicates = []
    for statement in attestations:
        require_keys(statement, {"layer_sha256", "predicate_type"}, "attestation")
        if SHA256.fullmatch(statement["layer_sha256"] or "") is None:
            raise ContractFailure("attestation layer digest is invalid")
        predicates.append(statement["predicate_type"])
    if sorted(predicates) != sorted([SLSA_V1, SPDX]):
        raise ContractFailure("attestation predicates are invalid")

    if not isinstance(index, dict) or not isinstance(index.get("manifests"), list):
        raise ContractFailure("image index is invalid")
    child_digest = "sha256:" + admission["amd64_manifest_sha256"]
    children = [
        item for item in index["manifests"]
        if isinstance(item, dict)
        and item.get("digest") == child_digest
        and item.get("platform") == {"architecture": "amd64", "os": "linux"}
    ]
    if len(children) != 1 or children[0].get("size") != len(manifest_raw):
        raise ContractFailure("amd64 image descriptor is invalid")
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != 2:
        raise ContractFailure("amd64 image manifest is invalid")
    descriptor = manifest.get("config")
    layers = manifest.get("layers")
    if (
        not isinstance(descriptor, dict)
        or descriptor.get("digest") != "sha256:" + admission["config_sha256"]
        or descriptor.get("size") != len(config_raw)
        or not isinstance(layers, list)
        or not 1 <= len(layers) <= 128
    ):
        raise ContractFailure("amd64 manifest descriptors are invalid")
    layer_digests = []
    for layer in layers:
        if (
            not isinstance(layer, dict)
            or not isinstance(layer.get("digest"), str)
            or not layer["digest"].startswith("sha256:")
            or SHA256.fullmatch(layer["digest"][7:]) is None
            or not isinstance(layer.get("size"), int)
            or isinstance(layer.get("size"), bool)
            or layer["size"] < 0
        ):
            raise ContractFailure("image layer descriptor is invalid")
        layer_digests.append(layer["digest"])
    if not isinstance(config, dict) or config.get("architecture") != "amd64" or config.get("os") != "linux":
        raise ContractFailure("image config platform is invalid")

    return {
        "source_commit": admission["source_commit"],
        "image_reference": image_reference,
        "child_reference": f"{GHCR_REPOSITORY}@{child_digest}",
        "child_sha256": admission["amd64_manifest_sha256"],
        "config_sha256": admission["config_sha256"],
        "layer_digests": layer_digests,
        "admission_sha256": digest(admission_raw),
        "release_sha256": digest(release_raw),
        "build_ops_log_reference_sha256": digest(ops_log_raw),
    }


class Evidence:
    def __init__(self, root, operation_id):
        self.root = root
        self.operation_id = operation_id
        self.logs = root / "logs"
        self.logs.mkdir(mode=0o700)

    def write(self, relative, value):
        target = self.root / relative
        target.parent.mkdir(mode=0o700, exist_ok=True)
        raw = canonical_json(value)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(raw)
                output.flush()
                os.fsync(output.fileno())
        except BaseException:
            try:
                target.unlink()
            except OSError:
                pass
            raise
        return digest(raw)

    def finalize(self, outcome, stage, started_at, baseline_receipt_sha256=None):
        if outcome == "succeeded":
            validate_deployment_baseline_binding(
                read_regular(self.root / "current.json", "current deployment", 65536),
                read_regular(
                    self.root / "official-openai-sdk-smoke.json",
                    "official OpenAI SDK baseline",
                    65536,
                ),
                baseline_receipt_sha256,
            )
        logs = []
        for path in sorted(self.logs.glob("*.json")):
            raw = path.read_bytes()
            logs.append({
                "path": path.relative_to(self.root).as_posix(),
                "bytes": len(raw),
                "sha256": digest(raw),
            })
        ops_manifest_sha256 = self.write("ops-log-manifest.json", {
            "schema_version": "milk.private-ops-log-manifest.v1",
            "operation_id": self.operation_id,
            "content_retained": False,
            "logs": logs,
        })
        ops_reference_sha256 = self.write("ops-log-reference.json", {
            "schema_version": "milk.private-ops-log-reference.v1",
            "authority": "private-deploy-evidence",
            "reference": "ops-log-manifest.json",
            "receipt_sha256": ops_manifest_sha256,
            "immutable": True,
            "content_retained": False,
        })
        files = []
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or path.name in {"manifest.json", "terminal.json"}:
                continue
            raw = path.read_bytes()
            files.append({
                "path": path.relative_to(self.root).as_posix(),
                "bytes": len(raw),
                "sha256": digest(raw),
            })
        manifest_sha256 = self.write("manifest.json", {
            "schema_version": "milk.private-gateway-deploy-manifest.v1",
            "operation_id": self.operation_id,
            "outcome": outcome,
            "files": files,
        })
        self.write("terminal.json", {
            "schema_version": "milk.private-gateway-deploy-terminal.v1",
            "operation_id": self.operation_id,
            "outcome": outcome,
            "failure_stage": stage,
            "started_at": started_at,
            "completed_at": utc_now(),
            "manifest_sha256": manifest_sha256,
            "ops_log_reference_sha256": ops_reference_sha256,
        })
        for path in self.root.rglob("*"):
            if path.is_file():
                os.chmod(path, 0o400, follow_symlinks=False)


@dataclass
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes


class Runner:
    def __init__(self, evidence, base_environment):
        self.evidence = evidence
        self.base_environment = base_environment
        self.sequence = 0

    def run(self, action, arguments, *, timeout=60, environment=None, input_bytes=None,
            sensitive_output=False, check=True):
        self.sequence += 1
        started_at = utc_now()
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.base_environment if environment is None else environment,
            start_new_session=True,
        )
        timed_out = False
        interrupted = None
        try:
            stdout, stderr = process.communicate(input=input_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                stdout, stderr = process.communicate()
        except BaseException as error:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                stdout, stderr = process.communicate(timeout=5)
            except BaseException:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                stdout, stderr = process.communicate()
            interrupted = error
        raw = stdout + b"\n--stderr--\n" + stderr
        observation = {
            "schema_version": "milk.content-free-operation-log.v1",
            "operation_id": self.evidence.operation_id,
            "sequence": self.sequence,
            "action": action,
            "started_at": started_at,
            "completed_at": utc_now(),
            "exit_code": process.returncode,
            "timed_out": timed_out,
            "content_retained": False,
            "hash_input": "stdout-lf-stderr-marker-v1",
        }
        if sensitive_output:
            observation.update({"bytes": None, "sha256": None, "sensitive_output": True})
        else:
            observation.update({"bytes": len(raw), "sha256": digest(raw), "sensitive_output": False})
        self.evidence.write(f"logs/{self.sequence:04d}-{action}.json", observation)
        result = Result(process.returncode, stdout, stderr)
        if interrupted is not None:
            raise interrupted
        if timed_out or (check and process.returncode != 0):
            raise CommandFailure(action)
        return result


def parse_active_worker(raw):
    status = parse_json(raw, "Worker deployment status")
    if not isinstance(status, dict) or not isinstance(status.get("versions"), list):
        raise ContractFailure("Worker deployment status is invalid")
    versions = status["versions"]
    for version in versions:
        if (
            not isinstance(version, dict)
            or set(version) != {"percentage", "version_id"}
            or not isinstance(version["percentage"], (int, float))
            or isinstance(version["percentage"], bool)
            or UUID.fullmatch(version["version_id"] or "") is None
        ):
            raise ContractFailure("Worker deployment version is invalid")
    if len(versions) == 1 and versions[0]["percentage"] == 100:
        return versions[0]["version_id"]
    return None


def parse_application(raw, application_id, account_id):
    info = parse_json(raw, "container application")
    if (
        not isinstance(info, dict)
        or info.get("id") != application_id
        or info.get("account_id") != account_id
        or info.get("name") != APPLICATION_NAME
        or not isinstance(info.get("version"), int)
        or isinstance(info.get("version"), bool)
        or info["version"] < 1
        or not isinstance(info.get("configuration"), dict)
        or not isinstance(info["configuration"].get("image"), str)
    ):
        raise ContractFailure("container application identity is invalid")
    return info["configuration"]["image"], info["version"]


def parse_images(raw):
    images = parse_json(raw, "Cloudflare image listing")
    if not isinstance(images, list):
        raise ContractFailure("Cloudflare image listing is invalid")
    result = {}
    for image in images:
        if (
            not isinstance(image, dict)
            or set(image) != {"name", "tags"}
            or REPOSITORY.fullmatch(image["name"] or "") is None
            or image["name"] in result
            or not isinstance(image["tags"], list)
            or any(not isinstance(tag, str) or TAG.fullmatch(tag) is None for tag in image["tags"])
            or len(set(image["tags"])) != len(image["tags"])
        ):
            raise ContractFailure("Cloudflare image listing entry is invalid")
        result[image["name"]] = set(image["tags"])
    return result


def parse_applications(raw):
    applications = parse_json(raw, "container application listing")
    if not isinstance(applications, list) or len(applications) > 1000:
        raise ContractFailure("container application listing is invalid")
    result = []
    identifiers = set()
    for application in applications:
        if (
            not isinstance(application, dict)
            or UUID.fullmatch(application.get("id") or "") is None
            or not isinstance(application.get("name"), str)
            or not 1 <= len(application["name"]) <= 128
            or application["id"] in identifiers
        ):
            raise ContractFailure("container application listing entry is invalid")
        identifiers.add(application["id"])
        result.append((application["id"], application["name"]))
    return result


def parse_secret_names(raw):
    values = parse_json(raw, "Worker secrets", 65536)
    if not isinstance(values, list) or len(values) > 100:
        raise ContractFailure("Worker secrets are invalid")
    names = []
    for value in values:
        if (
            not isinstance(value, dict)
            or set(value) != {"name", "type"}
            or not isinstance(value["name"], str)
            or not 1 <= len(value["name"]) <= 128
            or value["type"] != "secret_text"
        ):
            raise ContractFailure("Worker secret entry is invalid")
        names.append(value["name"])
    if len(names) != len(set(names)):
        raise ContractFailure("Worker secret names are duplicated")
    return set(names)


def parse_gateway_config(raw, allow_legacy=False):
    config = parse_json(raw, "gateway config", 65536)
    traffic_keys = config.get("traffic_keys") if isinstance(config, dict) else None
    if (
        raw != canonical_json(config)
        or not isinstance(traffic_keys, list)
        or not 1 <= len(traffic_keys) <= 64
    ):
        raise DeployFailure("gateway config is invalid")
    if "scope_id" in config:
        scope_id = config["scope_id"]
        if (
            not allow_legacy
            or not isinstance(scope_id, str)
            or UUID.fullmatch(scope_id) is None
            or scope_id == "00000000-0000-0000-0000-000000000000"
        ):
            raise DeployFailure("gateway config is invalid")
        hashes = set()
        for traffic_key in traffic_keys:
            if (
                not isinstance(traffic_key, dict)
                or set(traffic_key) != {"api_key_sha256", "capture_allowed"}
                or not isinstance(traffic_key["api_key_sha256"], str)
                or SHA256.fullmatch(traffic_key["api_key_sha256"]) is None
                or not isinstance(traffic_key["capture_allowed"], bool)
                or traffic_key["api_key_sha256"] in hashes
            ):
                raise DeployFailure("gateway traffic keys are invalid")
            hashes.add(traffic_key["api_key_sha256"])
        return config
    key_ids = set()
    hashes = set()
    scope_ids = set()
    for traffic_key in traffic_keys:
        revocation = traffic_key.get("revocation") if isinstance(traffic_key, dict) else None
        if (
            not isinstance(traffic_key, dict)
            or not {"key_id", "api_key_sha256", "scope_id", "capture_allowed"}.issubset(traffic_key)
            or not set(traffic_key).issubset({
                "key_id", "api_key_sha256", "scope_id", "capture_allowed", "revocation",
            })
            or UUID.fullmatch(traffic_key["key_id"]) is None
            or traffic_key["key_id"] == "00000000-0000-0000-0000-000000000000"
            or not isinstance(traffic_key["api_key_sha256"], str)
            or SHA256.fullmatch(traffic_key["api_key_sha256"]) is None
            or UUID.fullmatch(traffic_key["scope_id"]) is None
            or traffic_key["scope_id"] == "00000000-0000-0000-0000-000000000000"
            or not isinstance(traffic_key["capture_allowed"], bool)
            or traffic_key["key_id"] in key_ids
            or traffic_key["api_key_sha256"] in hashes
            or ("revocation" in traffic_key and (
                not isinstance(revocation, dict)
                or "revoked_at" not in revocation
                or not set(revocation).issubset({"revoked_at", "reason"})
                or not isinstance(revocation["revoked_at"], str)
                or RFC3339.fullmatch(revocation["revoked_at"]) is None
                or ("reason" in revocation and (
                    not isinstance(revocation["reason"], str)
                    or not 1 <= len(revocation["reason"].encode()) <= 256
                ))
            ))
        ):
            raise DeployFailure("gateway traffic keys are invalid")
        key_ids.add(traffic_key["key_id"])
        hashes.add(traffic_key["api_key_sha256"])
        scope_ids.add(traffic_key["scope_id"])
    if len(scope_ids) != 1:
        raise DeployFailure("gateway traffic keys must map to one scope")
    return config


def validate_gateway_config_file(path, repository, allow_legacy=False):
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise DeployFailure("gateway config must be an absolute regular file")
    metadata = path.stat()
    if (
        metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o777 != 0o600
        or not 1 <= metadata.st_size <= 65536
        or within(path.resolve(strict=True), repository)
    ):
        raise DeployFailure("gateway config file must be owner-only mode 0600 outside the checkout")
    raw = read_regular(path, "gateway config", 65536)
    return raw, parse_gateway_config(raw, allow_legacy)


def validate_bootstrap_secrets(path, repository, materialize=False):
    if not path.is_absolute() or path.is_symlink() or not path.is_file():
        raise DeployFailure("bootstrap secrets must be an absolute regular file")
    metadata = path.stat()
    if (
        metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o777 != 0o600
        or not 1 <= metadata.st_size <= MAX_JSON
        or within(path.resolve(strict=True), repository)
    ):
        raise DeployFailure("bootstrap secrets file must be owner-only mode 0600 outside the checkout")
    raw = read_regular(path, "bootstrap secrets")
    value = parse_json(raw, "bootstrap secrets")
    require_keys(value, {"schema_version", "secrets"}, "bootstrap secrets")
    secrets_value = value["secrets"]
    if (
        value["schema_version"] != "milk.gateway-bootstrap-secrets.v1"
        or not isinstance(secrets_value, dict)
        or not BOOTSTRAP_REQUIRED_SECRET_NAMES.issubset(secrets_value)
        or not set(secrets_value).issubset(
            BOOTSTRAP_REQUIRED_SECRET_NAMES | BOOTSTRAP_OPTIONAL_SECRET_NAMES
        )
        or any(
            not isinstance(secret, str) or not 1 <= len(secret.encode("utf-8")) <= 262144
            for secret in secrets_value.values()
        )
        or raw != canonical_json(value)
    ):
        raise DeployFailure("bootstrap secrets file is invalid")
    gateway_config_raw = secrets_value["MILK_CARTON_CONFIG_JSON"].encode("utf-8")
    gateway_config = parse_gateway_config(gateway_config_raw)
    if gateway_config.get("route") is not None and "MILK_CARTON_ROUTE_SECRET_HEX" not in secrets_value:
        raise DeployFailure("bootstrap route config requires its route secret")
    secret_input = bytearray(canonical_json(secrets_value)) if materialize else None
    return secret_input, digest(raw), set(secrets_value), gateway_config_raw, gateway_config


def validate_smoke_credential(path, gateway_config):
    raw = read_regular(path, "gateway credential", 8192)
    credential = parse_json(raw, "gateway credential", 8192)
    require_keys(credential, {"api_key", "cohort_id", "model"}, "gateway credential")
    api_key = credential["api_key"]
    value = api_key.removeprefix("milk_live_") if isinstance(api_key, str) else ""
    key_id, separator, secret = value.partition("_")
    if (
        raw != canonical_json(credential)
        or not separator
        or UUID.fullmatch(key_id) is None
        or key_id == "00000000-0000-0000-0000-000000000000"
        or not 16 <= len(secret) <= 256
        or any(
            not (byte.isascii() and (byte.isalnum() or byte in "-_.~"))
            for byte in secret
        )
        or not isinstance(credential["cohort_id"], str)
        or COHORT_ID.fullmatch(credential["cohort_id"]) is None
        or credential["model"] != PRODUCTION_PROOF["model"]
    ):
        raise DeployFailure("gateway credential is invalid")
    api_key_sha256 = digest(api_key.encode())
    matches = [
        traffic_key
        for traffic_key in gateway_config["traffic_keys"]
        if traffic_key["key_id"] == key_id
        and traffic_key["api_key_sha256"] == api_key_sha256
        and traffic_key["capture_allowed"] is False
        and "revocation" not in traffic_key
    ]
    if len(matches) != 1:
        raise DeployFailure("gateway smoke credential is not an exact non-capturable traffic key")
    return api_key_sha256, digest(credential["cohort_id"].encode())


def split_cloudflare_image(image, account_id):
    prefix = f"{REGISTRY}/{account_id}/"
    if not image.startswith(prefix) or "@" in image:
        raise ContractFailure("previous image is not a retained Cloudflare tag")
    name_and_tag = image[len(prefix):]
    if ":" not in name_and_tag:
        raise ContractFailure("previous image tag is missing")
    name, tag = name_and_tag.rsplit(":", 1)
    if REPOSITORY.fullmatch(name) is None or TAG.fullmatch(tag) is None:
        raise ContractFailure("previous image reference is invalid")
    return name, tag


def validate_base_config(path):
    raw = read_regular(path, "Wrangler config", 65536)
    config = parse_json(raw, "Wrangler config")
    containers = config.get("containers") if isinstance(config, dict) else None
    if (
        config.get("name") != DEPLOYMENT_TARGETS["production"][0]
        or config.get("main") != MAIN_SENTINEL
        or config.get("observability") != {"enabled": True}
        or config.get("routes") != [{
            "pattern": CUSTOM_DOMAIN_SENTINEL,
            "custom_domain": True,
        }]
        or not isinstance(containers, list)
        or len(containers) != 1
        or containers[0] != {
            "class_name": "MilkCarton",
            "image": IMAGE_SENTINEL,
            "instance_type": "lite",
            "max_instances": 1,
        }
        or b"Dockerfile" in raw
        or b"image_build_context" in raw
    ):
        raise ContractFailure("Wrangler deploy template is invalid")
    return config


def write_private(path, raw, mode=0o600):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())


def make_deploy_config(base, path, image, entrypoint, api_hostname):
    config = copy.deepcopy(base)
    config["name"] = WORKER
    config["main"] = str(entrypoint)
    config["containers"][0]["image"] = image
    config["routes"][0]["pattern"] = api_hostname
    raw = canonical_json(config)
    if (
        b"Dockerfile" in raw
        or b"image_build_context" in raw
        or image.encode() not in raw
        or api_hostname.encode() not in raw
        or CUSTOM_DOMAIN_SENTINEL.encode() in raw
    ):
        raise ContractFailure("temporary deploy config is invalid")
    write_private(path, raw)


def main():
    global WORKER, APPLICATION_NAME, EXPECTED_HOSTNAME
    arguments = sys.argv[2:]
    registry_token_file = None
    registry_token_stdin = False
    previous_gateway_config_file = None
    wrangler_oauth = False
    deployment_target = None
    while arguments and arguments[0].startswith("--") and arguments[0] != "--bootstrap":
        option = arguments.pop(0)
        if option == "--wrangler-oauth" and not wrangler_oauth:
            wrangler_oauth = True
        elif option == "--target" and arguments and deployment_target is None:
            deployment_target = arguments.pop(0)
        elif option == "--registry-token-file" and arguments and registry_token_file is None and not registry_token_stdin:
            registry_token_file = Path(arguments.pop(0))
        elif option == "--registry-token-stdin" and registry_token_file is None and not registry_token_stdin:
            registry_token_stdin = True
        elif option == "--previous-gateway-config-file" and arguments and previous_gateway_config_file is None:
            previous_gateway_config_file = Path(arguments.pop(0))
        else:
            raise DeployFailure("unsupported or duplicate deploy option")
    selected_target = deployment_target or "production"
    if selected_target not in DEPLOYMENT_TARGETS:
        raise DeployFailure("deployment target must be production or mechanics")
    WORKER, APPLICATION_NAME, EXPECTED_HOSTNAME = DEPLOYMENT_TARGETS[selected_target]
    if registry_token_file is None and not registry_token_stdin:
        raise DeployFailure("registry credential input must be selected exactly once")
    bootstrap = len(arguments) == 6 and arguments[0] == "--bootstrap"
    if (
        (bootstrap and previous_gateway_config_file is not None)
        or (not bootstrap and (len(arguments) != 6 or previous_gateway_config_file is None))
    ):
        raise DeployFailure(
            "usage: deploy-private-gateway.sh [--target production|mechanics] [--wrangler-oauth] (--registry-token-file ABSOLUTE_FILE | --registry-token-stdin) --previous-gateway-config-file ABSOLUTE_FILE RELEASE_EVIDENCE_DIR APPLICATION_ID NEW_DEPLOY_EVIDENCE_DIR GATEWAY_CREDENTIAL_FILE GATEWAY_CONFIG_FILE API_BASE_URL\n"
            "       deploy-private-gateway.sh [--target production|mechanics] [--wrangler-oauth] (--registry-token-file ABSOLUTE_FILE | --registry-token-stdin) --bootstrap RELEASE_EVIDENCE_DIR NEW_DEPLOY_EVIDENCE_DIR GATEWAY_CREDENTIAL_FILE BOOTSTRAP_SECRETS_FILE API_BASE_URL"
        )
    api_base_url, api_hostname, health_url = validate_api_base_url(arguments.pop())
    if api_hostname != EXPECTED_HOSTNAME:
        raise DeployFailure("API hostname does not match the deployment target")
    script = Path(sys.argv[1]).resolve(strict=True)
    repository = script.parent.parent.resolve(strict=True)
    sys.path.insert(0, str(repository / "tools"))
    from github_registry import read_token, write_docker_config
    registry_stream = os.fdopen(3, "rb", closefd=False) if registry_token_stdin else None
    github_token = bytearray(read_token(registry_token_file, repository, registry_stream))
    bootstrap_secret_input = None
    bootstrap_secrets_path = None
    bootstrap_secrets_sha256 = None
    if bootstrap:
        release_directory = Path(arguments[1]).resolve(strict=True)
        application_id = None
        requested_evidence = Path(arguments[2])
        credential_file = Path(arguments[3])
        bootstrap_secrets_path = Path(arguments[4])
        (
            _,
            bootstrap_secrets_sha256,
            expected_bootstrap_secret_names,
            gateway_config_raw,
            gateway_config,
        ) = validate_bootstrap_secrets(bootstrap_secrets_path, repository)
    else:
        release_directory = Path(arguments[0]).resolve(strict=True)
        application_id = arguments[1]
        requested_evidence = Path(arguments[2])
        credential_file = Path(arguments[3])
        gateway_config_raw, gateway_config = validate_gateway_config_file(
            Path(arguments[4]), repository,
        )
        previous_gateway_config_raw, _ = validate_gateway_config_file(
            previous_gateway_config_file, repository, allow_legacy=True,
        )
        expected_bootstrap_secret_names = None
    if not requested_evidence.is_absolute() or requested_evidence.exists():
        raise DeployFailure("deploy evidence directory must be a new absolute path")
    evidence_parent = requested_evidence.parent.resolve(strict=True)
    evidence_directory = evidence_parent / requested_evidence.name
    if within(evidence_directory, repository) or within(release_directory, repository):
        raise DeployFailure("release and deploy evidence must be outside the checkout")
    if not bootstrap and UUID.fullmatch(application_id) is None:
        raise DeployFailure("container application ID must be a lowercase UUID")
    if not credential_file.is_absolute() or credential_file.is_symlink() or not credential_file.is_file():
        raise DeployFailure("gateway credential must be an absolute regular file")
    credential_stat = credential_file.stat()
    if (
        credential_stat.st_uid != os.getuid()
        or credential_stat.st_nlink != 1
        or credential_stat.st_mode & 0o077
        or not 1 <= credential_stat.st_size <= 8192
        or within(credential_file.resolve(strict=True), repository)
    ):
        raise DeployFailure("gateway credential file is not private")
    smoke_key_sha256, smoke_cohort_sha256 = validate_smoke_credential(
        credential_file, gateway_config,
    )
    gateway_config_sha256 = digest(gateway_config_raw)
    previous_gateway_config_sha256 = (
        None if bootstrap else digest(previous_gateway_config_raw)
    )

    allowed_cloudflare = {"CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"}
    forbidden = re.compile(
        r"^(AWS_|AZURE_|GCP_|S3_|BASETEN_|MODAL_|OPENAI_|R2_|TEACHER_|WANDB_|MILK_CARTON_|DOCKER_|BUILDX_|BUILDKIT_).*"
        r"|^(GOOGLE_APPLICATION_CREDENTIALS|HF_TOKEN|HUGGING_FACE_HUB_TOKEN|NVIDIA_API_KEY|NGC_API_KEY|CODEX_API_KEY|CODEX_AUTH_TOKEN|CODEX_TOKEN|GH_TOKEN|GITHUB_TOKEN|GH_ENTERPRISE_TOKEN|GITHUB_ENTERPRISE_TOKEN|CR_PAT|CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|NPM_TOKEN|PYPI_TOKEN|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|REGISTRY_AUTH_FILE|HTTP_PROXY|HTTPS_PROXY|FTP_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|ftp_proxy|all_proxy|no_proxy)$"
        r"|^CARGO_REGISTRIES_.*_TOKEN$|^MILK_.*(AWS|R2|S3|STORE|TEACHER|PROVIDER|CREDENTIAL|SECRET|TOKEN|ACCESS_KEY)"
    )
    for name in os.environ:
        if name.startswith("CLOUDFLARE_") and name not in allowed_cloudflare:
            raise DeployFailure("deploy shell contains an unsupported Cloudflare setting")
        if forbidden.search(name):
            raise DeployFailure("deploy shell contains an ambient provider, store, registry, or model credential")
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    cloudflare_token = os.environ.get("CLOUDFLARE_API_TOKEN", "")
    if wrangler_oauth and "CLOUDFLARE_API_TOKEN" in os.environ:
        raise DeployFailure("--wrangler-oauth is mutually exclusive with CLOUDFLARE_API_TOKEN")
    if ACCOUNT_ID.fullmatch(account_id) is None or (
        not wrangler_oauth and not 1 <= len(cloudflare_token) <= 8192
    ):
        raise DeployFailure("exact Cloudflare account credentials are required")
    os.environ.pop("CLOUDFLARE_ACCOUNT_ID", None)
    os.environ.pop("CLOUDFLARE_API_TOKEN", None)
    base_environment = os.environ.copy()
    base_environment["CI"] = "1"
    base_environment["WRANGLER_SEND_METRICS"] = "false"
    cloudflare_environment = base_environment.copy()
    cloudflare_environment["CLOUDFLARE_ACCOUNT_ID"] = account_id
    if not wrangler_oauth:
        cloudflare_environment["CLOUDFLARE_API_TOKEN"] = cloudflare_token
        cloudflare_environment.pop("HOME", None)

    commands = {}
    for command in ("curl", "docker", "git", "node", "sleep", "wrangler"):
        resolved = shutil.which(command, path=base_environment.get("PATH"))
        if resolved is None:
            raise DeployFailure(f"{command} is unavailable")
        commands[command] = resolved

    buildx_candidates = []
    home = base_environment.get("HOME")
    if home:
        buildx_candidates.append(Path(home) / ".docker/cli-plugins/docker-buildx")
    buildx_candidates.extend(Path(value) for value in (
        "/opt/homebrew/lib/docker/cli-plugins/docker-buildx",
        "/usr/local/lib/docker/cli-plugins/docker-buildx",
        "/usr/libexec/docker/cli-plugins/docker-buildx",
        "/usr/lib/docker/cli-plugins/docker-buildx",
    ))
    buildx_plugin = next(
        (path for path in buildx_candidates if path.is_file() and os.access(path, os.X_OK)),
        None,
    )
    if buildx_plugin is None:
        raise DeployFailure("docker buildx plugin is unavailable in standard locations")

    base_config_path = repository / "deploy/cloudflare/wrangler.jsonc"
    oauth_preflight = None
    if wrangler_oauth:
        if not base_environment.get("HOME"):
            raise DeployFailure("Wrangler OAuth requires the actual HOME")
        oauth_preflight = validate_wrangler_oauth(
            commands["wrangler"], base_config_path, cloudflare_environment, account_id,
        )

    evidence_directory.mkdir(mode=0o700)
    operation_id = secrets.token_hex(12)
    evidence = Evidence(evidence_directory, operation_id)
    runner = Runner(evidence, base_environment)
    started_at = utc_now()
    stage = "initialization"
    deploy_started = False
    previous = None
    previous_worker = None
    temporary_config = None
    deployment_secrets = None
    rollback_config = None
    rollback_config_sha256 = None
    rollback_secrets = None
    rollback_secrets_sha256 = None
    worker_source_sha256 = None
    scratch = Path(tempfile.mkdtemp(prefix="milk-carton-deploy."))
    docker_config = scratch / "docker-config"
    docker_config.mkdir(mode=0o700)
    docker_plugins = docker_config / "cli-plugins"
    docker_plugins.mkdir(mode=0o700)
    (docker_plugins / "docker-buildx").symlink_to(buildx_plugin)

    def interrupt(signum, _frame):
        raise Interrupted(f"signal {signum}")

    for signal_number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_number, interrupt)

    if oauth_preflight is not None:
        evidence.write("wrangler-oauth-preflight.json", oauth_preflight)

    def wrangler(action, *arguments, timeout=60, sensitive=False, check=True,
                 input_bytes=None, config=base_config_path):
        return runner.run(
            action,
            [commands["wrangler"], *arguments, "--config", str(config)],
            timeout=timeout,
            environment=cloudflare_environment,
            input_bytes=input_bytes,
            sensitive_output=sensitive,
            check=check,
        )

    def docker(action, *arguments, timeout=120, input_bytes=None, check=True):
        return runner.run(
            action,
            [commands["docker"], "--config", str(scratch / "docker-config"), "--host", docker_endpoint, *arguments],
            timeout=timeout,
            input_bytes=input_bytes,
            check=check,
        )

    def worker_exists(action):
        result = wrangler(
            action, "secret", "list", "--name", WORKER, "--format", "json",
            check=False, sensitive=True,
        )
        if result.returncode == 0:
            parse_secret_names(result.stdout)
            return True
        try:
            stderr = result.stderr.decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise ContractFailure("Worker absence probe is invalid") from error
        if result.stdout.strip() or f'Worker "{WORKER}" not found.' not in stderr:
            raise ContractFailure("Worker absence is not authoritative")
        return False

    def matching_applications(action):
        values = parse_applications(wrangler(
            action, "containers", "list", "--json",
        ).stdout)
        matches = [identifier for identifier, name in values if name == APPLICATION_NAME]
        if len(matches) > 1:
            raise ContractFailure("container application name is ambiguous")
        return matches

    def cleanup_bootstrap():
        absence_proofs = 0
        worker_deleted = False
        application_deleted = False
        attempts = 0
        for attempt in range(1, BOOTSTRAP_CLEANUP_ATTEMPTS + 1):
            attempts = attempt
            try:
                worker_present = worker_exists(f"bootstrap-cleanup-worker-probe-{attempt:02d}")
                matches = matching_applications(f"bootstrap-cleanup-container-list-{attempt:02d}")
            except DeployFailure:
                absence_proofs = 0
                worker_present = None
                matches = None
            if worker_present is True:
                try:
                    wrangler(
                        f"bootstrap-cleanup-worker-delete-{attempt:02d}",
                        "delete", WORKER, "--force", timeout=300,
                    )
                    worker_deleted = True
                except DeployFailure:
                    pass
            if matches:
                try:
                    wrangler(
                        f"bootstrap-cleanup-container-delete-{attempt:02d}",
                        "containers", "delete", matches[0], timeout=300,
                    )
                    application_deleted = True
                except DeployFailure:
                    pass
            if worker_present is False and matches == []:
                absence_proofs += 1
                if absence_proofs == BOOTSTRAP_CLEANUP_ABSENCE_PROOFS:
                    break
            else:
                absence_proofs = 0
            if attempt != BOOTSTRAP_CLEANUP_ATTEMPTS:
                try:
                    runner.run(
                        f"bootstrap-cleanup-wait-{attempt:02d}",
                        [commands["sleep"], str(BOOTSTRAP_CLEANUP_INTERVAL_SECONDS)],
                        timeout=BOOTSTRAP_CLEANUP_INTERVAL_SECONDS + 5,
                    )
                except DeployFailure:
                    absence_proofs = 0
        succeeded = absence_proofs == BOOTSTRAP_CLEANUP_ABSENCE_PROOFS
        evidence.write("bootstrap-cleanup.json", {
            "schema_version": "milk.private-gateway-bootstrap-cleanup.v1",
            "operation_id": operation_id,
            "worker": WORKER,
            "application_name": APPLICATION_NAME,
            "attempts": attempts,
            "required_absence_proofs": BOOTSTRAP_CLEANUP_ABSENCE_PROOFS,
            "worker_deleted": worker_deleted,
            "application_deleted": application_deleted,
            "absence_proved": succeeded,
        })
        return succeeded

    def probe_health(phase, attempt):
        body_path = scratch / f"health-{phase}-{attempt}.json"
        result = runner.run(
            f"{phase}-health-{attempt:02d}",
            [
                commands["curl"], "--proto", "=https", "--tlsv1.2", "--silent",
                "--show-error", "--max-time", "15", "--max-filesize", "65536",
                "--output", str(body_path), "--write-out", "%{http_code}", health_url,
            ],
            timeout=20,
            check=False,
        )
        http_status = None
        healthy = False
        active_config_sha256 = None
        try:
            status_text = result.stdout.decode("ascii", errors="strict")
            if re.fullmatch(r"[0-9]{3}", status_text):
                http_status = int(status_text)
            if result.returncode == 0 and http_status == 200 and body_path.is_file():
                body = read_regular(body_path, "health response", 65536)
                value = parse_json(body, "health response", 65536)
                candidate_config_sha256 = value.get("config_sha256") if isinstance(value, dict) else None
                if isinstance(candidate_config_sha256, str) and SHA256.fullmatch(candidate_config_sha256):
                    active_config_sha256 = candidate_config_sha256
                healthy = isinstance(value, dict) and value.get("status") == "ok"
        except (ContractFailure, UnicodeError):
            healthy = False
        finally:
            try:
                body_path.unlink()
            except FileNotFoundError:
                pass
        return http_status, healthy, active_config_sha256

    def poll(phase, expected_image, expected_worker, worker_must_differ,
             expected_config_sha256):
        if SHA256.fullmatch(expected_config_sha256 or "") is None:
            raise ContractFailure("expected gateway config SHA-256 is invalid")
        last = {
            "http_status": None,
            "health_ready": False,
            "config_sha256": None,
            "worker_ready": False,
            "image_ready": False,
            "instances_observed": False,
            "active_instances": 0,
            "application_version": None,
        }
        for attempt in range(1, POLL_ATTEMPTS + 1):
            (
                last["http_status"],
                last["health_ready"],
                last["config_sha256"],
            ) = probe_health(phase, attempt)
            last["health_ready"] = (
                last["health_ready"]
                and last["config_sha256"] == expected_config_sha256
            )
            try:
                status = wrangler(
                    f"{phase}-worker-status-{attempt:02d}",
                    "deployments", "status", "--name", WORKER, "--json",
                )
                worker_version = parse_active_worker(status.stdout)
                last["worker_ready"] = (
                    worker_version is not None
                    and (
                        expected_worker is None
                        or (
                            (worker_version != expected_worker)
                            if worker_must_differ
                            else (worker_version == expected_worker)
                        )
                    )
                )
            except (CommandFailure, ContractFailure):
                worker_version = None
                last["worker_ready"] = False
            try:
                info = wrangler(
                    f"{phase}-container-info-{attempt:02d}",
                    "containers", "info", application_id, "--json",
                )
                image, application_version = parse_application(info.stdout, application_id, account_id)
                last["image_ready"] = image == expected_image
                last["application_version"] = application_version if last["image_ready"] else None
            except (CommandFailure, ContractFailure):
                image = None
                application_version = None
                last["image_ready"] = False
                last["application_version"] = None
            try:
                instances = wrangler(
                    f"{phase}-instances-{attempt:02d}",
                    "containers", "instances", application_id, "--json",
                )
                values = parse_json(instances.stdout, "container instances")
                if not isinstance(values, list):
                    raise ContractFailure("container instances are invalid")
                active = [item for item in values if isinstance(item, dict) and item.get("state") != "inactive"]
                last["instances_observed"] = True
                last["active_instances"] = len(active)
            except (CommandFailure, ContractFailure):
                last["instances_observed"] = False
                last["active_instances"] = 0
            if all(last[key] for key in ("health_ready", "worker_ready", "image_ready")):
                evidence.write(f"smoke-{phase}.json", {
                    "schema_version": "milk.content-free-gateway-smoke.v1",
                    "operation_id": operation_id,
                    "phase": phase,
                    "attempts": attempt,
                    "http_status": last["http_status"],
                    "health_contract": "status-ok-config-sha256",
                    "config_sha256": last["config_sha256"],
                    "content_retained": False,
                    "instances_observed": last["instances_observed"],
                    "active_instances": last["active_instances"],
                    "application_version": last["application_version"],
                    "succeeded": True,
                })
                return worker_version, image, application_version
            if attempt != POLL_ATTEMPTS:
                runner.run(
                    f"{phase}-poll-wait-{attempt:02d}",
                    [commands["sleep"], str(POLL_INTERVAL_SECONDS)],
                    timeout=POLL_INTERVAL_SECONDS + 5,
                )
        evidence.write(f"smoke-{phase}.json", {
            "schema_version": "milk.content-free-gateway-smoke.v1",
            "operation_id": operation_id,
            "phase": phase,
            "attempts": POLL_ATTEMPTS,
            "http_status": last["http_status"],
            "health_contract": "status-ok-config-sha256",
            "config_sha256": last["config_sha256"],
            "content_retained": False,
            "health_ready": last["health_ready"],
            "worker_ready": last["worker_ready"],
            "image_ready": last["image_ready"],
            "instances_observed": last["instances_observed"],
            "active_instances": last["active_instances"],
            "application_version": last["application_version"],
            "succeeded": False,
        })
        raise DeployFailure(f"{phase} acceptance did not converge")

    try:
        stage = "release-evidence"
        admitted = validate_release(release_directory)
        base_config = validate_base_config(base_config_path)
        worker_entrypoint = repository / "deploy/cloudflare/worker.js"
        worker_source_sha256 = digest(read_regular(
            worker_entrypoint, "Worker entrypoint", 262144,
        ))

        stage = "source-authority"
        top = runner.run("git-top-level", [commands["git"], "rev-parse", "--show-toplevel"]).stdout.decode().strip()
        if Path(top).resolve() != repository:
            raise ContractFailure("deploy script is not running from the Milk Carton checkout")
        commit = runner.run(
            "git-head", [commands["git"], "rev-parse", "--verify", "HEAD^{commit}"],
        ).stdout.decode().strip()
        if SHA1.fullmatch(commit) is None:
            raise ContractFailure("deploy checkout HEAD is invalid")
        dirty = runner.run(
            "git-clean", [commands["git"], "status", "--porcelain=v1", "--untracked-files=all"],
        ).stdout
        if dirty:
            raise ContractFailure("deploy checkout is not clean")
        origin = runner.run(
            "git-origin", [commands["git"], "remote", "get-url", "origin"],
        ).stdout.decode().strip()
        if origin not in {
            "git@github.com:milkinfrastructure/milk-carton.git",
            "https://github.com/milkinfrastructure/milk-carton.git",
        }:
            raise ContractFailure("origin is not milkinfrastructure/milk-carton")
        remote_head = runner.run(
            "git-published-main",
            [
                commands["git"], "ls-remote", "--exit-code", "origin",
                "refs/heads/main",
            ],
            timeout=60,
        ).stdout.decode().split()
        if (
            len(remote_head) != 2
            or SHA1.fullmatch(remote_head[0]) is None
            or remote_head[1] != "refs/heads/main"
            or remote_head[0] != commit
        ):
            raise ContractFailure("deploy checkout is not published origin main")
        published_main_commit = remote_head[0]
        runner.run(
            "git-fetch-published-main",
            [
                commands["git"], "fetch", "--quiet", "--no-tags", "origin",
                "refs/heads/main",
            ],
            timeout=60,
        )
        runner.run(
            "git-published-main-ancestor",
            [
                commands["git"], "merge-base", "--is-ancestor",
                admitted["source_commit"], commit,
            ],
        )

        def source_authority_unchanged(phase):
            rechecked_head = runner.run(
                f"git-{phase}-head",
                [commands["git"], "rev-parse", "--verify", "HEAD^{commit}"],
            ).stdout.decode().strip()
            rechecked_status = runner.run(
                f"git-{phase}-clean",
                [commands["git"], "status", "--porcelain=v1", "--untracked-files=all"],
            ).stdout
            rechecked_remote = runner.run(
                f"git-{phase}-published-main",
                [
                    commands["git"], "ls-remote", "--exit-code", "origin",
                    "refs/heads/main",
                ],
                timeout=60,
            ).stdout.decode().split()
            return (
                rechecked_head == commit
                and not rechecked_status
                and rechecked_remote == [published_main_commit, "refs/heads/main"]
            )

        stage = "tool-authority"
        version_raw = runner.run("wrangler-version", [commands["wrangler"], "--version"]).stdout.decode()
        versions = re.findall(r"(?<![0-9.])([0-9]+\.[0-9]+\.[0-9]+)(?![0-9.])", version_raw)
        if versions != [WRANGLER_VERSION]:
            raise ContractFailure("Wrangler is not pinned to 4.126.0")
        docker_context = runner.run(
            "docker-context", [commands["docker"], "context", "show"],
        ).stdout.decode().strip()
        if not docker_context:
            raise ContractFailure("Docker context is empty")
        docker_endpoint = runner.run(
            "docker-endpoint",
            [commands["docker"], "context", "inspect", docker_context, "--format", '{{ (index .Endpoints "docker").Host }}'],
        ).stdout.decode().strip()
        if not (docker_endpoint.startswith("unix://") or docker_endpoint.startswith("npipe://")):
            raise ContractFailure("Docker context is not a local socket")
        runner.run(
            "docker-buildx-version",
            [commands["docker"], "--config", str(docker_config), "--host", docker_endpoint, "buildx", "version"],
        )

        image_tag = f"milk-{admitted['child_sha256']}-op-{operation_id}"
        remote_image = f"{REGISTRY}/{account_id}/milk-carton:{image_tag}"
        evidence.write("intent.json", {
            "schema_version": "milk.private-gateway-deploy-intent.v1",
            "operation_id": operation_id,
            "worker": WORKER,
            "application_name": APPLICATION_NAME,
            "application_id": application_id,
            "bootstrap": bootstrap,
            "account_id": account_id,
            "source_repository": SOURCE_REPOSITORY,
            "source_commit": admitted["source_commit"],
            "deployment_source_commit": commit,
            "release_sha256": admitted["release_sha256"],
            "build_ops_log_reference_sha256": admitted["build_ops_log_reference_sha256"],
            "admission_sha256": admitted["admission_sha256"],
            "admitted_image_reference": admitted["image_reference"],
            "admitted_child_reference": admitted["child_reference"],
            "gateway_config_sha256": gateway_config_sha256,
            "target_image": remote_image,
            "rollout": "immediate",
            "started_at": started_at,
        })

        if bootstrap:
            stage = "bootstrap-preflight"
            if worker_exists("bootstrap-preflight-worker"):
                raise ContractFailure("bootstrap requires the Worker to be absent")
            if matching_applications("bootstrap-preflight-container-list"):
                raise ContractFailure("bootstrap container application already exists")
            images = parse_images(wrangler(
                "preflight-image-list", "containers", "images", "list", "--json",
            ).stdout)
            if image_tag in images.get("milk-carton", set()):
                raise ContractFailure("target Cloudflare image tag already exists")
            evidence.write("bootstrap-preflight.json", {
                "schema_version": "milk.private-gateway-bootstrap-preflight.v1",
                "operation_id": operation_id,
                "worker": WORKER,
                "application_name": APPLICATION_NAME,
                "worker_absent": True,
                "application_absent": True,
            })
        else:
            stage = "rollback-anchor"
            worker_status = wrangler(
                "previous-worker-status", "deployments", "status", "--name", WORKER, "--json",
            )
            previous_worker = parse_active_worker(worker_status.stdout)
            if previous_worker is None:
                raise ContractFailure("current Worker deployment is not a single 100 percent version")
            app_info = wrangler(
                "previous-container-info", "containers", "info", application_id, "--json",
            )
            previous_image, previous_app_version = parse_application(app_info.stdout, application_id, account_id)
            previous_health_status, previous_health_ready, previous_config_sha256 = probe_health(
                "previous", 1,
            )
            if (
                previous_health_status != 200
                or not previous_health_ready
                or SHA256.fullmatch(previous_config_sha256 or "") is None
            ):
                raise ContractFailure("previous gateway config is not healthy and observable")
            if previous_config_sha256 != previous_gateway_config_sha256:
                raise ContractFailure(
                    "operator-supplied previous gateway config does not match the live deployment"
                )
            previous_repository, previous_tag = split_cloudflare_image(previous_image, account_id)
            images = parse_images(wrangler(
                "preflight-image-list", "containers", "images", "list", "--json",
            ).stdout)
            if previous_tag not in images.get(previous_repository, set()):
                raise ContractFailure("previous rollback image is not retained")
            if image_tag in images.get("milk-carton", set()):
                raise ContractFailure("target Cloudflare image tag already exists")
            previous = {
                "worker_version_id": previous_worker,
                "image": previous_image,
                "application_version": previous_app_version,
                "config_sha256": previous_config_sha256,
            }
            evidence.write("previous.json", {
                "schema_version": "milk.private-gateway-previous-deployment.v1",
                "operation_id": operation_id,
                "worker_version_id": previous_worker,
                "application_id": application_id,
                "application_version": previous_app_version,
                "image": previous_image,
                "gateway_config_sha256": previous_config_sha256,
                "image_retained": True,
            })

        if bootstrap:
            stage = "bootstrap-secret-materialization"
            (
                bootstrap_secret_input,
                rechecked_bootstrap_secrets_sha256,
                rechecked_bootstrap_secret_names,
                rechecked_gateway_config_raw,
                _,
            ) = validate_bootstrap_secrets(
                bootstrap_secrets_path, repository, materialize=True,
            )
            try:
                if (
                    rechecked_bootstrap_secrets_sha256 != bootstrap_secrets_sha256
                    or rechecked_bootstrap_secret_names != expected_bootstrap_secret_names
                    or rechecked_gateway_config_raw != gateway_config_raw
                ):
                    raise ContractFailure("bootstrap secrets changed after validation")
                deployment_secrets = scratch / "deploy-secrets.json"
                write_private(deployment_secrets, bootstrap_secret_input)
            finally:
                clear_sensitive_bytes(bootstrap_secret_input)
                bootstrap_secret_input = None

        stage = "ghcr-auth"
        try:
            write_docker_config(docker_config, bytes(github_token))
        finally:
            for index in range(len(github_token)):
                github_token[index] = 0
        stage = "ghcr-pull"
        docker(
            "pull-admitted-amd64-child", "pull", "--platform", "linux/amd64", admitted["child_reference"],
            timeout=900,
        )
        local_image = f"milk-carton:{image_tag}"
        docker("tag-admitted-child", "tag", admitted["child_reference"], local_image)
        docker_config.joinpath("config.json").unlink()

        stage = "cloudflare-push"
        docker_wrapper = scratch / "docker"
        wrapper = (
            "#!/bin/sh\n"
            "unset CLOUDFLARE_ACCOUNT_ID CLOUDFLARE_API_TOKEN\n"
            f"exec {shlex.quote(commands['docker'])} --config {shlex.quote(str(scratch / 'docker-config'))} "
            f"--host {shlex.quote(docker_endpoint)} \"$@\"\n"
        ).encode()
        write_private(docker_wrapper, wrapper, 0o700)
        wrangler(
            "push-cloudflare-image", "containers", "push", local_image,
            "--path-to-docker", str(docker_wrapper), timeout=900,
        )
        images_after_push = parse_images(wrangler(
            "post-push-image-list", "containers", "images", "list", "--json",
        ).stdout)
        if image_tag not in images_after_push.get("milk-carton", set()):
            raise ContractFailure("pushed Cloudflare image tag is not visible")

        stage = "cloudflare-copy-verification"
        credentials_result = wrangler(
            "cloudflare-pull-credential", "containers", "registries", "credentials",
            REGISTRY, "--pull", "--expiration-minutes", "15", "--json", sensitive=True,
        )
        credentials = parse_json(credentials_result.stdout, "Cloudflare pull credential", 32768)
        require_keys(credentials, {"account_id", "registry_host", "username", "password"}, "Cloudflare pull credential")
        if (
            credentials["account_id"] != account_id
            or credentials["registry_host"] != REGISTRY
            or not isinstance(credentials["username"], str)
            or not 1 <= len(credentials["username"]) <= 512
            or not isinstance(credentials["password"], str)
            or not 1 <= len(credentials["password"]) <= 8192
        ):
            raise ContractFailure("Cloudflare pull credential identity is invalid")
        docker(
            "cloudflare-registry-login", "login", REGISTRY, "--username", credentials["username"],
            "--password-stdin", input_bytes=credentials["password"].encode() + b"\n",
        )
        credentials = None
        remote_manifest_raw = docker(
            "inspect-cloudflare-image", "buildx", "imagetools", "inspect", "--raw", remote_image,
            timeout=300,
        ).stdout
        remote_manifest = parse_json(remote_manifest_raw, "Cloudflare image manifest")
        remote_config = remote_manifest.get("config") if isinstance(remote_manifest, dict) else None
        remote_layers = remote_manifest.get("layers") if isinstance(remote_manifest, dict) else None
        if (
            remote_manifest.get("schemaVersion") != 2
            or not isinstance(remote_config, dict)
            or remote_config.get("digest") != "sha256:" + admitted["config_sha256"]
            or not isinstance(remote_layers, list)
            or [layer.get("digest") if isinstance(layer, dict) else None for layer in remote_layers]
            != admitted["layer_digests"]
        ):
            raise ContractFailure("Cloudflare image content does not match the admitted child")
        evidence.write("registry-copy.json", {
            "schema_version": "milk.private-gateway-registry-copy.v1",
            "operation_id": operation_id,
            "source_image": admitted["child_reference"],
            "target_image": remote_image,
            "config_sha256": admitted["config_sha256"],
            "ordered_layer_sha256": [value[7:] for value in admitted["layer_digests"]],
            "verified": True,
        })
        shutil.rmtree(scratch / "docker-config")

        stage = "worker-deploy"
        temporary_config = scratch / "wrangler.jsonc"
        make_deploy_config(
            base_config,
            temporary_config,
            remote_image,
            worker_entrypoint,
            api_hostname,
        )
        deploy_arguments = [
            "deploy", "--strict", "--containers-rollout", "immediate",
            "--message", f"milk private gateway {operation_id}",
        ]
        if not bootstrap:
            deployment_secrets = scratch / "deploy-secrets.json"
            write_private(deployment_secrets, canonical_json({
                "MILK_CARTON_CONFIG_JSON": gateway_config_raw.decode("utf-8"),
            }))
        if deployment_secrets is None:
            raise ContractFailure("deployment secrets were not materialized")
        deploy_arguments.extend(["--secrets-file", str(deployment_secrets)])
        stage = "source-authority-recheck"
        if not source_authority_unchanged("predeploy"):
            raise ContractFailure("source authority changed before deployment")
        if not bootstrap:
            stage = "rollback-anchor-recheck"
            rechecked_worker = parse_active_worker(wrangler(
                "predeploy-previous-worker-status",
                "deployments", "status", "--name", WORKER, "--json",
            ).stdout)
            rechecked_image, rechecked_app_version = parse_application(
                wrangler(
                    "predeploy-previous-container-info",
                    "containers", "info", application_id, "--json",
                ).stdout,
                application_id,
                account_id,
            )
            (
                rechecked_health_status,
                rechecked_health_ready,
                rechecked_config_sha256,
            ) = probe_health("predeploy-anchor", 1)
            rechecked_images = parse_images(wrangler(
                "predeploy-previous-image-list",
                "containers", "images", "list", "--json",
            ).stdout)
            if (
                rechecked_worker != previous["worker_version_id"]
                or rechecked_image != previous["image"]
                or rechecked_app_version != previous["application_version"]
                or rechecked_health_status != 200
                or not rechecked_health_ready
                or rechecked_config_sha256 != previous["config_sha256"]
                or previous_tag not in rechecked_images.get(previous_repository, set())
            ):
                raise ContractFailure("rollback anchor changed before deployment")
            rollback_config = scratch / "rollback-wrangler.jsonc"
            make_deploy_config(
                base_config,
                rollback_config,
                previous["image"],
                worker_entrypoint,
                api_hostname,
            )
            rollback_secrets = scratch / "rollback-secrets.json"
            write_private(rollback_secrets, canonical_json({
                "MILK_CARTON_CONFIG_JSON": previous_gateway_config_raw.decode("utf-8"),
            }))
            os.chmod(rollback_config, 0o400)
            os.chmod(rollback_secrets, 0o400)
            rollback_config_sha256 = digest(read_regular(
                rollback_config, "rollback deploy config", 65536,
            ))
            rollback_secrets_sha256 = digest(read_regular(
                rollback_secrets, "rollback deploy secrets", 65536,
            ))
            if digest(read_regular(
                worker_entrypoint, "Worker entrypoint", 262144,
            )) != worker_source_sha256:
                raise ContractFailure("Worker entrypoint changed before deployment")
        stage = "worker-deploy"
        deploy_started = True
        try:
            wrangler(
                "deploy-worker-and-container", *deploy_arguments, timeout=900,
                sensitive=True, config=temporary_config,
            )
        finally:
            if deployment_secrets is not None:
                deployment_secrets.unlink(missing_ok=True)
                deployment_secrets = None

        if bootstrap:
            stage = "bootstrap-application-discovery"
            for attempt in range(1, POLL_ATTEMPTS + 1):
                matches = matching_applications(f"bootstrap-container-list-{attempt:02d}")
                if matches:
                    application_id = matches[0]
                    break
                if attempt != POLL_ATTEMPTS:
                    runner.run(
                        f"bootstrap-discovery-wait-{attempt:02d}",
                        [commands["sleep"], str(POLL_INTERVAL_SECONDS)],
                        timeout=POLL_INTERVAL_SECONDS + 5,
                    )
            if application_id is None:
                raise ContractFailure("bootstrap container application was not created")
            created_image, created_app_version = parse_application(
                wrangler(
                    "bootstrap-container-info", "containers", "info", application_id, "--json",
                ).stdout,
                application_id,
                account_id,
            )
            if created_image != remote_image:
                raise ContractFailure("bootstrap container does not use the admitted image")

            stage = "bootstrap-secret-verification"
            installed_secrets = parse_secret_names(wrangler(
                "bootstrap-secret-list", "secret", "list", "--name", WORKER,
                "--format", "json", sensitive=True,
            ).stdout)
            if installed_secrets != expected_bootstrap_secret_names:
                raise ContractFailure("bootstrap Worker secrets are incomplete")
            evidence.write("bootstrap-created.json", {
                "schema_version": "milk.private-gateway-bootstrap-created.v1",
                "operation_id": operation_id,
                "worker": WORKER,
                "application_name": APPLICATION_NAME,
                "application_id": application_id,
                "application_version": created_app_version,
                "image": created_image,
                "secret_count": len(installed_secrets),
                "secrets_verified": True,
            })

        stage = "live-acceptance"
        current_worker, current_image, current_app_version = poll(
            "bootstrap" if bootstrap else "deploy", remote_image, previous_worker, True,
            gateway_config_sha256,
        )
        stage = "official-sdk-smoke"
        sdk_result = runner.run(
            "deploy-official-openai-sdk-smoke",
            [
                commands["node"],
                str(repository / "tools/openai-production-smoke.mjs"),
                api_base_url,
                str(credential_file),
            ],
            timeout=150,
        )
        sdk_smoke = parse_json(sdk_result.stdout, "official OpenAI SDK smoke", 65536)
        require_keys(
            sdk_smoke,
            OFFICIAL_OPENAI_SDK_BASELINE_FIELDS,
            "official OpenAI SDK smoke",
        )
        if (
            sdk_result.stdout != canonical_json(sdk_smoke)
            or sdk_smoke["schema_version"] != "milk.official-openai-sdk-smoke.v2"
            or sdk_smoke["sdk"] != "openai-node"
            or sdk_smoke["sdk_version"] != "6.33.0"
            or sdk_smoke["proof_contract_sha256"] != PRODUCTION_PROOF_SHA256
            or sdk_smoke["proof_step"] != "deployment_baseline"
            or sdk_smoke["model"] != PRODUCTION_PROOF["model"]
            or sdk_smoke["sdk_request_count"] != 1
            or sdk_smoke["baseline_request_count"] != 1
            or sdk_smoke["candidate_request_count"] != 0
            or sdk_smoke["max_completion_tokens"] != PRODUCTION_PROOF["short_max_completion_tokens"]
            or sdk_smoke["authenticated"] is not True
            or sdk_smoke["succeeded"] is not True
            or sdk_smoke["content_retained"] is not False
            or sdk_smoke["http_status"] != 200
            or sdk_smoke["choice_count"] != 1
            or not isinstance(sdk_smoke["response_bytes"], int)
            or isinstance(sdk_smoke["response_bytes"], bool)
            or not 1 <= sdk_smoke["response_bytes"] <= 65536
            or any(SHA256.fullmatch(sdk_smoke[key] or "") is None for key in (
                "endpoint_sha256", "request_sha256", "response_sha256",
                "traffic_cohort_sha256", "traffic_key_sha256",
            ))
            or sdk_smoke["traffic_key_sha256"] != smoke_key_sha256
            or sdk_smoke["traffic_cohort_sha256"] != smoke_cohort_sha256
            or not isinstance(sdk_smoke["finish_reason"], (str, type(None)))
        ):
            raise ContractFailure("official OpenAI SDK smoke receipt is invalid")
        baseline_receipt_sha256 = evidence.write(
            "official-openai-sdk-smoke.json", sdk_smoke,
        )
        evidence.write("current.json", {
            "schema_version": "milk.private-gateway-current-deployment.v2",
            "operation_id": operation_id,
            "worker_version_id": current_worker,
            "application_name": APPLICATION_NAME,
            "application_id": application_id,
            "application_version": current_app_version,
            "image": current_image,
            "gateway_config_sha256": gateway_config_sha256,
            "official_openai_sdk_baseline_receipt_sha256": baseline_receipt_sha256,
            "proof_contract_sha256": PRODUCTION_PROOF_SHA256,
            "rollout": "immediate",
            "accepted": True,
        })
        temporary_config.unlink()
        temporary_config = None
        shutil.rmtree(scratch)
        scratch = None
        evidence.finalize(
            "succeeded", None, started_at, baseline_receipt_sha256,
        )
        cloudflare_environment.pop("CLOUDFLARE_API_TOKEN", None)
        print(f"private gateway deployment verified at {evidence_directory}")
        return 0
    except BaseException as error:
        for index in range(len(github_token)):
            github_token[index] = 0
        for signal_number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(signal_number, signal.SIG_IGN)
        failure_stage = stage
        outcome = "predeploy_failed"
        rollback_observation = None
        clear_sensitive_bytes(bootstrap_secret_input)
        bootstrap_secret_input = None
        if deploy_started and bootstrap:
            outcome = "bootstrap_cleanup_failed"
            try:
                stage = "automatic-bootstrap-cleanup"
                if cleanup_bootstrap():
                    outcome = "bootstrap_failed_cleaned"
            except BaseException:
                pass
        elif deploy_started and previous is not None:
            outcome = "rollback_failed"
            resource_restore_command_succeeded = False
            resource_restore_accepted = False
            rollback_inputs_verified = False
            worker_rollback_command_succeeded = False
            rollback_accepted = False
            rollback_app_version = None
            try:
                stage = "automatic-resource-restore"
                if (
                    rollback_config is None
                    or rollback_config_sha256 is None
                    or rollback_secrets is None
                    or rollback_secrets_sha256 is None
                    or worker_source_sha256 is None
                    or digest(read_regular(
                        rollback_config, "rollback deploy config", 65536,
                    )) != rollback_config_sha256
                    or digest(read_regular(
                        rollback_secrets, "rollback deploy secrets", 65536,
                    )) != rollback_secrets_sha256
                    or digest(read_regular(
                        worker_entrypoint, "Worker entrypoint", 262144,
                    )) != worker_source_sha256
                ):
                    raise ContractFailure("staged rollback inputs changed")
                rollback_inputs_verified = True
                wrangler(
                    "restore-previous-image-and-config",
                    "deploy", "--strict", "--containers-rollout", "immediate",
                    "--message", f"milk automatic resource restore {operation_id}",
                    "--secrets-file", str(rollback_secrets),
                    timeout=900, sensitive=True, config=rollback_config,
                )
                resource_restore_command_succeeded = True
            except BaseException:
                pass
            finally:
                if rollback_secrets is not None:
                    rollback_secrets.unlink(missing_ok=True)
                if rollback_config is not None:
                    rollback_config.unlink(missing_ok=True)
            if rollback_inputs_verified:
                try:
                    stage = "automatic-resource-restore-acceptance"
                    poll(
                        "resource-restore", previous["image"], None, False,
                        previous["config_sha256"],
                    )
                    resource_restore_accepted = True
                except BaseException:
                    pass
            if resource_restore_accepted:
                try:
                    stage = "automatic-worker-rollback"
                    wrangler(
                        "rollback-worker", "rollback", previous["worker_version_id"], "--name", WORKER,
                        "--message", f"milk automatic rollback {operation_id}", "--yes", timeout=300,
                    )
                    worker_rollback_command_succeeded = True
                except BaseException:
                    pass
                try:
                    stage = "automatic-rollback-acceptance"
                    _, _, rollback_app_version = poll(
                        "rollback", previous["image"], previous["worker_version_id"], False,
                        previous["config_sha256"],
                    )
                    rollback_accepted = True
                    outcome = "deployment_failed_rolled_back"
                except BaseException:
                    pass
            rollback_observation = {
                "schema_version": "milk.private-gateway-rollback.v2",
                "operation_id": operation_id,
                "previous_worker_version_id": previous["worker_version_id"],
                "previous_image": previous["image"],
                "previous_gateway_config_sha256": previous["config_sha256"],
                "application_id": application_id,
                "application_version": rollback_app_version,
                "rollback_inputs_verified": rollback_inputs_verified,
                "resource_restore_command_succeeded": resource_restore_command_succeeded,
                "resource_restore_accepted": resource_restore_accepted,
                "worker_rollback_command_succeeded": worker_rollback_command_succeeded,
                "accepted": rollback_accepted,
            }
        try:
            if rollback_observation is not None:
                evidence.write("rollback.json", rollback_observation)
            if temporary_config is not None:
                temporary_config.unlink(missing_ok=True)
            if deployment_secrets is not None:
                deployment_secrets.unlink(missing_ok=True)
            if scratch is not None and scratch.exists():
                shutil.rmtree(scratch)
            cloudflare_environment.pop("CLOUDFLARE_API_TOKEN", None)
            evidence.finalize(outcome, failure_stage, started_at)
        except BaseException:
            outcome = "evidence_finalization_failed"
        print(f"deploy-private-gateway: {outcome} at {failure_stage}", file=sys.stderr)
        if isinstance(error, DeployFailure) and str(error).startswith("usage:"):
            print(str(error), file=sys.stderr)
        return 70


try:
    raise SystemExit(main())
except DeployFailure as error:
    print(f"deploy-private-gateway: {error}", file=sys.stderr)
    raise SystemExit(64)
except (OSError, ValueError):
    print("deploy-private-gateway: initialization failed", file=sys.stderr)
    raise SystemExit(70)
PY
