#!/usr/bin/env python3
import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import shutil
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.parse
from pathlib import Path


WORKER = "milk-carton"
APPLICATION_NAME = "milk-carton-milkcarton"
SECRET = "MILK_CARTON_CANDIDATE_API_KEY"
ADMIN_SECRET = "MILK_CARTON_CONTAINER_ADMIN_KEY"
SHA256_HEADER = "x-milk-candidate-api-key-sha256"
OPERATION_HEADER = "x-milk-candidate-operation"
WRANGLER_VERSION = "4.126.0"
DELIVERY_SCHEMA = "milk.baseten-candidate-key-delivery.v1"
VERIFY_SCHEMA = "milk.baseten-candidate-key-delivery-verify.v1"
REMOVE_SCHEMA = "milk.baseten-candidate-key-remove.v1"
OPERATOR_ROUTE_REMOVE_SCHEMA = "milk.baseten-candidate-key-remove-operator-route.v1"
ACK_SCHEMA = "milk.baseten-candidate-key-delivery-ack.v1"
RESTART_SCHEMA = "milk.gateway-candidate-container-restart.v1"
INSPECTION_SCHEMA = "milk.gateway-candidate-container-inspection.v1"
RELEASE_SCHEMA = "milk.gateway-process-release.v1"
TEARDOWN_SCHEMA = "milk.provider-teardown-authorization.v1"
ROUTE_RECEIPT_SCHEMA = "milk.route-publication-receipt.v2"
ACCOUNT_ID = re.compile(r"[0-9a-f]{32}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SHA256 = re.compile(r"[0-9a-f]{64}")
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,255}")
KEY_NAME = re.compile(r"[a-z0-9-]{1,64}")
IMAGE_TAG = re.compile(r"[a-z0-9_][a-z0-9._-]{0,127}")
HOSTNAME = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?\Z"
)
MAX_JSON = 64 * 1024
MAX_REQUEST = 32 * 1024
MAX_DELIVERY = 4096
MAX_ACK = 4096
POLL_ATTEMPTS = 12
POLL_SECONDS = 2
OPERATOR_CANARY_BASIS_POINTS = 100
ZERO_SHA256 = "0" * 64


class OperationFailure(Exception):
    pass


def canonical_json(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def gateway_json(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise OperationFailure("duplicate JSON key")
        value[key] = item
    return value


def parse_canonical(raw, max_bytes, description):
    if not 1 <= len(raw) <= max_bytes or not raw.endswith(b"\n"):
        raise OperationFailure(f"invalid {description}")
    try:
        value = json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise OperationFailure(f"invalid {description}") from error
    if canonical_json(value) != raw:
        raise OperationFailure(f"noncanonical {description}")
    return value


def require_exact_keys(value, keys, description):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise OperationFailure(f"invalid {description}")


def bounded_text(value, maximum):
    return (
        isinstance(value, str)
        and 1 <= len(value.encode()) <= maximum
        and all(33 <= byte <= 126 for byte in value.encode())
    )


def valid_positive_integer(value, maximum=None):
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
        and (maximum is None or value <= maximum)
    )


BASE_KEYS = {
    "run_id", "provider", "team_name", "model_id", "key_name", "key_prefix",
    "candidate_key_sha256", "payload_sha256", "payload_bytes",
}


def validate_base(value):
    if (
        SHA256.fullmatch(value.get("run_id") or "") is None
        or value.get("provider") != "baseten"
        or not bounded_text(value.get("team_name"), 128)
        or IDENTITY.fullmatch(value.get("model_id") or "") is None
        or KEY_NAME.fullmatch(value.get("key_name") or "") is None
        or not bounded_text(value.get("key_prefix"), 256)
        or SHA256.fullmatch(value.get("candidate_key_sha256") or "") is None
        or SHA256.fullmatch(value.get("payload_sha256") or "") is None
        or not valid_positive_integer(value.get("payload_bytes"), MAX_DELIVERY)
    ):
        raise OperationFailure("invalid candidate credential identity")
    return {key: value[key] for key in BASE_KEYS}


def parse_delivery(raw):
    value = parse_canonical(raw, MAX_DELIVERY, "candidate delivery frame")
    require_exact_keys(
        value,
        {
            "schema_version", "run_id", "provider", "team_name", "model_id",
            "key_name", "key_prefix", "candidate_key_sha256", "candidate_api_key",
        },
        "candidate delivery frame",
    )
    candidate = value["candidate_api_key"]
    if (
        value["schema_version"] != DELIVERY_SCHEMA
        or SHA256.fullmatch(value["run_id"] or "") is None
        or value["provider"] != "baseten"
        or not bounded_text(value["team_name"], 128)
        or IDENTITY.fullmatch(value["model_id"] or "") is None
        or KEY_NAME.fullmatch(value["key_name"] or "") is None
        or not bounded_text(value["key_prefix"], 256)
        or SHA256.fullmatch(value["candidate_key_sha256"] or "") is None
        or not bounded_text(candidate, 4096)
    ):
        raise OperationFailure("invalid candidate delivery frame")
    candidate_bytes = bytearray(candidate.encode())
    if not hmac.compare_digest(
        hashlib.sha256(candidate_bytes).hexdigest(), value["candidate_key_sha256"]
    ):
        raise OperationFailure("candidate delivery digest mismatch")
    return {
        "candidate_key_sha256": value["candidate_key_sha256"],
        "key_name": value["key_name"],
        "key_prefix": value["key_prefix"],
        "model_id": value["model_id"],
        "payload_bytes": len(raw),
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "provider": value["provider"],
        "run_id": value["run_id"],
        "team_name": value["team_name"],
    }, candidate_bytes


def parse_verify(value):
    require_exact_keys(value, BASE_KEYS | {"schema_version"}, "verify request")
    if value["schema_version"] != VERIFY_SCHEMA:
        raise OperationFailure("invalid verify request")
    return validate_base(value)


AUTH_KEYS = (
    "schema_version", "scope", "student_job_id", "claim_sha256",
    "winner_result_object_key", "winner_result_sha256",
    "provider_acceptance_sha256", "run_id", "selected_provider",
    "execution_id", "trigger", "authorized_at",
)
SCOPE_KEYS = ("tenant_id", "project_id", "environment_id", "workload_id", "eval_id")
ROUTE_RECEIPT_KEYS = (
    "schema_version", "route_revision", "student_job_id", "student_result_sha256",
    "model_manifest_sha256", "dev_receipt_sha256", "previous_route_revision",
    "candidate_basis_points", "manifest_object_key", "signature_object_key",
    "live_pointer_object_key", "state",
)


def ordered(value, keys, description):
    require_exact_keys(value, set(keys), description)
    return {key: value[key] for key in keys}


def validate_timestamp(value):
    if not isinstance(value, str) or not value.endswith("Z"):
        raise OperationFailure("invalid UTC timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise OperationFailure("invalid UTC timestamp") from error
    if parsed.utcoffset() != dt.timedelta(0):
        raise OperationFailure("invalid UTC timestamp")


def ordered_route_receipt(value):
    receipt = ordered(value, ROUTE_RECEIPT_KEYS, "route receipt")
    digest_fields = (
        "route_revision", "student_job_id", "student_result_sha256",
        "model_manifest_sha256", "dev_receipt_sha256",
    )
    if (
        receipt["schema_version"] != ROUTE_RECEIPT_SCHEMA
        or any(SHA256.fullmatch(receipt[field] or "") is None for field in digest_fields)
        or (
            receipt["previous_route_revision"] is not None
            and SHA256.fullmatch(receipt["previous_route_revision"] or "") is None
        )
        or not isinstance(receipt["candidate_basis_points"], int)
        or isinstance(receipt["candidate_basis_points"], bool)
        or not 0 <= receipt["candidate_basis_points"] <= 10_000
        or any(
            not bounded_text(receipt[field], 1024)
            for field in (
                "manifest_object_key", "signature_object_key", "live_pointer_object_key", "state"
            )
        )
    ):
        raise OperationFailure("invalid route receipt")
    return receipt


def operator_route_receipt_prefix(receipt):
    revision = receipt["route_revision"]
    manifest_suffix = f"/routes/versions/{revision}.json"
    manifest_key = receipt["manifest_object_key"]
    if not manifest_key.endswith(manifest_suffix):
        raise OperationFailure("operator route receipt manifest is invalid")
    prefix = manifest_key.removesuffix(manifest_suffix)
    scope_id = prefix.removeprefix("milk/v1/scopes/")
    signature_prefix = f"{prefix}/routes/signatures/{revision}/"
    signature_key = receipt["signature_object_key"]
    signature_sha256 = (
        signature_key.removeprefix(signature_prefix).removesuffix(".ed25519")
    )
    if (
        prefix != f"milk/v1/scopes/{scope_id}"
        or UUID.fullmatch(scope_id or "") is None
        or not signature_key.startswith(signature_prefix)
        or not signature_key.endswith(".ed25519")
        or SHA256.fullmatch(signature_sha256) is None
        or receipt["live_pointer_object_key"] != f"{prefix}/routes/current.json"
        or receipt["state"] != "active"
    ):
        raise OperationFailure("operator route receipt object identity is invalid")
    return prefix


def parse_operator_route_remove(value):
    require_exact_keys(
        value,
        BASE_KEYS | {
            "schema_version", "gateway_release_id", "gateway_release_sha256",
            "proposal_sha256", "candidate_sha256", "canary_route_receipt",
            "zero_route_receipt",
        },
        "operator route remove request",
    )
    if (
        value["schema_version"] != OPERATOR_ROUTE_REMOVE_SCHEMA
        or UUID.fullmatch(value["gateway_release_id"] or "") is None
        or SHA256.fullmatch(value["gateway_release_sha256"] or "") is None
        or SHA256.fullmatch(value["proposal_sha256"] or "") is None
        or SHA256.fullmatch(value["candidate_sha256"] or "") is None
        or value["proposal_sha256"] == ZERO_SHA256
        or value["candidate_sha256"] == ZERO_SHA256
    ):
        raise OperationFailure("invalid operator route remove request")
    canary = ordered_route_receipt(value["canary_route_receipt"])
    zero = ordered_route_receipt(value["zero_route_receipt"])
    if (
        operator_route_receipt_prefix(canary) != operator_route_receipt_prefix(zero)
        or canary["candidate_basis_points"] != OPERATOR_CANARY_BASIS_POINTS
        or zero["candidate_basis_points"] != 0
        or zero["previous_route_revision"] != canary["route_revision"]
        or zero["route_revision"] == canary["route_revision"]
        or canary["student_result_sha256"] != value["proposal_sha256"]
        or zero["student_result_sha256"] != value["proposal_sha256"]
        or canary["student_job_id"] != value["candidate_sha256"]
        or canary["model_manifest_sha256"] == ZERO_SHA256
        or canary["dev_receipt_sha256"] != ZERO_SHA256
        or zero["student_job_id"] != ZERO_SHA256
        or zero["model_manifest_sha256"] != ZERO_SHA256
        or zero["dev_receipt_sha256"] != ZERO_SHA256
    ):
        raise OperationFailure("invalid operator route receipt sequence")
    metadata = validate_base(value)
    metadata["gateway_release_id"] = value["gateway_release_id"]
    metadata["gateway_release_sha256"] = value["gateway_release_sha256"]
    return metadata


def ordered_trigger(value):
    if not isinstance(value, dict):
        raise OperationFailure("invalid teardown trigger")
    if value.get("kind") == "service_expired":
        trigger = ordered(value, ("kind", "service_not_after"), "service-expired trigger")
        validate_timestamp(trigger["service_not_after"])
        return trigger
    trigger = ordered(
        value,
        (
            "kind", "retirement_object_key", "retirement_sha256", "zero_route_revision",
            "canary_route_receipt", "zero_route_receipt",
        ),
        "route-zero trigger",
    )
    if (
        trigger["kind"] != "route_zero"
        or not bounded_text(trigger["retirement_object_key"], 1024)
        or SHA256.fullmatch(trigger["retirement_sha256"] or "") is None
        or SHA256.fullmatch(trigger["zero_route_revision"] or "") is None
    ):
        raise OperationFailure("invalid route-zero trigger")
    trigger["canary_route_receipt"] = ordered_route_receipt(trigger["canary_route_receipt"])
    trigger["zero_route_receipt"] = ordered_route_receipt(trigger["zero_route_receipt"])
    if (
        trigger["canary_route_receipt"]["candidate_basis_points"] != 100
        or trigger["zero_route_receipt"]["candidate_basis_points"] != 0
        or trigger["zero_route_receipt"]["previous_route_revision"]
        != trigger["canary_route_receipt"]["route_revision"]
        or trigger["zero_route_receipt"]["route_revision"] != trigger["zero_route_revision"]
    ):
        raise OperationFailure("invalid route-zero receipt sequence")
    return trigger


def ordered_authorization(value, metadata):
    authorization = ordered(value, AUTH_KEYS, "teardown authorization")
    authorization["scope"] = ordered(authorization["scope"], SCOPE_KEYS, "teardown scope")
    authorization["trigger"] = ordered_trigger(authorization["trigger"])
    if (
        authorization["schema_version"] != TEARDOWN_SCHEMA
        or any(
            UUID.fullmatch(authorization["scope"][key] or "") is None
            for key in SCOPE_KEYS[:-1]
        )
        or SHA256.fullmatch(authorization["scope"]["eval_id"] or "") is None
        or SHA256.fullmatch(authorization["student_job_id"] or "") is None
        or SHA256.fullmatch(authorization["claim_sha256"] or "") is None
        or not bounded_text(authorization["winner_result_object_key"], 1024)
        or SHA256.fullmatch(authorization["winner_result_sha256"] or "") is None
        or SHA256.fullmatch(authorization["provider_acceptance_sha256"] or "") is None
        or authorization["run_id"] != metadata["run_id"]
        or authorization["selected_provider"] != metadata["provider"]
        or not bounded_text(authorization["execution_id"], 256)
        or authorization["trigger"] != metadata["trigger"]
    ):
        raise OperationFailure("invalid teardown authorization")
    validate_timestamp(authorization["authorized_at"])
    return authorization


def parse_remove(value):
    require_exact_keys(
        value,
        BASE_KEYS | {
            "schema_version", "gateway_release_id", "gateway_release_sha256",
            "gateway_cleanup_authorization", "gateway_cleanup_authorization_sha256", "trigger",
        },
        "remove request",
    )
    if (
        value["schema_version"] != REMOVE_SCHEMA
        or UUID.fullmatch(value["gateway_release_id"] or "") is None
        or SHA256.fullmatch(value["gateway_release_sha256"] or "") is None
        or SHA256.fullmatch(value["gateway_cleanup_authorization_sha256"] or "") is None
    ):
        raise OperationFailure("invalid remove request")
    metadata = validate_base(value)
    metadata["trigger"] = ordered_trigger(value["trigger"])
    authorization = ordered_authorization(value["gateway_cleanup_authorization"], metadata)
    if not hmac.compare_digest(
        hashlib.sha256(gateway_json(authorization)).hexdigest(),
        value["gateway_cleanup_authorization_sha256"],
    ):
        raise OperationFailure("teardown authorization digest mismatch")
    metadata["gateway_release_id"] = value["gateway_release_id"]
    metadata["gateway_release_sha256"] = value["gateway_release_sha256"]
    return metadata


def read_admin_key(descriptor):
    if descriptor < 3:
        raise OperationFailure("admin key descriptor is invalid")
    try:
        status = os.fstat(descriptor)
    except OSError as error:
        raise OperationFailure("admin key descriptor is unavailable") from error
    if not (stat.S_ISFIFO(status.st_mode) or stat.S_ISSOCK(status.st_mode)):
        raise OperationFailure("admin key descriptor must be a pipe or socket")
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as stream:
            raw = bytearray(stream.read(514))
    except OSError as error:
        raise OperationFailure("admin key read failed") from error
    if raw.endswith(b"\n"):
        raw.pop()
    if not 32 <= len(raw) <= 512 or any(not 33 <= byte <= 126 for byte in raw):
        raise OperationFailure("admin key is invalid")
    return raw


def parse_json(raw, description):
    if not 1 <= len(raw) <= MAX_JSON:
        raise OperationFailure(f"invalid {description}")
    try:
        return json.loads(
            raw,
            object_pairs_hook=unique_object,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(item)),
        )
    except (UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise OperationFailure(f"invalid {description}") from error


def parse_active_worker(raw):
    value = parse_json(raw, "Worker deployment status")
    if not isinstance(value, dict) or not isinstance(value.get("versions"), list):
        raise OperationFailure("invalid Worker deployment status")
    versions = value["versions"]
    if len(versions) != 1:
        raise OperationFailure("Worker deployment is not singular")
    version = versions[0]
    if (
        not isinstance(version, dict)
        or version.get("percentage") != 100
        or UUID.fullmatch(version.get("version_id") or "") is None
    ):
        raise OperationFailure("invalid Worker deployment status")
    return version["version_id"]


def parse_application(raw, application_id, account_id):
    value = parse_json(raw, "container application")
    if (
        not isinstance(value, dict)
        or value.get("id") != application_id
        or value.get("account_id") != account_id
        or value.get("name") != APPLICATION_NAME
        or not valid_positive_integer(value.get("version"))
        or not isinstance(value.get("configuration"), dict)
        or not isinstance(value["configuration"].get("image"), str)
    ):
        raise OperationFailure("invalid container application")
    return value["configuration"]["image"], value["version"]


def parse_instance(raw, application_version):
    value = parse_json(raw, "container instances")
    if not isinstance(value, list):
        raise OperationFailure("invalid container instances")
    active = [item for item in value if isinstance(item, dict) and item.get("state") != "inactive"]
    if (
        len(active) != 1
        or active[0].get("state") != "running"
        or active[0].get("version") != application_version
        or not bounded_text(active[0].get("id"), 128)
    ):
        raise OperationFailure("container instance is not singular and running")
    return active[0]["id"]


def parse_secret_names(raw):
    value = parse_json(raw, "Worker secrets")
    if not isinstance(value, list):
        raise OperationFailure("invalid Worker secrets")
    names = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "type"}
            or not bounded_text(item.get("name"), 128)
            or item.get("type") != "secret_text"
        ):
            raise OperationFailure("invalid Worker secret entry")
        names.append(item["name"])
    if len(names) != len(set(names)) or ADMIN_SECRET not in names:
        raise OperationFailure("container admin secret is not installed")
    return set(names)


def parse_wrangler_oauth_identity(raw, account_id):
    value = parse_json(raw, "Wrangler OAuth identity")
    accounts = value.get("accounts") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("loggedIn") is not True
        or not isinstance(accounts, list)
        or not any(
            isinstance(account, dict) and account.get("id") == account_id
            for account in accounts
        )
    ):
        raise OperationFailure("Wrangler OAuth account does not match")


class Runner:
    def __init__(self, commands, environment, repository):
        self.commands = commands
        self.environment = environment
        self.repository = repository

    def run(self, command, *arguments, input_bytes=None, timeout=60):
        try:
            result = subprocess.run(
                [self.commands[command], *arguments], cwd=self.repository,
                env=self.environment, input=input_bytes, capture_output=True,
                check=False, timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise OperationFailure("command failed") from error
        if result.returncode != 0 or len(result.stdout) > MAX_JSON or len(result.stderr) > MAX_JSON:
            raise OperationFailure("command failed")
        return result.stdout

    def wrangler(self, *arguments, input_bytes=None, timeout=60):
        return self.run("wrangler", *arguments, input_bytes=input_bytes, timeout=timeout)


def current_identity(runner, application_id, account_id):
    worker = parse_active_worker(runner.wrangler("deployments", "status", "--name", WORKER, "--json"))
    image, application_version = parse_application(
        runner.wrangler("containers", "info", application_id, "--json"), application_id, account_id,
    )
    instance = parse_instance(
        runner.wrangler("containers", "instances", application_id, "--json"), application_version,
    )
    return worker, image, application_version, instance


def wait_for_worker(runner, previous_worker):
    for attempt in range(POLL_ATTEMPTS):
        worker = parse_active_worker(runner.wrangler("deployments", "status", "--name", WORKER, "--json"))
        if worker != previous_worker:
            return worker
        if attempt + 1 != POLL_ATTEMPTS:
            runner.run("sleep", str(POLL_SECONDS), timeout=POLL_SECONDS + 2)
    raise OperationFailure("Worker version did not advance")


def call_container_admin(runner, admin_key, operation, candidate_sha256, admin_url):
    authorization = bytearray(b"Authorization: Bearer ")
    authorization.extend(admin_key)
    authorization.extend(b"\n")
    try:
        output = runner.run(
            "curl", "--header", "@-", "--silent", "--show-error",
            "--connect-timeout", "10", "--max-time", "50", "--request", "POST",
            "--header", f"{OPERATION_HEADER}: {operation}",
            "--header", f"{SHA256_HEADER}: {candidate_sha256}",
            "--write-out", "\n%{http_code}", admin_url,
            input_bytes=bytes(authorization), timeout=55,
        )
    finally:
        for index in range(len(authorization)):
            authorization[index] = 0
    try:
        body, status = output.rsplit(b"\n", 1)
    except ValueError as error:
        raise OperationFailure("invalid admin response") from error
    if status != b"200":
        raise OperationFailure("container admin operation failed")
    value = parse_json(body, "container admin receipt")
    if operation == "inspect":
        require_exact_keys(
            value,
            {
                "candidate_api_key_sha256", "container_instance",
                "container_last_change", "schema_version", "state",
            },
            "container inspection receipt",
        )
        if (
            value["schema_version"] != INSPECTION_SCHEMA
            or value["container_instance"] != "gateway"
            or value["state"] not in {"loaded", "absent"}
            or (
                value["state"] == "loaded"
                and value["candidate_api_key_sha256"] != candidate_sha256
            )
            or (
                value["state"] == "absent"
                and value["candidate_api_key_sha256"] is not None
            )
            or not valid_positive_integer(value["container_last_change"])
        ):
            raise OperationFailure("invalid container inspection receipt")
        return value
    require_exact_keys(
        value,
        {
            "candidate_api_key_sha256", "container_instance", "container_last_change",
            "previous_container_last_change", "schema_version", "state",
        },
        "container restart receipt",
    )
    if (
        value["schema_version"] != RESTART_SCHEMA
        or value["container_instance"] != "gateway"
        or value["state"] not in {"loaded", "absent"}
        or (value["state"] == "loaded" and value["candidate_api_key_sha256"] != candidate_sha256)
        or (value["state"] == "absent" and value["candidate_api_key_sha256"] is not None)
        or (operation == "install" and value["state"] != "loaded")
        or (operation == "remove" and value["state"] != "absent")
        or not valid_positive_integer(value["container_last_change"])
        or not isinstance(value["previous_container_last_change"], int)
        or isinstance(value["previous_container_last_change"], bool)
        or value["container_last_change"] <= value["previous_container_last_change"]
    ):
        raise OperationFailure("invalid container restart receipt")
    return value


def validate_image(image, account_id):
    prefix = f"registry.cloudflare.com/{account_id}/milk-carton:"
    if (
        not isinstance(image, str)
        or not image.startswith(prefix)
        or IMAGE_TAG.fullmatch(image[len(prefix):]) is None
    ):
        raise OperationFailure("expected container image is invalid")


def process_release_sha256(worker, application_id, application_version, image, restart):
    return hashlib.sha256(canonical_json({
        "application_id": application_id,
        "application_version": application_version,
        "container_image": image,
        "container_instance": restart["container_instance"],
        "container_last_change": restart["container_last_change"],
        "schema_version": RELEASE_SCHEMA,
        "worker_version_id": worker,
    })).hexdigest()


def acknowledgement(metadata, state, worker=None, release_sha256=None):
    return {
        "candidate_key_sha256": metadata["candidate_key_sha256"],
        "gateway_release_id": worker if state == "installed" else None,
        "gateway_release_sha256": release_sha256 if state == "installed" else None,
        "key_name": metadata["key_name"],
        "key_prefix": metadata["key_prefix"],
        "model_id": metadata["model_id"],
        "payload_bytes": metadata["payload_bytes"],
        "payload_sha256": metadata["payload_sha256"],
        "provider": metadata["provider"],
        "run_id": metadata["run_id"],
        "schema_version": ACK_SCHEMA,
        "state": state,
        "team_name": metadata["team_name"],
        "verified_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }


def assert_admitted_identity(arguments, runner, account_id, expected_worker=None):
    validate_image(arguments.expected_container_image, account_id)
    current = current_identity(runner, arguments.application_id, account_id)
    worker, image, application_version, instance = current
    if (
        (expected_worker is not None and worker != expected_worker)
        or image != arguments.expected_container_image
        or application_version != arguments.expected_application_version
        or instance != "gateway"
    ):
        raise OperationFailure("gateway identity changed")
    return current


def install(metadata, candidate, arguments, runner, account_id, admin_key):
    expected_worker = arguments.expected_worker_version_id
    assert_admitted_identity(arguments, runner, account_id, expected_worker)
    names = parse_secret_names(runner.wrangler("secret", "list", "--name", WORKER, "--format", "json"))
    if SECRET in names:
        raise OperationFailure("candidate credential is already installed")
    mutated = False
    try:
        runner.wrangler(
            "secret", "put", SECRET, "--name", WORKER,
            input_bytes=bytes(candidate) + b"\n",
        )
        mutated = True
        worker = wait_for_worker(runner, expected_worker)
        restart = call_container_admin(
            runner, admin_key, "install", metadata["candidate_key_sha256"], arguments.admin_url
        )
        final = assert_admitted_identity(arguments, runner, account_id, worker)
        return acknowledgement(
            metadata, "installed", worker,
            process_release_sha256(worker, arguments.application_id, final[2], final[1], restart),
        )
    except OperationFailure:
        if mutated:
            try:
                before_cleanup = parse_active_worker(
                    runner.wrangler("deployments", "status", "--name", WORKER, "--json")
                )
                runner.wrangler("secret", "delete", SECRET, "--name", WORKER)
                wait_for_worker(runner, before_cleanup)
                call_container_admin(
                    runner, admin_key, "remove", metadata["candidate_key_sha256"], arguments.admin_url
                )
            except OperationFailure:
                pass
        raise
    finally:
        for index in range(len(candidate)):
            candidate[index] = 0


def verify(metadata, arguments, runner, account_id, admin_key):
    worker, image, application_version, _instance = assert_admitted_identity(arguments, runner, account_id)
    names = parse_secret_names(runner.wrangler("secret", "list", "--name", WORKER, "--format", "json"))
    restart = call_container_admin(
        runner, admin_key, "verify", metadata["candidate_key_sha256"], arguments.admin_url
    )
    if (SECRET in names) != (restart["state"] == "loaded"):
        raise OperationFailure("candidate secret state changed during verification")
    assert_admitted_identity(arguments, runner, account_id, worker)
    if restart["state"] == "absent":
        return acknowledgement(metadata, "absent")
    return acknowledgement(
        metadata, "installed", worker,
        process_release_sha256(worker, arguments.application_id, application_version, image, restart),
    )


def remove(metadata, arguments, runner, account_id, admin_key):
    worker, image, application_version, _instance = assert_admitted_identity(
        arguments, runner, account_id
    )
    names = parse_secret_names(runner.wrangler("secret", "list", "--name", WORKER, "--format", "json"))
    if SECRET in names:
        if worker != metadata["gateway_release_id"]:
            raise OperationFailure("installed gateway release changed")
        live = call_container_admin(
            runner, admin_key, "inspect", metadata["candidate_key_sha256"], arguments.admin_url
        )
        if (
            live["state"] != "loaded"
            or not hmac.compare_digest(
                process_release_sha256(
                    worker,
                    arguments.application_id,
                    application_version,
                    image,
                    live,
                ),
                metadata["gateway_release_sha256"],
            )
        ):
            raise OperationFailure("installed gateway release changed")
        worker = assert_admitted_identity(
            arguments, runner, account_id, worker
        )[0]
        runner.wrangler("secret", "delete", SECRET, "--name", WORKER)
        worker = wait_for_worker(runner, worker)
    elif worker == metadata["gateway_release_id"]:
        raise OperationFailure("candidate deletion did not advance Worker version")
    call_container_admin(
        runner, admin_key, "remove", metadata["candidate_key_sha256"], arguments.admin_url
    )
    assert_admitted_identity(arguments, runner, account_id, worker)
    final_names = parse_secret_names(runner.wrangler("secret", "list", "--name", WORKER, "--format", "json"))
    if SECRET in final_names:
        raise OperationFailure("candidate credential remains installed")
    return acknowledgement(metadata, "absent")


def validate_admin_url(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise argparse.ArgumentTypeError("admin URL is invalid") from error
    hostname = parsed.hostname
    if (
        parsed.scheme != "https"
        or hostname is None
        or HOSTNAME.fullmatch(hostname) is None
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.netloc != hostname
        or parsed.path != "/__milk/candidate-credential"
        or parsed.query
        or parsed.fragment
    ):
        raise argparse.ArgumentTypeError(
            "admin URL must be a lowercase HTTPS domain with the candidate-credential path"
        )
    return value


def parse_arguments():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    modes = parser.add_subparsers(dest="mode", required=True)
    baseten = modes.add_parser("serve-baseten", allow_abbrev=False)
    baseten.add_argument("--socket-path", type=Path, required=True)
    baseten.add_argument("--admin-key-fd", type=int, required=True)
    baseten.add_argument("--admin-url", type=validate_admin_url, required=True)
    baseten.add_argument("--application-id", required=True)
    baseten.add_argument("--expected-application-version", type=int, required=True)
    baseten.add_argument("--expected-container-image", required=True)
    baseten.add_argument("--expected-worker-version-id", required=True)
    baseten.add_argument("--wrangler-oauth", action="store_true")
    arguments = parser.parse_args()
    if (
        UUID.fullmatch(arguments.application_id or "") is None
        or not valid_positive_integer(arguments.expected_application_version)
        or UUID.fullmatch(arguments.expected_worker_version_id or "") is None
    ):
        parser.error("exact gateway identity is invalid")
    if arguments.admin_key_fd < 3:
        parser.error("secret descriptors are invalid")
    return arguments


def command_environment(scratch, wrangler_oauth):
    allowed_cloudflare = {"CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_CANDIDATE_SECRET_API_TOKEN"}
    forbidden = re.compile(
        r"^(AWS_|AZURE_|GCP_|S3_|BASETEN_|MODAL_|OPENAI_|R2_|TEACHER_|WANDB_|MILK_CARTON_|DOCKER_|BUILDX_|BUILDKIT_).*"
        r"|^(GOOGLE_APPLICATION_CREDENTIALS|HF_TOKEN|HUGGING_FACE_HUB_TOKEN|NVIDIA_API_KEY|NGC_API_KEY|CODEX_API_KEY|CODEX_AUTH_TOKEN|CODEX_TOKEN|GH_TOKEN|GITHUB_TOKEN|CR_PAT|CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|NPM_TOKEN|PYPI_TOKEN|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|REGISTRY_AUTH_FILE|HTTP_PROXY|HTTPS_PROXY|FTP_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|ftp_proxy|all_proxy|no_proxy)$"
        r"|^CARGO_REGISTRIES_.*_TOKEN$|^MILK_.*(AWS|R2|S3|STORE|TEACHER|PROVIDER|CREDENTIAL|SECRET|TOKEN|ACCESS_KEY)"
    )
    for name in os.environ:
        if name.startswith("CLOUDFLARE_") and name not in allowed_cloudflare:
            raise OperationFailure("unsupported Cloudflare environment")
        if forbidden.search(name):
            raise OperationFailure("ambient credential is forbidden")
    account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID", "")
    token = os.environ.get("CLOUDFLARE_CANDIDATE_SECRET_API_TOKEN", "")
    if (
        ACCOUNT_ID.fullmatch(account_id) is None
        or (wrangler_oauth and "CLOUDFLARE_CANDIDATE_SECRET_API_TOKEN" in os.environ)
        or (not wrangler_oauth and not 32 <= len(token) <= 8192)
    ):
        raise OperationFailure("dedicated Cloudflare credentials are required")
    path = os.environ.get("PATH", "")
    if not path:
        raise OperationFailure("PATH is unavailable")
    environment = {
        "CI": "1", "CLOUDFLARE_ACCOUNT_ID": account_id,
        "PATH": path,
        "TMPDIR": str(scratch), "WRANGLER_LOG_SANITIZE": "true",
        "WRANGLER_SEND_METRICS": "false", "WRANGLER_WRITE_LOGS": "false",
        "XDG_CACHE_HOME": str(scratch),
    }
    if wrangler_oauth:
        home = os.environ.get("HOME", "")
        if not home:
            raise OperationFailure("Wrangler OAuth requires HOME")
        environment["HOME"] = home
    else:
        environment.update({
            "CLOUDFLARE_API_TOKEN": token,
            "HOME": str(scratch),
            "XDG_CONFIG_HOME": str(scratch),
        })
    return account_id, environment


def resolve_commands(path):
    commands = {}
    for name in ("curl", "sleep", "wrangler"):
        resolved = shutil.which(name, path=path)
        if resolved is None:
            raise OperationFailure(f"{name} is unavailable")
        commands[name] = resolved
    return commands


def verify_pinned_wrangler(runner):
    version = runner.wrangler("--version").decode("ascii", "strict").strip()
    if version != WRANGLER_VERSION:
        raise OperationFailure("Wrangler version is not pinned")


def verify_wrangler_oauth(runner, account_id):
    raw = runner.wrangler(
        "whoami", "--json", "--config",
        str(runner.repository / "deploy/cloudflare/wrangler.jsonc"),
    )
    parse_wrangler_oauth_identity(raw, account_id)


def validate_peer(connection):
    if hasattr(connection, "getpeereid"):
        uid, _gid = connection.getpeereid()
    elif hasattr(socket, "SO_PEERCRED"):
        raw = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        _pid, uid, _gid = struct.unpack("3i", raw)
    elif hasattr(socket, "LOCAL_PEERCRED"):
        raw = connection.getsockopt(0, socket.LOCAL_PEERCRED, 256)
        version, uid, groups = struct.unpack_from("@IIh", raw)
        if version != 0 or not 1 <= groups <= 16:
            raise OperationFailure("peer credentials are invalid")
    else:
        raise OperationFailure("peer credentials are unavailable")
    if uid != os.geteuid():
        raise OperationFailure("candidate client owner differs")


def read_request(connection):
    raw = bytearray()
    while True:
        chunk = connection.recv(4096)
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > MAX_REQUEST:
            raise OperationFailure("candidate request is too large")
    request = parse_canonical(bytes(raw), MAX_REQUEST, "candidate socket request")
    schema = request.get("schema_version") if isinstance(request, dict) else None
    if schema in {DELIVERY_SCHEMA, VERIFY_SCHEMA} and len(raw) > MAX_DELIVERY:
        raise OperationFailure("candidate request is too large")
    for index in range(len(raw)):
        raw[index] = 0
    return request


def validate_socket_path(path):
    normalized = Path(os.path.normpath(str(path)))
    if (
        not path.is_absolute()
        or path != normalized
        or path.name in {"", ".", ".."}
        or len(os.fsencode(path)) > 103
    ):
        raise OperationFailure("candidate socket path is invalid")
    parent = path.parent
    try:
        parent_metadata = os.lstat(parent)
    except OSError as error:
        raise OperationFailure("candidate socket parent is unavailable") from error
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        or parent_metadata.st_uid != os.geteuid()
    ):
        raise OperationFailure("candidate socket parent is not owner-only")
    try:
        os.lstat(path)
    except FileNotFoundError:
        pass
    else:
        raise OperationFailure("candidate socket path already exists")
    return parent_metadata.st_dev, parent_metadata.st_ino


def handle_request(request, arguments, runner, account_id, admin_key):
    schema = request.get("schema_version") if isinstance(request, dict) else None
    if schema == DELIVERY_SCHEMA:
        metadata, candidate = parse_delivery(canonical_json(request))
        return install(metadata, candidate, arguments, runner, account_id, admin_key)
    if schema == VERIFY_SCHEMA:
        return verify(parse_verify(request), arguments, runner, account_id, admin_key)
    if schema == REMOVE_SCHEMA:
        return remove(parse_remove(request), arguments, runner, account_id, admin_key)
    if schema == OPERATOR_ROUTE_REMOVE_SCHEMA:
        return remove(
            parse_operator_route_remove(request),
            arguments,
            runner,
            account_id,
            admin_key,
        )
    raise OperationFailure("unsupported candidate request")


def serve_once(path, arguments, runner, account_id, admin_key):
    parent_identity = validate_socket_path(path)
    previous_umask = os.umask(0o177)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    identity = None
    try:
        listener.bind(str(path))
        os.chmod(path, 0o600)
        metadata = os.lstat(path)
        identity = (metadata.st_dev, metadata.st_ino)
        parent_metadata = os.lstat(path.parent)
        if (
            not stat.S_ISSOCK(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_uid != os.geteuid()
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
            or parent_metadata.st_uid != os.geteuid()
            or (parent_metadata.st_dev, parent_metadata.st_ino) != parent_identity
        ):
            raise OperationFailure("candidate endpoint is not owner-only")
        listener.listen(1)
        connection, _address = listener.accept()
        with connection:
            validate_peer(connection)
            accepted_metadata = os.lstat(path)
            if (
                not stat.S_ISSOCK(accepted_metadata.st_mode)
                or (accepted_metadata.st_dev, accepted_metadata.st_ino) != identity
            ):
                raise OperationFailure("candidate endpoint changed before acceptance")
            os.unlink(path)
            identity = None
            listener.close()
            acknowledgement_value = handle_request(
                read_request(connection), arguments, runner, account_id, admin_key
            )
            encoded = canonical_json(acknowledgement_value)
            if len(encoded) > MAX_ACK:
                raise OperationFailure("candidate acknowledgement is too large")
            connection.sendall(encoded)
            connection.shutdown(socket.SHUT_WR)
    finally:
        os.umask(previous_umask)
        listener.close()
        if identity is not None:
            try:
                metadata = os.lstat(path)
                if stat.S_ISSOCK(metadata.st_mode) and (metadata.st_dev, metadata.st_ino) == identity:
                    os.unlink(path)
            except FileNotFoundError:
                pass


def main():
    arguments = parse_arguments()
    admin_key = None
    try:
        validate_socket_path(arguments.socket_path)
        admin_key = read_admin_key(arguments.admin_key_fd)
        with tempfile.TemporaryDirectory(prefix="milk-candidate-credential.") as scratch_name:
            scratch = Path(scratch_name)
            account_id, environment = command_environment(
                scratch, arguments.wrangler_oauth
            )
            runner = Runner(
                resolve_commands(environment["PATH"]), environment,
                Path(__file__).resolve().parent.parent,
            )
            verify_pinned_wrangler(runner)
            if arguments.wrangler_oauth:
                verify_wrangler_oauth(runner, account_id)
            serve_once(arguments.socket_path, arguments, runner, account_id, admin_key)
        return 0
    except (OperationFailure, UnicodeError, ValueError, OSError):
        sys.stderr.write("candidate credential operation failed\n")
        return 1
    finally:
        if admin_key is not None:
            for index in range(len(admin_key)):
                admin_key[index] = 0


if __name__ == "__main__":
    raise SystemExit(main())
