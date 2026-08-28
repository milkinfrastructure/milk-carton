#!/bin/sh
set -eu
umask 077

exec python3 - "$0" "$@" <<'PY'
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
from dataclasses import dataclass
from pathlib import Path


WORKER = "dragontales-gateway"
APPLICATION_NAME = "dragontales-gateway-dragontalesgateway"
SOURCE_REPOSITORY = "https://github.com/milkinfrastructure/milk-gateway"
GHCR_REPOSITORY = "ghcr.io/milkinfrastructure/milk-gateway"
REGISTRY = "registry.cloudflare.com"
HEALTH_URL = "https://api.dragontales.milkinfrastructure.com/healthz"
WRANGLER_VERSION = "4.126.0"
MAIN_SENTINEL = ".milk-private-deploy-script-required"
IMAGE_SENTINEL = "MILK_PRIVATE_GATEWAY_ADMITTED_IMAGE_REQUIRED"
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
POLL_ATTEMPTS = 20
POLL_INTERVAL_SECONDS = 15
MAX_JSON = 1024 * 1024
BOOTSTRAP_SECRET_NAMES = {
    "DRAGONTALES_CONFIG_JSON",
    "DRAGONTALES_CONTAINER_ADMIN_KEY",
    "DRAGONTALES_OPENAI_API_KEY",
    "DRAGONTALES_ROUTE_SECRET_HEX",
    "MILK_CAPTURE_STORE_ACCESS_KEY_ID",
    "MILK_CAPTURE_STORE_SECRET_ACCESS_KEY",
    "MILK_ROUTE_STORE_ACCESS_KEY_ID",
    "MILK_ROUTE_STORE_SECRET_ACCESS_KEY",
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

    def finalize(self, outcome, stage, started_at):
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
        or info.get("jobs") is not False
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


def validate_bootstrap_secrets(path, repository):
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
        or set(secrets_value) != BOOTSTRAP_SECRET_NAMES
        or any(
            not isinstance(secret, str) or not 1 <= len(secret.encode("utf-8")) <= 262144
            for secret in secrets_value.values()
        )
        or raw != canonical_json(value)
    ):
        raise DeployFailure("bootstrap secrets file is invalid")
    return canonical_json(secrets_value)


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
        config.get("name") != WORKER
        or config.get("main") != MAIN_SENTINEL
        or config.get("observability") != {"enabled": True}
        or not isinstance(containers, list)
        or len(containers) != 1
        or containers[0] != {
            "class_name": "DragontalesGateway",
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


def make_deploy_config(base, path, image, entrypoint):
    config = copy.deepcopy(base)
    config["main"] = str(entrypoint)
    config["containers"][0]["image"] = image
    raw = canonical_json(config)
    if b"Dockerfile" in raw or b"image_build_context" in raw or image.encode() not in raw:
        raise ContractFailure("temporary deploy config is invalid")
    write_private(path, raw)


def main():
    bootstrap = len(sys.argv) == 7 and sys.argv[2] == "--bootstrap"
    if not bootstrap and len(sys.argv) != 6:
        raise DeployFailure(
            "usage: deploy-private-gateway.sh RELEASE_EVIDENCE_DIR APPLICATION_ID NEW_DEPLOY_EVIDENCE_DIR GATEWAY_CREDENTIAL_FILE\n"
            "       deploy-private-gateway.sh --bootstrap RELEASE_EVIDENCE_DIR NEW_DEPLOY_EVIDENCE_DIR GATEWAY_CREDENTIAL_FILE BOOTSTRAP_SECRETS_FILE"
        )
    script = Path(sys.argv[1]).resolve(strict=True)
    repository = script.parent.parent.resolve(strict=True)
    if bootstrap:
        release_directory = Path(sys.argv[3]).resolve(strict=True)
        application_id = None
        requested_evidence = Path(sys.argv[4])
        credential_file = Path(sys.argv[5])
        bootstrap_secret_input = validate_bootstrap_secrets(Path(sys.argv[6]), repository)
    else:
        release_directory = Path(sys.argv[2]).resolve(strict=True)
        application_id = sys.argv[3]
        requested_evidence = Path(sys.argv[4])
        credential_file = Path(sys.argv[5])
        bootstrap_secret_input = None
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

    allowed_cloudflare = {"CLOUDFLARE_ACCOUNT_ID", "CLOUDFLARE_API_TOKEN"}
    forbidden = re.compile(
        r"^(AWS_|AZURE_|GCP_|S3_|BASETEN_|MODAL_|OPENAI_|R2_|TEACHER_|WANDB_|DRAGONTALES_|DOCKER_|BUILDX_|BUILDKIT_).*"
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
    if ACCOUNT_ID.fullmatch(account_id) is None or not 1 <= len(cloudflare_token) <= 8192:
        raise DeployFailure("exact Cloudflare account credentials are required")
    os.environ.pop("CLOUDFLARE_ACCOUNT_ID", None)
    os.environ.pop("CLOUDFLARE_API_TOKEN", None)
    base_environment = os.environ.copy()
    base_environment["CI"] = "1"
    base_environment["WRANGLER_SEND_METRICS"] = "false"
    cloudflare_environment = base_environment.copy()
    cloudflare_environment["CLOUDFLARE_ACCOUNT_ID"] = account_id
    cloudflare_environment["CLOUDFLARE_API_TOKEN"] = cloudflare_token

    commands = {}
    for command in ("curl", "docker", "gh", "git", "node", "sleep", "wrangler"):
        resolved = shutil.which(command, path=base_environment.get("PATH"))
        if resolved is None:
            raise DeployFailure(f"{command} is unavailable")
        commands[command] = resolved

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
    scratch = Path(tempfile.mkdtemp(prefix="milk-gateway-deploy."))

    def interrupt(signum, _frame):
        raise Interrupted(f"signal {signum}")

    for signal_number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(signal_number, interrupt)

    base_config_path = repository / "deploy/cloudflare/wrangler.jsonc"

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
                "--output", str(body_path), "--write-out", "%{http_code}", HEALTH_URL,
            ],
            timeout=20,
            check=False,
        )
        http_status = None
        healthy = False
        try:
            status_text = result.stdout.decode("ascii", errors="strict")
            if re.fullmatch(r"[0-9]{3}", status_text):
                http_status = int(status_text)
            if result.returncode == 0 and http_status == 200 and body_path.is_file():
                body = read_regular(body_path, "health response", 65536)
                value = parse_json(body, "health response", 65536)
                healthy = isinstance(value, dict) and value.get("status") == "ok"
        except (ContractFailure, UnicodeError):
            healthy = False
        finally:
            try:
                body_path.unlink()
            except FileNotFoundError:
                pass
        return http_status, healthy

    def poll(phase, expected_image, expected_worker, worker_must_differ):
        last = {
            "http_status": None,
            "health_ready": False,
            "worker_ready": False,
            "image_ready": False,
            "instances_ready": False,
            "active_instances": 0,
            "application_version": None,
        }
        for attempt in range(1, POLL_ATTEMPTS + 1):
            last["http_status"], last["health_ready"] = probe_health(phase, attempt)
            try:
                status = wrangler(
                    f"{phase}-worker-status-{attempt:02d}",
                    "deployments", "status", "--name", WORKER, "--json",
                )
                worker_version = parse_active_worker(status.stdout)
                last["worker_ready"] = (
                    worker_version is not None
                    and ((worker_version != expected_worker) if worker_must_differ else (worker_version == expected_worker))
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
                last["active_instances"] = len(active)
                last["instances_ready"] = (
                    application_version is not None
                    and len(active) == 1
                    and active[0].get("state") == "running"
                    and active[0].get("version") == application_version
                )
            except (CommandFailure, ContractFailure):
                last["active_instances"] = 0
                last["instances_ready"] = False
            if all(last[key] for key in ("health_ready", "worker_ready", "image_ready", "instances_ready")):
                evidence.write(f"smoke-{phase}.json", {
                    "schema_version": "milk.content-free-gateway-smoke.v1",
                    "operation_id": operation_id,
                    "phase": phase,
                    "attempts": attempt,
                    "http_status": last["http_status"],
                    "health_contract": "status-ok",
                    "content_retained": False,
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
            "health_contract": "status-ok",
            "content_retained": False,
            "active_instances": last["active_instances"],
            "application_version": last["application_version"],
            "succeeded": False,
        })
        raise DeployFailure(f"{phase} acceptance did not converge")

    try:
        stage = "release-evidence"
        admitted = validate_release(release_directory)
        base_config = validate_base_config(base_config_path)
        if not (repository / "deploy/cloudflare/worker.js").is_file():
            raise ContractFailure("Worker entrypoint is missing")

        stage = "source-authority"
        top = runner.run("git-top-level", [commands["git"], "rev-parse", "--show-toplevel"]).stdout.decode().strip()
        if Path(top).resolve() != repository:
            raise ContractFailure("deploy script is not running from the Milk gateway checkout")
        commit = runner.run(
            "git-head", [commands["git"], "rev-parse", "--verify", "HEAD^{commit}"],
        ).stdout.decode().strip()
        if SHA1.fullmatch(commit) is None or commit != admitted["source_commit"]:
            raise ContractFailure("release commit is not the deploy checkout HEAD")
        dirty = runner.run(
            "git-clean", [commands["git"], "status", "--porcelain=v1", "--untracked-files=all"],
        ).stdout
        if dirty:
            raise ContractFailure("deploy checkout is not clean")
        origin = runner.run(
            "git-origin", [commands["git"], "remote", "get-url", "origin"],
        ).stdout.decode().strip()
        if origin not in {
            "git@github.com:milkinfrastructure/milk-gateway.git",
            "https://github.com/milkinfrastructure/milk-gateway.git",
        }:
            raise ContractFailure("origin is not milkinfrastructure/milk-gateway")
        remote_head = runner.run(
            "git-published-head", [commands["git"], "ls-remote", "--exit-code", "origin", "HEAD"],
            timeout=60,
        ).stdout.decode().split()
        if remote_head != [commit, "HEAD"]:
            raise ContractFailure("local HEAD is not the published origin HEAD")

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
        (scratch / "docker-config").mkdir(mode=0o700)
        runner.run(
            "docker-buildx-version",
            [commands["docker"], "--config", str(scratch / "docker-config"), "--host", docker_endpoint, "buildx", "version"],
        )

        image_tag = f"sha256-{admitted['child_sha256']}-op-{operation_id}"
        remote_image = f"{REGISTRY}/{account_id}/milk-gateway:{image_tag}"
        evidence.write("intent.json", {
            "schema_version": "milk.private-gateway-deploy-intent.v1",
            "operation_id": operation_id,
            "worker": WORKER,
            "application_name": APPLICATION_NAME,
            "application_id": application_id,
            "bootstrap": bootstrap,
            "account_id": account_id,
            "source_repository": SOURCE_REPOSITORY,
            "source_commit": commit,
            "release_sha256": admitted["release_sha256"],
            "build_ops_log_reference_sha256": admitted["build_ops_log_reference_sha256"],
            "admission_sha256": admitted["admission_sha256"],
            "admitted_image_reference": admitted["image_reference"],
            "admitted_child_reference": admitted["child_reference"],
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
            if image_tag in images.get("milk-gateway", set()):
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
            previous_repository, previous_tag = split_cloudflare_image(previous_image, account_id)
            images = parse_images(wrangler(
                "preflight-image-list", "containers", "images", "list", "--json",
            ).stdout)
            if previous_tag not in images.get(previous_repository, set()):
                raise ContractFailure("previous rollback image is not retained")
            if image_tag in images.get("milk-gateway", set()):
                raise ContractFailure("target Cloudflare image tag already exists")
            previous = {
                "worker_version_id": previous_worker,
                "image": previous_image,
                "application_version": previous_app_version,
            }
            evidence.write("previous.json", {
                "schema_version": "milk.private-gateway-previous-deployment.v1",
                "operation_id": operation_id,
                "worker_version_id": previous_worker,
                "application_id": application_id,
                "application_version": previous_app_version,
                "image": previous_image,
                "image_retained": True,
            })

        stage = "ghcr-pull"
        github_token = runner.run(
            "github-registry-credential", [commands["gh"], "auth", "token", "--hostname", "github.com"],
            sensitive_output=True,
        ).stdout.strip()
        if not 1 <= len(github_token) <= 8192:
            raise ContractFailure("GitHub registry credential is invalid")
        docker(
            "github-registry-login", "login", "ghcr.io", "--username", "ShantanuJoshi", "--password-stdin",
            input_bytes=github_token + b"\n",
        )
        del github_token
        docker(
            "pull-admitted-amd64-child", "pull", "--platform", "linux/amd64", admitted["child_reference"],
            timeout=900,
        )
        local_image = f"milk-gateway:{image_tag}"
        docker("tag-admitted-child", "tag", admitted["child_reference"], local_image)

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
        if image_tag not in images_after_push.get("milk-gateway", set()):
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
            repository / "deploy/cloudflare/worker.js",
        )
        rechecked_head = runner.run(
            "git-predeploy-head",
            [commands["git"], "rev-parse", "--verify", "HEAD^{commit}"],
        ).stdout.decode().strip()
        rechecked_status = runner.run(
            "git-predeploy-clean",
            [commands["git"], "status", "--porcelain=v1", "--untracked-files=all"],
        ).stdout
        rechecked_remote = runner.run(
            "git-predeploy-published-head",
            [commands["git"], "ls-remote", "--exit-code", "origin", "HEAD"],
            timeout=60,
        ).stdout.decode().split()
        if rechecked_head != commit or rechecked_status or rechecked_remote != [commit, "HEAD"]:
            raise ContractFailure("source authority changed before deployment")
        deploy_started = True
        wrangler(
            "deploy-worker-and-container", "deploy", "--strict", "--containers-rollout", "immediate",
            "--message", f"milk private gateway {operation_id}", timeout=900, config=temporary_config,
        )

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

            stage = "bootstrap-secrets"
            wrangler(
                "bootstrap-secret-bulk", "secret", "bulk", "--name", WORKER,
                timeout=300, sensitive=True, input_bytes=bootstrap_secret_input,
            )
            bootstrap_secret_input = None
            installed_secrets = parse_secret_names(wrangler(
                "bootstrap-secret-list", "secret", "list", "--name", WORKER,
                "--format", "json", sensitive=True,
            ).stdout)
            if installed_secrets != BOOTSTRAP_SECRET_NAMES:
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
        )
        stage = "official-sdk-smoke"
        sdk_result = runner.run(
            "deploy-official-openai-sdk-smoke",
            [
                commands["node"],
                str(repository / "tools/openai-production-smoke.mjs"),
                "https://api.dragontales.milkinfrastructure.com/v1",
                str(credential_file),
            ],
            timeout=30,
        )
        sdk_smoke = parse_json(sdk_result.stdout, "official OpenAI SDK smoke", 65536)
        require_keys(sdk_smoke, {
            "authenticated", "choice_count", "content_retained", "endpoint_sha256",
            "finish_reason", "http_status", "request_sha256", "response_bytes",
            "response_sha256", "schema_version", "sdk", "sdk_version", "succeeded",
        }, "official OpenAI SDK smoke")
        if (
            sdk_result.stdout != canonical_json(sdk_smoke)
            or sdk_smoke["schema_version"] != "milk.official-openai-sdk-smoke.v1"
            or sdk_smoke["sdk"] != "openai-node"
            or sdk_smoke["sdk_version"] != "6.33.0"
            or sdk_smoke["authenticated"] is not True
            or sdk_smoke["succeeded"] is not True
            or sdk_smoke["content_retained"] is not False
            or sdk_smoke["http_status"] != 200
            or sdk_smoke["choice_count"] != 1
            or not isinstance(sdk_smoke["response_bytes"], int)
            or isinstance(sdk_smoke["response_bytes"], bool)
            or not 1 <= sdk_smoke["response_bytes"] <= 65536
            or any(SHA256.fullmatch(sdk_smoke[key] or "") is None for key in (
                "endpoint_sha256", "request_sha256", "response_sha256"
            ))
            or not isinstance(sdk_smoke["finish_reason"], (str, type(None)))
        ):
            raise ContractFailure("official OpenAI SDK smoke receipt is invalid")
        evidence.write("official-openai-sdk-smoke.json", sdk_smoke)
        evidence.write("current.json", {
            "schema_version": "milk.private-gateway-current-deployment.v1",
            "operation_id": operation_id,
            "worker_version_id": current_worker,
            "application_name": APPLICATION_NAME,
            "application_id": application_id,
            "application_version": current_app_version,
            "image": current_image,
            "rollout": "immediate",
            "accepted": True,
        })
        temporary_config.unlink()
        temporary_config = None
        shutil.rmtree(scratch)
        scratch = None
        evidence.finalize("succeeded", None, started_at)
        cloudflare_environment.pop("CLOUDFLARE_API_TOKEN", None)
        print(f"private gateway deployment verified at {evidence_directory}")
        return 0
    except BaseException as error:
        for signal_number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            signal.signal(signal_number, signal.SIG_IGN)
        failure_stage = stage
        outcome = "predeploy_failed"
        rollback_observation = None
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
            rollback_command_succeeded = False
            rollback_accepted = False
            try:
                stage = "automatic-rollback"
                wrangler(
                    "rollback-worker", "rollback", previous["worker_version_id"], "--name", WORKER,
                    "--message", f"milk automatic rollback {operation_id}", "--yes", timeout=300,
                )
                rollback_command_succeeded = True
                _, _, rollback_app_version = poll(
                    "rollback", previous["image"], previous["worker_version_id"], False,
                )
                rollback_accepted = True
                outcome = "deployment_failed_rolled_back"
            except BaseException:
                rollback_app_version = None
            rollback_observation = {
                "schema_version": "milk.private-gateway-rollback.v1",
                "operation_id": operation_id,
                "previous_worker_version_id": previous["worker_version_id"],
                "previous_image": previous["image"],
                "application_id": application_id,
                "application_version": rollback_app_version,
                "command_succeeded": rollback_command_succeeded,
                "accepted": rollback_accepted,
            }
        try:
            if rollback_observation is not None:
                evidence.write("rollback.json", rollback_observation)
            if temporary_config is not None:
                temporary_config.unlink(missing_ok=True)
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
