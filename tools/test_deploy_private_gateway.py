import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools/deploy-private-gateway.sh"
ACCOUNT = "a" * 32
APPLICATION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
APPLICATION_NAME = "milk-carton-milkcarton"
API_BASE_URL = "https://carton.example/v1"
COMMIT = "1" * 40
PREVIOUS_WORKER = "11111111-1111-1111-1111-111111111111"
CURRENT_WORKER = "22222222-2222-2222-2222-222222222222"
PREVIOUS_IMAGE = f"registry.cloudflare.com/{ACCOUNT}/legacy-gateway:previous"
BUILDKIT_IMAGE = "moby/buildkit@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e"
DOCKERFILE_FRONTEND = "docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e"
SMOKE_API_KEY = "milk_live_aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee_private-test-secret"
SMOKE_COHORT = "deployment-smoke-v1"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


SMOKE_GATEWAY_CONFIG = json.loads(
    (ROOT / "deploy/milk-carton-config.example.json").read_text()
)
SMOKE_GATEWAY_CONFIG["traffic_keys"] = [{
    "key_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    "api_key_sha256": sha256(SMOKE_API_KEY.encode()),
    "scope_id": "00000000-0000-4000-8000-000000000010",
    "capture_allowed": False,
}]
PREVIOUS_GATEWAY_CONFIG = json.loads(json.dumps(SMOKE_GATEWAY_CONFIG))
PREVIOUS_GATEWAY_CONFIG["traffic_keys"][0]["scope_id"] = (
    "00000000-0000-4000-8000-000000000011"
)
BOOTSTRAP_SECRETS = {
    "MILK_CARTON_CONFIG_JSON": canonical(SMOKE_GATEWAY_CONFIG).decode(),
    "MILK_CARTON_CONTAINER_ADMIN_KEY": "bootstrap-container-admin-private",
    "MILK_CARTON_OPENAI_API_KEY": "bootstrap-openai-private",
    "MILK_CARTON_ROUTE_SECRET_HEX": "0" * 64,
    "MILK_CAPTURE_SAMPLING_KEY_HEX": "1" * 64,
    "MILK_CAPTURE_SAMPLING_KEY_VERSION": "pilot-v1",
    "MILK_CAPTURE_STORE_ACCESS_KEY_ID": "bootstrap-capture-access-private",
    "MILK_CAPTURE_STORE_SECRET_ACCESS_KEY": "bootstrap-capture-secret-private",
    "MILK_ROUTE_STORE_ACCESS_KEY_ID": "bootstrap-route-access-private",
    "MILK_ROUTE_STORE_SECRET_ACCESS_KEY": "bootstrap-route-secret-private",
}


def load_deploy_contract():
    source = SCRIPT.read_text(encoding="utf-8")
    payload = source.split("<<'PY'\n", 1)[1].rsplit(
        "\ntry:\n    raise SystemExit(main())", 1,
    )[0]
    name = "_milk_deploy_private_gateway_contract"
    module = types.ModuleType(name)
    sys.modules[name] = module
    try:
        exec(compile(payload, str(SCRIPT), "exec"), module.__dict__)
    finally:
        sys.modules.pop(name, None)
    return module


DEPLOY_CONTRACT = load_deploy_contract()


def make_release(directory):
    config_raw = canonical({"architecture": "amd64", "os": "linux"})
    config_sha = sha256(config_raw)
    layer_digests = ["sha256:" + sha256(b"layer-one"), "sha256:" + sha256(b"layer-two")]
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:" + config_sha,
            "size": len(config_raw),
        },
        "layers": [
            {
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": value,
                "size": index + 10,
            }
            for index, value in enumerate(layer_digests)
        ],
    }
    manifest_raw = canonical(manifest)
    manifest_sha = sha256(manifest_raw)
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": "sha256:" + manifest_sha,
                "size": len(manifest_raw),
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }
    index_raw = canonical(index)
    index_sha = sha256(index_raw)
    image_reference = f"ghcr.io/milkinfrastructure/milk-carton@sha256:{index_sha}"
    admission = {
        "schema_version": "milk.private-image-admission.v1",
        "artifact": "gateway",
        "repository": "ghcr.io/milkinfrastructure/milk-carton",
        "image_reference": image_reference,
        "source_repository": "https://github.com/milkinfrastructure/milk-carton",
        "source_commit": COMMIT,
        "source_context_method": "git-archive-tar-v1",
        "source_context_sha256": "2" * 64,
        "gateway_image_reference": None,
        "index_sha256": index_sha,
        "amd64_manifest_sha256": manifest_sha,
        "config_sha256": config_sha,
        "attestation_manifest_sha256": "3" * 64,
        "attestations": [
            {"layer_sha256": "4" * 64, "predicate_type": "https://slsa.dev/provenance/v1"},
            {"layer_sha256": "5" * 64, "predicate_type": "https://spdx.dev/Document"},
        ],
        "platform": "linux/amd64",
        "visibility": "private",
        "builder": {
            "authority": "local-socket",
            "driver": "docker-container",
            "endpoint_kind": "local-socket",
            "buildkit_image_reference": BUILDKIT_IMAGE,
            "buildkit_version": "v0.23.2",
            "dockerfile_frontend_reference": DOCKERFILE_FRONTEND,
            "provenance_mode": "max",
            "provenance_version": "v1",
            "sbom": True,
        },
    }
    admission_raw = canonical(admission)
    build_log_raw = canonical({
        "schema_version": "milk.content-free-build-log.v1",
        "artifact": "gateway",
        "exit_code": 0,
        "content_retained": False,
    })
    ops_log_raw = canonical({
        "schema_version": "milk.private-ops-log-reference.v1",
        "authority": "private-release-evidence",
        "reference": "build-log.json",
        "receipt_sha256": sha256(build_log_raw),
        "immutable": True,
        "content_retained": False,
    })
    release = {
        "schema_version": "milk.private-gateway-release.v1",
        "source_commit": COMMIT,
        "source_date_epoch": 1700000000,
        "source_repository": "https://github.com/milkinfrastructure/milk-carton",
        "buildkit_image_reference": BUILDKIT_IMAGE,
        "dockerfile_frontend_reference": DOCKERFILE_FRONTEND,
        "build_authority": "local-socket",
        "platform": "linux/amd64",
        "ops_log_reference_sha256": sha256(ops_log_raw),
        "image": {
            "admission_sha256": sha256(admission_raw),
            "artifact": "gateway",
            "image_reference": image_reference,
        },
        "started_at": "2026-08-27T00:00:00Z",
        "completed_at": "2026-08-27T00:01:00Z",
    }
    for name, raw in {
        "release.json": canonical(release),
        "admission.json": admission_raw,
        "index.json": index_raw,
        "amd64-manifest.json": manifest_raw,
        "config.json": config_raw,
        "build-log.json": build_log_raw,
        "ops-log-reference.json": ops_log_raw,
    }.items():
        (directory / name).write_bytes(raw)
    return manifest, manifest_sha


FAKE_COMMAND = r'''#!/usr/bin/env python3
import base64
import copy
import hashlib
import json
import os
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
state_path = Path(os.environ["FAKE_STATE"])
state = json.loads(state_path.read_text())
state.setdefault("commands", []).append({"command": name, "arguments": args})

def save():
    state_path.write_text(json.dumps(state, sort_keys=True))

def done(code=0):
    save()
    raise SystemExit(code)

def without_global(values):
    result = list(values)
    while "--config" in result:
        index = result.index("--config")
        del result[index:index + 2]
    while "--host" in result:
        index = result.index("--host")
        del result[index:index + 2]
    return result

if name == "git":
    if args[:2] == ["rev-parse", "--show-toplevel"]:
        print(os.environ["FAKE_REPO"])
    elif args[:2] == ["rev-parse", "--verify"]:
        print(state["commit"])
    elif args[:2] == ["status", "--porcelain=v1"]:
        if state["mode"] == "dirty" or (
            state["mode"] == "rollback_source_dirty"
            and state["active_image"] != state["previous_image"]
        ):
            print(" M deploy/cloudflare/wrangler.jsonc")
    elif args[:3] == ["remote", "get-url", "origin"]:
        print("https://github.com/milkinfrastructure/milk-carton.git")
    elif args[:3] == ["ls-remote", "--exit-code", "origin"]:
        print(state["commit"] + "\trefs/heads/main")
    elif args[:4] == ["fetch", "--quiet", "--no-tags", "origin"]:
        pass
    elif args[:2] == ["merge-base", "--is-ancestor"]:
        if state["mode"] == "unpublished":
            done(1)
    else:
        done(2)
    done()

if name == "node":
    if state["mode"] in {
        "sdk_fail", "resource_restore_fail", "rollback_source_dirty",
        "rollback_input_tamper", "bootstrap_sdk_fail",
        "bootstrap_cleanup_fail",
    }:
        done(70)
    credential = json.loads(Path(args[-1]).read_text())
    proof_contract = {
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
    print(json.dumps({
        "authenticated": True,
        "baseline_request_count": 1,
        "candidate_request_count": 0,
        "choice_count": 1,
        "content_retained": False,
        "endpoint_sha256": "6" * 64,
        "finish_reason": "stop",
        "http_status": 200,
        "max_completion_tokens": 256,
        "model": "zai-org/GLM-5.3-Flash",
        "proof_contract_sha256": hashlib.sha256(json.dumps(
            proof_contract, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest(),
        "proof_step": "deployment_baseline",
        "request_sha256": "7" * 64,
        "response_bytes": 123,
        "response_sha256": "8" * 64,
        "schema_version": "milk.official-openai-sdk-smoke.v2",
        "sdk": "openai-node",
        "sdk_request_count": 1,
        "sdk_version": "6.33.0",
        "succeeded": True,
        "traffic_cohort_sha256": hashlib.sha256(credential["cohort_id"].encode()).hexdigest(),
        "traffic_key_sha256": hashlib.sha256(credential["api_key"].encode()).hexdigest(),
    }, sort_keys=True, separators=(",", ":")))
    done()

if name == "sleep":
    done()

if name == "curl":
    output = Path(args[args.index("--output") + 1])
    failed = (
        state["mode"] in {"health_fail", "rollback_fail"}
        and state["active_image"] != state["previous_image"]
    )
    output.write_text(json.dumps({
        "config_sha256": state["active_config_sha256"],
        "provider": "uncontrolled",
        "status": "degraded" if failed else "ok",
    }, sort_keys=True, separators=(",", ":")))
    print("503" if failed else "200", end="")
    done()

if name == "docker":
    if "--config" in args:
        config = Path(args[args.index("--config") + 1])
        plugin = config / "cli-plugins/docker-buildx"
        expected = Path(os.environ["HOME"]) / ".docker/cli-plugins/docker-buildx"
        if not plugin.is_symlink() or plugin.resolve() != expected.resolve():
            done(94)
    values = without_global(args)
    expected_child = (
        "ghcr.io/milkinfrastructure/milk-carton@sha256:" + state["child_sha"]
    )
    if values == ["pull", "--platform", "linux/amd64", expected_child]:
        expected_auth = base64.b64encode(b"ShantanuJoshi:github-test-token").decode()
        if json.loads((config / "config.json").read_text()) != {
            "auths": {"ghcr.io": {"auth": expected_auth}}
        } or (config / "config.json").stat().st_mode & 0o777 != 0o600:
            done(95)
        state["ghcr_auth_verified"] = True
    if values == ["context", "show"]:
        print("default")
    elif values[:2] == ["context", "inspect"]:
        print("unix:///fake/docker.sock")
    elif values[:2] == ["buildx", "version"]:
        print("github.com/docker/buildx v0.23.0")
    elif values and values[0] == "login":
        sys.stdin.buffer.read()
    elif values[:2] == ["buildx", "imagetools"]:
        manifest = copy.deepcopy(state["remote_manifest"])
        if state["mode"] == "remote_mismatch":
            manifest["config"]["digest"] = "sha256:" + "0" * 64
        print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    elif values and values[0] in {"pull", "tag", "push"}:
        pass
    else:
        done(2)
    done()

if name == "wrangler":
    if args == ["--version"]:
        print("4.126.0")
        done()
    values = without_global(args)
    if values[:2] == ["whoami", "--json"]:
        if Path(os.environ["FAKE_EVIDENCE"]).exists() or os.environ.get("CLOUDFLARE_API_TOKEN"):
            done(96)
        print(json.dumps({
            "loggedIn": True,
            "accounts": [{"id": state.get("whoami_account", state["account"])}],
        }))
    elif values[:2] == ["secret", "list"]:
        worker_missing = state.get("bootstrap", False) and state["mode"] != "bootstrap_preexisting_worker" and (
            state["deployment"] == "initial" or state.get("worker_deleted", False)
        )
        if worker_missing:
            print('Worker "milk-carton" not found.', file=sys.stderr)
            done(1)
        names = state.get("installed_secret_names", [])
        print(json.dumps([{"name": value, "type": "secret_text"} for value in names]))
    elif values[:2] == ["secret", "bulk"]:
        done(2)
    elif values[:2] == ["deployments", "status"]:
        print(json.dumps({"id": "deployment", "source": "api", "strategy": "percentage", "versions": [{"percentage": 100, "version_id": state["active_worker"]}]}))
    elif values[:2] == ["containers", "list"]:
        present = (
            not state.get("bootstrap", False)
            or state["deployment"] != "initial"
            or state["mode"] == "bootstrap_preexisting_app"
        ) and not state.get("application_deleted", False)
        values = []
        if present:
            values.append({
                "id": state["application"], "name": state["application_name"],
                "state": "active", "instances": 1, "image": state.get("target_image", state["previous_image"]),
                "version": 8, "updated_at": "2026-08-27T00:00:00Z",
                "created_at": "2026-08-27T00:00:00Z",
            })
        print(json.dumps(values))
    elif values[:2] == ["containers", "info"]:
        state["container_info_calls"] = state.get("container_info_calls", 0) + 1
        if state["mode"] == "anchor_drift" and state["container_info_calls"] == 2:
            state["active_image"] = (
                f"registry.cloudflare.com/{state['account']}/legacy-gateway:drifted"
            )
            state["application_version"] += 1
        print(json.dumps({
            "id": state["application"], "account_id": state["account"], "name": state["application_name"],
            "version": state["application_version"],
            "configuration": {"image": state["active_image"]},
        }))
    elif values[:3] == ["containers", "images", "list"]:
        milk_tags = list(state.get("milk_tags", []))
        if state["mode"] == "collision" and not milk_tags:
            intent = json.loads((Path(os.environ["FAKE_EVIDENCE"]) / "intent.json").read_text())
            milk_tags.append(intent["target_image"].rsplit(":", 1)[1])
        images = [{"name": "legacy-gateway", "tags": ["previous"]}]
        if milk_tags:
            images.append({"name": "milk-carton", "tags": milk_tags})
        print(json.dumps(images))
    elif values[:2] == ["containers", "push"]:
        tag = values[2].rsplit(":", 1)[1]
        state.setdefault("milk_tags", []).append(tag)
    elif values[:3] == ["containers", "registries", "credentials"]:
        print(json.dumps({
            "account_id": state["account"], "registry_host": "registry.cloudflare.com",
            "username": "temporary-user", "password": "temporary-password",
        }))
    elif values and values[0] == "deploy":
        config_path = Path(args[args.index("--config") + 1])
        config = json.loads(config_path.read_text())
        state["deploy_config"] = config
        state["target_image"] = config["containers"][0]["image"]
        if "--secrets-file" not in values:
            done(2)
        secrets_path = Path(values[values.index("--secrets-file") + 1])
        if secrets_path.stat().st_mode & 0o777 not in {0o400, 0o600}:
            done(2)
        supplied = json.loads(secrets_path.read_text())
        state["deployment_secrets_path"] = str(secrets_path)
        state["deployment_secrets_mode"] = secrets_path.stat().st_mode & 0o777
        if state.get("bootstrap", False):
            required = {
                "MILK_CARTON_CONFIG_JSON", "MILK_CARTON_CONTAINER_ADMIN_KEY",
                "MILK_CARTON_OPENAI_API_KEY", "MILK_CARTON_ROUTE_SECRET_HEX",
                "MILK_CAPTURE_SAMPLING_KEY_HEX", "MILK_CAPTURE_SAMPLING_KEY_VERSION",
                "MILK_CAPTURE_STORE_ACCESS_KEY_ID", "MILK_CAPTURE_STORE_SECRET_ACCESS_KEY",
                "MILK_ROUTE_STORE_ACCESS_KEY_ID", "MILK_ROUTE_STORE_SECRET_ACCESS_KEY",
            }
            optional = {
                "MILK_CAPTURE_STORE_SESSION_TOKEN", "MILK_ROUTE_STORE_SESSION_TOKEN",
            }
            if not required.issubset(supplied) or not set(supplied).issubset(required | optional):
                done(2)
            state["installed_secret_names"] = sorted(supplied)
        else:
            if set(supplied) != {"MILK_CARTON_CONFIG_JSON"}:
                done(2)
        state["deployed_secret_names"] = sorted(supplied)
        supplied_config_sha256 = hashlib.sha256(
            supplied["MILK_CARTON_CONFIG_JSON"].encode()
        ).hexdigest()
        restoring = state["target_image"] == state["previous_image"]
        state.setdefault("deployments", []).append({
            "config_sha256": supplied_config_sha256,
            "image": state["target_image"],
            "restoring": restoring,
        })
        restore_failed = state["mode"] == "resource_restore_fail" and restoring
        if restore_failed:
            done(1)
        state["active_worker"] = state["current_worker"]
        state["active_image"] = state["target_image"]
        state["active_config_sha256"] = supplied_config_sha256
        state["application_version"] += 1
        if state["mode"] == "rollback_input_tamper" and not restoring:
            rollback_secrets = config_path.parent / "rollback-secrets.json"
            rollback_secrets.chmod(0o600)
            rollback_secrets.write_text("{}\n")
            rollback_secrets.chmod(0o400)
        if state["mode"] == "config_mismatch" and not restoring:
            state["active_config_sha256"] = "0" * 64
        target_failed = (
            state["mode"] in {"deploy_fail", "bootstrap_deploy_fail"}
            and not restoring
        )
        state["deployment"] = "partial" if target_failed else "deployed"
        if target_failed:
            done(1)
    elif values and values[0] == "rollback":
        if state["mode"] == "rollback_fail":
            done(1)
        state["active_worker"] = state["previous_worker"]
        state["deployment"] = "rollback"
    elif values[:2] == ["containers", "instances"]:
        print(json.dumps([{
            "id": "33333333-3333-3333-3333-333333333333", "state": "running",
            "location": "sfo06", "version": state["application_version"],
            "created": "2026-08-27T00:00:00Z",
        }]))
    elif values[:2] == ["containers", "delete"]:
        if state["mode"] == "bootstrap_cleanup_fail":
            done(1)
        state["application_deleted"] = True
    elif values and values[0] == "delete":
        state["worker_deleted"] = True
    else:
        done(2)
    done()

done(2)
'''


class Fixture:
    def __init__(self, mode="success", bootstrap=False):
        self.temporary = tempfile.TemporaryDirectory(prefix="milk-deploy-test.")
        self.root = Path(self.temporary.name)
        self.release = self.root / "release"
        self.release.mkdir()
        remote_manifest, child_sha = make_release(self.release)
        self.evidence = self.root / "deploy-evidence"
        self.state_path = self.root / "state.json"
        self.state_path.write_text(json.dumps({
            "mode": mode,
            "commit": "2" * 40 if mode == "published_ancestor" else COMMIT,
            "account": ACCOUNT,
            "application": APPLICATION,
            "application_name": APPLICATION_NAME,
            "bootstrap": bootstrap,
            "previous_worker": PREVIOUS_WORKER,
            "current_worker": CURRENT_WORKER,
            "previous_image": PREVIOUS_IMAGE,
            "previous_config_sha256": sha256(canonical(PREVIOUS_GATEWAY_CONFIG)),
            "active_config_sha256": sha256(canonical(PREVIOUS_GATEWAY_CONFIG)),
            "active_worker": PREVIOUS_WORKER,
            "active_image": PREVIOUS_IMAGE,
            "application_version": 7,
            "deployment": "initial",
            "remote_manifest": remote_manifest,
            "child_sha": child_sha,
            "commands": [],
            "milk_tags": [],
            "installed_secret_names": [],
        }))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.home = self.root / "home"
        self.buildx_plugin = self.home / ".docker/cli-plugins/docker-buildx"
        self.buildx_plugin.parent.mkdir(parents=True)
        self.buildx_plugin.write_text("#!/bin/sh\nexit 0\n")
        self.buildx_plugin.chmod(0o700)
        command = self.bin / "command"
        command.write_text(textwrap.dedent(FAKE_COMMAND))
        command.chmod(0o755)
        for name in ("curl", "docker", "git", "node", "sleep", "wrangler"):
            os.link(command, self.bin / name)
        self.registry_token = self.root / "registry-token"
        self.registry_token.write_text("github-test-token\n", encoding="ascii")
        self.registry_token.chmod(0o600)
        self.credential = self.root / "gateway-credential.json"
        self.credential.write_bytes(canonical({
            "api_key": SMOKE_API_KEY,
            "cohort_id": SMOKE_COHORT,
            "model": "zai-org/GLM-5.3-Flash",
        }))
        self.credential.chmod(0o600)
        self.gateway_config = self.root / "gateway-config.json"
        self.gateway_config.write_bytes(canonical(SMOKE_GATEWAY_CONFIG))
        self.gateway_config.chmod(0o600)
        self.previous_gateway_config = self.root / "previous-gateway-config.json"
        self.previous_gateway_config.write_bytes(canonical(PREVIOUS_GATEWAY_CONFIG))
        self.previous_gateway_config.chmod(0o600)
        self.bootstrap_secrets = self.root / "bootstrap-secrets.json"
        self.bootstrap_secrets.write_bytes(canonical({
            "schema_version": "milk.gateway-bootstrap-secrets.v1",
            "secrets": BOOTSTRAP_SECRETS,
        }))
        self.bootstrap_secrets.chmod(0o600)
        self.bootstrap = bootstrap
        python_directory = str(Path(sys.executable).resolve().parent)
        self.environment = {
            "HOME": str(self.home),
            "PATH": str(self.bin) + os.pathsep + python_directory + os.pathsep + "/usr/bin:/bin",
            "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
            "CLOUDFLARE_API_TOKEN": "cloudflare-test-token",
            "FAKE_STATE": str(self.state_path),
            "FAKE_REPO": str(ROOT),
            "FAKE_EVIDENCE": str(self.evidence),
        }

    def run(self, script=SCRIPT, token_stdin=False, wrangler_oauth=False):
        registry_arguments = ["--registry-token-stdin"] if token_stdin else [
            "--registry-token-file", str(self.registry_token),
        ]
        arguments = [
            str(script), *( ["--wrangler-oauth"] if wrangler_oauth else [] ), *registry_arguments,
            "--previous-gateway-config-file", str(self.previous_gateway_config),
            str(self.release), APPLICATION, str(self.evidence),
            str(self.credential), str(self.gateway_config), API_BASE_URL,
        ]
        if self.bootstrap:
            arguments = [
                str(script), *( ["--wrangler-oauth"] if wrangler_oauth else [] ), *registry_arguments,
                "--bootstrap", str(self.release), str(self.evidence),
                str(self.credential), str(self.bootstrap_secrets), API_BASE_URL,
            ]
        environment = self.environment.copy()
        if wrangler_oauth:
            environment.pop("CLOUDFLARE_API_TOKEN")
        return subprocess.run(
            arguments,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            input=b"github-test-token\n" if token_stdin else None,
            check=False,
        )

    @property
    def state(self):
        return json.loads(self.state_path.read_text())

    def terminal(self):
        return json.loads((self.evidence / "terminal.json").read_text())

    def close(self):
        self.temporary.cleanup()


class DeployPrivateGatewayTests(unittest.TestCase):
    def test_api_base_url_is_explicit_and_strict(self):
        self.assertEqual(
            DEPLOY_CONTRACT.validate_api_base_url(API_BASE_URL),
            (API_BASE_URL, "carton.example", "https://carton.example/healthz"),
        )
        for invalid in (
            "http://carton.example/v1",
            "https://Carton.example/v1",
            "https://carton.example:443/v1",
            "https://carton.example/v1/",
            "https://carton.example/v1?query=true",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(DEPLOY_CONTRACT.DeployFailure):
                    DEPLOY_CONTRACT.validate_api_base_url(invalid)

    def test_sensitive_secret_buffer_is_zeroed(self):
        value = bytearray(b"private-bootstrap-secret")
        DEPLOY_CONTRACT.clear_sensitive_bytes(value)
        self.assertEqual(value, bytearray(len(value)))

    def test_bootstrap_with_optional_r2_session_tokens_installs_exact_submitted_set(self):
        fixture = Fixture(bootstrap=True)
        self.addCleanup(fixture.close)
        value = json.loads(fixture.bootstrap_secrets.read_text())
        value["secrets"]["MILK_CAPTURE_STORE_SESSION_TOKEN"] = "capture-session-private"
        value["secrets"]["MILK_ROUTE_STORE_SESSION_TOKEN"] = "route-session-private"
        self.assertEqual(
            set(value["secrets"]),
            DEPLOY_CONTRACT.BOOTSTRAP_REQUIRED_SECRET_NAMES
            | DEPLOY_CONTRACT.BOOTSTRAP_OPTIONAL_SECRET_NAMES,
        )
        fixture.bootstrap_secrets.write_bytes(canonical(value))
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(
            fixture.state["installed_secret_names"],
            sorted(value["secrets"]),
        )
        self.assertEqual(
            fixture.state["deployed_secret_names"],
            sorted(value["secrets"]),
        )

    def test_registry_credential_can_be_streamed_without_evidence(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        result = fixture.run(token_stdin=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        evidence_raw = b"".join(
            path.read_bytes() for path in fixture.evidence.rglob("*") if path.is_file()
        )
        self.assertNotIn(b"github-test-token", evidence_raw)

    def test_wrangler_oauth_preflight_matches_account_before_evidence_write(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        result = fixture.run(wrangler_oauth=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        commands = fixture.state["commands"]
        wrangler_commands = [item for item in commands if item["command"] == "wrangler"]
        self.assertEqual(wrangler_commands[0]["arguments"], ["--version"])
        whoami = next(
            item for item in wrangler_commands
            if item["arguments"][:2] == ["whoami", "--json"]
        )
        self.assertEqual(whoami["arguments"][:2], ["whoami", "--json"])
        preflight = json.loads(
            (fixture.evidence / "wrangler-oauth-preflight.json").read_text()
        )
        self.assertIs(preflight["logged_in"], True)
        self.assertIs(preflight["account_match"], True)
        self.assertIs(preflight["content_retained"], False)

    def test_wrangler_oauth_rejects_api_token(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        arguments = [
            str(SCRIPT), "--wrangler-oauth", "--registry-token-file", str(fixture.registry_token),
            "--previous-gateway-config-file", str(fixture.previous_gateway_config),
            str(fixture.release), APPLICATION, str(fixture.evidence), str(fixture.credential),
            str(fixture.gateway_config), API_BASE_URL,
        ]
        result = subprocess.run(
            arguments, cwd=ROOT, env=fixture.environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"mutually exclusive", result.stderr)
        self.assertFalse(fixture.evidence.exists())
        self.assertEqual(fixture.state["commands"], [])

    def test_wrangler_oauth_rejects_wrong_account_before_evidence_write(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        state = fixture.state
        state["whoami_account"] = "b" * 32
        fixture.state_path.write_text(json.dumps(state))
        result = fixture.run(wrangler_oauth=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"does not match", result.stderr)
        self.assertFalse(fixture.evidence.exists())

    def test_smoke_model_is_fixed_before_cloud_mutation(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        credential = json.loads(fixture.credential.read_text())
        credential["model"] = "another-model"
        fixture.credential.write_bytes(canonical(credential))
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"gateway credential is invalid", result.stderr)
        self.assertFalse(fixture.evidence.exists())
        self.assertEqual(fixture.state["commands"], [])

    def test_smoke_key_must_be_exactly_non_capturable_in_canonical_gateway_config(self):
        for defect in ("capture", "key"):
            with self.subTest(defect=defect):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                config = json.loads(fixture.gateway_config.read_text())
                if defect == "capture":
                    config["traffic_keys"][0]["capture_allowed"] = True
                else:
                    config["traffic_keys"][0]["api_key_sha256"] = "0" * 64
                fixture.gateway_config.write_bytes(canonical(config))
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"not an exact non-capturable traffic key", result.stderr)
                self.assertFalse(fixture.evidence.exists())
                self.assertEqual(fixture.state["commands"], [])

    def test_nonbootstrap_requires_operator_supplied_previous_config(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        arguments = [
            str(SCRIPT), "--registry-token-file", str(fixture.registry_token),
            str(fixture.release), APPLICATION, str(fixture.evidence),
            str(fixture.credential), str(fixture.gateway_config), API_BASE_URL,
        ]
        result = subprocess.run(
            arguments, cwd=ROOT, env=fixture.environment,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"--previous-gateway-config-file", result.stderr)
        self.assertFalse(fixture.evidence.exists())
        self.assertEqual(fixture.state["commands"], [])

    def test_previous_config_must_match_live_digest_before_mutation(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        changed = json.loads(fixture.previous_gateway_config.read_text())
        changed["capture_basis_points"] += 1
        fixture.previous_gateway_config.write_bytes(canonical(changed))
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"predeploy_failed at rollback-anchor", result.stderr)
        self.assertFalse(any(
            item["command"] == "wrangler"
            and any(value in item["arguments"] for value in ("push", "deploy", "rollback"))
            for item in fixture.state["commands"]
        ))
        self.assertEqual(fixture.terminal()["outcome"], "predeploy_failed")
        self.assertEqual(fixture.terminal()["failure_stage"], "rollback-anchor")

    def test_rollback_anchor_is_rechecked_immediately_before_deploy(self):
        fixture = Fixture("anchor_drift")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(
            item["command"] == "wrangler"
            and any(value in item["arguments"] for value in ("deploy", "rollback"))
            for item in fixture.state["commands"]
        ))
        self.assertEqual(fixture.terminal()["outcome"], "predeploy_failed")
        self.assertEqual(
            fixture.terminal()["failure_stage"],
            "rollback-anchor-recheck",
        )

    def test_success_uses_only_admitted_prebuilt_image_and_content_free_evidence(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        state = fixture.state
        commands = state["commands"]
        child_reference = (
            "ghcr.io/milkinfrastructure/milk-carton@sha256:" + state["child_sha"]
        )
        expected_pull = ["pull", "--platform", "linux/amd64", child_reference]
        pull = next(
            item for item in commands
            if item["command"] == "docker"
            and item["arguments"][-len(expected_pull):] == expected_pull
        )
        self.assertIs(state.get("ghcr_auth_verified"), True)
        self.assertFalse(any(
            item["command"] == "docker"
            and ("login", "ghcr.io") in zip(
                item["arguments"], item["arguments"][1:]
            )
            for item in commands
        ))
        config_path = Path(pull["arguments"][pull["arguments"].index("--config") + 1])
        self.assertFalse(config_path.parent.exists())
        deploy = next(
            item for item in commands
            if item["command"] == "wrangler" and "deploy" in item["arguments"]
        )
        self.assertIn("--strict", deploy["arguments"])
        self.assertIn("--containers-rollout", deploy["arguments"])
        self.assertIn("immediate", deploy["arguments"])
        self.assertIn("--secrets-file", deploy["arguments"])
        self.assertEqual(state["deployed_secret_names"], ["MILK_CARTON_CONFIG_JSON"])
        gateway_config_sha256 = sha256(fixture.gateway_config.read_bytes())
        self.assertEqual(state["active_config_sha256"], gateway_config_sha256)
        deployed_config = state["deploy_config"]
        self.assertEqual(
            deployed_config["main"],
            str(ROOT / "deploy/cloudflare/worker.js"),
        )
        self.assertEqual(
            deployed_config["routes"],
            [{"pattern": "carton.example", "custom_domain": True}],
        )
        self.assertRegex(
            deployed_config["containers"][0]["image"],
            rf"^registry\.cloudflare\.com/{ACCOUNT}/milk-carton:milk-[0-9a-f]{{64}}-op-[0-9a-f]{{24}}$",
        )
        self.assertIn(f":milk-{state['child_sha']}-op-", deployed_config["containers"][0]["image"])
        self.assertNotIn("Dockerfile", json.dumps(deployed_config))
        self.assertNotIn("image_build_context", json.dumps(deployed_config))
        self.assertEqual(fixture.terminal()["outcome"], "succeeded")
        self.assertFalse(any("delete" in item["arguments"] for item in commands))

        evidence_raw = b"".join(path.read_bytes() for path in fixture.evidence.rglob("*") if path.is_file())
        for secret in (
            b"cloudflare-test-token", b"github-test-token", b"temporary-password",
            b"private-test-secret",
        ):
            self.assertNotIn(secret, evidence_raw)
            self.assertNotIn(secret, result.stdout)
            self.assertNotIn(secret, result.stderr)
            self.assertFalse(any(secret.decode() in " ".join(item["arguments"]) for item in commands))
        self.assertNotIn(b'"provider":"uncontrolled"', evidence_raw)
        self.assertNotIn(b'"prompt"', evidence_raw)
        self.assertNotIn(b'"model_output"', evidence_raw)
        logs = sorted((fixture.evidence / "logs").glob("*.json"))
        self.assertEqual(len(logs), len(commands))
        for path in logs:
            observation = json.loads(path.read_text())
            self.assertIs(observation["content_retained"], False)
        registry_copy = json.loads((fixture.evidence / "registry-copy.json").read_text())
        self.assertIs(registry_copy["verified"], True)
        self.assertEqual(len(registry_copy["ordered_layer_sha256"]), 2)
        manifest_raw = (fixture.evidence / "manifest.json").read_bytes()
        terminal = fixture.terminal()
        self.assertEqual(terminal["manifest_sha256"], sha256(manifest_raw))
        self.assertRegex(terminal["ops_log_reference_sha256"], r"^[0-9a-f]{64}$")
        sdk_smoke = json.loads(
            (fixture.evidence / "official-openai-sdk-smoke.json").read_text()
        )
        sdk_smoke_raw = (
            fixture.evidence / "official-openai-sdk-smoke.json"
        ).read_bytes()
        self.assertIs(sdk_smoke["authenticated"], True)
        self.assertIs(sdk_smoke["content_retained"], False)
        self.assertEqual(
            sdk_smoke["proof_contract_sha256"],
            "d9fb8b4daa1754acdbadc3b4028601434b79bf9c2096343c7a790df838bbcc66",
        )
        current = json.loads((fixture.evidence / "current.json").read_text())
        self.assertEqual(
            current["schema_version"],
            "milk.private-gateway-current-deployment.v2",
        )
        self.assertEqual(current["gateway_config_sha256"], gateway_config_sha256)
        self.assertEqual(
            current["official_openai_sdk_baseline_receipt_sha256"],
            sha256(sdk_smoke_raw),
        )
        self.assertEqual(
            current["proof_contract_sha256"],
            sdk_smoke["proof_contract_sha256"],
        )
        live_smoke = json.loads((fixture.evidence / "smoke-deploy.json").read_text())
        self.assertEqual(live_smoke["config_sha256"], gateway_config_sha256)
        self.assertEqual(live_smoke["health_contract"], "status-ok-config-sha256")
        manifest = json.loads(manifest_raw)
        for item in manifest["files"]:
            raw = (fixture.evidence / item["path"]).read_bytes()
            self.assertEqual(item["bytes"], len(raw))
            self.assertEqual(item["sha256"], sha256(raw))

    def test_current_deployment_baseline_binding_rejects_missing_mismatch_and_tamper(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        current_raw = (fixture.evidence / "current.json").read_bytes()
        baseline_raw = (
            fixture.evidence / "official-openai-sdk-smoke.json"
        ).read_bytes()
        expected_sha256 = sha256(baseline_raw)
        validate = DEPLOY_CONTRACT.validate_deployment_baseline_binding
        validate(current_raw, baseline_raw, expected_sha256)

        missing = json.loads(current_raw)
        missing.pop("official_openai_sdk_baseline_receipt_sha256")
        with self.assertRaises(DEPLOY_CONTRACT.ContractFailure):
            validate(canonical(missing), baseline_raw, expected_sha256)

        mismatch = json.loads(current_raw)
        mismatch["proof_contract_sha256"] = "0" * 64
        with self.assertRaises(DEPLOY_CONTRACT.ContractFailure):
            validate(canonical(mismatch), baseline_raw, expected_sha256)

        tampered_baseline = json.loads(baseline_raw)
        tampered_baseline["response_sha256"] = "9" * 64
        tampered_baseline_raw = canonical(tampered_baseline)
        tampered_current = json.loads(current_raw)
        tampered_current["official_openai_sdk_baseline_receipt_sha256"] = sha256(
            tampered_baseline_raw
        )
        with self.assertRaises(DEPLOY_CONTRACT.ContractFailure):
            validate(canonical(tampered_current), tampered_baseline_raw, expected_sha256)

    def test_published_release_ancestor_remains_deployable(self):
        fixture = Fixture("published_ancestor")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        commands = fixture.state["commands"]
        self.assertTrue(any(
            item["command"] == "git"
            and item["arguments"][:2] == ["merge-base", "--is-ancestor"]
            for item in commands
        ))
        intent = json.loads((fixture.evidence / "intent.json").read_text())
        self.assertEqual(intent["source_commit"], COMMIT)
        self.assertEqual(intent["deployment_source_commit"], "2" * 40)

    def test_release_not_reachable_from_published_main_fails_closed(self):
        fixture = Fixture("unpublished")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.terminal()["failure_stage"], "source-authority")
        self.assertFalse(any(
            item["command"] in {"gh", "docker", "wrangler", "curl"}
            for item in fixture.state["commands"]
        ))

    def test_remote_copy_mismatch_fails_before_deploy(self):
        fixture = Fixture("remote_mismatch")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        commands = fixture.state["commands"]
        self.assertFalse(any(
            item["command"] == "wrangler" and (
                "deploy" in item["arguments"] or "rollback" in item["arguments"]
            ) for item in commands
        ))
        terminal = fixture.terminal()
        self.assertEqual(terminal["outcome"], "predeploy_failed")
        self.assertEqual(terminal["failure_stage"], "cloudflare-copy-verification")

    def test_partial_deploy_failure_is_rolled_back_and_still_fails(self):
        fixture = Fixture("deploy_fail")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.state["deployment"], "rollback")
        self.assertEqual(fixture.state["active_worker"], PREVIOUS_WORKER)
        self.assertEqual(fixture.state["active_image"], PREVIOUS_IMAGE)
        self.assertEqual(
            fixture.state["active_config_sha256"],
            fixture.state["previous_config_sha256"],
        )
        deployments = fixture.state["deployments"]
        self.assertEqual(len(deployments), 2)
        self.assertIs(deployments[0]["restoring"], False)
        self.assertEqual(deployments[1], {
            "config_sha256": fixture.state["previous_config_sha256"],
            "image": PREVIOUS_IMAGE,
            "restoring": True,
        })
        wrangler_mutations = [
            item["arguments"]
            for item in fixture.state["commands"]
            if item["command"] == "wrangler"
            and any(value in item["arguments"] for value in ("deploy", "rollback"))
        ]
        self.assertEqual(
            ["deploy" if "deploy" in arguments else "rollback" for arguments in wrangler_mutations],
            ["deploy", "deploy", "rollback"],
        )
        rollback = json.loads((fixture.evidence / "rollback.json").read_text())
        self.assertEqual(rollback["schema_version"], "milk.private-gateway-rollback.v2")
        self.assertIs(rollback["rollback_inputs_verified"], True)
        self.assertIs(rollback["resource_restore_command_succeeded"], True)
        self.assertIs(rollback["resource_restore_accepted"], True)
        self.assertIs(rollback["worker_rollback_command_succeeded"], True)
        self.assertIs(rollback["accepted"], True)
        self.assertEqual(
            rollback["previous_gateway_config_sha256"],
            fixture.state["previous_config_sha256"],
        )
        self.assertFalse(Path(fixture.state["deployment_secrets_path"]).exists())
        evidence_raw = b"".join(
            path.read_bytes() for path in fixture.evidence.rglob("*") if path.is_file()
        )
        self.assertNotIn(fixture.previous_gateway_config.read_bytes(), evidence_raw)
        self.assertEqual(fixture.terminal()["outcome"], "deployment_failed_rolled_back")

    def test_official_sdk_smoke_failure_rolls_back(self):
        fixture = Fixture("sdk_fail")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.state["deployment"], "rollback")
        self.assertEqual(fixture.terminal()["failure_stage"], "official-sdk-smoke")
        self.assertEqual(fixture.terminal()["outcome"], "deployment_failed_rolled_back")

    def test_live_config_digest_mismatch_rolls_back(self):
        fixture = Fixture("config_mismatch")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.state["deployment"], "rollback")
        self.assertEqual(
            fixture.state["active_config_sha256"],
            fixture.state["previous_config_sha256"],
        )
        self.assertEqual(fixture.terminal()["failure_stage"], "live-acceptance")
        self.assertEqual(fixture.terminal()["outcome"], "deployment_failed_rolled_back")

    def test_failed_rollback_is_a_distinct_terminal_failure(self):
        fixture = Fixture("rollback_fail")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        rollback = json.loads((fixture.evidence / "rollback.json").read_text())
        self.assertIs(rollback["resource_restore_command_succeeded"], True)
        self.assertIs(rollback["resource_restore_accepted"], True)
        self.assertIs(rollback["worker_rollback_command_succeeded"], False)
        self.assertIs(rollback["accepted"], False)
        self.assertEqual(fixture.terminal()["outcome"], "rollback_failed")

    def test_failed_resource_restore_does_not_expose_old_worker_to_new_resources(self):
        fixture = Fixture("resource_restore_fail")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        rollback = json.loads((fixture.evidence / "rollback.json").read_text())
        self.assertIs(rollback["rollback_inputs_verified"], True)
        self.assertIs(rollback["resource_restore_command_succeeded"], False)
        self.assertIs(rollback["resource_restore_accepted"], False)
        self.assertIs(rollback["worker_rollback_command_succeeded"], False)
        self.assertIs(rollback["accepted"], False)
        self.assertEqual(fixture.state["active_worker"], CURRENT_WORKER)
        self.assertNotEqual(fixture.state["active_image"], PREVIOUS_IMAGE)
        self.assertNotEqual(
            fixture.state["active_config_sha256"],
            fixture.state["previous_config_sha256"],
        )
        self.assertEqual(fixture.terminal()["outcome"], "rollback_failed")

    def test_staged_rollback_input_tamper_fails_closed_without_git(self):
        fixture = Fixture("rollback_input_tamper")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        rollback = json.loads((fixture.evidence / "rollback.json").read_text())
        self.assertIs(rollback["rollback_inputs_verified"], False)
        self.assertIs(rollback["resource_restore_command_succeeded"], False)
        self.assertIs(rollback["resource_restore_accepted"], False)
        self.assertIs(rollback["worker_rollback_command_succeeded"], False)
        self.assertIs(rollback["accepted"], False)
        self.assertEqual(len(fixture.state["deployments"]), 1)
        self.assertEqual(fixture.terminal()["outcome"], "rollback_failed")

    def test_postmutation_repo_drift_does_not_block_staged_rollback(self):
        fixture = Fixture("rollback_source_dirty")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        rollback = json.loads((fixture.evidence / "rollback.json").read_text())
        self.assertIs(rollback["rollback_inputs_verified"], True)
        self.assertIs(rollback["resource_restore_command_succeeded"], True)
        self.assertIs(rollback["resource_restore_accepted"], True)
        self.assertIs(rollback["worker_rollback_command_succeeded"], True)
        self.assertIs(rollback["accepted"], True)
        commands = fixture.state["commands"]
        deploy_index = next(
            index for index, item in enumerate(commands)
            if item["command"] == "wrangler" and "deploy" in item["arguments"]
        )
        self.assertFalse(any(
            item["command"] == "git" for item in commands[deploy_index + 1:]
        ))
        self.assertEqual(len(fixture.state["deployments"]), 2)
        self.assertEqual(
            fixture.terminal()["outcome"],
            "deployment_failed_rolled_back",
        )

    def test_existing_target_tag_fails_before_registry_or_deploy_mutation(self):
        fixture = Fixture("collision")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        commands = fixture.state["commands"]
        self.assertFalse(any(item["command"] == "gh" for item in commands))
        self.assertFalse(any(
            item["command"] == "wrangler"
            and any(value in item["arguments"] for value in ("push", "deploy", "rollback"))
            for item in commands
        ))
        self.assertEqual(fixture.terminal()["outcome"], "predeploy_failed")

    def test_required_only_empty_account_bootstrap_installs_exact_submitted_set(self):
        fixture = Fixture(bootstrap=True)
        self.addCleanup(fixture.close)
        self.assertEqual(
            set(BOOTSTRAP_SECRETS),
            DEPLOY_CONTRACT.BOOTSTRAP_REQUIRED_SECRET_NAMES,
        )
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        state = fixture.state
        self.assertEqual(state["installed_secret_names"], sorted(BOOTSTRAP_SECRETS))
        self.assertEqual(state["deployed_secret_names"], sorted(BOOTSTRAP_SECRETS))
        self.assertEqual(state["deployment_secrets_mode"], 0o600)
        self.assertFalse(Path(state["deployment_secrets_path"]).exists())
        commands = state["commands"]
        deploy_index = next(
            index for index, item in enumerate(commands)
            if item["command"] == "wrangler" and "deploy" in item["arguments"]
        )
        acceptance_index = next(
            index for index, item in enumerate(commands)
            if item["command"] == "curl"
        )
        self.assertLess(deploy_index, acceptance_index)
        deploy = commands[deploy_index]
        self.assertIn("--secrets-file", deploy["arguments"])
        self.assertFalse(any(
            item["command"] == "wrangler"
            and item["arguments"][:2] == ["secret", "bulk"]
            for item in commands
        ))
        self.assertFalse(any("delete" in item["arguments"] for item in commands))

        intent = json.loads((fixture.evidence / "intent.json").read_text())
        self.assertIs(intent["bootstrap"], True)
        self.assertIsNone(intent["application_id"])
        created = json.loads((fixture.evidence / "bootstrap-created.json").read_text())
        self.assertEqual(created["application_id"], APPLICATION)
        self.assertEqual(created["application_name"], APPLICATION_NAME)
        self.assertEqual(created["secret_count"], len(BOOTSTRAP_SECRETS))
        self.assertIn(f":milk-{state['child_sha']}-op-", created["image"])
        self.assertEqual(fixture.terminal()["outcome"], "succeeded")

        evidence_raw = b"".join(
            path.read_bytes() for path in fixture.evidence.rglob("*") if path.is_file()
        )
        for secret in BOOTSTRAP_SECRETS.values():
            self.assertNotIn(secret.encode(), evidence_raw)

    def test_bootstrap_rejects_preexisting_worker_or_exact_application(self):
        for mode in ("bootstrap_preexisting_worker", "bootstrap_preexisting_app"):
            with self.subTest(mode=mode):
                fixture = Fixture(mode, bootstrap=True)
                self.addCleanup(fixture.close)
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                commands = fixture.state["commands"]
                self.assertFalse(any(item["command"] == "gh" for item in commands))
                self.assertFalse(any(
                    item["command"] == "wrangler"
                    and any(value in item["arguments"] for value in ("push", "deploy", "delete"))
                    for item in commands
                ))
                self.assertEqual(fixture.terminal()["failure_stage"], "bootstrap-preflight")
                self.assertEqual(fixture.terminal()["outcome"], "predeploy_failed")

    def test_partial_bootstrap_failure_deletes_only_new_worker_and_application(self):
        fixture = Fixture("bootstrap_deploy_fail", bootstrap=True)
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        state = fixture.state
        self.assertIs(state.get("worker_deleted"), True)
        self.assertIs(state.get("application_deleted"), True)
        commands = state["commands"]
        self.assertTrue(any(
            item["command"] == "wrangler"
            and item["arguments"][:2] == ["delete", "milk-carton"]
            for item in commands
        ))
        self.assertTrue(any(
            item["command"] == "wrangler"
            and item["arguments"][:2] == ["containers", "delete"]
            and APPLICATION in item["arguments"]
            for item in commands
        ))
        cleanup = json.loads((fixture.evidence / "bootstrap-cleanup.json").read_text())
        self.assertIs(cleanup["absence_proved"], True)
        self.assertFalse(Path(state["deployment_secrets_path"]).exists())
        self.assertEqual(fixture.terminal()["outcome"], "bootstrap_failed_cleaned")
        self.assertFalse(any(
            item["command"] == "wrangler"
            and item["arguments"][:3] == ["containers", "images", "delete"]
            for item in commands
        ))

    def test_failed_bootstrap_cleanup_is_a_distinct_terminal_failure(self):
        fixture = Fixture("bootstrap_cleanup_fail", bootstrap=True)
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        cleanup = json.loads((fixture.evidence / "bootstrap-cleanup.json").read_text())
        self.assertIs(cleanup["absence_proved"], False)
        self.assertFalse(Path(fixture.state["deployment_secrets_path"]).exists())
        self.assertEqual(fixture.terminal()["outcome"], "bootstrap_cleanup_failed")

    def test_bootstrap_secrets_file_must_be_canonical_owner_only_mode_0600(self):
        for defect in ("mode", "noncanonical", "missing-secret"):
            with self.subTest(defect=defect):
                fixture = Fixture(bootstrap=True)
                self.addCleanup(fixture.close)
                if defect == "mode":
                    fixture.bootstrap_secrets.chmod(0o640)
                else:
                    value = {
                        "schema_version": "milk.gateway-bootstrap-secrets.v1",
                        "secrets": dict(BOOTSTRAP_SECRETS),
                    }
                    if defect == "noncanonical":
                        fixture.bootstrap_secrets.write_text(json.dumps(value, indent=2) + "\n")
                    else:
                        value["secrets"].pop("MILK_CARTON_OPENAI_API_KEY")
                        fixture.bootstrap_secrets.write_bytes(canonical(value))
                result = fixture.run()
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(fixture.evidence.exists())
                state = fixture.state
                self.assertEqual(state["commands"], [])
                self.assertEqual(state["milk_tags"], [])
                self.assertEqual(state["deployment"], "initial")
                self.assertNotIn("deploy_config", state)
                self.assertNotIn("worker_deleted", state)
                self.assertNotIn("application_deleted", state)

    def test_dirty_checkout_fails_before_any_provider_mutation(self):
        fixture = Fixture("dirty")
        self.addCleanup(fixture.close)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        commands = fixture.state["commands"]
        self.assertFalse(any(item["command"] in {"gh", "docker", "wrangler", "curl"} for item in commands))
        self.assertEqual(fixture.terminal()["failure_stage"], "source-authority")

    def test_buildx_plugin_must_exist_in_a_standard_location(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        fixture.buildx_plugin.unlink()
        source = SCRIPT.read_text(encoding="utf-8")
        isolated_tools = fixture.root / "missing-plugin-repo/tools"
        isolated_tools.mkdir(parents=True)
        for candidate in (
            "/opt/homebrew/lib/docker/cli-plugins/docker-buildx",
            "/usr/local/lib/docker/cli-plugins/docker-buildx",
            "/usr/libexec/docker/cli-plugins/docker-buildx",
            "/usr/lib/docker/cli-plugins/docker-buildx",
        ):
            source = source.replace(candidate, str(fixture.root / candidate.removeprefix("/")))
        script = isolated_tools / SCRIPT.name
        script.write_text(source, encoding="utf-8")
        script.chmod(0o700)
        isolated_tools.joinpath("github_registry.py").write_bytes(
            ROOT.joinpath("tools/github_registry.py").read_bytes()
        )
        result = fixture.run(script)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"buildx plugin is unavailable", result.stderr)
        self.assertFalse(fixture.evidence.exists())
        self.assertEqual(fixture.state["commands"], [])

    def test_committed_config_is_a_fail_closed_prebuilt_template(self):
        config_raw = (ROOT / "deploy/cloudflare/wrangler.jsonc").read_text()
        config = json.loads(config_raw)
        self.assertEqual(config["main"], ".milk-private-deploy-script-required")
        self.assertEqual(
            config["containers"][0]["image"],
            "registry.invalid/milk-carton:admitted-image-required",
        )
        self.assertEqual(
            config["routes"],
            [{"pattern": "MILK_CARTON_CUSTOM_DOMAIN_REQUIRED", "custom_domain": True}],
        )
        self.assertEqual(config["observability"], {"enabled": True})
        self.assertNotIn("Dockerfile", config_raw)
        self.assertNotIn("image_build_context", config_raw)
        script_raw = SCRIPT.read_text()
        self.assertNotIn("containers images delete", script_raw)
        self.assertIn('"containers", "delete", matches[0]', script_raw)
        self.assertNotRegex(script_raw, r"\bgh\b")

    def test_committed_lite_config_preserves_runtime_memory_headroom(self):
        config = json.loads(
            (ROOT / "deploy/milk-carton-config.example.json").read_text()
        )
        self.assertEqual(config["max_request_bytes"], 4 * 1024 * 1024)
        self.assertEqual(config["max_in_flight"], 4)
        self.assertEqual(config["max_outcomes_in_flight"], 1)
        self.assertEqual(config["max_active_body_bytes"], 80 * 1024 * 1024)
        self.assertEqual(config["capture_response_bytes"], 4 * 1024 * 1024)
        self.assertEqual(config["capture_record_bytes"], 12 * 1024 * 1024)
        self.assertEqual(config["capture_queue_bytes"], 48 * 1024 * 1024)
        worst_active_bodies = (
            (config["max_request_bytes"] + config["capture_record_bytes"])
            * config["max_in_flight"]
            + config["capture_record_bytes"] * config["max_outcomes_in_flight"]
        )
        self.assertEqual(worst_active_bodies, 76 * 1024 * 1024)
        self.assertLessEqual(worst_active_bodies, config["max_active_body_bytes"])
        self.assertEqual(
            config["max_active_body_bytes"] + config["capture_queue_bytes"],
            128 * 1024 * 1024,
        )


if __name__ == "__main__":
    unittest.main()
