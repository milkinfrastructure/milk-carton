import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


root = Path(__file__).parent
config = json.loads((root / "wrangler.jsonc").read_text())
worker = (root / "worker.js").read_text()
dockerfile = (root / "Dockerfile").read_text()
package = json.loads((root / "package.json").read_text())
deploy_script = (root.parents[1] / "tools/deploy-private-gateway.sh").read_text()
production_smoke = (root.parents[1] / "tools/openai-production-smoke.mjs").read_text()
operator_notes = (root.parents[1] / "crates/dragontales-gateway/README.md").read_text()
assert not (root / "entrypoint.sh").exists()
assert not (root / "prepare-context.sh").exists()
assert package["scripts"]["deploy"] == "../../tools/deploy-private-gateway.sh"
assert "official-sdk-smoke" in deploy_script
assert "automatic-rollback" in deploy_script
assert "milk.private-gateway-current-deployment.v2" in deploy_script
assert '"official_openai_sdk_baseline_receipt_sha256"' in deploy_script
assert 'PRODUCTION_PROOF_SHA256 = "cf9e41c3220544bc163a6dfb82721154a8e078c9db3c9fa86a148a84ea275263"' in deploy_script
assert "validate_deployment_baseline_binding" in deploy_script
assert 'deploy_arguments.extend(["--secrets-file", str(deployment_secrets)])' in deploy_script
assert '"DRAGONTALES_CONFIG_JSON": gateway_config_raw.decode("utf-8")' in deploy_script
assert "expected_config_sha256" in deploy_script
assert 'import OpenAI from "openai"' in production_smoke
assert "maxRetries: 0" in production_smoke
assert 'model: "gpt-5.4"' in production_smoke
assert "max_sdk_requests: 324" in production_smoke
assert "baseline_requests: 322" in production_smoke
assert "candidate_requests: 2" in production_smoke
assert "generated_request_timeout_ms: 30_000" in production_smoke
assert "timeout: PRODUCTION_PROOF.generated_request_timeout_ms" in production_smoke
assert "AbortSignal.timeout(PRODUCTION_PROOF.generated_health_timeout_ms)" in production_smoke
assert "short_max_completion_tokens: 128" in production_smoke
assert "saturation_max_completion_tokens: 3_840" in production_smoke
assert "proof_contract_sha256" in production_smoke
assert "99.5% monthly" in operator_notes
assert "staging run forces that one instance to restart" in operator_notes
assert "versioned Worker deploy" in operator_notes

assert config["workers_dev"] is False
assert config["preview_urls"] is False
assert config["main"] == ".milk-private-deploy-script-required"
assert config["observability"] == {"enabled": True}
assert config["routes"] == [
    {
        "pattern": "api.dragontales.milkinfrastructure.com",
        "custom_domain": True,
    }
]
assert config["containers"] == [
    {
        "class_name": "DragontalesGateway",
        "image": "MILK_PRIVATE_GATEWAY_ADMITTED_IMAGE_REQUIRED",
        "instance_type": "lite",
        "max_instances": 1,
    }
]
assert config["durable_objects"] == {
    "bindings": [
        {
            "name": "DRAGONTALES_GATEWAY",
            "class_name": "DragontalesGateway",
        }
    ]
}
assert config["migrations"] == [
    {"tag": "v1", "new_sqlite_classes": ["DragontalesGateway"]}
]
assert config["secrets"]["required"] == [
    "DRAGONTALES_CONFIG_JSON",
    "DRAGONTALES_CONTAINER_ADMIN_KEY",
    "DRAGONTALES_OPENAI_API_KEY",
    "MILK_CAPTURE_STORE_ACCESS_KEY_ID",
    "MILK_CAPTURE_STORE_SECRET_ACCESS_KEY",
    "MILK_ROUTE_STORE_ACCESS_KEY_ID",
    "MILK_ROUTE_STORE_SECRET_ACCESS_KEY",
]
assert "DRAGONTALES_CANDIDATE_API_KEY" not in config["secrets"]["required"]
assert not set(config) & {
    "d1_databases",
    "kv_namespaces",
    "queues",
    "r2_buckets",
    "services",
    "workflows",
}

direct = re.compile(
    r"return\s+getContainer\(env\.DRAGONTALES_GATEWAY,\s*GATEWAY_INSTANCE\)"
    r"\s*\.fetch\(\s*request,?\s*\);"
)
assert direct.search(worker)
for buffered_or_mutated in (
    "request.arrayBuffer",
    "request.blob",
    "request.formData",
    "request.json",
    "request.text",
    "response.arrayBuffer",
    "response.blob",
    "response.json",
    "response.text",
    "TransformStream",
):
    assert buffered_or_mutated not in worker
assert 'sleepAfter = "1m"' in worker
assert "ctx.storage" not in worker
assert "MILK_CAPTURE_STORE_ACCESS_KEY_ID" in worker
assert "MILK_CAPTURE_STORE_SECRET_ACCESS_KEY" in worker
assert "MILK_CAPTURE_STORE_SESSION_TOKEN" in worker
assert "MILK_ROUTE_STORE_ACCESS_KEY_ID" in worker
assert "MILK_ROUTE_STORE_SECRET_ACCESS_KEY" in worker
assert "MILK_ROUTE_STORE_SESSION_TOKEN" in worker
assert "MILK_CONTROL_STORE" not in worker
assert worker.count("=== undefined") == 5
assert "? {}" in worker
container_env = worker.split("function containerEnvVars", 1)[1].split("\n}\n", 1)[0]
assert "DRAGONTALES_CANDIDATE_API_KEY" in container_env
assert "DRAGONTALES_CONTAINER_ADMIN_KEY" not in container_env
assert 'const CANDIDATE_ADMIN_PATH = "/__milk/candidate-credential"' in worker
assert 'const CANDIDATE_OPERATION_HEADER = "x-milk-candidate-operation"' in worker
inspection = worker.split("async inspectCandidateCredential", 1)[1].split(
    "async restartCandidateCredential", 1
)[0]
assert 'schema_version: "milk.gateway-candidate-container-inspection.v1"' in inspection
assert "await this.getState()" in inspection
assert "await this.checkCandidateCredential" in inspection
assert "current.lastChange !== previous.lastChange" in inspection
assert "await this.stop()" not in inspection
assert "await this.startAndWaitForPorts" not in inspection
assert '["inspect", "install", "remove", "verify"]' in worker
assert "await this.stop()" in worker
assert "await this.startAndWaitForPorts" in worker
assert "R2Bucket" not in worker
assert "AWS" not in worker.upper()

assert "cargo build --locked --release --package dragontales-gateway" in dockerfile
runtime_base = (
    "FROM cgr.dev/chainguard/glibc-dynamic:latest@sha256:"
    "d0046044cd28948d3380eb0d98709dc7e63f98161fe7105135e1025650bad17a"
)
assert dockerfile.count(runtime_base) == 1
runtime = dockerfile.split(runtime_base, 1)[1]
assert runtime.count("COPY ") == 2
assert (
    "COPY --from=build --chmod=0555 /src/target/release/dragontales-gateway "
    "/usr/local/bin/dragontales-gateway"
) in runtime
assert (
    "COPY --from=build --chmod=0444 /src/LICENSE /src/THIRD_PARTY_LICENSES.txt "
    "/usr/share/licenses/dragontales/"
) in runtime
assert "COPY LICENSE ./" in dockerfile
assert "COPY deploy/licenses/bundle-rust.sh ./deploy/licenses/bundle-rust.sh" in dockerfile
assert (
    "/bin/sh deploy/licenses/bundle-rust.sh /src/THIRD_PARTY_LICENSES.txt"
    in dockerfile
)
assert "USER 65532:65532" in runtime
assert 'ENTRYPOINT ["/usr/local/bin/dragontales-gateway"]' in runtime
assert 'CMD ["serve"]' in runtime
for forbidden in ("run ", "/bin/sh", "apt", "apk", "dnf", "yum", "python", "node"):
    assert forbidden not in runtime.lower()
assert "entrypoint.sh" not in dockerfile
assert "DRAGONTALES_CONFIG=" not in dockerfile
assert "FUSE" not in dockerfile.upper()
assert "AWS" not in dockerfile.upper()
assert "MODAL" not in dockerfile.upper()
license_bundle = root.parent / "licenses/bundle-rust.sh"
with tempfile.TemporaryDirectory(prefix="dragontales-license-failure-") as temporary:
    output = Path(temporary) / "THIRD_PARTY_LICENSES.txt"
    environment = os.environ.copy()
    environment["CARGO"] = str(Path(temporary) / "missing-cargo")
    failed = subprocess.run(
        ["/bin/sh", str(license_bundle), str(output)],
        cwd=root.parents[1],
        env=environment,
        capture_output=True,
        check=False,
    )
    assert failed.returncode != 0
    assert not output.exists()

print("cloudflare edge contract: ok")
