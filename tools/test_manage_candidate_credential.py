import hashlib
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools/manage-candidate-credential.py"
ADMIN_URL = "https://carton.example/__milk/candidate-credential"
ACCOUNT = "a" * 32
APPLICATION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PREVIOUS_WORKER = "11111111-1111-1111-1111-111111111111"
INSTALLED_WORKER = "22222222-2222-2222-2222-222222222222"
REMOVED_WORKER = "33333333-3333-3333-3333-333333333333"
IMAGE = f"registry.cloudflare.com/{ACCOUNT}/milk-carton:sha256-admitted"
ADMIN_KEY = "milk_admin_" + "A" * 48
CANDIDATE_KEY = "bt_candidate_test_secret_123456789"
CANDIDATE_SHA = hashlib.sha256(CANDIDATE_KEY.encode()).hexdigest()
CLOUDFLARE_TOKEN = "D" * 40
ZERO_SHA256 = "0" * 64
ROUTE_SCOPE_PREFIX = "milk/v1/scopes/10000000-0000-0000-0000-000000000001"


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def gateway(value):
    return (json.dumps(value, separators=(",", ":")) + "\n").encode()


def candidate_frame(candidate=CANDIDATE_KEY, digest=None):
    return canonical({
        "candidate_api_key": candidate,
        "candidate_key_sha256": digest or hashlib.sha256(candidate.encode()).hexdigest(),
        "key_name": "milk-winner-run",
        "key_prefix": "bt_test_prefix",
        "model_id": "model_test_123",
        "provider": "baseten",
        "run_id": "b" * 64,
        "schema_version": "milk.baseten-candidate-key-delivery.v1",
        "team_name": "milk-infrastructure",
    })


def verify_request(frame=None):
    raw = candidate_frame() if frame is None else frame
    delivery = json.loads(raw)
    return canonical({
        "candidate_key_sha256": delivery["candidate_key_sha256"],
        "key_name": delivery["key_name"],
        "key_prefix": delivery["key_prefix"],
        "model_id": delivery["model_id"],
        "payload_bytes": len(raw),
        "payload_sha256": hashlib.sha256(raw).hexdigest(),
        "provider": delivery["provider"],
        "run_id": delivery["run_id"],
        "schema_version": "milk.baseten-candidate-key-delivery-verify.v1",
        "team_name": delivery["team_name"],
    })


def route_receipt(revision, basis_points, previous_revision=None):
    return {
        "schema_version": "milk.route-publication-receipt.v2",
        "route_revision": revision,
        "student_job_id": "1" * 64,
        "student_result_sha256": "5" * 64,
        "model_manifest_sha256": "6" * 64,
        "dev_receipt_sha256": "7" * 64,
        "previous_route_revision": previous_revision,
        "candidate_basis_points": basis_points,
        "manifest_object_key": "routes/manifest.json",
        "signature_object_key": "routes/signature.json",
        "live_pointer_object_key": "routes/current.json",
        "state": "published",
    }


def operator_route_receipt(
    revision,
    basis_points,
    proposal_sha256,
    candidate_sha256,
    previous_revision=None,
):
    candidate = basis_points != 0
    return {
        "schema_version": "milk.route-publication-receipt.v2",
        "route_revision": revision,
        "student_job_id": candidate_sha256 if candidate else ZERO_SHA256,
        "student_result_sha256": proposal_sha256,
        "model_manifest_sha256": "6" * 64 if candidate else ZERO_SHA256,
        "dev_receipt_sha256": ZERO_SHA256,
        "previous_route_revision": previous_revision,
        "candidate_basis_points": basis_points,
        "manifest_object_key": f"{ROUTE_SCOPE_PREFIX}/routes/versions/{revision}.json",
        "signature_object_key": (
            f"{ROUTE_SCOPE_PREFIX}/routes/signatures/{revision}/{'a' * 64}.ed25519"
        ),
        "live_pointer_object_key": f"{ROUTE_SCOPE_PREFIX}/routes/current.json",
        "state": "active",
    }


def operator_route_remove_request(installed_ack):
    proposal_sha256 = "5" * 64
    candidate_sha256 = "1" * 64
    canary_revision = "8" * 64
    zero_revision = "9" * 64
    return {
        "candidate_key_sha256": installed_ack["candidate_key_sha256"],
        "candidate_sha256": candidate_sha256,
        "canary_route_receipt": operator_route_receipt(
            canary_revision, 100, proposal_sha256, candidate_sha256
        ),
        "gateway_release_id": installed_ack["gateway_release_id"],
        "gateway_release_sha256": installed_ack["gateway_release_sha256"],
        "key_name": installed_ack["key_name"],
        "key_prefix": installed_ack["key_prefix"],
        "model_id": installed_ack["model_id"],
        "payload_bytes": installed_ack["payload_bytes"],
        "payload_sha256": installed_ack["payload_sha256"],
        "proposal_sha256": proposal_sha256,
        "provider": installed_ack["provider"],
        "run_id": installed_ack["run_id"],
        "schema_version": "milk.baseten-candidate-key-remove-operator-route.v1",
        "team_name": installed_ack["team_name"],
        "zero_route_receipt": operator_route_receipt(
            zero_revision,
            0,
            proposal_sha256,
            candidate_sha256,
            canary_revision,
        ),
    }


def remove_request(installed_ack, trigger=None):
    trigger = trigger or {
        "kind": "service_expired",
        "service_not_after": "2026-08-27T20:00:00Z",
    }
    authorization = {
        "schema_version": "milk.provider-teardown-authorization.v1",
        "scope": {
            "tenant_id": "10000000-0000-0000-0000-000000000001",
            "project_id": "20000000-0000-0000-0000-000000000002",
            "environment_id": "30000000-0000-0000-0000-000000000003",
            "workload_id": "40000000-0000-0000-0000-000000000004",
            "eval_id": "e" * 64,
        },
        "student_job_id": "1" * 64,
        "claim_sha256": "2" * 64,
        "winner_result_object_key": "control/winner-result.json",
        "winner_result_sha256": "3" * 64,
        "provider_acceptance_sha256": "4" * 64,
        "run_id": installed_ack["run_id"],
        "selected_provider": "baseten",
        "execution_id": "execution-1",
        "trigger": trigger,
        "authorized_at": "2026-08-27T20:00:00Z",
    }
    return canonical({
        "candidate_key_sha256": installed_ack["candidate_key_sha256"],
        "gateway_cleanup_authorization": authorization,
        "gateway_cleanup_authorization_sha256": hashlib.sha256(gateway(authorization)).hexdigest(),
        "gateway_release_id": installed_ack["gateway_release_id"],
        "gateway_release_sha256": installed_ack["gateway_release_sha256"],
        "key_name": installed_ack["key_name"],
        "key_prefix": installed_ack["key_prefix"],
        "model_id": installed_ack["model_id"],
        "payload_bytes": installed_ack["payload_bytes"],
        "payload_sha256": installed_ack["payload_sha256"],
        "provider": installed_ack["provider"],
        "run_id": installed_ack["run_id"],
        "schema_version": "milk.baseten-candidate-key-remove.v1",
        "team_name": installed_ack["team_name"],
        "trigger": trigger,
    })


FAKE_COMMAND = r'''#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from pathlib import Path

name = Path(sys.argv[0]).name
args = sys.argv[1:]
state_path = Path(sys.argv[0]).resolve().parent.parent / "state.json"
state = json.loads(state_path.read_text())
state.setdefault("commands", []).append({"command": name, "arguments": args})

def done(code=0):
    state_path.write_text(json.dumps(state, sort_keys=True))
    raise SystemExit(code)

def transition():
    state["worker"] = state["future_workers"].pop(0)

if state.get("oauth"):
    if "CLOUDFLARE_API_TOKEN" in os.environ:
        done(90)
else:
    if os.environ.get("CLOUDFLARE_API_TOKEN") != "D" * 40:
        done(90)
if "CLOUDFLARE_CANDIDATE_SECRET_API_TOKEN" in os.environ:
    done(91)
if os.environ.get("WRANGLER_WRITE_LOGS") != "false":
    done(92)

if name == "sleep":
    done()

if name == "wrangler":
    if args == ["--version"]:
        print("4.125.0" if state["mode"] == "wrong_wrangler" else "4.126.0")
    elif args[:2] == ["whoami", "--json"]:
        account = "f" * 32 if state["mode"] == "wrong_oauth_account" else state["account"]
        print(json.dumps({"accounts": [{"id": account}], "loggedIn": True}))
    elif args[:2] == ["deployments", "status"]:
        print(json.dumps({"versions": [{"percentage": 100, "version_id": state["worker"]}]}))
    elif args[:2] == ["containers", "info"]:
        print(json.dumps({
            "account_id": state["account"], "configuration": {"image": state["image"]},
            "id": state["application"], "name": "milk-carton-milkcarton",
            "version": state["application_version"],
        }))
    elif args[:2] == ["containers", "instances"]:
        print(json.dumps([{"id": "gateway", "state": "running", "version": state["application_version"]}]))
    elif args[:2] == ["secret", "list"]:
        values = [{"name": "MILK_CARTON_CONTAINER_ADMIN_KEY", "type": "secret_text"}]
        if state["candidate_installed"]:
            values.append({"name": "MILK_CARTON_CANDIDATE_API_KEY", "type": "secret_text"})
        print(json.dumps(values))
    elif args[:3] == ["secret", "put", "MILK_CARTON_CANDIDATE_API_KEY"]:
        candidate = sys.stdin.buffer.read().removesuffix(b"\n")
        if hashlib.sha256(candidate).hexdigest() != state["candidate_sha256"]:
            done(93)
        if state["mode"] == "hold_install":
            marker = state_path.parent / "request-accepted"
            marker.write_text("accepted")
            release = state_path.parent / "continue-request"
            while not release.exists():
                import time
                time.sleep(0.01)
        state["candidate_installed"] = True
        transition()
        if state["mode"] == "put_ambiguous":
            done(97)
        if state["mode"] == "hold_after_put":
            state_path.write_text(json.dumps(state, sort_keys=True))
            marker = state_path.parent / "request-accepted"
            marker.write_text("accepted")
            release = state_path.parent / "continue-request"
            while not release.exists():
                import time
                time.sleep(0.01)
    elif args[:3] == ["secret", "delete", "MILK_CARTON_CANDIDATE_API_KEY"]:
        if not state["candidate_installed"]:
            done(96)
        if state["mode"] == "delete_fail_once" and not state.get("delete_failed"):
            state["delete_failed"] = True
            done(99)
        state["candidate_installed"] = False
        transition()
        if state["mode"] == "delete_ambiguous":
            done(98)
    else:
        done(2)
    done()

if name == "curl":
    authorization = sys.stdin.buffer.read()
    prefix = b"Authorization: Bearer "
    if not authorization.startswith(prefix) or not authorization.endswith(b"\n"):
        done(94)
    admin_sha256 = hashlib.sha256(authorization[len(prefix):-1]).hexdigest()
    allowed_admin_sha256s = {
        hashlib.sha256(b"milk_admin_" + b"A" * 48).hexdigest(),
        hashlib.sha256(b'milk_admin_"\\' + b"A" * 40).hexdigest(),
    }
    if admin_sha256 not in allowed_admin_sha256s:
        done(95)
    expected = next(value.split(": ", 1)[1] for value in args if value.startswith("x-milk-candidate-api-key-sha256: "))
    operation = next(value.split(": ", 1)[1] for value in args if value.startswith("x-milk-candidate-operation: "))
    if state["mode"] == "restart_fail_once" and not state.get("restart_failed"):
        state["restart_failed"] = True
        print('{"state":"restart_failed"}\n503', end="")
        done()
    if state["candidate_installed"]:
        if expected != state["candidate_sha256"] or operation == "remove":
            print('{"state":"binding_mismatch"}\n409', end="")
            done()
        candidate_sha256, result_state = expected, "loaded"
    else:
        if operation == "install":
            print('{"state":"binding_mismatch"}\n409', end="")
            done()
        candidate_sha256, result_state = None, "absent"
    if operation == "inspect":
        receipt = {
            "candidate_api_key_sha256": candidate_sha256,
            "container_instance": "gateway",
            "container_last_change": state["container_last_change"],
            "schema_version": "milk.gateway-candidate-container-inspection.v1",
            "state": result_state,
        }
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n200", end="")
        done()
    previous = state["container_last_change"]
    state["container_last_change"] += 100
    receipt = {
        "candidate_api_key_sha256": candidate_sha256,
        "container_instance": "gateway",
        "container_last_change": state["container_last_change"],
        "previous_container_last_change": previous,
        "schema_version": "milk.gateway-candidate-container-restart.v1",
        "state": result_state,
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n200", end="")
    done()

done(2)
'''


class Fixture:
    def __init__(self, mode="success", candidate_installed=False, worker=PREVIOUS_WORKER, oauth=False):
        self.temporary = tempfile.TemporaryDirectory(prefix="milk-candidate-helper-test.")
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        fake = self.bin / "fake-command"
        fake.write_text(FAKE_COMMAND)
        fake.chmod(0o700)
        for command in ("curl", "sleep", "wrangler"):
            (self.bin / command).symlink_to(fake)
        self.socket_path = self.root / "candidate.sock"
        self.state_path = self.root / "state.json"
        self.state_path.write_text(json.dumps({
            "account": ACCOUNT,
            "application": APPLICATION,
            "application_version": 7,
            "candidate_installed": candidate_installed,
            "candidate_sha256": CANDIDATE_SHA,
            "commands": [],
            "container_last_change": 1000,
            "future_workers": [INSTALLED_WORKER, REMOVED_WORKER],
            "image": IMAGE,
            "mode": mode,
            "oauth": oauth,
            "worker": worker,
        }, sort_keys=True))

    @property
    def state(self):
        return json.loads(self.state_path.read_text())

    def transact(
        self,
        request,
        admin=ADMIN_KEY.encode(),
        regular_admin=False,
        socket_path=None,
        after_send=None,
    ):
        socket_path = self.socket_path if socket_path is None else Path(socket_path)
        if regular_admin:
            path = self.root / "admin"
            path.write_bytes(admin)
            read_descriptor = os.open(path, os.O_RDONLY)
        else:
            read_descriptor, write_descriptor = os.pipe()
            os.write(write_descriptor, admin)
            os.close(write_descriptor)
        environment = {
            "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
        }
        arguments = []
        if self.state["oauth"]:
            environment["HOME"] = str(self.root / "oauth-home")
            arguments.append("--wrangler-oauth")
        else:
            environment["CLOUDFLARE_CANDIDATE_SECRET_API_TOKEN"] = CLOUDFLARE_TOKEN
        process = subprocess.Popen(
            [
                sys.executable, str(SCRIPT),
                "serve-baseten",
                "--socket-path", str(socket_path),
                "--admin-key-fd", str(read_descriptor),
                "--admin-url", ADMIN_URL,
                "--application-id", APPLICATION,
                "--expected-application-version", "7",
                "--expected-container-image", IMAGE,
                "--expected-worker-version-id", PREVIOUS_WORKER,
                *arguments,
            ],
            cwd=ROOT, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            pass_fds=(read_descriptor,),
        )
        os.close(read_descriptor)
        response = bytearray()
        deadline = time.monotonic() + 5
        while not socket_path.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if socket_path.exists() and stat.S_ISSOCK(os.lstat(socket_path).st_mode):
            metadata = os.lstat(socket_path)
            if not stat.S_ISSOCK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
                process.kill()
                raise AssertionError("test socket is not owner-only")
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(5)
            try:
                connection.connect(str(socket_path))
                connection.sendall(request)
                connection.shutdown(socket.SHUT_WR)
                if after_send is not None:
                    after_send(socket_path)
                while True:
                    chunk = connection.recv(4096)
                    if not chunk:
                        break
                    response.extend(chunk)
            finally:
                connection.close()
        stdout, stderr = process.communicate(timeout=10)
        return process.returncode, bytes(response), stdout, stderr

    def close(self):
        self.temporary.cleanup()


class CandidateCredentialHelperTests(unittest.TestCase):
    def test_only_baseten_socket_mode_is_exposed(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--help"],
            cwd=ROOT,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"serve-baseten", result.stdout)
        for removed in (b"install-modal", b"verify-modal", b"remove-modal"):
            self.assertNotIn(removed, result.stdout)

    def test_socket_install_verify_remove_are_canonical_and_secret_free(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code, installed_raw, stdout, stderr = fixture.transact(candidate_frame())
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        installed = json.loads(installed_raw)
        self.assertEqual(installed_raw, canonical(installed))
        self.assertEqual(installed["state"], "installed")
        self.assertEqual(installed["gateway_release_id"], INSTALLED_WORKER)
        self.assertNotIn(CANDIDATE_KEY.encode(), installed_raw)
        self.assertNotIn(ADMIN_KEY.encode(), installed_raw)

        code, verified_raw, stdout, stderr = fixture.transact(verify_request())
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        verified = json.loads(verified_raw)
        self.assertEqual(verified["state"], "installed")
        self.assertEqual(verified["gateway_release_id"], INSTALLED_WORKER)

        code, removed_raw, stdout, stderr = fixture.transact(remove_request(verified))
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        removed = json.loads(removed_raw)
        self.assertEqual(removed["state"], "absent")
        self.assertIsNone(removed["gateway_release_id"])
        self.assertFalse(fixture.state["candidate_installed"])
        serialized = self.state_path_bytes(fixture)
        self.assertNotIn(CANDIDATE_KEY.encode(), serialized)
        self.assertNotIn(ADMIN_KEY.encode(), serialized)
        for command in fixture.state["commands"]:
            arguments = " ".join(command["arguments"])
            self.assertNotIn(CANDIDATE_KEY, arguments)
            self.assertNotIn(ADMIN_KEY, arguments)

    def test_wrangler_oauth_is_account_bound_before_install(self):
        fixture = Fixture(oauth=True)
        self.addCleanup(fixture.close)
        code, response, stdout, stderr = fixture.transact(candidate_frame())
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        self.assertEqual(json.loads(response)["state"], "installed")
        self.assertEqual(fixture.state["commands"][1]["arguments"][:2], ["whoami", "--json"])

        wrong = Fixture(mode="wrong_oauth_account", oauth=True)
        self.addCleanup(wrong.close)
        code, response, stdout, stderr = wrong.transact(candidate_frame())
        self.assertEqual((code, response, stdout), (1, b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertFalse(wrong.state["candidate_installed"])

    def test_baseten_remove_requires_the_latest_exact_gateway_release(self):
        stale = Fixture()
        self.addCleanup(stale.close)
        code, installed_raw, _stdout, _stderr = stale.transact(candidate_frame())
        self.assertEqual(code, 0)
        code, _verified_raw, _stdout, _stderr = stale.transact(verify_request())
        self.assertEqual(code, 0)
        code, response, stdout, stderr = stale.transact(
            remove_request(json.loads(installed_raw))
        )
        self.assertEqual((code, response, stdout), (1, b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertTrue(stale.state["candidate_installed"])
        self.assertEqual(stale.state["container_last_change"], 1200)

        forged = Fixture()
        self.addCleanup(forged.close)
        code, installed_raw, _stdout, _stderr = forged.transact(candidate_frame())
        self.assertEqual(code, 0)
        request = json.loads(remove_request(json.loads(installed_raw)))
        request["gateway_release_sha256"] = "f" * 64
        code, response, stdout, stderr = forged.transact(canonical(request))
        self.assertEqual((code, response, stdout), (1, b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertTrue(forged.state["candidate_installed"])
        self.assertEqual(forged.state["container_last_change"], 1100)

    def test_baseten_remove_is_replay_safe_after_secret_delete_failure(self):
        fixture = Fixture("delete_fail_once")
        self.addCleanup(fixture.close)
        code, installed_raw, _stdout, _stderr = fixture.transact(candidate_frame())
        self.assertEqual(code, 0)
        request = remove_request(json.loads(installed_raw))

        code, response, stdout, stderr = fixture.transact(request)
        self.assertEqual((code, response, stdout), (1, b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertTrue(fixture.state["candidate_installed"])
        self.assertEqual(fixture.state["container_last_change"], 1100)

        code, removed_raw, stdout, stderr = fixture.transact(request)
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        self.assertEqual(json.loads(removed_raw)["state"], "absent")
        self.assertFalse(fixture.state["candidate_installed"])

    def test_route_zero_removal_requires_the_exact_one_percent_canary(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code, installed_raw, _stdout, _stderr = fixture.transact(candidate_frame())
        self.assertEqual(code, 0)
        installed = json.loads(installed_raw)
        canary_revision = "8" * 64
        zero_revision = "9" * 64
        trigger = {
            "kind": "route_zero",
            "retirement_object_key": "routes/retirement.json",
            "retirement_sha256": "a" * 64,
            "zero_route_revision": zero_revision,
            "canary_route_receipt": route_receipt(canary_revision, 100),
            "zero_route_receipt": route_receipt(zero_revision, 0, canary_revision),
        }
        code, removed_raw, stdout, stderr = fixture.transact(
            remove_request(installed, trigger)
        )
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        self.assertEqual(json.loads(removed_raw)["state"], "absent")

        trigger["canary_route_receipt"]["candidate_basis_points"] = 500
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code, installed_raw, _stdout, _stderr = fixture.transact(candidate_frame())
        self.assertEqual(code, 0)
        code, response, stdout, stderr = fixture.transact(
            remove_request(json.loads(installed_raw), trigger)
        )
        self.assertEqual(code, 1)
        self.assertEqual((response, stdout), (b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertTrue(fixture.state["candidate_installed"])

    def test_operator_route_zero_removes_the_exact_installed_release(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code, installed_raw, _stdout, _stderr = fixture.transact(candidate_frame())
        self.assertEqual(code, 0)
        request = operator_route_remove_request(json.loads(installed_raw))
        code, removed_raw, stdout, stderr = fixture.transact(canonical(request))
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        self.assertEqual(json.loads(removed_raw)["state"], "absent")
        self.assertFalse(fixture.state["candidate_installed"])

    def test_operator_route_zero_rejects_mixed_or_legacy_route_receipts(self):
        mutations = (
            lambda request: request["zero_route_receipt"].__setitem__(
                "previous_route_revision", "f" * 64
            ),
            lambda request: request["canary_route_receipt"].__setitem__(
                "candidate_basis_points", 500
            ),
            lambda request: request["zero_route_receipt"].__setitem__(
                "candidate_basis_points", 1
            ),
            lambda request: request["zero_route_receipt"].__setitem__(
                "student_result_sha256", "e" * 64
            ),
            lambda request: request["canary_route_receipt"].__setitem__(
                "student_job_id", "e" * 64
            ),
            lambda request: request["zero_route_receipt"].__setitem__(
                "student_job_id", request["candidate_sha256"]
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                fixture = Fixture()
                self.addCleanup(fixture.close)
                code, installed_raw, _stdout, _stderr = fixture.transact(candidate_frame())
                self.assertEqual(code, 0)
                request = operator_route_remove_request(json.loads(installed_raw))
                mutate(request)
                code, response, stdout, stderr = fixture.transact(canonical(request))
                self.assertEqual((code, response, stdout), (1, b"", b""))
                self.assertEqual(stderr, b"candidate credential operation failed\n")
                self.assertTrue(fixture.state["candidate_installed"])

    def test_recovery_verify_reports_installed_or_absent_without_plaintext(self):
        installed = Fixture(candidate_installed=True, worker=INSTALLED_WORKER)
        self.addCleanup(installed.close)
        code, response, _stdout, _stderr = installed.transact(verify_request())
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(response)["state"], "installed")

        absent = Fixture(candidate_installed=False, worker=REMOVED_WORKER)
        self.addCleanup(absent.close)
        code, response, _stdout, _stderr = absent.transact(verify_request())
        self.assertEqual(code, 0)
        value = json.loads(response)
        self.assertEqual(value["state"], "absent")
        self.assertIsNone(value["gateway_release_sha256"])

    def test_digest_mismatch_and_second_frame_fail_before_mutation(self):
        for raw in (candidate_frame(digest="0" * 64), candidate_frame() + candidate_frame()):
            fixture = Fixture()
            self.addCleanup(fixture.close)
            code, response, stdout, stderr = fixture.transact(raw)
            self.assertEqual(code, 1)
            self.assertEqual((response, stdout), (b"", b""))
            self.assertEqual(stderr, b"candidate credential operation failed\n")
            self.assertFalse(fixture.state["candidate_installed"])
            self.assertFalse(any(
                command["command"] == "wrangler" and command["arguments"][:2] == ["secret", "put"]
                for command in fixture.state["commands"]
            ))

    def test_restart_failure_rolls_back_and_proves_absence(self):
        fixture = Fixture("restart_fail_once")
        self.addCleanup(fixture.close)
        code, response, stdout, stderr = fixture.transact(candidate_frame())
        self.assertEqual(code, 1)
        self.assertEqual((response, stdout), (b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertFalse(fixture.state["candidate_installed"])
        operations = [
            argument.split(": ", 1)[1]
            for command in fixture.state["commands"] if command["command"] == "curl"
            for argument in command["arguments"] if argument.startswith("x-milk-candidate-operation: ")
        ]
        self.assertEqual(operations, ["install", "remove"])

    def test_accepted_request_unlinks_socket_before_provider_mutation(self):
        fixture = Fixture("hold_install")
        self.addCleanup(fixture.close)

        def release(socket_path):
            deadline = time.monotonic() + 5
            marker = fixture.root / "request-accepted"
            while not marker.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            self.assertFalse(socket_path.exists())
            (fixture.root / "continue-request").write_text("continue")

        code, response, stdout, stderr = fixture.transact(
            candidate_frame(),
            after_send=release,
        )
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        self.assertEqual(json.loads(response)["state"], "installed")

    def test_regular_admin_file_and_unpinned_wrangler_are_rejected(self):
        regular = Fixture()
        self.addCleanup(regular.close)
        code, response, stdout, stderr = regular.transact(candidate_frame(), regular_admin=True)
        self.assertEqual(code, 1)
        self.assertEqual((response, stdout), (b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertEqual(regular.state["commands"], [])

        unpinned = Fixture("wrong_wrangler")
        self.addCleanup(unpinned.close)
        code, response, stdout, stderr = unpinned.transact(candidate_frame())
        self.assertEqual(code, 1)
        self.assertEqual((response, stdout), (b"", b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")

    def test_printable_admin_key_is_not_interpreted_as_curl_configuration(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        admin = ('milk_admin_"\\' + "A" * 40).encode()
        code, response, stdout, stderr = fixture.transact(
            candidate_frame(), admin=admin
        )
        self.assertEqual((code, stdout, stderr), (0, b"", b""))
        self.assertEqual(json.loads(response)["state"], "installed")

    def test_socket_path_requires_absolute_owner_only_real_parent_and_no_existing_path(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        open_parent = fixture.root / "open-parent"
        open_parent.mkdir(mode=0o755)
        real_parent = fixture.root / "real-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = fixture.root / "linked-parent"
        linked_parent.symlink_to(real_parent, target_is_directory=True)
        existing = real_parent / "existing.sock"
        existing.write_bytes(b"not a socket")
        for path in (
            Path("relative.sock"),
            open_parent / "candidate.sock",
            linked_parent / "candidate.sock",
            existing,
        ):
            code, response, stdout, stderr = fixture.transact(
                candidate_frame(), socket_path=path
            )
            self.assertEqual(code, 1)
            self.assertEqual((response, stdout), (b"", b""))
            self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertEqual(fixture.state["commands"], [])

    @staticmethod
    def state_path_bytes(fixture):
        return fixture.state_path.read_bytes()


if __name__ == "__main__":
    unittest.main()
