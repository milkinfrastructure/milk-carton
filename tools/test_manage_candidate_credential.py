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
ACCOUNT = "a" * 32
APPLICATION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PREVIOUS_WORKER = "11111111-1111-1111-1111-111111111111"
INSTALLED_WORKER = "22222222-2222-2222-2222-222222222222"
REMOVED_WORKER = "33333333-3333-3333-3333-333333333333"
IMAGE = f"registry.cloudflare.com/{ACCOUNT}/milk-gateway:sha256-admitted"
ADMIN_KEY = "milk_admin_" + "A" * 48
CANDIDATE_KEY = "bt_candidate_test_secret_123456789"
CANDIDATE_SHA = hashlib.sha256(CANDIDATE_KEY.encode()).hexdigest()
CLOUDFLARE_TOKEN = "D" * 40
MODAL_ADMISSION_SHA = "4" * 64
MODAL_RESULT_SHA = "3" * 64
MODAL_RESULT_OBJECT_SHA = "8" * 64
MODAL_SERVICE_NOT_AFTER = "2030-08-27T20:00:00Z"
GATEWAY_ANCHOR = {
    "source_commit": "c" * 40,
    "image_admission_sha256": "d" * 64,
    "release_sha256": "e" * 64,
    "application_id": APPLICATION,
    "application_version": 7,
    "container_image": IMAGE,
    "worker_version_id": PREVIOUS_WORKER,
}


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


def modal_request(schema, **extra):
    value = {
        "candidate_key_sha256": CANDIDATE_SHA,
        "gateway_anchor": GATEWAY_ANCHOR,
        "gateway_result_sha256": MODAL_RESULT_SHA,
        "run_id": "b" * 64,
        "schema_version": schema,
        "selected_provider": "modal",
        "service_not_after": MODAL_SERVICE_NOT_AFTER,
        "winner_admission_sha256": MODAL_ADMISSION_SHA,
    }
    value.update(extra)
    return canonical(value)


def modal_install_request(candidate_sha=CANDIDATE_SHA):
    return modal_request(
        "milk.modal-candidate-key-install.v1",
        candidate_key_sha256=candidate_sha,
    )


def modal_verify_request(ack=None):
    return modal_request(
        "milk.modal-candidate-key-verify.v1",
        gateway_release_id=None if ack is None else ack["gateway_release_id"],
        gateway_release_sha256=None if ack is None else ack["gateway_release_sha256"],
    )


def route_receipt(revision, basis_points, previous_revision=None):
    return {
        "schema_version": "dragontales.route-publication-receipt.v2",
        "route_revision": revision,
        "student_job_id": "1" * 64,
        "student_result_sha256": "5" * 64,
        "model_manifest_sha256": "6" * 64,
        "dev_receipt_sha256": "7" * 64,
        "previous_route_revision": previous_revision,
        "candidate_basis_points": basis_points,
        "manifest_object_key": "routes/manifest.json",
        "signature_object_key": "routes/signature.json",
        "live_pointer_object_key": "routes/live.json",
        "state": "published",
    }


def remove_request(installed_ack, trigger=None):
    trigger = trigger or {
        "kind": "service_expired",
        "service_not_after": "2026-08-27T20:00:00Z",
    }
    authorization = {
        "schema_version": "dragontales.provider-teardown-authorization.v1",
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


def modal_remove_request(installed_ack, trigger=None):
    trigger = trigger or {
        "kind": "service_expired",
        "service_not_after": MODAL_SERVICE_NOT_AFTER,
    }
    authorization = {
        "schema_version": "dragontales.provider-teardown-authorization.v1",
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
        "winner_result_sha256": MODAL_RESULT_OBJECT_SHA,
        "provider_acceptance_sha256": "4" * 64,
        "run_id": "b" * 64,
        "selected_provider": "modal",
        "execution_id": "execution-1",
        "trigger": trigger,
        "authorized_at": "2026-08-27T20:00:00Z",
    }
    return modal_request(
        "milk.modal-candidate-key-remove.v1",
        gateway_cleanup_authorization=authorization,
        gateway_cleanup_authorization_sha256=hashlib.sha256(
            gateway(authorization)
        ).hexdigest(),
        gateway_release_id=installed_ack["gateway_release_id"],
        gateway_release_sha256=installed_ack["gateway_release_sha256"],
    )


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
    elif args[:2] == ["deployments", "status"]:
        print(json.dumps({"versions": [{"percentage": 100, "version_id": state["worker"]}]}))
    elif args[:2] == ["containers", "info"]:
        print(json.dumps({
            "account_id": state["account"], "configuration": {"image": state["image"]},
            "id": state["application"], "jobs": False,
            "name": "dragontales-gateway-dragontalesgateway", "version": state["application_version"],
        }))
    elif args[:2] == ["containers", "instances"]:
        print(json.dumps([{"id": "gateway", "state": "running", "version": state["application_version"]}]))
    elif args[:2] == ["secret", "list"]:
        values = [{"name": "DRAGONTALES_CONTAINER_ADMIN_KEY", "type": "secret_text"}]
        if state["candidate_installed"]:
            values.append({"name": "DRAGONTALES_CANDIDATE_API_KEY", "type": "secret_text"})
        print(json.dumps(values))
    elif args[:3] == ["secret", "put", "DRAGONTALES_CANDIDATE_API_KEY"]:
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
    elif args[:3] == ["secret", "delete", "DRAGONTALES_CANDIDATE_API_KEY"]:
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
    if hashlib.sha256(authorization[len(prefix):-1]).hexdigest() != state["admin_sha256"]:
        done(95)
    expected = next(value.split(": ", 1)[1] for value in args if value.startswith("x-dragontales-candidate-api-key-sha256: "))
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
    def __init__(self, mode="success", candidate_installed=False, worker=PREVIOUS_WORKER):
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
            "admin_sha256": hashlib.sha256(ADMIN_KEY.encode()).hexdigest(),
            "application": APPLICATION,
            "application_version": 7,
            "candidate_installed": candidate_installed,
            "candidate_sha256": CANDIDATE_SHA,
            "commands": [],
            "container_last_change": 1000,
            "future_workers": [INSTALLED_WORKER, REMOVED_WORKER],
            "image": IMAGE,
            "mode": mode,
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
            "CLOUDFLARE_CANDIDATE_SECRET_API_TOKEN": CLOUDFLARE_TOKEN,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
        }
        process = subprocess.Popen(
            [
                sys.executable, str(SCRIPT),
                "serve-baseten",
                "--socket-path", str(socket_path),
                "--admin-key-fd", str(read_descriptor),
                "--application-id", APPLICATION,
                "--expected-application-version", "7",
                "--expected-container-image", IMAGE,
                "--expected-worker-version-id", PREVIOUS_WORKER,
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

    def start_modal(self, mode, request, candidate=CANDIDATE_KEY.encode(), regular_candidate=False):
        request_path = self.root / f"{mode}-{time.monotonic_ns()}.json"
        request_path.write_bytes(request)
        admin_read, admin_write = os.pipe()
        os.write(admin_write, ADMIN_KEY.encode())
        os.close(admin_write)
        descriptors = [admin_read]
        arguments = [
            sys.executable,
            str(SCRIPT),
            mode,
            "--request",
            str(request_path),
            "--admin-key-fd",
            str(admin_read),
        ]
        if mode == "install-modal":
            if regular_candidate:
                candidate_path = self.root / "candidate.key"
                candidate_path.write_bytes(candidate)
                candidate_read = os.open(candidate_path, os.O_RDONLY)
            else:
                candidate_read, candidate_write = os.pipe()
                os.write(candidate_write, candidate)
                os.close(candidate_write)
            descriptors.append(candidate_read)
            arguments.extend(["--candidate-key-fd", str(candidate_read)])
        environment = {
            "CLOUDFLARE_ACCOUNT_ID": ACCOUNT,
            "CLOUDFLARE_CANDIDATE_SECRET_API_TOKEN": CLOUDFLARE_TOKEN,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
        }
        process = subprocess.Popen(
            arguments,
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=tuple(descriptors),
        )
        for descriptor in descriptors:
            os.close(descriptor)
        return process

    def transact_modal(
        self,
        mode,
        request,
        candidate=CANDIDATE_KEY.encode(),
        regular_candidate=False,
    ):
        process = self.start_modal(mode, request, candidate, regular_candidate)
        stdout, stderr = process.communicate(timeout=10)
        return process.returncode, stdout, stderr

    def crash_modal_install_after_secret_put(self):
        process = self.start_modal(
            "install-modal",
            modal_install_request(),
        )
        marker = self.root / "request-accepted"
        deadline = time.monotonic() + 5
        while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        if not marker.exists():
            process.kill()
            process.communicate(timeout=5)
            raise AssertionError("Modal secret write did not become observable")
        process.kill()
        (self.root / "continue-request").write_text("continue")
        process.communicate(timeout=5)

    def close(self):
        self.temporary.cleanup()


class CandidateCredentialHelperTests(unittest.TestCase):
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
        state = fixture.state
        state["admin_sha256"] = hashlib.sha256(admin).hexdigest()
        fixture.state_path.write_text(json.dumps(state, sort_keys=True))
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

    def test_modal_install_verify_remove_are_canonical_idempotent_and_secret_free(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code, installed_raw, stderr = fixture.transact_modal(
            "install-modal", modal_install_request()
        )
        self.assertEqual((code, stderr), (0, b""))
        installed = json.loads(installed_raw)
        self.assertEqual(installed_raw, canonical(installed))
        self.assertEqual(installed["schema_version"], "milk.modal-candidate-key-ack.v1")
        self.assertEqual(installed["state"], "installed")
        self.assertEqual(installed["gateway_anchor"], GATEWAY_ANCHOR)
        self.assertEqual(installed["gateway_release_id"], INSTALLED_WORKER)
        self.assertRegex(installed["gateway_release_sha256"], r"^[0-9a-f]{64}$")

        code, verified_raw, stderr = fixture.transact_modal(
            "verify-modal", modal_verify_request(installed)
        )
        self.assertEqual((code, stderr), (0, b""))
        verified = json.loads(verified_raw)
        self.assertEqual(verified["state"], "installed")
        self.assertEqual(verified["gateway_release_id"], INSTALLED_WORKER)
        self.assertNotEqual(
            verified["gateway_release_sha256"], installed["gateway_release_sha256"]
        )

        request = modal_remove_request(verified)
        code, removed_raw, stderr = fixture.transact_modal("remove-modal", request)
        self.assertEqual((code, stderr), (0, b""))
        removed = json.loads(removed_raw)
        self.assertEqual(removed["state"], "absent")
        self.assertEqual(removed["gateway_release_id"], REMOVED_WORKER)
        self.assertRegex(removed["gateway_release_sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(fixture.state["candidate_installed"])

        code, repeated_raw, stderr = fixture.transact_modal("remove-modal", request)
        self.assertEqual((code, stderr), (0, b""))
        self.assertEqual(json.loads(repeated_raw)["state"], "absent")
        for raw in (installed_raw, verified_raw, removed_raw, repeated_raw, fixture.state_path.read_bytes()):
            self.assertNotIn(CANDIDATE_KEY.encode(), raw)
            self.assertNotIn(ADMIN_KEY.encode(), raw)
        for command in fixture.state["commands"]:
            arguments = " ".join(command["arguments"])
            self.assertNotIn(CANDIDATE_KEY, arguments)
            self.assertNotIn(ADMIN_KEY, arguments)

    def test_modal_digest_mismatch_and_regular_candidate_file_fail_before_commands(self):
        for request, regular_candidate in (
            (modal_install_request("0" * 64), False),
            (modal_install_request(), True),
        ):
            fixture = Fixture()
            self.addCleanup(fixture.close)
            code, stdout, stderr = fixture.transact_modal(
                "install-modal",
                request,
                regular_candidate=regular_candidate,
            )
            self.assertEqual(code, 1)
            self.assertEqual(stdout, b"")
            self.assertEqual(stderr, b"candidate credential operation failed\n")
            self.assertFalse(fixture.state["candidate_installed"])
            self.assertEqual(fixture.state["commands"], [])

    def test_modal_ambiguous_secret_write_rolls_back_to_proven_absence(self):
        fixture = Fixture("put_ambiguous")
        self.addCleanup(fixture.close)
        code, stdout, stderr = fixture.transact_modal(
            "install-modal", modal_install_request()
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertFalse(fixture.state["candidate_installed"])
        operations = [
            argument.split(": ", 1)[1]
            for command in fixture.state["commands"]
            if command["command"] == "curl"
            for argument in command["arguments"]
            if argument.startswith("x-milk-candidate-operation: ")
        ]
        self.assertEqual(operations, ["verify", "remove"])

    def test_modal_crash_after_secret_write_recovers_without_plaintext(self):
        fixture = Fixture("hold_after_put")
        self.addCleanup(fixture.close)
        fixture.crash_modal_install_after_secret_put()
        self.assertTrue(fixture.state["candidate_installed"])
        code, recovered_raw, stderr = fixture.transact_modal(
            "verify-modal", modal_verify_request()
        )
        self.assertEqual((code, stderr), (0, b""))
        recovered = json.loads(recovered_raw)
        self.assertEqual(recovered["state"], "installed")
        self.assertEqual(recovered["gateway_release_id"], INSTALLED_WORKER)
        self.assertNotIn(CANDIDATE_KEY.encode(), recovered_raw)
        self.assertNotIn(ADMIN_KEY.encode(), recovered_raw)

    def test_modal_ambiguous_delete_is_recovered_and_returns_absence_proof(self):
        fixture = Fixture("delete_ambiguous")
        self.addCleanup(fixture.close)
        code, installed_raw, _stderr = fixture.transact_modal(
            "install-modal", modal_install_request()
        )
        self.assertEqual(code, 0)
        installed = json.loads(installed_raw)
        code, verified_raw, _stderr = fixture.transact_modal(
            "verify-modal", modal_verify_request(installed)
        )
        self.assertEqual(code, 0)
        code, removed_raw, stderr = fixture.transact_modal(
            "remove-modal", modal_remove_request(json.loads(verified_raw))
        )
        self.assertEqual((code, stderr), (0, b""))
        removed = json.loads(removed_raw)
        self.assertEqual(removed["state"], "absent")
        self.assertEqual(removed["gateway_release_id"], REMOVED_WORKER)
        self.assertFalse(fixture.state["candidate_installed"])

    def test_modal_remove_is_replay_safe_after_secret_delete_failure(self):
        fixture = Fixture("delete_fail_once")
        self.addCleanup(fixture.close)
        code, installed_raw, _stderr = fixture.transact_modal(
            "install-modal", modal_install_request()
        )
        self.assertEqual(code, 0)
        code, verified_raw, _stderr = fixture.transact_modal(
            "verify-modal", modal_verify_request(json.loads(installed_raw))
        )
        self.assertEqual(code, 0)
        request = modal_remove_request(json.loads(verified_raw))

        code, stdout, stderr = fixture.transact_modal("remove-modal", request)
        self.assertEqual((code, stdout), (1, b""))
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertTrue(fixture.state["candidate_installed"])
        self.assertEqual(fixture.state["container_last_change"], 1200)

        code, removed_raw, stderr = fixture.transact_modal("remove-modal", request)
        self.assertEqual((code, stderr), (0, b""))
        self.assertEqual(json.loads(removed_raw)["state"], "absent")
        self.assertFalse(fixture.state["candidate_installed"])

    def test_modal_remove_requires_exact_gateway_expiry_authorization(self):
        fixture = Fixture()
        self.addCleanup(fixture.close)
        code, installed_raw, _stderr = fixture.transact_modal(
            "install-modal", modal_install_request()
        )
        self.assertEqual(code, 0)
        installed = json.loads(installed_raw)
        code, verified_raw, _stderr = fixture.transact_modal(
            "verify-modal", modal_verify_request(installed)
        )
        self.assertEqual(code, 0)
        wrong_trigger = {
            "kind": "service_expired",
            "service_not_after": "2030-08-27T20:00:01Z",
        }
        code, stdout, stderr = fixture.transact_modal(
            "remove-modal",
            modal_remove_request(json.loads(verified_raw), wrong_trigger),
        )
        self.assertEqual(code, 1)
        self.assertEqual(stdout, b"")
        self.assertEqual(stderr, b"candidate credential operation failed\n")
        self.assertTrue(fixture.state["candidate_installed"])

    @staticmethod
    def state_path_bytes(fixture):
        return fixture.state_path.read_bytes()


if __name__ == "__main__":
    unittest.main()
