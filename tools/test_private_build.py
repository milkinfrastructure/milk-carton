import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
VERIFY_PATH = ROOT / "tools/verify-private-gateway.py"
SPEC = importlib.util.spec_from_file_location("verify_private_gateway", VERIFY_PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class VerifierFixture:
    def __init__(self, root, *, bad_predicate=False, extra_descriptor=False):
        self.root = Path(root)
        self.evidence = self.root / "evidence"
        self.docker_config = self.root / "docker-config"
        self.evidence.mkdir()
        self.docker_config.mkdir()
        self.commit = "1" * 40
        self.context_sha256 = "2" * 64
        self.source_epoch = 1_700_000_000
        build_log_raw = _json(
            {
                    "schema_version": "milk.content-free-build-log.v1",
                    "artifact": "gateway",
                    "exit_code": 0,
                    "started_at": "2026-01-01T00:00:00Z",
                    "completed_at": "2026-01-01T00:01:00Z",
                    "sha256": "3" * 64,
                    "bytes": 123,
                    "content_retained": False,
            }
        ) + b"\n"
        (self.evidence / "build-log.json").write_bytes(build_log_raw)
        (self.evidence / "ops-log-reference.json").write_bytes(
            _json(
                {
                    "schema_version": "milk.private-ops-log-reference.v1",
                    "authority": "private-release-evidence",
                    "reference": "build-log.json",
                    "receipt_sha256": hashlib.sha256(build_log_raw).hexdigest(),
                    "immutable": True,
                    "content_retained": False,
                }
            )
            + b"\n"
        )
        config = {
            "architecture": "amd64",
            "os": "linux",
            "config": {
                "User": "65532:65532",
                "Entrypoint": ["/usr/local/bin/dragontales-gateway"],
                "Cmd": ["serve"],
                "Labels": {
                    "org.opencontainers.image.source": VERIFY.SOURCE_REPOSITORY,
                    "org.opencontainers.image.revision": self.commit,
                },
            },
            "rootfs": {"type": "layers", "diff_ids": []},
        }
        self.raw_config = _json(config)
        self.config_digest = _digest(self.raw_config)
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": self.config_digest,
                "size": len(self.raw_config),
            },
            "layers": [],
        }
        self.raw_manifest = _json(manifest)
        self.manifest_digest = _digest(self.raw_manifest)
        subject = [
            {
                "name": VERIFY.REPOSITORY,
                "digest": {"sha256": self.manifest_digest.removeprefix("sha256:")},
            }
        ]
        slsa = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": subject,
            "predicateType": VERIFY.SPDX if bad_predicate else VERIFY.SLSA_V1,
            "predicate": {
                "buildDefinition": {
                    "buildType": VERIFY.BUILDKIT_BUILD_TYPE,
                    "externalParameters": {
                        "source": None,
                        "frontend": "dockerfile.v0",
                        "args": {
                            "build-arg:BUILDKIT_SYNTAX": VERIFY.DOCKERFILE_FRONTEND,
                            "build-arg:MILK_BUILDKIT_IMAGE_REFERENCE": VERIFY.BUILDKIT_IMAGE,
                            "build-arg:MILK_SOURCE_COMMIT": self.commit,
                            "build-arg:MILK_SOURCE_CONTEXT_SHA256": self.context_sha256,
                            "build-arg:SOURCE_DATE_EPOCH": str(self.source_epoch),
                            "label:org.opencontainers.image.revision": self.commit,
                            "label:org.opencontainers.image.source": VERIFY.SOURCE_REPOSITORY,
                        },
                        "locals": [{"name": "context"}, {"name": "dockerfile"}],
                    },
                    "internalParameters": {"load": True},
                    "resolvedDependencies": [
                        {"uri": f"pkg:docker/dependency-{index}", "digest": {"sha256": digest}}
                        for index, digest in enumerate(sorted(
                            VERIFY.BASE_IMAGE_SHA256
                            | {VERIFY.DOCKERFILE_FRONTEND.rsplit("@sha256:", 1)[1]}
                        ))
                    ],
                },
                "runDetails": {
                    "builder": {"id": "https://mobyproject.org/buildkit@v0.23.2"},
                    "metadata": {
                        "invocationId": "fixture-build",
                        "startedOn": "2026-01-01T00:00:00Z",
                        "finishedOn": "2026-01-01T00:01:00Z",
                    },
                    "byproducts": [],
                },
            },
        }
        spdx = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "subject": subject,
            "predicateType": VERIFY.SPDX,
            "predicate": {
                "spdxVersion": "SPDX-2.3",
                "SPDXID": "SPDXRef-DOCUMENT",
                "documentDescribes": ["SPDXRef-Package-gateway"],
                "packages": [
                    {
                        "SPDXID": "SPDXRef-Package-gateway",
                        "name": "milk-gateway",
                        "checksums": [
                            {
                                "algorithm": "SHA256",
                                "checksumValue": self.manifest_digest.removeprefix("sha256:"),
                            }
                        ],
                    }
                ],
            },
        }
        self.raw_slsa = _json(slsa)
        self.raw_spdx = _json(spdx)
        self.slsa_digest = _digest(self.raw_slsa)
        self.spdx_digest = _digest(self.raw_spdx)
        attestation = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": "application/vnd.docker.attestation.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": _digest(b"{}"),
                "size": 2,
            },
            "layers": [
                {
                    "mediaType": "application/vnd.in-toto+json",
                    "digest": self.slsa_digest,
                    "size": len(self.raw_slsa),
                    "annotations": {"in-toto.io/predicate-type": VERIFY.SLSA_V1},
                },
                {
                    "mediaType": "application/vnd.in-toto+json",
                    "digest": self.spdx_digest,
                    "size": len(self.raw_spdx),
                    "annotations": {"in-toto.io/predicate-type": VERIFY.SPDX},
                },
            ],
            "subject": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": self.manifest_digest,
                "size": len(self.raw_manifest),
            },
        }
        self.raw_attestation = _json(attestation)
        self.attestation_digest = _digest(self.raw_attestation)
        descriptors = [
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": self.manifest_digest,
                "size": len(self.raw_manifest),
                "platform": {"architecture": "amd64", "os": "linux"},
            },
            {
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": self.attestation_digest,
                "size": len(self.raw_attestation),
                "annotations": {
                    "vnd.docker.reference.type": "attestation-manifest",
                    "vnd.docker.reference.digest": self.manifest_digest,
                },
                "platform": {"architecture": "unknown", "os": "unknown"},
            },
        ]
        if extra_descriptor:
            descriptors.append(
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": "sha256:" + "9" * 64,
                    "size": 1,
                    "platform": {"architecture": "arm64", "os": "linux"},
                }
            )
        self.raw_index = _json(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": descriptors,
            }
        )
        self.index_digest = _digest(self.raw_index)
        self.metadata = self.evidence / "metadata.json"
        self.metadata.write_bytes(_json({"containerimage.digest": self.index_digest}) + b"\n")
        self.args = argparse.Namespace(
            tagged_reference=VERIFY.REPOSITORY + ":source-" + self.commit,
            source_commit=self.commit,
            source_date_epoch=self.source_epoch,
            source_context_sha256=self.context_sha256,
            metadata=self.metadata,
            docker_config=self.docker_config,
            evidence_dir=self.evidence,
            registry_token_stdin=True,
        )
        self.blobs = {
            self.config_digest: self.raw_config,
            self.slsa_digest: self.raw_slsa,
            self.spdx_digest: self.raw_spdx,
        }

    def run(self, *, visibility="private"):
        references = {
            VERIFY.REPOSITORY + "@" + self.index_digest: self.raw_index,
            VERIFY.REPOSITORY + "@" + self.manifest_digest: self.raw_manifest,
            VERIFY.REPOSITORY + "@" + self.attestation_digest: self.raw_attestation,
        }

        def command(*arguments):
            if arguments[0] == "gh":
                return (visibility + "\n").encode()
            return references[arguments[-1]]

        def blob(_bearer, digest):
            raw = self.blobs[digest]
            if _digest(raw) != digest:
                raise ValueError("fixture blob digest mismatch")
            return raw

        with mock.patch.object(VERIFY, "_run", side_effect=command), mock.patch.object(
            VERIFY, "_registry_bearer", return_value="bounded-bearer"
        ), mock.patch.object(VERIFY, "_registry_blob", side_effect=blob):
            return VERIFY.verify(self.args, "bounded-github-token")


class PrivateImageVerifierTests(unittest.TestCase):
    def test_verifies_raw_content_and_writes_harness_compatible_admission(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = VerifierFixture(directory)
            image_reference, admission_sha256 = fixture.run()
            admission_raw = (fixture.evidence / "admission.json").read_bytes()
            admission = json.loads(admission_raw)
            self.assertEqual(image_reference, VERIFY.REPOSITORY + "@" + fixture.index_digest)
            self.assertEqual(admission_sha256, hashlib.sha256(admission_raw).hexdigest())
            self.assertEqual(
                set(admission),
                {
                    "schema_version",
                    "artifact",
                    "repository",
                    "image_reference",
                    "source_repository",
                    "source_commit",
                    "source_context_method",
                    "source_context_sha256",
                    "gateway_image_reference",
                    "index_sha256",
                    "amd64_manifest_sha256",
                    "config_sha256",
                    "attestation_manifest_sha256",
                    "attestations",
                    "platform",
                    "visibility",
                    "builder",
                },
            )
            self.assertEqual(admission["schema_version"], "milk.private-image-admission.v1")
            self.assertEqual(admission["artifact"], "gateway")
            self.assertIsNone(admission["gateway_image_reference"])
            self.assertEqual(admission["source_context_method"], "git-archive-tar-v1")
            self.assertEqual(admission["visibility"], "private")
            self.assertEqual(admission["builder"]["authority"], "local-socket")
            self.assertEqual(admission["builder"]["provenance_mode"], "max")
            self.assertEqual(admission["builder"]["provenance_version"], "v1")
            self.assertIs(admission["builder"]["sbom"], True)
            self.assertEqual(
                [item["predicate_type"] for item in admission["attestations"]],
                [VERIFY.SLSA_V1, VERIFY.SPDX],
            )
            for name, raw in {
                "index.json": fixture.raw_index,
                "amd64-manifest.json": fixture.raw_manifest,
                "config.json": fixture.raw_config,
                "attestation-manifest.json": fixture.raw_attestation,
                "slsa-provenance.json": fixture.raw_slsa,
                "spdx-sbom.json": fixture.raw_spdx,
            }.items():
                self.assertEqual((fixture.evidence / name).read_bytes(), raw)

    def test_admission_is_deterministic(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            one = VerifierFixture(first)
            two = VerifierFixture(second)
            one.run()
            two.run()
            self.assertEqual(
                (one.evidence / "admission.json").read_bytes(),
                (two.evidence / "admission.json").read_bytes(),
            )

    def test_rejects_raw_blob_digest_mismatch(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = VerifierFixture(directory)
            fixture.blobs[fixture.config_digest] += b" "
            with self.assertRaisesRegex(ValueError, "fixture blob digest mismatch"):
                fixture.run()

    def test_rejects_attestation_payload_that_disagrees_with_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = VerifierFixture(directory, bad_predicate=True)
            with self.assertRaisesRegex(ValueError, "predicate differs"):
                fixture.run()

    def test_rejects_unexpected_platform_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = VerifierFixture(directory, extra_descriptor=True)
            with self.assertRaisesRegex(ValueError, "unauthorized descriptor"):
                fixture.run()

    def test_rejects_public_package(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = VerifierFixture(directory)
            with self.assertRaisesRegex(ValueError, "not private"):
                fixture.run(visibility="public")

    def test_slsa_requires_exact_release_inputs_and_dependencies(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = VerifierFixture(directory)
            predicate = json.loads(fixture.raw_slsa)["predicate"]
            VERIFY._validate_slsa(predicate, fixture.args)
            predicate["buildDefinition"]["externalParameters"]["args"][
                "build-arg:MILK_SOURCE_CONTEXT_SHA256"
            ] = "0" * 64
            with self.assertRaisesRegex(ValueError, "bind release inputs"):
                VERIFY._validate_slsa(predicate, fixture.args)

    def test_spdx_requires_described_package_sha256(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = VerifierFixture(directory)
            predicate = json.loads(fixture.raw_spdx)["predicate"]
            VERIFY._validate_spdx(predicate)
            predicate["packages"][0]["checksums"] = []
            with self.assertRaisesRegex(ValueError, "checksum"):
                VERIFY._validate_spdx(predicate)


class PrivateBuildScriptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.test_root = Path(self.temporary.name)
        self.bin = self.test_root / "bin"
        self.bin.mkdir()
        self.buildx_plugin = (
            self.test_root / "home" / ".docker" / "cli-plugins" / "docker-buildx"
        )
        self.buildx_plugin.parent.mkdir(parents=True)
        self.buildx_plugin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.buildx_plugin.chmod(0o700)
        self.command_log = self.test_root / "commands.log"
        self.revision = "4" * 40
        self.source_context = self.test_root / "source-context.tar"
        with tarfile.open(self.source_context, "w", format=tarfile.USTAR_FORMAT) as archive:
            raw = (
                "# syntax="
                + VERIFY.DOCKERFILE_FRONTEND
                + "\n\nFROM scratch\n"
            ).encode()
            item = tarfile.TarInfo("deploy/cloudflare/Dockerfile")
            item.mode = 0o644
            item.mtime = 1_700_000_000
            item.size = len(raw)
            import io

            archive.addfile(item, io.BytesIO(raw))
        self.context_sha256 = hashlib.sha256(self.source_context.read_bytes()).hexdigest()
        self.fake_verifier = self.test_root / "fake-verifier.py"
        self.fake_verifier.write_text(
            textwrap.dedent(
                r"""
                import argparse
                import hashlib
                import json
                import os
                from pathlib import Path
                import sys

                parser = argparse.ArgumentParser()
                parser.add_argument("--tagged-reference", required=True)
                parser.add_argument("--source-commit", required=True)
                parser.add_argument("--source-date-epoch", required=True)
                parser.add_argument("--source-context-sha256", required=True)
                parser.add_argument("--metadata", required=True)
                parser.add_argument("--docker-config", required=True)
                parser.add_argument("--evidence-dir", required=True)
                parser.add_argument("--registry-token-stdin", action="store_true")
                arguments = parser.parse_args()
                if sys.stdin.read().strip() != "ephemeral-test-password":
                    raise SystemExit(93)
                if os.environ.get("TEST_FAIL_VERIFY") == "1":
                    raise SystemExit(70)
                root = Path(arguments.evidence_dir)
                for name in (
                    "index.json", "amd64-manifest.json", "config.json",
                    "attestation-manifest.json", "slsa-provenance.json", "spdx-sbom.json",
                ):
                    root.joinpath(name).write_text("{}", encoding="utf-8")
                root.joinpath("receipt.json").write_text(
                    '{"schema_version":"milk.private-gateway-image-build.v1"}\n', encoding="utf-8"
                )
                admission = {
                    "schema_version": "milk.private-image-admission.v1",
                    "artifact": "gateway",
                    "source_commit": arguments.source_commit,
                    "source_context_sha256": arguments.source_context_sha256,
                }
                raw = json.dumps(admission, sort_keys=True, separators=(",", ":")) + "\n"
                root.joinpath("admission.json").write_text(raw, encoding="utf-8")
                root.joinpath("verify-args.json").write_text(
                    json.dumps(vars(arguments), sort_keys=True, separators=(",", ":")) + "\n",
                    encoding="utf-8",
                )
                image = "ghcr.io/milkinfrastructure/milk-gateway@sha256:" + "a" * 64
                print(image + "\t" + hashlib.sha256(raw.encode()).hexdigest())
                """
            ).lstrip(),
            encoding="utf-8",
        )
        self._write_mocks()

    def tearDown(self):
        self.temporary.cleanup()

    def _write_executable(self, name, body):
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(0o700)

    def _write_mocks(self):
        self._write_executable(
            "git",
            textwrap.dedent(
                r"""#!/bin/sh
                set -eu
                if [ "${1:-}" = archive ]; then
                  output=
                  for argument do
                    case "$argument" in --output=*) output=${argument#--output=} ;; esac
                  done
                  [ -n "$output" ]
                  cp "$TEST_SOURCE_CONTEXT" "$output"
                  exit 0
                fi
                case "$*" in
                  'rev-parse --show-toplevel') printf '%s\n' "$TEST_REPO" ;;
                  'rev-parse --verify HEAD^{commit}') printf '%s\n' "$TEST_REVISION" ;;
                  "show -s --format=%ct $TEST_REVISION") printf '%s\n' '1700000000' ;;
                  'status --porcelain=v1 --untracked-files=all')
                    [ "${TEST_GIT_DIRTY:-0}" -eq 0 ] || printf '%s\n' ' M dirty'
                    ;;
                  'remote get-url origin')
                    printf '%s\n' "${TEST_ORIGIN:-git@github.com:milkinfrastructure/milk-gateway.git}"
                    ;;
                  'ls-remote --exit-code origin HEAD')
                    printf '%s\tHEAD\n' "${TEST_REMOTE_HEAD:-$TEST_REVISION}"
                    ;;
                  *) exit 90 ;;
                esac
                """
            ),
        )
        self._write_executable(
            "gh",
            textwrap.dedent(
                r"""#!/bin/sh
                set -eu
                printf 'gh' >>"$TEST_COMMAND_LOG"
                for argument do printf '|%s' "$argument" >>"$TEST_COMMAND_LOG"; done
                printf '\n' >>"$TEST_COMMAND_LOG"
                case "$*" in
                  'auth token --hostname github.com') printf '%s\n' 'ephemeral-test-password' ;;
                  *'/orgs/milkinfrastructure/packages?package_type=container&per_page=100'*)
                    if [ "${TEST_PUBLIC_PACKAGE:-0}" -eq 1 ]; then
                      printf 'milk-gateway\tpublic\n'
                    else
                      printf 'milk-gateway\tprivate\n'
                    fi
                    ;;
                  *) exit 91 ;;
                esac
                """
            ),
        )
        self._write_executable(
            "docker",
            textwrap.dedent(
                r"""#!/bin/sh
                set -eu
                printf 'docker' >>"$TEST_COMMAND_LOG"
                for argument do printf '|%s' "$argument" >>"$TEST_COMMAND_LOG"; done
                printf '\n' >>"$TEST_COMMAND_LOG"
                if [ "${1:-}" = --config ]; then
                  [ -x "$2/cli-plugins/docker-buildx" ] || exit 94
                  shift 2
                fi
                case "${1:-} ${2:-}" in
                  'context show') printf '%s\n' 'desktop-linux' ;;
                  'context inspect') printf '%s\n' "${TEST_ENDPOINT:-unix:///tmp/test-docker.sock}" ;;
                  'buildx version') printf '%s\n' 'github.com/docker/buildx v0.25.0' ;;
                  'login ghcr.io')
                    read -r password
                    [ "$password" = ephemeral-test-password ]
                    ;;
                  'buildx create') printf '%s\n' 'test-builder' ;;
                  'buildx inspect')
                    printf '%s\n' \
                      'Name: test-builder' \
                      'Driver: docker-container' \
                      "Endpoint: ${TEST_ENDPOINT:-unix:///tmp/test-docker.sock}" \
                      'BuildKit version: v0.23.2'
                    ;;
                  'buildx build')
                    metadata=
                    while [ "$#" -gt 0 ]; do
                      if [ "$1" = --metadata-file ]; then metadata=$2; shift 2; continue; fi
                      shift
                    done
                    [ -n "$metadata" ]
                    if [ "${TEST_FAIL_BUILD:-0}" -eq 1 ]; then
                      printf '%s\n' 'raw failing build output must not persist'
                      exit 55
                    fi
                    printf '{"containerimage.digest":"sha256:%s"}\n' \
                      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >"$metadata"
                    printf '%s\n' 'contentful fake build output'
                    ;;
                  'buildx rm') ;;
                  *) exit 92 ;;
                esac
                """
            ),
        )
        self._write_executable(
            "python3",
            textwrap.dedent(
                r"""#!/bin/sh
                set -eu
                if [ "${1:-}" = "$TEST_REPO/tools/verify-private-gateway.py" ]; then
                  shift
                  exec "$TEST_REAL_PYTHON" "$TEST_FAKE_VERIFIER" "$@"
                fi
                exec "$TEST_REAL_PYTHON" "$@"
                """
            ),
        )

    def _environment(self, **updates):
        environment = {
            "HOME": str(self.test_root / "home"),
            "LC_ALL": "C",
            "PATH": str(self.bin) + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "TEST_COMMAND_LOG": str(self.command_log),
            "TEST_FAKE_VERIFIER": str(self.fake_verifier),
            "TEST_REAL_PYTHON": sys.executable,
            "TEST_REPO": str(ROOT),
            "TEST_REVISION": self.revision,
            "TEST_SOURCE_CONTEXT": str(self.source_context),
            "TMPDIR": str(self.test_root),
        }
        environment.update({key: str(value) for key, value in updates.items()})
        return environment

    def _run(self, name, *, environment=None):
        evidence = self.test_root / name
        result = subprocess.run(
            [str(ROOT / "tools/build-private-gateway.sh"), str(evidence)],
            env=environment or self._environment(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return result, evidence

    def test_release_uses_committed_context_fresh_local_builder_and_hash_only_logs(self):
        result, evidence = self._run("success")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((evidence / "release.json").is_file())
        self.assertFalse((evidence / "failure.json").exists())
        self.assertEqual(list(evidence.rglob("*.log")), [])
        input_receipt = json.loads((evidence / "input.json").read_bytes())
        self.assertEqual(input_receipt["source_context_sha256"], self.context_sha256)
        self.assertEqual(input_receipt["source_context_method"], "git-archive-tar-v1")
        builder = json.loads((evidence / "builder.json").read_bytes())
        self.assertEqual(builder["authority"], "local-socket")
        self.assertIs(builder["content_retained"], False)
        log = json.loads((evidence / "build-log.json").read_bytes())
        self.assertEqual(log["exit_code"], 0)
        self.assertIs(log["content_retained"], False)
        commands = self.command_log.read_text(encoding="utf-8")
        self.assertIn("--driver|docker-container", commands)
        self.assertIn("--driver-opt|image=" + VERIFY.BUILDKIT_IMAGE, commands)
        self.assertIn("--platform|linux/amd64", commands)
        self.assertIn("--provenance=mode=max,version=v1", commands)
        self.assertIn("--sbom=true", commands)
        self.assertIn("--build-arg|BUILDKIT_SYNTAX=" + VERIFY.DOCKERFILE_FRONTEND, commands)
        self.assertIn("--build-arg|SOURCE_DATE_EPOCH=1700000000", commands)
        self.assertIn("--push", commands)
        self.assertNotIn("--load", commands)
        build_line = next(line for line in commands.splitlines() if "|build|" in line)
        self.assertNotIn("|" + str(ROOT), build_line)
        self.assertIn("/milk-gateway-release.", build_line)
        self.assertEqual(commands.count("|buildx|create|"), 1)
        self.assertEqual(commands.count("|buildx|rm|"), 1)
        version_lines = [line for line in commands.splitlines() if "|buildx|version" in line]
        self.assertEqual(len(version_lines), 2)
        self.assertTrue(any("|--config|" in line for line in version_lines))

    def test_requires_buildx_plugin_in_a_standard_location(self):
        self.buildx_plugin.unlink()
        result, evidence = self._run("missing-buildx-plugin")
        self.assertEqual(result.returncode, 69, result.stderr)
        self.assertIn("plugin is unavailable in standard locations", result.stderr)
        self.assertFalse(evidence.exists())

    def test_public_preexisting_package_fails_before_build(self):
        result, evidence = self._run(
            "public-package", environment=self._environment(TEST_PUBLIC_PACKAGE=1)
        )
        self.assertEqual(result.returncode, 77)
        self.assertTrue((evidence / "failure.json").is_file())
        commands = self.command_log.read_text(encoding="utf-8")
        self.assertNotIn("|buildx|build|", commands)

    def test_build_failure_retains_only_content_free_log_observation(self):
        result, evidence = self._run(
            "build-failure", environment=self._environment(TEST_FAIL_BUILD=1)
        )
        self.assertEqual(result.returncode, 70)
        observation = json.loads((evidence / "build-log.json").read_bytes())
        self.assertEqual(observation["exit_code"], 55)
        self.assertIs(observation["content_retained"], False)
        self.assertEqual(list(evidence.rglob("*.log")), [])
        self.assertNotIn(
            "raw failing build output must not persist",
            "".join(path.read_text(errors="ignore") for path in evidence.rglob("*") if path.is_file()),
        )

    def test_rejects_dirty_wrong_origin_unpublished_head_credentials_and_remote_docker(self):
        cases = {
            "dirty": {"TEST_GIT_DIRTY": 1},
            "origin": {"TEST_ORIGIN": "https://github.com/example/milk-gateway.git"},
            "remote-head": {"TEST_REMOTE_HEAD": "5" * 40},
            "ambient-provider": {"AWS_SECRET_ACCESS_KEY": "secret"},
            "remote-docker": {"TEST_ENDPOINT": "tcp://builder.example:2376"},
        }
        for name, updates in cases.items():
            with self.subTest(name=name):
                self.command_log.unlink(missing_ok=True)
                result, evidence = self._run(name, environment=self._environment(**updates))
                self.assertEqual(result.returncode, 64, result.stderr)
                self.assertFalse(evidence.exists())


class PrivateBuildStaticContractTests(unittest.TestCase):
    def test_dockerfile_and_script_pin_release_inputs(self):
        dockerfile = (ROOT / "deploy/cloudflare/Dockerfile").read_text(encoding="utf-8")
        self.assertTrue(dockerfile.startswith("# syntax=" + VERIFY.DOCKERFILE_FRONTEND + "\n"))
        self.assertIn("USER 65532:65532", dockerfile)
        script = (ROOT / "tools/build-private-gateway.sh").read_text(encoding="utf-8")
        self.assertIn(VERIFY.REPOSITORY, script)
        self.assertIn(VERIFY.BUILDKIT_IMAGE, script)
        self.assertIn("git archive --format=tar", script)
        self.assertIn("git ls-remote --exit-code origin HEAD", script)
        self.assertIn("--provenance=mode=max,version=v1", script)
        self.assertIn("--sbom=true", script)
        self.assertNotIn("tee ", script)
        self.assertNotIn("modal run", script.lower())


if __name__ == "__main__":
    unittest.main()
