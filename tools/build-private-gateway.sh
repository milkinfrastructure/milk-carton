#!/bin/sh
set -eu
umask 077

REPOSITORY=ghcr.io/milkinfrastructure/milk-gateway
SOURCE_REPOSITORY=https://github.com/milkinfrastructure/milk-gateway
BUILDKIT_IMAGE=moby/buildkit@sha256:ddd1ca44b21eda906e81ab14a3d467fa6c39cd73b9a39df1196210edcb8db59e
BUILDKIT_VERSION=v0.23.2
DOCKERFILE_FRONTEND=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

fail() {
  printf 'build-private-gateway: %s\n' "$1" >&2
  exit "${2:-1}"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is unavailable" 69
}

[ "$#" -eq 1 ] || fail 'usage: build-private-gateway.sh NEW_EVIDENCE_DIR' 64
requested_evidence_dir=$1
case "$requested_evidence_dir" in
  /*) ;;
  *) fail 'evidence directory must be absolute' 64 ;;
esac
[ ! -e "$requested_evidence_dir" ] || fail 'evidence directory must be new' 64
evidence_parent=$(dirname -- "$requested_evidence_dir")
[ -d "$evidence_parent" ] || fail 'evidence directory parent does not exist' 64
evidence_parent=$(CDPATH= cd -- "$evidence_parent" && pwd -P)
evidence_dir=$evidence_parent/$(basename -- "$requested_evidence_dir")

for command_name in date docker env gh git grep ln python3 sed tar; do
  require_command "$command_name"
done

credential_names=$(env | sed 's/=.*//' | LC_ALL=C sort)
if printf '%s\n' "$credential_names" | grep -Eq \
  '^(AWS_|AZURE_|GCP_|S3_|BASETEN_|MODAL_|OPENAI_|R2_|CLOUDFLARE_|TEACHER_|WANDB_|DRAGONTALES_|DOCKER_|BUILDX_|BUILDKIT_).*|^(GOOGLE_APPLICATION_CREDENTIALS|HF_TOKEN|HUGGING_FACE_HUB_TOKEN|NVIDIA_API_KEY|NGC_API_KEY|CODEX_API_KEY|CODEX_AUTH_TOKEN|CODEX_TOKEN|GH_TOKEN|GITHUB_TOKEN|GH_ENTERPRISE_TOKEN|GITHUB_ENTERPRISE_TOKEN|CR_PAT|CI_JOB_TOKEN|CI_REGISTRY_PASSWORD|NPM_TOKEN|PYPI_TOKEN|PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|REGISTRY_AUTH_FILE|HTTP_PROXY|HTTPS_PROXY|FTP_PROXY|ALL_PROXY|NO_PROXY|http_proxy|https_proxy|ftp_proxy|all_proxy|no_proxy)$|^CARGO_REGISTRIES_.*_TOKEN$|^MILK_.*(AWS|R2|S3|STORE|TEACHER|PROVIDER|CREDENTIAL|SECRET|TOKEN|ACCESS_KEY)'; then
  fail 'build shell contains an ambient registry, provider, store, teacher, OpenAI, or Codex credential/configuration' 64
fi

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
cd "$repo"
top_level=$(git rev-parse --show-toplevel 2>/dev/null) || fail 'release source is not a git checkout' 64
[ "$top_level" = "$repo" ] || fail 'release script must run from the milk-gateway checkout' 64
commit=$(git rev-parse --verify 'HEAD^{commit}' 2>/dev/null) || fail 'release checkout has no commit' 64
[ "${#commit}" -eq 40 ] || fail 'source commit must be a full SHA-1' 64
case "$commit" in
  *[!0-9a-f]*) fail 'source commit must be a full lowercase SHA-1' 64 ;;
esac
source_epoch=$(git show -s --format=%ct "$commit" 2>/dev/null) || fail 'cannot derive source commit time' 64
case "$source_epoch" in
  ''|*[!0-9]*) fail 'source commit time is invalid' 64 ;;
esac
[ -z "$(git status --porcelain=v1 --untracked-files=all)" ] || fail 'release checkout must be clean' 64
origin=$(git remote get-url origin 2>/dev/null) || fail 'release checkout has no origin' 64
case "$origin" in
  git@github.com:milkinfrastructure/milk-gateway.git|https://github.com/milkinfrastructure/milk-gateway.git) ;;
  *) fail 'origin must be milkinfrastructure/milk-gateway' 64 ;;
esac
remote_head=$(git ls-remote --exit-code origin HEAD 2>/dev/null) || fail 'cannot resolve origin HEAD' 64
set -- $remote_head
[ "$#" -eq 2 ] && [ "$1" = "$commit" ] && [ "$2" = HEAD ] || \
  fail 'local HEAD must equal the published origin HEAD' 64
case "$evidence_dir/" in
  "$repo"/*) fail 'evidence directory must be outside the release checkout' 64 ;;
esac

docker=$(command -v docker)
gh=$(command -v gh)
python=$(command -v python3)
context=$("$docker" context show 2>/dev/null) || fail 'cannot resolve the Docker context' 69
[ -n "$context" ] || fail 'Docker context is empty' 69
endpoint=$("$docker" context inspect "$context" --format '{{ (index .Endpoints "docker").Host }}' 2>/dev/null) || \
  fail 'cannot inspect the Docker context' 69
case "$endpoint" in
  unix://*|npipe://*) ;;
  *) fail 'Docker context must use a local socket' 64 ;;
esac
"$docker" buildx version >/dev/null 2>&1 || fail 'docker buildx is unavailable' 69
buildx_plugin=
if [ -n "${HOME:-}" ] && [ -x "$HOME/.docker/cli-plugins/docker-buildx" ]; then
  buildx_plugin=$HOME/.docker/cli-plugins/docker-buildx
else
  for candidate in \
    /opt/homebrew/lib/docker/cli-plugins/docker-buildx \
    /usr/local/lib/docker/cli-plugins/docker-buildx \
    /usr/libexec/docker/cli-plugins/docker-buildx \
    /usr/lib/docker/cli-plugins/docker-buildx; do
    if [ -x "$candidate" ]; then
      buildx_plugin=$candidate
      break
    fi
  done
fi
[ -n "$buildx_plugin" ] || fail 'docker buildx plugin is unavailable in standard locations' 69

mkdir -m 0700 -- "$evidence_dir" || fail 'could not create evidence directory' 73
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
failure_stage=initialization
release_complete=0
builder_created=0
scratch=
docker_config=
builder=

cleanup() {
  status=$?
  trap - EXIT HUP INT TERM
  if [ "$status" -ne 0 ] && [ "$release_complete" -eq 0 ]; then
    completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf 'unknown')
    "$python" - "$evidence_dir/failure.json" "$commit" "$failure_stage" \
      "$status" "$started_at" "$completed_at" <<'PY' >/dev/null 2>&1 || :
import json
import sys
from pathlib import Path

path, commit, stage, status, started_at, completed_at = sys.argv[1:]
Path(path).write_text(json.dumps({
    "schema_version": "milk.private-gateway-release-failure.v1",
    "source_commit": commit,
    "stage": stage,
    "exit_code": int(status),
    "started_at": started_at,
    "completed_at": completed_at,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
  fi
  if [ "$builder_created" -eq 1 ]; then
    "$docker" --config "$docker_config" buildx rm --force "$builder" >/dev/null 2>&1 || :
  fi
  case "$scratch" in
    "${TMPDIR:-/tmp}"/milk-gateway-release.*) rm -rf -- "$scratch" ;;
  esac
  exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

scratch=$(mktemp -d "${TMPDIR:-/tmp}/milk-gateway-release.XXXXXX") || \
  fail 'cannot create release scratch directory' 73
docker_config=$scratch/docker-config
mkdir -m 0700 -- "$docker_config" || fail 'cannot create isolated Docker configuration' 73
mkdir -m 0700 -- "$docker_config/cli-plugins" || \
  fail 'cannot create isolated Docker plugin directory' 73
ln -s -- "$buildx_plugin" "$docker_config/cli-plugins/docker-buildx" || \
  fail 'cannot install buildx in the isolated Docker configuration' 73
"$docker" --config "$docker_config" buildx version >/dev/null 2>&1 || \
  fail 'docker buildx is unavailable in the isolated Docker configuration' 69
builder=milk-gateway-$(printf '%.12s' "$commit")-$$

failure_stage=source-context
source_context=$scratch/source-context.tar
git archive --format=tar --output="$source_context" "$commit" || \
  fail 'cannot materialize the committed source context' 70
context_sha256=$(
  "$python" - "$source_context" <<'PY'
import hashlib
import sys
from pathlib import Path

print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PY
) || fail 'cannot hash the committed source context' 70
build_context=$scratch/context
mkdir -m 0700 -- "$build_context" || fail 'cannot create the committed build context' 73
tar -xf "$source_context" -C "$build_context" || fail 'cannot extract the committed build context' 70
rm -f -- "$source_context"
dockerfile=$build_context/deploy/cloudflare/Dockerfile
[ -f "$dockerfile" ] || fail 'committed source is missing deploy/cloudflare/Dockerfile' 66
grep -Fxq "# syntax=$DOCKERFILE_FRONTEND" "$dockerfile" || \
  fail 'gateway Dockerfile frontend is not digest-pinned' 66

"$python" - "$evidence_dir/input.json" "$commit" "$source_epoch" \
  "$context_sha256" "$BUILDKIT_IMAGE" "$DOCKERFILE_FRONTEND" "$started_at" <<'PY'
import json
import sys
from pathlib import Path

path, commit, source_epoch, context_sha256, buildkit, frontend, started_at = sys.argv[1:]
Path(path).write_text(json.dumps({
    "schema_version": "milk.private-gateway-release-input.v1",
    "source_commit": commit,
    "source_date_epoch": int(source_epoch),
    "source_repository": "https://github.com/milkinfrastructure/milk-gateway",
    "source_context_method": "git-archive-tar-v1",
    "source_context_sha256": context_sha256,
    "buildkit_image_reference": buildkit,
    "dockerfile_frontend_reference": frontend,
    "platform": "linux/amd64",
    "started_at": started_at,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY

failure_stage=package-preflight
packages=$scratch/packages.tsv
"$gh" api --hostname github.com --paginate \
  '/orgs/milkinfrastructure/packages?package_type=container&per_page=100' \
  --jq '.[] | [.name, .visibility] | @tsv' >"$packages" || \
  fail 'cannot inspect Milk container packages' 77
"$python" - "$packages" <<'PY' || fail 'an existing milk-gateway package is not private' 77
import sys
from pathlib import Path

seen = {}
for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    fields = line.split("\t")
    if len(fields) != 2:
        raise SystemExit(1)
    name, visibility = fields
    if name in seen:
        raise SystemExit(1)
    seen[name] = visibility
if "milk-gateway" in seen and seen["milk-gateway"] != "private":
    raise SystemExit(1)
PY

failure_stage=registry-login
if ! "$gh" auth token --hostname github.com | \
  "$docker" --config "$docker_config" login ghcr.io \
    --username ShantanuJoshi --password-stdin >/dev/null; then
  fail 'private GHCR login failed' 77
fi

failure_stage=builder-create
"$docker" --config "$docker_config" buildx create \
  --name "$builder" \
  --driver docker-container \
  --driver-opt "image=$BUILDKIT_IMAGE" \
  "$endpoint" >/dev/null || fail 'cannot create the pinned local BuildKit builder' 70
builder_created=1
bootstrap_log=$scratch/builder.log
failure_stage=builder-bootstrap
if ! "$docker" --config "$docker_config" buildx inspect "$builder" --bootstrap >"$bootstrap_log" 2>&1; then
  cat "$bootstrap_log" >&2 || :
  fail 'cannot bootstrap the pinned local BuildKit builder' 70
fi
cat "$bootstrap_log" || :
builder_driver=$(sed -n 's/^Driver:[[:space:]]*//p' "$bootstrap_log")
builder_endpoint=$(sed -n 's/^Endpoint:[[:space:]]*//p' "$bootstrap_log")
builder_version=$(sed -n 's/^BuildKit version:[[:space:]]*//p' "$bootstrap_log")
[ "$builder_driver" = docker-container ] || fail 'builder driver is not docker-container' 70
[ "$builder_endpoint" = "$endpoint" ] || fail 'builder endpoint differs from the local Docker socket' 70
[ "$builder_version" = "$BUILDKIT_VERSION" ] || \
  fail "builder version differs from $BUILDKIT_VERSION" 70
"$python" - "$bootstrap_log" "$evidence_dir/builder.json" "$BUILDKIT_IMAGE" \
  "$BUILDKIT_VERSION" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, target, image, version = sys.argv[1:]
raw = Path(source).read_bytes()
Path(target).write_text(json.dumps({
    "schema_version": "milk.local-builder-observation.v1",
    "authority": "local-socket",
    "driver": "docker-container",
    "endpoint_kind": "local-socket",
    "buildkit_image_reference": image,
    "buildkit_version": version,
    "observation_sha256": hashlib.sha256(raw).hexdigest(),
    "observation_bytes": len(raw),
    "content_retained": False,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rm -f -- "$bootstrap_log"

tagged=$REPOSITORY:source-$commit
metadata=$evidence_dir/metadata.json
build_log=$scratch/build.log
build_started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
failure_stage=build
set +e
"$docker" --config "$docker_config" buildx build \
  --builder "$builder" \
  --platform linux/amd64 \
  --file "$dockerfile" \
  --label "org.opencontainers.image.revision=$commit" \
  --label "org.opencontainers.image.source=$SOURCE_REPOSITORY" \
  --provenance=mode=max,version=v1 \
  --sbom=true \
  --build-arg "BUILDKIT_SYNTAX=$DOCKERFILE_FRONTEND" \
  --build-arg "MILK_BUILDKIT_IMAGE_REFERENCE=$BUILDKIT_IMAGE" \
  --build-arg "MILK_SOURCE_COMMIT=$commit" \
  --build-arg "MILK_SOURCE_CONTEXT_SHA256=$context_sha256" \
  --build-arg "SOURCE_DATE_EPOCH=$source_epoch" \
  --metadata-file "$metadata" \
  --tag "$tagged" \
  --push \
  "$build_context" >"$build_log" 2>&1
build_status=$?
set -e
build_completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
cat "$build_log" || :
"$python" - "$build_log" "$evidence_dir/build-log.json" "$build_status" \
  "$build_started_at" "$build_completed_at" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, target, status, started_at, completed_at = sys.argv[1:]
raw = Path(source).read_bytes()
Path(target).write_text(json.dumps({
    "schema_version": "milk.content-free-build-log.v1",
    "artifact": "gateway",
    "exit_code": int(status),
    "started_at": started_at,
    "completed_at": completed_at,
    "sha256": hashlib.sha256(raw).hexdigest(),
    "bytes": len(raw),
    "content_retained": False,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
rm -f -- "$build_log"
"$python" - "$evidence_dir/build-log.json" "$evidence_dir/ops-log-reference.json" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

source, target = map(Path, sys.argv[1:])
raw = source.read_bytes()
Path(target).write_text(json.dumps({
    "schema_version": "milk.private-ops-log-reference.v1",
    "authority": "private-release-evidence",
    "reference": "build-log.json",
    "receipt_sha256": hashlib.sha256(raw).hexdigest(),
    "immutable": True,
    "content_retained": False,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
[ "$build_status" -eq 0 ] || fail 'gateway image build failed' 70

failure_stage=verify
verification=$(
  "$gh" auth token --hostname github.com | \
    "$python" "$repo/tools/verify-private-gateway.py" \
      --tagged-reference "$tagged" \
      --source-commit "$commit" \
      --source-date-epoch "$source_epoch" \
      --source-context-sha256 "$context_sha256" \
      --metadata "$metadata" \
      --docker-config "$docker_config" \
      --evidence-dir "$evidence_dir" \
      --registry-token-stdin
) || fail 'gateway image verification failed' 70
set -- $verification
[ "$#" -eq 2 ] || fail 'gateway admission result is invalid' 70
image_reference=$1
admission_sha256=$2

failure_stage=release-receipt
completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
"$python" - "$evidence_dir/release.json" "$commit" "$source_epoch" \
  "$image_reference" "$admission_sha256" "$BUILDKIT_IMAGE" "$DOCKERFILE_FRONTEND" \
  "$started_at" "$completed_at" "$evidence_dir/ops-log-reference.json" <<'PY'
import hashlib
import json
import re
import sys
from pathlib import Path

(
    path, commit, source_epoch, image_reference, admission_sha256, buildkit,
    frontend, started_at, completed_at, ops_log_path,
) = sys.argv[1:]
if re.fullmatch(r"ghcr\.io/milkinfrastructure/milk-gateway@sha256:[0-9a-f]{64}", image_reference) is None:
    raise SystemExit(1)
if re.fullmatch(r"[0-9a-f]{64}", admission_sha256) is None:
    raise SystemExit(1)
Path(path).write_text(json.dumps({
    "schema_version": "milk.private-gateway-release.v1",
    "source_commit": commit,
    "source_date_epoch": int(source_epoch),
    "source_repository": "https://github.com/milkinfrastructure/milk-gateway",
    "buildkit_image_reference": buildkit,
    "dockerfile_frontend_reference": frontend,
    "build_authority": "local-socket",
    "platform": "linux/amd64",
    "ops_log_reference_sha256": hashlib.sha256(Path(ops_log_path).read_bytes()).hexdigest(),
    "image": {
        "admission_sha256": admission_sha256,
        "artifact": "gateway",
        "image_reference": image_reference,
    },
    "started_at": started_at,
    "completed_at": completed_at,
}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
PY
"$python" - "$evidence_dir" <<'PY'
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
for path in root.rglob("*"):
    if path.is_file():
        os.chmod(path, 0o400, follow_symlinks=False)
PY
release_complete=1
printf 'private gateway image release verified at %s\n' "$evidence_dir"
