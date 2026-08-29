#!/usr/bin/env python3
import argparse
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


API_ROOT = "https://api.github.com"
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_TOKEN_BYTES = 8192
PACKAGE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
VISIBILITIES = {"internal", "private", "public"}
GITHUB_USERNAME = "ShantanuJoshi"


class GitHubRegistryError(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        raise GitHubRegistryError("GitHub API redirected unexpectedly")


def read_token(path, repository, stream=None):
    if path is None:
        raw = (stream or sys.stdin.buffer).read(MAX_TOKEN_BYTES + 1)
    else:
        path = Path(path)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            raise GitHubRegistryError("registry credential must be an absolute regular file")
        metadata = path.stat()
        try:
            path.resolve(strict=True).relative_to(Path(repository).resolve(strict=True))
        except ValueError:
            pass
        else:
            raise GitHubRegistryError("registry credential must be outside the checkout")
        if (
            metadata.st_uid != os.getuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o077
            or not 1 <= metadata.st_size <= MAX_TOKEN_BYTES
        ):
            raise GitHubRegistryError("registry credential file is not private")
        raw = path.read_bytes()
    if len(raw) > MAX_TOKEN_BYTES:
        raise GitHubRegistryError("registry credential exceeds its byte limit")
    token = raw.rstrip(b"\n")
    if (
        not token
        or len(raw) - len(token) > 1
        or any(byte < 33 or byte > 126 for byte in token)
        or b"\r" in raw
    ):
        raise GitHubRegistryError("registry credential is invalid")
    return token


def write_docker_config(directory, token):
    directory = Path(directory)
    if directory.is_symlink() or not directory.is_dir():
        raise GitHubRegistryError("Docker configuration directory is invalid")
    metadata = directory.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
        raise GitHubRegistryError("Docker configuration directory is not owner-only")
    encoded = base64.b64encode(GITHUB_USERNAME.encode("ascii") + b":" + token).decode("ascii")
    raw = (json.dumps(
        {"auths": {"ghcr.io": {"auth": encoded}}},
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n").encode("ascii")
    path = directory / "config.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    written = path.stat()
    if (
        written.st_uid != os.getuid()
        or written.st_nlink != 1
        or written.st_mode & 0o077
        or path.read_bytes() != raw
    ):
        raise GitHubRegistryError("Docker configuration was not written securely")
    return path


def _get_json(path, token):
    url = API_ROOT + path
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + token.decode("ascii"),
            "User-Agent": "milk-carton-release/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=60) as response:
            if response.url != url:
                raise GitHubRegistryError("GitHub API response URL changed")
            declared = response.headers.get("Content-Length")
            if declared is not None and int(declared) > MAX_RESPONSE_BYTES:
                raise GitHubRegistryError("GitHub API response exceeds its byte limit")
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError, ValueError) as error:
        if isinstance(error, GitHubRegistryError):
            raise
        raise GitHubRegistryError("cannot inspect GitHub container packages") from None
    if len(raw) > MAX_RESPONSE_BYTES:
        raise GitHubRegistryError("GitHub API response exceeds its byte limit")
    try:
        return json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GitHubRegistryError("GitHub API returned invalid JSON") from error


def package_visibility(token, organization, package_name):
    if organization != "milkinfrastructure" or PACKAGE_NAME.fullmatch(package_name) is None:
        raise GitHubRegistryError("GitHub package identity is invalid")
    found = None
    for page in range(1, 101):
        query = urllib.parse.urlencode(
            {"package_type": "container", "per_page": 100, "page": page}
        )
        packages = _get_json(f"/orgs/{organization}/packages?{query}", token)
        if not isinstance(packages, list) or len(packages) > 100:
            raise GitHubRegistryError("GitHub package inventory is invalid")
        for package in packages:
            if not isinstance(package, dict):
                raise GitHubRegistryError("GitHub package inventory is invalid")
            name = package.get("name")
            visibility = package.get("visibility")
            if (
                PACKAGE_NAME.fullmatch(name if isinstance(name, str) else "") is None
                or visibility not in VISIBILITIES
            ):
                raise GitHubRegistryError("GitHub package inventory is invalid")
            if name == package_name:
                if found is not None:
                    raise GitHubRegistryError("GitHub package inventory contains duplicates")
                found = visibility
        if len(packages) < 100:
            return found
    raise GitHubRegistryError("GitHub package inventory exceeds its page limit")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--token-file", type=Path)
    source.add_argument("--token-stdin", action="store_true")
    subcommands = parser.add_subparsers(dest="command", required=True)
    subcommands.add_parser("credential")
    docker_config = subcommands.add_parser("docker-config")
    docker_config.add_argument("directory", type=Path)
    visibility = subcommands.add_parser("package-visibility")
    visibility.add_argument("organization")
    visibility.add_argument("package")
    arguments = parser.parse_args(argv)
    try:
        token = read_token(arguments.token_file, arguments.repository)
        if arguments.command == "credential":
            sys.stdout.buffer.write(token + b"\n")
        elif arguments.command == "docker-config":
            write_docker_config(arguments.directory, token)
        else:
            value = package_visibility(token, arguments.organization, arguments.package)
            print(value or "absent")
        return 0
    except (OSError, UnicodeError, GitHubRegistryError) as error:
        print(f"github-registry: {error}", file=sys.stderr)
        return 77


if __name__ == "__main__":
    raise SystemExit(main())
