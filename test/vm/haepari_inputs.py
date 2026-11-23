#!/usr/bin/env python3
"""Opaque input sealing, execution request validation, and Job v2 spec builder for Mulgae VM qualification.

Provenance:
- Adapted from Haepari v0.1.0 (`800da97b7e2ca84a15d4ee5921702ec57bbc7d61`,
  build revision `fc3b975f8a99cacb96aecc988d3adbc04dda7309`)
  `examples/project-test/haepari_inputs.py`.
- Adapted for Mulgae `TASK-080` (`EPIC-016`, `aquarium/EPIC-032/TASK-092/mulgae-rollout/v1`).
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import errno
import struct
import unicodedata
import hashlib
import gzip
import json
import os
import platform
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any


HAEPARI_UPSTREAM_SOURCE_COMMIT = "800da97b7e2ca84a15d4ee5921702ec57bbc7d61"
HAEPARI_UPSTREAM_BUILD_REVISION = "fc3b975f8a99cacb96aecc988d3adbc04dda7309"
EXECUTION_REQUEST_SCHEMA = "mulgae.haepari-vm-request/v2"
BUNDLE_MANIFEST_SCHEMA = "mulgae.haepari-bundle-manifest/v1"
PRIOR_RELEASE_VERSION = "v0.1.26"
PRIOR_RELEASE_TAG_COMMIT = "c422590155f62380709c8f6fd08c9ad423badaaa"
PRIOR_RELEASE_INSTALL_TARGET = "github.com/irootkernel/mulgae@v0.1.26"

IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)
FORBIDDEN_CREDENTIAL_NAMES = {
    ".env",
    ".netrc",
    "auth.json",
    "credentials.json",
    "id_ed25519",
    "id_rsa",
    "known_hosts",
    "local.yaml",
}
FORBIDDEN_SECRET_FIELD_NAMES = {
    "api_key",
    "auth_token",
    "bearer_token",
    "client_secret",
    "cursor_auth_token",
    "password",
    "private_key",
    "refresh_token",
    "secret",
    "secret_key",
    "session_token",
    "token",
}

SKILL_SELECTED_FILES = [
    "skills/use-mulgae/SKILL.md",
    "skills/use-mulgae/references/authoring.md",
    "skills/use-mulgae/references/legacy.md",
    "skills/use-mulgae/references/lifecycle.md",
    "skills/use-mulgae/references/recovery.md",
    "skills/use-mulgae/references/verified-reads.md",
]

TEST_SELECTED_FILES = [
    "test/vm/run.sh",
    "test/vm/guest.py",
    "test/vm/gui.py",
    "test/vm/finalize.py",
    "test/vm/haepari_inputs.py",
    "test/vm/scenarios.md",
]

DEFAULT_SELECTED_FILES = TEST_SELECTED_FILES + SKILL_SELECTED_FILES

MANUAL_SCENARIO_IDS = [
    "installed-cli-mcp-transport-check",
    "fresh-session-skill-discovery-check",
    "prior-state-migration-coexistence-check",
    "post-manual-cleanup-inventory-check",
]

DEFAULT_SUITES: dict[str, dict[str, Any]] = {
    "guest-qualification": {
        "command": ["/bin/sh", "bundle/test/vm/run.sh", "guest-qualification"],
        "requires_live_accounts": False,
        "outputs": [
            "results/guest-qualification/result.json",
            "results/guest-qualification/inventory-before.json",
            "results/guest-qualification/prior-release-baseline.json",
            "results/guest-qualification/candidate-install.json",
            "results/guest-qualification/transport-qualification.json",
            "results/guest-qualification/coordination-scenarios.json",
            "results/guest-qualification/native-driver.log",
            "results/guest-qualification/prior-build.log",
            "results/guest-qualification/prior-module.json",
            "results/guest-qualification/prior-module.stderr.log",
            "results/guest-qualification/prior-state.json",
            "results/guest-qualification/native-evidence.json",
            "results/guest-qualification/inventory-after.json",
            "results/guest-qualification/consumer-cleanup.json",
            "results/guest-qualification/post-cleanup-inventory.json",
        ],
        "manual": {
            "instructions": "bundle/test/vm/scenarios.md",
            "scenarios": list(MANUAL_SCENARIO_IDS),
        },
    },
    "live-providers": {
        "command": ["/bin/sh", "bundle/test/vm/run.sh", "live-providers"],
        "requires_live_accounts": True,
        "outputs": [
            "results/live-providers/result.json",
            "results/live-providers/gui-execution.json",
            "results/live-providers/gui-worker-result.json",
            "results/live-providers/gui-guest.log",
            "results/live-providers/inventory-before.json",
            "results/live-providers/live-providers-summary.json",
            "results/live-providers/test-e2e.log",
            "results/live-providers/test-grok.log",
            "results/live-providers/test-mcp-requirements-clients.log",
            "results/live-providers/inventory-after.json",
            "results/live-providers/consumer-cleanup.json",
            "results/live-providers/post-cleanup-inventory.json",
        ],
    },
    "manual-qualification": {
        "command": ["/bin/sh", "bundle/test/vm/run.sh", "manual-qualification"],
        "requires_live_accounts": False,
        "outputs": [
            "results/manual-qualification/result.json",
            "results/manual-qualification/inventory-before.json",
            "results/manual-qualification/manual-staging.json",
            "results/manual-qualification/inventory-after.json",
            "results/manual-qualification/consumer-cleanup.json",
            "results/manual-qualification/post-cleanup-inventory.json",
        ],
        "manual": {
            "instructions": "bundle/test/vm/scenarios.md",
            "scenarios": list(MANUAL_SCENARIO_IDS),
        },
    },
}

DEFAULT_TIMEOUTS = {
    "prepare": "2m",
    "workload": "25m",
    "manual": "30m",
    "collect": "2m",
    "cleanup": "2m",
    "total": "65m",
    "wait": "10m",
}


class Refusal(Exception):
    """Classified contract refusal that fails closed before or around native submission."""


@contextmanager
def _open_regular(path: Path):
    # Haepari v0.1.0 example: descriptor-relative, no-follow traversal and stable reads.
    path = Path(path).absolute()
    parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            successor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = successor
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
            raise Refusal(f"input must use physical directories and a regular file: {path}") from None
        raise
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise Refusal(f"input must be a regular file with one link: {path}")
        yield stream, before
        after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_mode")
        if any(getattr(before, key) != getattr(after, key) for key in fields):
            raise Refusal(f"input changed during capture: {path}")


def _relative_paths(paths: list[str]) -> list[str]:
    if not isinstance(paths, list) or not 1 <= len(paths) <= 1000:
        raise Refusal("selected_files must declare between one and 1000 paths")
    seen: list[tuple[str, ...]] = []
    spellings: list[str] = []
    sensitive = FORBIDDEN_CREDENTIAL_NAMES | {
        ".ssh", ".aws", ".gnupg", ".kube", ".codex", ".azure", ".docker", "gcloud",
        ".npmrc", ".pypirc", "credentials", "application_default_credentials.json",
        "id_ecdsa", "id_dsa",
    }
    for name in paths:
        if (not isinstance(name, str) or not name or len(name.encode("utf-8")) > 512
                or name.startswith("/") or "\\" in name
                or any(ord(char) < 32 or ord(char) == 127 for char in name)
                or any(part in ("", ".", "..") for part in name.split("/"))):
            raise Refusal(f"input requires a normalized relative POSIX path: {name!r}")
        if any(part in sensitive or part.startswith(".env.") or part.endswith((".pem", ".key", ".p12", ".pfx"))
               for part in name.lower().split("/")):
            raise Refusal(f"credential-like input path is forbidden: {name}")
        folded = tuple(unicodedata.normalize("NFC", part).casefold() for part in name.split("/"))
        if any(folded[:len(other)] == other or other[:len(folded)] == folded for other in seen):
            raise Refusal(f"input paths repeat, alias or overlap: {name}")
        for previous in spellings:
            for left, right in zip(name.split("/"), previous.split("/")):
                if unicodedata.normalize("NFC", left).casefold() != unicodedata.normalize("NFC", right).casefold():
                    break
                if left != right:
                    raise Refusal(f"input components alias by case or Unicode: {name}")
        seen.append(folded)
        spellings.append(name)
    return paths


def regular_file(root: Path, raw: str) -> tuple[str, Path]:
    _relative_paths([raw])
    path = root / raw
    with _open_regular(path):
        pass
    return raw, path


def regular_bytes(path: Path, label: str | None = None) -> bytes:
    with _open_regular(path) as (stream, _):
        return stream.read()

def file_digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(regular_bytes(path)).hexdigest()


def validate_paths(root: Path, paths: list[str]) -> list[tuple[str, Path]]:
    return [regular_file(root, name) for name in sorted(_relative_paths(paths))]


def tree_digest(entries: list[tuple[str, Path]]) -> str:
    # Exact haepari-tree-sha256/v1 bytes; the prefix is only this consumer's display convention.
    _relative_paths([name for name, _ in entries])
    digest = hashlib.sha256(b"haepari-tree-sha256/v1\0")
    for name, full in sorted(entries, key=lambda item: item[0].encode("utf-8")):
        with _open_regular(full) as (stream, info):
            content = hashlib.sha256(stream.read()).digest()
            encoded = name.encode("utf-8")
            digest.update(struct.pack(">Q", len(encoded)) + encoded + bytes([bool(info.st_mode & 0o111)]))
            digest.update(struct.pack(">Q", info.st_size) + content)
    return "sha256:" + digest.hexdigest()


def validate_guest_identity(
    raw_parent: str, platform_name: str, hypervisor_present: str,
    actual_uuid: str, expected_uuid: str, installation_id: str,
) -> dict[str, object]:
    """Validate observed machine facts without changing the native inherited chain."""
    if platform_name != "Darwin" or hypervisor_present != "1":
        raise Refusal("physical host execution is forbidden; a Darwin virtual guest is required")
    if (not isinstance(expected_uuid, str) or not UUID_RE.fullmatch(expected_uuid)
            or not isinstance(actual_uuid, str) or actual_uuid.upper() != expected_uuid.upper()):
        raise Refusal("guest hardware UUID mismatch")
    if not isinstance(raw_parent, str) or len(raw_parent.encode("utf-8")) > 8192:
        raise Refusal("invalid HAEPARI_PARENT_CONTEXT")
    try:
        chain = json.loads(raw_parent)
    except (ValueError, TypeError) as exc:
        raise Refusal("invalid HAEPARI_PARENT_CONTEXT") from exc
    if not isinstance(chain, list) or not 1 <= len(chain) <= 32:
        raise Refusal("HAEPARI_PARENT_CONTEXT must be a nonempty native ParentChain array")
    for entry in chain:
        if not isinstance(entry, dict) or set(entry) != {"installation_id", "job_id", "lease_generation", "nonce"}:
            raise Refusal("invalid native parent entry fields")
        valid_identifier(entry["installation_id"], "native parent installation_id")
        valid_identifier(entry["job_id"], "native parent job_id")
        if (type(entry["lease_generation"]) is not int or not 1 <= entry["lease_generation"] < 2**63
                or not isinstance(entry["nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["nonce"])):
            raise Refusal("invalid native parent lease or nonce")
    current = chain[-1]
    if current["installation_id"] != installation_id:
        raise Refusal("native parent Installation does not match the sealed execution request")
    return {key: current[key] for key in ("installation_id", "job_id", "lease_generation")}


def duration_seconds(value: str) -> int:
    match = re.fullmatch(r"([1-9][0-9]*)([smh])", value)
    if not match:
        raise Refusal("phase budgets must be positive whole seconds, minutes or hours")
    seconds = int(match[1]) * {"s": 1, "m": 60, "h": 3600}[match[2]]
    if seconds > 86400:
        raise Refusal("phase budget exceeds the native 24-hour limit")
    return seconds

def valid_identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.match(value):
        raise Refusal(f"{field} must be a safe identifier")
    return value


def _require_mapping(obj: object, field: str) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise Refusal(f"{field} must be a JSON object")
    return obj


def _require_non_empty_str(obj: dict[str, Any], key: str, parent: str) -> str:
    val = obj.get(key)
    if not isinstance(val, str) or not val.strip():
        raise Refusal(f"{parent}.{key} must be a non-empty string")
    return val.strip()


def _require_sha256(obj: dict[str, Any], key: str, parent: str) -> str:
    val = _require_non_empty_str(obj, key, parent)
    if not SHA256_DIGEST_RE.match(val):
        raise Refusal(f"{parent}.{key} must match sha256:<64 lowercase hex>")
    return val


def _reject_embedded_secrets(node: object, path: str = "request") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            lowered = str(key).strip().lower()
            if lowered in FORBIDDEN_SECRET_FIELD_NAMES:
                raise Refusal(
                    f"{path}.{key} is forbidden: execution requests must never embed raw secrets or credentials"
                )
            _reject_embedded_secrets(value, f"{path}.{key}")
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            _reject_embedded_secrets(item, f"{path}[{idx}]")


def _validate_profile_file(repo_root: Path, raw_path: str, expected_digest: str, label: str) -> tuple[Path, bytes]:
    candidate = Path(raw_path)
    if not candidate.is_absolute():
        _, candidate = regular_file(repo_root, raw_path)
    else:
        try:
            st = candidate.lstat()
        except OSError as exc:
            raise Refusal(f"missing {label} profile file {raw_path}: {exc}") from exc
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            raise Refusal(f"{label} profile file must be a regular non-symlink file: {raw_path}")
    data = regular_bytes(candidate, raw_path)
    actual_digest = "sha256:" + hashlib.sha256(data).hexdigest()
    if actual_digest != expected_digest:
        raise Refusal(
            f"{label} profile digest mismatch for {raw_path}: expected {expected_digest}, got {actual_digest}"
        )
    return candidate, data


def validate_execution_request(
    request_data: object,
    repo_root: Path,
    suite_name: str,
    suite_cfg: dict[str, Any],
) -> dict[str, Any]:
    req = _require_mapping(request_data, "request")
    if req.get("schema") != EXECUTION_REQUEST_SCHEMA:
        raise Refusal(f"request.schema must be {EXECUTION_REQUEST_SCHEMA}; regenerate v1 requests with the current toolchain declarations")
    _reject_embedded_secrets(req)

    haepari_cfg = _require_mapping(req.get("haepari"), "request.haepari")
    executable_path = _require_non_empty_str(haepari_cfg, "executable", "request.haepari")
    executable_sha256 = _require_sha256(haepari_cfg, "executable_sha256", "request.haepari")
    installation_root = _require_non_empty_str(haepari_cfg, "installation_root", "request.haepari")
    if not Path(installation_root).is_absolute():
        raise Refusal("request.haepari.installation_root must be an absolute path")
    installation_id = _require_non_empty_str(haepari_cfg, "installation_id", "request.haepari")

    resource_cfg = _require_mapping(req.get("resource"), "request.resource")
    resource_id = valid_identifier(resource_cfg.get("id"), "request.resource.id")
    resource_kind = _require_non_empty_str(resource_cfg, "kind", "request.resource")
    if resource_kind != "utm-macos":
        raise Refusal("request.resource.kind must be utm-macos")
    config_rev = resource_cfg.get("configuration_revision")
    if isinstance(config_rev, bool) or not isinstance(config_rev, int) or config_rev < 1:
        raise Refusal("request.resource.configuration_revision must be a positive integer")

    guest_cfg = _require_mapping(req.get("guest"), "request.guest")
    expected_uuid = _require_non_empty_str(guest_cfg, "expected_hardware_uuid", "request.guest")
    if not UUID_RE.match(expected_uuid):
        raise Refusal("request.guest.expected_hardware_uuid must be a canonical UUID")

    guest_tools = {}
    for field in ("go_executable", "python_executable", "prior_go_executable"):
        if field not in guest_cfg:
            raise Refusal(f"request.guest.{field} is required")
        if field in guest_cfg:
            value = _require_non_empty_str(guest_cfg, field, "request.guest")
            if not Path(value).is_absolute() or str(Path(value)) != value:
                raise Refusal(f"request.guest.{field} must be an absolute normalized path")
            guest_tools[field] = value

    profiles_cfg = _require_mapping(req.get("profiles"), "request.profiles")
    starting_id = _require_non_empty_str(profiles_cfg, "starting_profile_id", "request.profiles")
    starting_file = _require_non_empty_str(profiles_cfg, "starting_profile_file", "request.profiles")
    starting_sha = _require_sha256(profiles_cfg, "starting_profile_sha256", "request.profiles")
    target_id = _require_non_empty_str(profiles_cfg, "target_profile_id", "request.profiles")
    target_file = _require_non_empty_str(profiles_cfg, "target_profile_file", "request.profiles")
    target_sha = _require_sha256(profiles_cfg, "target_profile_sha256", "request.profiles")

    starting_path, starting_bytes = _validate_profile_file(repo_root, starting_file, starting_sha, "starting")
    target_path, target_bytes = _validate_profile_file(repo_root, target_file, target_sha, "target")

    if starting_id != target_id and starting_sha == target_sha:
        raise Refusal(
            f"profile relabeling is forbidden: starting_profile_id ({starting_id}) and "
            f"target_profile_id ({target_id}) share identical digest {target_sha}"
        )
    if "v0.2.16" in target_id and b"v0.2.14" in target_bytes and b"v0.2.16" not in target_bytes:
        raise Refusal(
            "profile relabeling is forbidden: target_profile_file contains v0.2.14 profile identity while claiming v0.2.16"
        )

    candidate_cfg = _require_mapping(req.get("candidate"), "request.candidate")
    source_commit = _require_non_empty_str(candidate_cfg, "source_commit", "request.candidate")
    if not GIT_SHA_RE.match(source_commit):
        raise Refusal("request.candidate.source_commit must be a 40-hex Git commit SHA")
    binary_sha256 = _require_sha256(candidate_cfg, "binary_sha256", "request.candidate")
    skill_tree_obj = _require_non_empty_str(candidate_cfg, "skill_tree_git_object", "request.candidate")
    if not GIT_SHA_RE.match(skill_tree_obj):
        raise Refusal("request.candidate.skill_tree_git_object must be a 40-hex Git tree SHA")
    auth_ref = _require_non_empty_str(candidate_cfg, "authorization_reference", "request.candidate")

    prior_cfg = _require_mapping(req.get("prior_release"), "request.prior_release")
    prior_ver = _require_non_empty_str(prior_cfg, "version", "request.prior_release")
    prior_commit = _require_non_empty_str(prior_cfg, "tag_commit", "request.prior_release")
    prior_target = _require_non_empty_str(prior_cfg, "install_target", "request.prior_release")
    if prior_ver != PRIOR_RELEASE_VERSION:
        raise Refusal(f"request.prior_release.version must be {PRIOR_RELEASE_VERSION}")
    if prior_commit != PRIOR_RELEASE_TAG_COMMIT:
        raise Refusal(f"request.prior_release.tag_commit must be {PRIOR_RELEASE_TAG_COMMIT}")
    if prior_target != PRIOR_RELEASE_INSTALL_TARGET:
        raise Refusal(f"request.prior_release.install_target must be {PRIOR_RELEASE_INSTALL_TARGET}")
    toolchains = toolchain_versions(repo_root)
    if "toolchains" in req and req["toolchains"] != toolchains:
        raise Refusal("request toolchains differ from the project declarations")
    go_toolchain = "go" + toolchains["PRIOR_GO_VERSION"]
    if prior_cfg.get("go_toolchain", go_toolchain) != go_toolchain:
        raise Refusal("prior release Go differs from the declared prior-release compiler")
    goproxy = _require_non_empty_str(prior_cfg, "goproxy", "request.prior_release")
    network_exposure = _require_non_empty_str(prior_cfg, "network_exposure", "request.prior_release")

    review_controller_home = _require_non_empty_str(req, "review_controller_home", "request")
    if not Path(review_controller_home).is_absolute():
        raise Refusal("request.review_controller_home must be an absolute guest path")
    if Path(review_controller_home) == Path(installation_root):
        raise Refusal(
            "request.review_controller_home must be isolated from outer request.haepari.installation_root"
        )

    live_accounts = req.get("live_accounts")
    validated_live: dict[str, Any] | None = None
    if suite_cfg.get("requires_live_accounts") or live_accounts is not None:
        if live_accounts is None:
            raise Refusal(f"suite {suite_name} requires request.live_accounts")
        live_map = _require_mapping(live_accounts, "request.live_accounts")
        if set(live_map) != {"zcode", "grok", "mcp_clients"}:
            raise Refusal(
                "request.live_accounts must declare only zcode, grok, and mcp_clients"
            )
        zcode_cfg = _require_mapping(live_map.get("zcode"), "request.live_accounts.zcode")
        _require_non_empty_str(zcode_cfg, "app_bundle", "request.live_accounts.zcode")
        _require_non_empty_str(zcode_cfg, "account_alias", "request.live_accounts.zcode")

        grok_cfg = _require_mapping(live_map.get("grok"), "request.live_accounts.grok")
        _require_non_empty_str(grok_cfg, "executable", "request.live_accounts.grok")
        _require_non_empty_str(grok_cfg, "account_alias", "request.live_accounts.grok")

        mcp_cfg = _require_mapping(live_map.get("mcp_clients"), "request.live_accounts.mcp_clients")
        _require_non_empty_str(mcp_cfg, "codex_binary", "request.live_accounts.mcp_clients")
        _require_non_empty_str(mcp_cfg, "claude_binary", "request.live_accounts.mcp_clients")
        _require_non_empty_str(mcp_cfg, "claude_account_alias", "request.live_accounts.mcp_clients")
        validated_live = live_map

    return {
        "schema": EXECUTION_REQUEST_SCHEMA,
        "toolchains": toolchains,
        "haepari": {
            "executable": executable_path,
            "executable_sha256": executable_sha256,
            "installation_root": installation_root,
            "installation_id": installation_id,
        },
        "resource": {
            "id": resource_id,
            "kind": resource_kind,
            "configuration_revision": config_rev,
        },
        "guest": {
            "expected_hardware_uuid": expected_uuid,
            **guest_tools,
        },
        "profiles": {
            "starting_profile_id": starting_id,
            "starting_profile_file": str(starting_path),
            "starting_profile_sha256": starting_sha,
            "target_profile_id": target_id,
            "target_profile_file": str(target_path),
            "target_profile_sha256": target_sha,
        },
        "candidate": {
            "source_commit": source_commit,
            "binary_sha256": binary_sha256,
            "skill_tree_git_object": skill_tree_obj,
            "authorization_reference": auth_ref,
        },
        "prior_release": {
            "version": prior_ver,
            "tag_commit": prior_commit,
            "install_target": prior_target,
            "go_toolchain": go_toolchain,
            "goproxy": goproxy,
            "network_exposure": network_exposure,
        },
        "review_controller_home": review_controller_home,
        "live_accounts": validated_live,
    }


def capture_inputs(
    repo_root: Path,
    run_dir: Path,
    selected_files: list[str],
    validated_request: dict[str, Any] | None = None,
) -> dict[str, str]:
    entries = validate_paths(repo_root, selected_files)
    bundle = run_dir / "bundle"
    if bundle.exists():
        raise Refusal("sealed bundle already exists; preserve this incomplete preparation")
    bundle.mkdir(mode=0o700)

    copied: list[tuple[str, Path]] = []
    file_hashes: dict[str, str] = {}
    for rel, src in entries:
        dst = bundle / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        with _open_regular(src) as (stream, info):
            data = stream.read()
            with dst.open("xb") as output:
                output.write(data)
                output.flush()
                os.fsync(output.fileno())
            dst.chmod(0o700 if info.st_mode & 0o111 else 0o600)
        copied.append((rel, dst))
        file_hashes[rel] = "sha256:" + hashlib.sha256(data).hexdigest()

    if validated_request is not None:
        profiles = validated_request["profiles"]
        profiles_dir = bundle / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        for slot in ("starting", "target"):
            src_path = Path(profiles[f"{slot}_profile_file"])
            pdata = regular_bytes(src_path, str(src_path))
            rel_prof = f"profiles/{slot}-profile.json"
            dst_prof = bundle / rel_prof
            dst_prof.write_bytes(pdata)
            dst_prof.chmod(0o600)
            copied.append((rel_prof, dst_prof))
            file_hashes[rel_prof] = "sha256:" + hashlib.sha256(pdata).hexdigest()

        req_rel = "profiles/execution-request.json"
        req_bytes = (json.dumps(validated_request, indent=2, sort_keys=True) + "\n").encode("utf-8")
        req_dst = bundle / req_rel
        req_dst.write_bytes(req_bytes)
        req_dst.chmod(0o600)
        copied.append((req_rel, req_dst))
        file_hashes[req_rel] = "sha256:" + hashlib.sha256(req_bytes).hexdigest()

    bundle_tree = tree_digest(copied)
    skill_entries = [(rel, full) for rel, full in copied if rel.startswith("skills/use-mulgae/")]
    test_entries = [(rel, full) for rel, full in copied if rel.startswith(("test/vm/", "source/"))]
    profile_entries = [(rel, full) for rel, full in copied if rel.startswith("profiles/")]

    candidate_digest = (
        validated_request["candidate"]["binary_sha256"]
        if validated_request is not None
        else bundle_tree
    )
    tests_digest = tree_digest(test_entries) if test_entries else bundle_tree
    inventory_digest = tree_digest(skill_entries) if skill_entries else bundle_tree
    profile_digest = (
        validated_request["profiles"]["target_profile_sha256"]
        if validated_request is not None
        else (tree_digest(profile_entries) if profile_entries else bundle_tree)
    )

    digests = {
        "candidate_digest": candidate_digest,
        "tests_digest": tests_digest,
        "inventory_digest": inventory_digest,
        "profile_digest": profile_digest,
    }
    manifest_payload = {
        "schema": BUNDLE_MANIFEST_SCHEMA,
        "bundle_tree_digest": bundle_tree,
        "digests": digests,
        "files": file_hashes,
    }
    manifest_bytes = (json.dumps(manifest_payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    manifest_file = bundle / "bundle-manifest.json"
    manifest_file.write_bytes(manifest_bytes)
    manifest_file.chmod(0o600)
    (run_dir / "bundle-manifest.json").write_bytes(manifest_bytes)
    (run_dir / "bundle-manifest.json").chmod(0o600)
    return digests



def remove_owned_tree(root: Path) -> None:
    """Remove a private owned tree, including Go's read-only cache directories."""
    for base, _, _ in os.walk(root, followlinks=False):
        path = Path(base)
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise Refusal("temporary cleanup encountered an unowned directory")
        os.chmod(path, stat.S_IMODE(info.st_mode) | stat.S_IWUSR | stat.S_IXUSR,
                 follow_symlinks=False)
    shutil.rmtree(root)


def toolchain_root() -> Path:
    base = Path(__file__).resolve().parents[2]
    return base if (base / "go.mod").is_file() else base / "source"


def toolchain_versions(root: Path) -> dict[str, str]:
    values = {}
    for line in regular_bytes(root / "tools/toolchains.env").decode().splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(GO_VERSION|PYTHON_VERSION|PRIOR_GO_VERSION)=([0-9]+\.[0-9]+\.[0-9]+)", line)
        if not match or match[1] in values:
            raise Refusal("invalid or duplicate exact toolchain declaration")
        values[match[1]] = match[2]
    if set(values) != {"GO_VERSION", "PYTHON_VERSION", "PRIOR_GO_VERSION"}:
        raise Refusal("incomplete toolchain declarations")
    return values


def require_python(root: Path | None = None) -> dict[str, str]:
    values = toolchain_versions(root or toolchain_root())
    if platform.python_version() != values["PYTHON_VERSION"]:
        raise Refusal("Python differs from the exact project pin; invoke through ./dev python")
    return values


def check_python_entrypoint() -> None:
    try:
        require_python()
    except (Refusal, OSError, UnicodeError) as exc:
        print("refused: " + str(exc), file=sys.stderr)
        raise SystemExit(2) from exc


def resolve_tool(root: Path, role: str, executable: str) -> str:
    names = {"go": "MULGAE_GO_EXECUTABLE", "prior-go": "MULGAE_PRIOR_GO_EXECUTABLE"}
    env = dict(os.environ)
    if executable:
        env[names[role]] = executable
    try:
        result = subprocess.run([str(root / "dev"), "path", role], env=env,
                                capture_output=True, text=True, check=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise Refusal(f"{role} does not satisfy the declared toolchain") from exc
    return result.stdout.strip()


def candidate_binary_bytes(root: Path) -> bytes:
    """Read one sealed candidate representation without changing executable identity."""
    plain = root / "artifacts/mulgae"
    compressed = root / "artifacts/mulgae.gz"
    if os.path.lexists(plain) == os.path.lexists(compressed):
        raise Refusal("prepared candidate requires exactly one binary representation")
    if compressed.exists():
        try:
            return gzip.decompress(regular_bytes(compressed))
        except (OSError, EOFError) as exc:
            raise Refusal("prepared candidate gzip is invalid") from exc
    return regular_bytes(plain)


def verify_prepared_candidate(root: Path, request: dict[str, Any]) -> dict[str, Any]:
    """Bind the prepared artifact and all declared bytes before VM admission."""
    receipt = json.loads(regular_bytes(root / "artifacts/candidate.json"))
    if not isinstance(receipt, dict) or receipt.get("schema") != "mulgae.vm-prepared-candidate/v1":
        raise Refusal("unsupported prepared candidate receipt")
    for field in ("source_commit", "binary_sha256", "skill_tree_git_object"):
        if receipt.get(field) != request["candidate"][field]:
            raise Refusal("prepared candidate identity does not match the execution request")
    files = receipt.get("files")
    if (not isinstance(files, dict) or not files
            or len({"artifacts/mulgae", "artifacts/mulgae.gz"} & set(files)) != 1):
        raise Refusal("prepared candidate file inventory is incomplete")
    if request.get("schema") == EXECUTION_REQUEST_SCHEMA:
        required = {"source/dev", "source/tools/toolchains.env", "source/tools/mise.toml"}
        if (receipt.get("toolchains") != request["toolchains"]
                or not required.issubset(files)
                or toolchain_versions(root / "source") != request["toolchains"]):
            raise Refusal("prepared toolchain declarations or runner inventory differ from the request")
    for name in _relative_paths(list(files)):
        _, path = regular_file(root, name)
        if file_digest(path) != files[name]:
            raise Refusal("prepared candidate file changed: " + name)
    if "artifacts/haepari" in files:
        expected_native = request["haepari"]["executable_sha256"]
        if files["artifacts/haepari"] != expected_native or receipt.get("native_controller_sha256") != expected_native:
            raise Refusal("prepared Haepari does not match the admitted released unit")
    if "sha256:"+hashlib.sha256(candidate_binary_bytes(root)).hexdigest() != request["candidate"]["binary_sha256"]:
        raise Refusal("prepared binary does not match the admitted candidate")
    if "artifacts/mulgae" in files and not (root / "artifacts/mulgae").stat().st_mode & 0o111:
        raise Refusal("prepared candidate binary is not executable")
    return receipt

def verify_sealed_bundle(bundle_root: Path, manifest_path: Path | None = None) -> dict[str, Any]:
    if manifest_path is None:
        manifest_path = bundle_root / "bundle-manifest.json"
    raw = regular_bytes(manifest_path, str(manifest_path))
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise Refusal(f"invalid bundle manifest JSON: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != BUNDLE_MANIFEST_SCHEMA:
        raise Refusal(f"bundle manifest schema must be {BUNDLE_MANIFEST_SCHEMA}")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise Refusal("bundle manifest files map must not be empty")

    entries: list[tuple[str, Path]] = []
    for rel, expected_hash in sorted(files.items()):
        rel_clean, full = regular_file(bundle_root, str(rel))
        actual_hash = file_digest(full)
        if actual_hash != expected_hash:
            raise Refusal(
                f"sealed bundle file tampered for {rel_clean}: expected {expected_hash}, got {actual_hash}"
            )
        entries.append((rel_clean, full))

    actual_tree = tree_digest(entries)
    if actual_tree != manifest.get("bundle_tree_digest"):
        raise Refusal(
            f"sealed bundle tree digest mismatch: expected {manifest.get('bundle_tree_digest')}, got {actual_tree}"
        )
    return manifest


def validate_recipe(suite_name: str, suite_cfg: dict[str, Any], selected_files: list[str]) -> list[str]:
    valid_identifier(suite_name, "suite")
    command = suite_cfg.get("command")
    if not isinstance(command, list) or len(command) < 2 or not all(isinstance(x, str) and x for x in command):
        raise Refusal(f"suite {suite_name} command must be a non-empty string argv list")
    if command[0] != "/bin/sh":
        raise Refusal(f"suite {suite_name} must use /bin/sh as explicit interpreter")
    recipe = command[1]
    if not recipe.startswith("bundle/"):
        raise Refusal(f"suite {suite_name} recipe must run from bundle/")
    rel = recipe.removeprefix("bundle/")
    if rel not in selected_files:
        raise Refusal(f"suite {suite_name} recipe {rel} must be listed in selected_files")
    return command


def validate_manual_selection(
    suite_name: str, suite_cfg: dict[str, Any], mode: str, selected_files: list[str]
) -> dict[str, object] | None:
    if mode == "auto":
        return None
    if mode != "manual":
        raise Refusal("mode must be auto or manual")
    manual = suite_cfg.get("manual")
    if not isinstance(manual, dict):
        raise Refusal(f"suite {suite_name} does not declare manual instructions and scenarios")
    instructions = manual.get("instructions")
    scenarios = manual.get("scenarios")
    if not isinstance(instructions, str) or not instructions.startswith("bundle/"):
        raise Refusal(f"suite {suite_name} manual instructions must point into bundle/")
    rel = instructions.removeprefix("bundle/")
    if rel not in selected_files:
        raise Refusal(f"suite {suite_name} manual instructions {rel} must be in selected_files")
    if not isinstance(scenarios, list) or not scenarios:
        raise Refusal(f"suite {suite_name} manual scenarios must not be empty")
    cleaned = [valid_identifier(item, "manual scenario") for item in scenarios]
    return {"instructions": instructions, "scenarios": cleaned}


def validate_manual_completion_ready(
    run_dir: Path, suite_name: str, manual_result_path: Path, expected: dict[str, Any],
) -> dict[str, Any]:
    results_dir = run_dir / "results" / suite_name
    cleanup_path = results_dir / "consumer-cleanup.json"
    inventory_path = results_dir / "post-cleanup-inventory.json"
    if not cleanup_path.is_file() or not inventory_path.is_file():
        raise Refusal("manual complete requires consumer-cleanup.json and post-cleanup-inventory.json")
    cleanup = json.loads(regular_bytes(cleanup_path))
    inventory = json.loads(regular_bytes(inventory_path))
    manual = json.loads(regular_bytes(manual_result_path))
    for doc, schema in (
        (cleanup, "mulgae.vm-consumer-cleanup/v1"),
        (inventory, "mulgae.vm-guest-inventory/v1"),
    ):
        if not isinstance(doc, dict) or doc.get("schema") != schema:
            raise Refusal("unsupported consumer cleanup or inventory schema")
        if any(doc.get(key) != value for key, value in expected.items() if key != "expected_revision"):
            raise Refusal("consumer cleanup/inventory does not match this Job and sealed candidate/profile")
    if (cleanup.get("status") != "clean"
            or cleanup.get("post_cleanup_inventory_sha256") != file_digest(inventory_path)
            or inventory.get("remaining_owned_roots") != [] or inventory.get("remaining_helper_pids") != []):
        raise Refusal("consumer cleanup has not verified its actual owned inventory")
    fields = {"schema", "job_id", "installation_id", "profile_id", "profile_digest",
              "expected_revision", "observer", "scenarios"}
    if (not isinstance(manual, dict) or set(manual) != fields
            or manual["schema"] != "haepari.manual-result/v1"
            or not isinstance(manual["observer"], str) or not manual["observer"].strip()):
        raise Refusal("manual input must use the closed native haepari.manual-result/v1 fields")
    for key in ("job_id", "installation_id", "profile_id", "profile_digest", "expected_revision"):
        if manual.get(key) != expected[key]:
            raise Refusal("native manual input does not match the current Job/profile/revision")
    scenarios = manual["scenarios"]
    if not isinstance(scenarios, list):
        raise Refusal("native manual scenarios must be a list")
    seen = set()
    for scenario in scenarios:
        if (not isinstance(scenario, dict) or set(scenario) != {"id", "status", "evidence_references"}
                or not isinstance(scenario.get("id"), str)
                or scenario.get("id") in seen or scenario.get("id") not in MANUAL_SCENARIO_IDS
                or scenario.get("status") not in {"pass", "fail", "unobserved"}):
            raise Refusal("invalid native manual scenario")
        seen.add(scenario["id"])
        references = scenario["evidence_references"]
        if not isinstance(references, list) or (scenario["status"] != "unobserved" and not references):
            raise Refusal("observed manual scenarios require original staged evidence")
        if references:
            for name in _relative_paths(references):
                regular_file(run_dir, name)
    if seen != set(MANUAL_SCENARIO_IDS):
        raise Refusal("manual input omits a required scenario")
    return {"cleanup": cleanup, "post_cleanup_inventory": inventory, "manual_result": manual}


def job_spec(
    *,
    resource: str,
    command: list[str],
    suite_name: str,
    mode: str,
    digests: dict[str, str],
    outputs: list[str],
    timeouts: dict[str, str],
    manual: dict[str, object] | None,
    validated_request: dict[str, Any],
    run_dir: Path,
) -> dict[str, object]:
    _relative_paths(outputs)
    manifest = verify_sealed_bundle(run_dir / "bundle")
    selected = ["bundle/" + name for name in manifest["files"]] + ["bundle/bundle-manifest.json"]
    input_entries = [(name, run_dir / name) for name in selected]
    env = {
        "MULGAE_VM_SUITE": suite_name, "MULGAE_VM_MODE": mode,
        "MULGAE_VM_EXPECTED_GUEST_UUID": validated_request["guest"]["expected_hardware_uuid"],
        "MULGAE_VM_REVIEW_CONTROLLER_HOME": validated_request["review_controller_home"],
        "MULGAE_VM_CANDIDATE_COMMIT": validated_request["candidate"]["source_commit"],
        "MULGAE_VM_CANDIDATE_BINARY_SHA256": validated_request["candidate"]["binary_sha256"],
        "MULGAE_VM_SKILL_TREE_OBJECT": validated_request["candidate"]["skill_tree_git_object"],
    }
    tools = validated_request["guest"]
    env.update(PYTHON=tools["python_executable"],
               MULGAE_PYTHON_EXECUTABLE=tools["python_executable"],
               MULGAE_GO_EXECUTABLE=tools["go_executable"],
               MULGAE_PRIOR_GO_EXECUTABLE=tools["prior_go_executable"])
    env["PATH"] = str(Path(tools["go_executable"]).parent) + ":" + str(Path(tools["python_executable"]).parent) + ":/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    deadlines = {
        "queue_seconds": 30,
        "prepare_seconds": duration_seconds(timeouts["prepare"]),
        "collect_seconds": duration_seconds(timeouts["collect"]),
        "cleanup_seconds": duration_seconds(timeouts["cleanup"]),
    }
    deadlines["manual_seconds" if manual else "run_seconds"] = duration_seconds(
        timeouts["manual" if manual else "workload"]
    )
    spec = {
        "schema": "haepari.job/v2", "execution_mode": "managed",
        "resource_id": resource, "mode": mode, "suite": suite_name,
        "input": {
            "root": str(run_dir), "selected_files": selected,
            "inventory_digest": tree_digest(input_entries).removeprefix("sha256:"),
        },
        "environment": {
            "profile_id": validated_request["profiles"]["target_profile_id"],
            "profile_digest": digests["profile_digest"].removeprefix("sha256:"),
        },
        "provenance": {
            "candidate_digest": digests["candidate_digest"].removeprefix("sha256:"),
            "tests_digest": digests["tests_digest"].removeprefix("sha256:"),
            "target_profile_digest": digests["profile_digest"].removeprefix("sha256:"),
            "evidence_class": "development",
        },
        "workload": {"argv": [command[0], command[1].removeprefix("bundle/"), *command[2:]],
                     "cwd": "bundle", "environment": env, "required_outputs": outputs},
        "deadlines": deadlines,
        "effects": {
            "mode": "live",
            "authorization_reference": validated_request["candidate"]["authorization_reference"],
        },
    }
    if manual:
        spec["manual"] = {
            "scenario_document": manual["instructions"],
            "required_scenarios": manual["scenarios"],
        }
    return spec

def _cli_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify a sealed Mulgae Haepari bundle.")
    parser.add_argument("--verify-bundle", action="store_true", help="Verify sealed bundle manifest and digests")
    parser.add_argument("--bundle", default="bundle", help="Path to bundle root directory")
    parser.add_argument("--manifest", default="", help="Optional explicit path to bundle-manifest.json")
    args = parser.parse_args(argv)
    if not args.verify_bundle:
        parser.error("--verify-bundle is required when invoking haepari_inputs.py directly")
    try:
        bundle_root = Path(args.bundle)
        manifest_path = Path(args.manifest) if args.manifest else None
        manifest = verify_sealed_bundle(bundle_root, manifest_path)
    except Refusal as exc:
        print(json.dumps({"status": "refused", "reason": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "verified",
                "schema": manifest["schema"],
                "bundle_tree_digest": manifest["bundle_tree_digest"],
                "digests": manifest["digests"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    check_python_entrypoint()
    sys.exit(_cli_main())
