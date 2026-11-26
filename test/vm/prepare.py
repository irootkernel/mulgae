#!/usr/bin/env python3
"""Prepare immutable build inputs and a candidate artifact without VM effects."""
from __future__ import annotations

import argparse
import hashlib
import gzip
import json
import os
from pathlib import Path
import re
import subprocess

from haepari_inputs import check_python_entrypoint, require_python, resolve_tool, toolchain_versions
from haepari_inputs import Refusal, SKILL_SELECTED_FILES, PRIOR_RELEASE_TAG_COMMIT, regular_bytes, _relative_paths, remove_owned_tree, candidate_binary_bytes


def git(root: Path, *args: str) -> bytes:
    return subprocess.run(["git", "-C", str(root), *args], check=True, stdout=subprocess.PIPE).stdout


def prepare(root: Path, output: Path, commit: str, go: str, reuse: Path | None = None,
            haepari: Path | None = None) -> dict:
    toolchains = require_python(root)
    go = resolve_tool(root, "go", go)
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or git(root, "rev-parse", commit+"^{commit}").decode().strip() != commit:
        raise Refusal("candidate must be an exact commit")
    if output.exists() or not output.is_absolute() or output.parent.resolve() != output.parent:
        raise Refusal("output must be a new path under a physical absolute directory")
    output.mkdir(mode=0o700)
    files = git(root, "ls-tree", "-rz", "--full-tree", commit).split(b"\0")
    selected = []
    production_hashes = {}
    for record in files:
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        name = raw_name.decode("utf-8")
        production = (name in {"go.mod", "go.sum", "main.go", "Makefile", "dev", "tools/toolchains.env", "tools/mise.toml"}
                      or name.startswith("assets/") and not name.endswith("_test.go")
                      or name.startswith("internal/") and
                      (name.endswith(".go") and (not name.endswith("_test.go") or name.startswith(("internal/adapters/herdr/", "internal/adapters/providercli/", "internal/mcpclientcheck/")))
                       or name.startswith("internal/builtin/assets/")))
        if not production:
            continue
        _relative_paths([name])
        if kind != b"blob" or mode not in (b"100644", b"100755"):
            raise Refusal("build input is not a regular Git blob: "+name)
        destination = output / "source" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(git(root, "cat-file", "blob", object_id.decode()))
        destination.chmod(0o700 if mode == b"100755" else 0o600)
        selected.append("source/"+name)
        production_hashes[name] = "sha256:"+hashlib.sha256(regular_bytes(destination)).hexdigest()

    # The test overlay is deliberately separate from committed production input.
    overlay = [p.relative_to(root).as_posix() for p in (root/"test/e2e").rglob("*.go") if not p.is_dir()]
    overlay += [str(p.relative_to(root)) for p in (root/"test/vm").glob("*")
                if p.is_file() and p.suffix in {".py", ".sh", ".md"}]
    overlay.append("Makefile")
    for name in sorted(set(overlay + SKILL_SELECTED_FILES)):
        _relative_paths([name])
        target_name = "source/"+name if name.startswith("test/e2e/") or name == "Makefile" else name
        destination = output/target_name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(regular_bytes(root/name))
        destination.chmod(0o700 if (root/name).stat().st_mode & 0o111 else 0o600)
        if target_name not in selected:
            selected.append(target_name)

    build = output/"build"
    build.mkdir(mode=0o700)
    for name in ("bin", "cache", "modules", "home", "tmp"):
        (build/name).mkdir(mode=0o700)
    env = dict(os.environ, GOTOOLCHAIN="local", GOENV="off", GOWORK="off",
               GOOS="darwin", GOARCH="arm64", GOBIN=str(build/"bin"), GOCACHE=str(build/"cache"),
               GOMODCACHE=str(build/"modules"), HOME=str(build/"home"), TMPDIR=str(build/"tmp"))
    version_text = git(root, "show", commit+":Makefile").decode()
    version = re.search(r"^RELEASE_VERSION := (v[0-9]+\.[0-9]+\.[0-9]+)$", version_text, re.M)
    if not version:
        raise Refusal("candidate Makefile release version is not recognized")
    if toolchain_versions(output / "source") != toolchains:
        raise Refusal("candidate declarations differ from the selected preparation toolchain")
    toolchain = subprocess.run([go, "version"], env=env, check=True, capture_output=True, text=True).stdout.strip()
    binary_origin = {"kind": "fresh_go_install"}
    if reuse is None:
        subprocess.run([go, "install", "-trimpath", "-ldflags",
                        f"-X main.buildVersion={version[1]} -X main.buildRevision={commit}", "."],
                       cwd=output/"source", env=env, check=True)
    else:
        previous_bytes = regular_bytes(reuse/"artifacts/candidate.json")
        previous = json.loads(previous_bytes)
        previous_binary = candidate_binary_bytes(reuse)
        if (previous.get("schema") != "mulgae.vm-prepared-candidate/v1"
                or previous.get("source_commit") != commit or previous.get("version") != version[1]
                or previous.get("go_version") != toolchain
                or previous.get("production_inputs") != production_hashes
                or previous.get("binary_sha256") != "sha256:"+hashlib.sha256(previous_binary).hexdigest()):
            raise Refusal("previous prepared binary does not match the exact build inputs")
        (build/"bin/mulgae").write_bytes(previous_binary)
        binary_origin = {"kind":"reused_verified_preparation", "receipt_sha256":"sha256:"+hashlib.sha256(previous_bytes).hexdigest()}
    artifacts = output/"artifacts"
    artifacts.mkdir(mode=0o700)
    prior_files = {}
    for record in git(root, "ls-tree", "-rz", "--full-tree", PRIOR_RELEASE_TAG_COMMIT).split(b"\0"):
        if not record:
            continue
        metadata, raw_name = record.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        name = raw_name.decode("utf-8")
        if (name in {"go.mod", "go.sum", "main.go"}
                or name.startswith("assets/") and not name.endswith("_test.go")
                or name.startswith("internal/") and
                (name.endswith(".go") and not name.endswith("_test.go")
                 or name.startswith("internal/builtin/assets/"))):
            _relative_paths([name])
            if kind != b"blob" or mode not in (b"100644", b"100755"):
                raise Refusal("prior build input is not a regular Git blob")
            prior_files[name] = "sha256:"+hashlib.sha256(git(root, "cat-file", "blob", object_id.decode())).hexdigest()
    write_prior = {"schema":"mulgae.vm-prior-build-inputs/v1", "source_commit":PRIOR_RELEASE_TAG_COMMIT, "files":prior_files}
    (artifacts/"prior-inputs.json").write_text(json.dumps(write_prior, indent=2, sort_keys=True)+"\n")
    selected.append("artifacts/prior-inputs.json")
    binary_bytes = regular_bytes(build/"bin/mulgae")
    binary = artifacts/"mulgae.gz"
    binary.write_bytes(gzip.compress(binary_bytes, mtime=0))
    binary.chmod(0o600)
    selected.append("artifacts/mulgae.gz")
    native_controller_sha256 = None
    if haepari is not None:
        native_bytes = regular_bytes(haepari)
        (artifacts/"haepari").write_bytes(native_bytes)
        (artifacts/"haepari").chmod(0o700)
        selected.append("artifacts/haepari")
        native_controller_sha256 = "sha256:"+hashlib.sha256(native_bytes).hexdigest()
    receipt = {
        "schema": "mulgae.vm-prepared-candidate/v1", "source_commit": commit,
        "version": version[1], "binary_sha256": "sha256:"+hashlib.sha256(binary_bytes).hexdigest(),
        "skill_tree_git_object": git(root, "rev-parse", commit+":skills/use-mulgae").decode().strip(),
        "toolchains": toolchains, "go_version": toolchain, "binary_origin": binary_origin, "test_overlay": "working tree; not a committed test revision",
        "test_base_commit": git(root, "rev-parse", "HEAD").decode().strip(),
        "production_inputs": production_hashes,
        "native_controller_sha256": native_controller_sha256,
        "test_overlay_files": sorted(overlay),
        "files": {name: "sha256:"+hashlib.sha256(regular_bytes(output/name)).hexdigest() for name in sorted(selected)},
    }
    for name in SKILL_SELECTED_FILES:
        if regular_bytes(output/name) != git(root, "show", commit+":"+name):
            raise Refusal("skill bytes do not match candidate Git tree: "+name)
    (artifacts/"candidate.json").write_text(json.dumps(receipt, indent=2, sort_keys=True)+"\n")
    selected.append("artifacts/candidate.json")
    config = {"schema": "haepari.project-test-example/v1", "selected_files": sorted(selected)}
    (output/"project.json").write_text(json.dumps(config, indent=2, sort_keys=True)+"\n")
    # Only build scratch created above is disposable; the prepared source and
    # artifact stay available for admission, readback and exact replay.
    remove_owned_tree(build)
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--go", default="", help="Explicit exact-version Go executable; otherwise resolve the project pin")
    parser.add_argument("--haepari", default="", help="Stage this released controller in the private test fixture; never install it globally")
    parser.add_argument("--reuse-prepared", default="", help="Reuse an artifact only when its exact production inputs and toolchain match")
    args = parser.parse_args()
    try:
        receipt = prepare(Path(__file__).resolve().parents[2], Path(args.output), args.commit, args.go,
                          Path(args.reuse_prepared) if args.reuse_prepared else None,
                          Path(args.haepari) if args.haepari else None)
    except (Refusal, OSError, subprocess.SubprocessError) as exc:
        print("refused: "+str(exc), file=__import__("sys").stderr)
        return 2
    print(json.dumps({key: receipt[key] for key in ("source_commit", "binary_sha256", "skill_tree_git_object")}))
    return 0


if __name__ == "__main__":
    check_python_entrypoint()
    raise SystemExit(main())
