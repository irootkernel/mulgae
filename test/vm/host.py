#!/usr/bin/env python3
"""Host-side Haepari v0.1.0 adapter for Mulgae VM qualification and live-provider suites.

Provenance:
- Adapted from Haepari v0.1.0 (`800da97b7e2ca84a15d4ee5921702ec57bbc7d61`,
  build revision `fc3b975f8a99cacb96aecc988d3adbc04dda7309`)
  `examples/project-test/host.py`.
- Adapted for Mulgae `TASK-080` (`EPIC-016`, `aquarium/EPIC-032/TASK-092/mulgae-rollout/v1`).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Any

from haepari_inputs import check_python_entrypoint
from haepari_inputs import (
    DEFAULT_SELECTED_FILES,
    DEFAULT_SUITES,
    DEFAULT_TIMEOUTS,
    HAEPARI_UPSTREAM_BUILD_REVISION,
    HAEPARI_UPSTREAM_SOURCE_COMMIT,
    Refusal,
    capture_inputs,
    file_digest,
    duration_seconds,
    job_spec,
    regular_bytes,
    valid_identifier,
    validate_execution_request,
    validate_manual_completion_ready,
    validate_manual_selection,
    validate_recipe,
    verify_sealed_bundle,
    verify_prepared_candidate,
)


EXIT_CODES = {
    "PASS": 0,
    "FAIL": 1,
    "UNKNOWN": 2,
    "INCOMPLETE": 3,
    "CANCELLED": 4,
    "PENDING": 5,
}


def load_json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = regular_bytes(path, str(path)).decode("utf-8")
    except OSError as exc:
        raise Refusal(f"read {label} {path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise Refusal(f"parse {label} {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise Refusal(f"{label} must be a JSON object")
    return data


def atomic_write_json(path: Path, payload: object) -> str:
    raw = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".tmp.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
    return digest


def prepare_run_dir(raw: str | None) -> Path:
    if not raw:
        return Path(tempfile.mkdtemp(prefix="mulgae-haepari-", dir=Path("/tmp").resolve()))
    path = Path(raw)
    if not path.is_absolute() or path != path.resolve(strict=False):
        raise Refusal("run_dir must be an absolute physical path without symlink ancestry")
    if not path.exists():
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700):
        raise Refusal("run_dir must be a private owned physical directory with mode 0700")
    return path

def lock_run_dir(run_dir: Path) -> Any:
    lock_path = run_dir / "caller.lock"
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(lock_path, flags, 0o600)
    handle = os.fdopen(fd, "r+", encoding="utf-8")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        handle.close()
        raise Refusal(f"run_dir is already in use by another caller: {run_dir}") from exc
    return handle


def resolve_and_verify_haepari_binary(haepari_arg: str, validated_request: dict[str, Any]) -> str:
    req_exec = validated_request["haepari"]["executable"]
    expected_sha = validated_request["haepari"]["executable_sha256"]
    candidate_cmd = haepari_arg if haepari_arg != "haepari" else req_exec
    resolved = shutil.which(candidate_cmd) if "/" not in candidate_cmd else candidate_cmd
    if not resolved:
        raise Refusal(f"haepari executable not found: {candidate_cmd}")
    exec_path = Path(resolved)
    try:
        st = exec_path.lstat()
    except OSError as exc:
        raise Refusal(f"stat haepari executable {exec_path}: {exc}") from exc
    if stat.S_ISLNK(st.st_mode):
        exec_path = exec_path.resolve(strict=True)
    actual_sha = file_digest(exec_path)
    if actual_sha != expected_sha:
        raise Refusal(
            f"haepari executable digest mismatch for {exec_path}: expected {expected_sha}, got {actual_sha}"
        )
    return str(exec_path)


def run_cli(
    haepari_bin: str,
    args: list[str],
    cwd: Path,
    haepari_home: str = "",
) -> tuple[int, dict[str, Any] | None, str]:
    env = dict(os.environ)
    if haepari_home:
        env["HAEPARI_HOME"] = haepari_home
    timeout = 25
    if args[0] == "wait" and "--timeout" in args:
        timeout = duration_seconds(args[args.index("--timeout") + 1]) + 5
    try:
        proc = subprocess.run(
            [haepari_bin, *args], cwd=cwd, env=env, text=True,
            capture_output=True, check=False, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal(
            "Haepari reply unavailable; retain the original run, key and exact spec and reconnect"
        ) from exc
    try:
        envelope = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise Refusal("Haepari response is not JSON; preserve the original run and request") from exc
    if (not isinstance(envelope, dict) or envelope.get("schema") != "haepari.envelope/v1"
            or type(envelope.get("ok")) is not bool):
        raise Refusal("unsupported Haepari envelope; preserve the original run and request")
    payload = envelope.get("data" if envelope["ok"] else "error")
    if not isinstance(payload, dict) or (not envelope["ok"] and proc.returncode == 0):
        raise Refusal("malformed Haepari response; preserve the original run and request")
    if not envelope["ok"]:
        return proc.returncode, None, json.dumps(payload, sort_keys=True)
    return proc.returncode, payload, proc.stderr.strip()

def check_doctor(
    haepari_bin: str,
    resource: str,
    run_dir: Path,
    haepari_home: str,
    validated_request: dict[str, Any],
) -> dict[str, Any]:
    code, payload, detail = run_cli(
        haepari_bin, ["doctor", "--resource", resource, "--json"], run_dir,
        haepari_home=haepari_home,
    )
    if (code != 0 or not payload or payload.get("schema") != "haepari.doctor/v1"
            or type(payload.get("ready")) is not bool or not isinstance(payload.get("gaps"), list)):
        raise Refusal(f"invalid Haepari doctor response: {detail}")
    if payload.get("installation_id") != validated_request["haepari"]["installation_id"]:
        raise Refusal("haepari installation_id mismatch")
    item = payload.get("resource")
    if (payload.get("resource_id") != resource or not isinstance(item, dict)
            or item.get("resource_id") != resource or item.get("kind") != "utm-macos"
            or item.get("config_revision") != validated_request["resource"]["configuration_revision"]
            or not isinstance(item.get("configuration_digest"), str)):
        raise Refusal("haepari resource identity or configuration revision mismatch")
    return payload

def select_suites(suites: dict[str, Any], suite_arg: str) -> list[tuple[str, dict[str, Any]]]:
    if suite_arg == "all":
        names = list(suites.keys())
    else:
        valid_identifier(suite_arg, "suite")
        if suite_arg not in suites:
            raise Refusal(f"unknown suite: {suite_arg}")
        names = [suite_arg]
    selected: list[tuple[str, dict[str, Any]]] = []
    for name in names:
        cfg = suites.get(name)
        if not isinstance(cfg, dict):
            raise Refusal(f"suite {name} configuration must be an object")
        selected.append((name, cfg))
    return selected


def load_or_init_run(
    run_file: Path,
    resource: str,
    suite_arg: str,
    mode: str,
    installation_id: str,
    request_sha256: str,
    validated_request: dict[str, Any],
) -> dict[str, Any]:
    if not run_file.exists():
        return {
            "schema": "haepari.project-run/v1",
            "upstream_contract": {
                "haepari_source_commit": HAEPARI_UPSTREAM_SOURCE_COMMIT,
                "haepari_build_revision": HAEPARI_UPSTREAM_BUILD_REVISION,
            },
            "resource": resource,
            "suite": suite_arg,
            "mode": mode,
            "installation_id": installation_id,
            "request_sha256": request_sha256,
            "pre_submission": {
                "haepari": validated_request["haepari"],
                "resource": validated_request["resource"],
                "guest": validated_request["guest"],
                "profiles": validated_request["profiles"],
                "candidate": validated_request["candidate"],
                "prior_release": validated_request["prior_release"],
                "review_controller_home": validated_request["review_controller_home"],
            },
            "inputs": None,
            "entries": [],
        }
    saved = load_json_file(run_file, "run.json")
    if saved.get("schema") != "haepari.project-run/v1":
        raise Refusal("run.json has an unsupported schema")
    if saved.get("resource") != resource or saved.get("suite") != suite_arg or saved.get("mode") != mode:
        raise Refusal("run_dir already belongs to a different resource, suite, or mode selection")
    if saved.get("installation_id") != installation_id:
        raise Refusal("run_dir belongs to a different Haepari installation_id")
    if saved.get("request_sha256") != request_sha256:
        raise Refusal("run_dir belongs to a different execution request digest")
    if not isinstance(saved.get("entries"), list):
        raise Refusal("run.json entries must be a list")
    return saved


def ensure_entry(
    saved: dict[str, Any],
    index: int,
    suite_name: str,
    spec_path: Path,
    spec_payload: dict[str, object],
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = saved["entries"]
    if index < len(entries):
        entry = entries[index]
        if not isinstance(entry, dict) or entry.get("suite") != suite_name:
            raise Refusal(f"saved run.json entry {index} does not match suite {suite_name}")
        request_key = entry.get("request_key")
        if not isinstance(request_key, str) or not request_key:
            raise Refusal(f"saved run.json entry {index} is missing request_key")
        spec_sha = atomic_write_json(spec_path, spec_payload)
        if entry.get("spec_sha256") != spec_sha or entry.get("spec_path") != spec_path.name:
            raise Refusal(f"saved spec for suite {suite_name} does not match the current Job spec")
        return entry
    entry = {
        "suite": suite_name,
        "request_key": f"mulgae-{suite_name}-{uuid.uuid4().hex}",
        "spec_path": spec_path.name,
        "spec_sha256": atomic_write_json(spec_path, spec_payload),
        "job_id": None,
        "job_revision": None,
    }
    entries.append(entry)
    return entry


def submit_and_wait(
    haepari_bin: str,
    run_dir: Path,
    run_file: Path,
    saved: dict[str, Any],
    entry: dict[str, Any],
    wait_timeout: str,
    haepari_home: str,
) -> tuple[str, dict[str, Any]]:
    entry["submission_started"] = True
    atomic_write_json(run_file, saved)
    code, receipt, detail = run_cli(
        haepari_bin,
        ["submit", "--spec", str(run_dir / entry["spec_path"]),
         "--request-key", entry["request_key"], "--json"],
        run_dir, haepari_home=haepari_home,
    )
    if code != 0 or not receipt:
        return "UNKNOWN", {"suite": entry["suite"], "verdict": "UNKNOWN", "reason": detail}
    job_id = valid_identifier(receipt.get("job_id"), "native job_id")
    revision = receipt.get("job_revision")
    if (type(revision) is not int or revision < 1 or receipt.get("resource_id") != saved["resource"]
            or (entry.get("job_id") and entry["job_id"] != job_id)):
        raise Refusal("native admission receipt disagrees with the saved Job/resource identity")
    entry.update(job_id=job_id, job_revision=revision, last_state=receipt.get("job_state"))
    atomic_write_json(run_file, saved)
    wait_code, result, detail = run_cli(
        haepari_bin, ["wait", job_id, "--timeout", wait_timeout, "--json"],
        run_dir, haepari_home=haepari_home,
    )
    if wait_code == 5 and result is None:
        entry.update(last_verdict="PENDING", last_exit_code=5)
        atomic_write_json(run_file, saved)
        return "PENDING", {"suite": entry["suite"], "job_id": job_id,
                           "verdict": "PENDING", "reason": detail, "wait_exit_code": 5}
    verdict = result.get("final_verdict") if result else None
    expected_exit = {"PASS": 0, "FAIL": 1, "INCOMPLETE": 3, "CANCELLED": 4}.get(verdict)
    if (expected_exit is None or wait_code != expected_exit or result.get("job_id") != job_id
            or result.get("resource_id") != saved["resource"] or result.get("job_state") != "finished"):
        raise Refusal("native terminal result and exit/Job/resource disagree; no PASS is available")
    entry.update(last_state="finished", last_verdict=verdict, last_exit_code=wait_code)
    atomic_write_json(run_file, saved)
    return verdict, dict(result, suite=entry["suite"], verdict=verdict, wait_exit_code=wait_code)

def complete_manual_job(
    haepari_bin: str,
    run_dir: Path,
    run_file: Path,
    suite_name: str,
    manual_result_path: Path,
    expected_revision: int,
    haepari_home: str,
) -> int:
    saved = load_json_file(run_file, "run.json")
    entries = [entry for entry in saved["entries"] if entry.get("suite") == suite_name]
    if len(entries) != 1 or not entries[0].get("job_id"):
        raise Refusal("manual completion needs this saved suite's native Job identity")
    job_id = entries[0]["job_id"]
    code, inspection, detail = run_cli(
        haepari_bin, ["inspect", job_id, "--json"], run_dir, haepari_home=haepari_home,
    )
    receipt = inspection.get("receipt") if inspection else None
    if (code != 0 or not isinstance(receipt, dict) or receipt.get("job_id") != job_id
            or receipt.get("job_state") != "awaiting_manual"
            or receipt.get("job_revision") != expected_revision
            or receipt.get("resource_id") != saved["resource"]):
        raise Refusal("manual Job state/revision changed; reconcile the existing Job without resubmission")
    lease = receipt.get("lease_generation")
    if type(lease) is not int or lease < 1:
        raise Refusal("manual Job has no current native lease identity")
    before = saved["pre_submission"]
    expected = {
        "job_id": job_id, "installation_id": saved["installation_id"], "lease_generation": lease,
        "guest_hardware_uuid": before["guest"]["expected_hardware_uuid"].upper(),
        "candidate_commit": before["candidate"]["source_commit"],
        "candidate_binary_sha256": before["candidate"]["binary_sha256"],
        "skill_tree_git_object": before["candidate"]["skill_tree_git_object"],
        "profile_id": before["profiles"]["target_profile_id"],
        "profile_digest": before["profiles"]["target_profile_sha256"].removeprefix("sha256:"),
        "expected_revision": expected_revision,
    }
    verified = validate_manual_completion_ready(run_dir, suite_name, manual_result_path, expected)
    operation = {"input_sha256": file_digest(manual_result_path),
                 "job_id": job_id, "expected_revision": expected_revision}
    if saved.get("manual_completion", operation) != operation:
        raise Refusal("manual completion input changed; retain the original uncertain operation")
    saved["manual_completion"] = operation
    atomic_write_json(run_file, saved)
    code, receipt, detail = run_cli(
        haepari_bin,
        ["manual", "complete", job_id, "--input", str(manual_result_path),
         "--expected-revision", str(expected_revision), "--json"],
        run_dir, haepari_home=haepari_home,
    )
    if code != 0 or not receipt or receipt.get("job_id") != job_id:
        raise Refusal(f"manual completion reply unavailable or refused; retain the existing Job: {detail}")
    print(json.dumps({
        "schema": "mulgae.haepari-manual-complete/v1", "job_id": job_id,
        "suite": suite_name, "acknowledgment": receipt,
        "consumer_cleanup": verified["cleanup"],
        "limits": "Native completion acknowledged; collection, native cleanup and final verdict remain pending.",
    }, sort_keys=True))
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Submit and observe Mulgae VM qualification Jobs via Haepari.")
    parser.add_argument(
        "--config",
        default="",
        help="Optional suite config JSON override (defaults to built-in Mulgae suite registry)",
    )
    parser.add_argument("--prepared-dir", default="", help="Physical output directory from test/vm/prepare.py")
    parser.add_argument("--haepari", default=os.environ.get("HAEPARI") or "haepari")
    parser.add_argument("--haepari-home", default=os.environ.get("HAEPARI_HOME") or "")
    parser.add_argument("--resource", default=os.environ.get("RESOURCE") or "")
    parser.add_argument("--suite", default=os.environ.get("SUITE") or "guest-qualification")
    parser.add_argument("--mode", default=os.environ.get("MODE") or "auto")
    parser.add_argument("--run-dir", default=os.environ.get("RUN_DIR") or "")
    parser.add_argument(
        "--request",
        default=os.environ.get("REQUEST") or "",
        help="Path to external non-secret mulgae.haepari-vm-request/v2 JSON document",
    )
    parser.add_argument(
        "--manual-complete-input",
        default="",
        help="Complete an awaiting_manual Job using a validated haepari.manual-result/v1 file after verifying cleanup",
    )
    parser.add_argument(
        "--expected-revision",
        type=int,
        default=0,
        help="Expected Job revision for --manual-complete-input",
    )
    return parser.parse_args(argv)


def run(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if os.environ.get("HAEPARI_PARENT_CONTEXT"):
        raise Refusal("host submission is forbidden inside a managed guest or parent job context")

    repo_root = Path(__file__).resolve().parents[2]
    toolchain_source_root = repo_root
    if args.prepared_dir:
        repo_root = Path(args.prepared_dir)
        if not repo_root.is_absolute() or repo_root.resolve() != repo_root:
            raise Refusal("prepared directory must be an absolute physical path")
        if not args.config:
            args.config = str(repo_root / "project.json")
        toolchain_source_root = repo_root / "source"
    if args.config:
        cfg_path = Path(args.config).resolve()
        config = load_json_file(cfg_path, "project config")
        if config.get("schema") != "haepari.project-test-example/v1":
            raise Refusal("project config schema must be haepari.project-test-example/v1")
        selected_files = config.get("selected_files", DEFAULT_SELECTED_FILES)
        suites_map = config.get("suites", DEFAULT_SUITES)
        timeouts = dict(DEFAULT_TIMEOUTS)
        if isinstance(config.get("timeouts"), dict):
            timeouts.update({str(k): str(v) for k, v in config["timeouts"].items()})
    else:
        selected_files = list(DEFAULT_SELECTED_FILES)
        suites_map = DEFAULT_SUITES
        timeouts = dict(DEFAULT_TIMEOUTS)

    if not isinstance(selected_files, list) or not all(isinstance(x, str) for x in selected_files):
        raise Refusal("selected_files must be a string list")
    if not isinstance(suites_map, dict) or not suites_map:
        raise Refusal("suites must be a non-empty object")

    if not args.request:
        raise Refusal("REQUEST (--request) is required: supply an external mulgae.haepari-vm-request/v2 JSON file")
    request_path = Path(args.request)
    if not request_path.is_absolute():
        request_path = (Path.cwd() / request_path).resolve()
    raw_request_bytes = regular_bytes(request_path, str(request_path))
    request_sha256 = "sha256:" + hashlib.sha256(raw_request_bytes).hexdigest()
    raw_request = load_json_file(request_path, "execution request")

    selected = select_suites(suites_map, args.suite)
    if args.mode == "manual" and len(selected) != 1:
        raise Refusal("manual mode requires selecting exactly one suite")

    validated_request = validate_execution_request(
        raw_request,
        repo_root,
        selected[0][0],
        selected[0][1],
        toolchain_source_root=toolchain_source_root,
    )
    for suite_name, suite_cfg in selected[1:]:
        validate_execution_request(
            raw_request,
            repo_root,
            suite_name,
            suite_cfg,
            toolchain_source_root=toolchain_source_root,
        )

    if args.prepared_dir:
        prepared = verify_prepared_candidate(repo_root, validated_request)
        if set(selected_files) != set(prepared["files"]) | {"artifacts/candidate.json"}:
            raise Refusal("prepared selected-file inventory differs from its exact receipt")

    resource_arg = args.resource or validated_request["resource"]["id"]
    resource = valid_identifier(resource_arg, "resource")
    if resource != validated_request["resource"]["id"]:
        raise Refusal(
            f"resource mismatch: --resource {resource} does not match request.resource.id "
            f"{validated_request['resource']['id']}"
        )

    haepari_home = args.haepari_home or validated_request["haepari"]["installation_root"]
    haepari_bin = resolve_and_verify_haepari_binary(args.haepari, validated_request)

    run_dir = prepare_run_dir(args.run_dir)
    lock_handle = lock_run_dir(run_dir)
    try:
        run_file = run_dir / "run.json"
        doctor = check_doctor(haepari_bin, resource, run_dir, haepari_home, validated_request)
        saved = load_or_init_run(
            run_file,
            resource,
            args.suite,
            args.mode,
            str(doctor["installation_id"]),
            request_sha256,
            validated_request,
        )
        native_digest = doctor["resource"]["configuration_digest"]
        if saved.get("resource_configuration_digest", native_digest) != native_digest:
            raise Refusal("native resource configuration changed; preserve this original run")
        saved["resource_configuration_digest"] = native_digest
        if args.manual_complete_input:
            if args.expected_revision < 1:
                raise Refusal("--expected-revision must be a positive integer when completing a manual job")
            return complete_manual_job(
                haepari_bin,
                run_dir,
                run_file,
                selected[0][0],
                Path(args.manual_complete_input),
                args.expected_revision,
                haepari_home,
            )

        if not saved["entries"] and not doctor["ready"]:
            raise Refusal("Haepari resource is not ready; inspect its prerequisite gaps")
        if saved.get("inputs") is None:
            saved["inputs"] = capture_inputs(repo_root, run_dir, selected_files, validated_request)
        else:
            bundle_dir = run_dir / "bundle"
            manifest_path = run_dir / "bundle-manifest.json"
            if not bundle_dir.is_dir() or not manifest_path.is_file():
                raise Refusal("saved run_dir is missing sealed bundle or bundle-manifest.json")
            manifest = verify_sealed_bundle(bundle_dir, manifest_path)
            if manifest.get("digests") != saved["inputs"]:
                raise Refusal("sealed bundle digests do not match saved run.json inputs")

        results: list[dict[str, Any]] = []
        overall = "PASS"
        for index, (suite_name, suite_cfg) in enumerate(selected):
            command = validate_recipe(suite_name, suite_cfg, selected_files)
            manual = validate_manual_selection(suite_name, suite_cfg, args.mode, selected_files)
            spec = job_spec(
                resource=resource,
                command=command,
                suite_name=suite_name,
                mode=args.mode,
                digests=saved["inputs"],
                outputs=suite_cfg.get("outputs", []),
                timeouts=timeouts,
                manual=manual,
                validated_request=validated_request,
                run_dir=run_dir,
            )
            spec_path = run_dir / f"spec-{index}.json"
            entry = ensure_entry(saved, index, suite_name, spec_path, spec)
            atomic_write_json(run_file, saved)
            if not entry.get("submission_started") and not doctor["ready"]:
                raise Refusal("Haepari resource is not ready for a new submission")
            verdict, result = submit_and_wait(
                haepari_bin,
                run_dir,
                run_file,
                saved,
                entry,
                timeouts["wait"],
                haepari_home,
            )
            results.append(result)
            if verdict != "PASS":
                overall = verdict
                break

        summary = {
            "schema": "haepari.project-run-summary/v1",
            "run_dir": str(run_dir),
            "resource": resource,
            "suite": args.suite,
            "mode": args.mode,
            "installation_id": doctor["installation_id"],
            "request_sha256": request_sha256,
            "verdict": overall,
            "results": results,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        return EXIT_CODES.get(overall, 2)
    finally:
        lock_handle.close()


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except Refusal as exc:
        print(
            json.dumps(
                {
                    "schema": "haepari.project-run-summary/v1",
                    "verdict": "UNKNOWN",
                    "reason": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return EXIT_CODES["UNKNOWN"]


if __name__ == "__main__":
    check_python_entrypoint()
    sys.exit(main())
