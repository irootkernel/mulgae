#!/usr/bin/env python3
"""Execute sealed Mulgae qualification inside an admitted Darwin guest."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

from haepari_inputs import Refusal, regular_bytes, verify_sealed_bundle, remove_owned_tree, candidate_binary_bytes


UNVERIFIED_GROUPS: list[int] = []
COMMAND_RESULTS: list[dict] = []


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    path.chmod(0o600)


def digest(path: Path) -> str:
    return "sha256:"+hashlib.sha256(regular_bytes(path)).hexdigest()


def execute(argv: list[str], cwd: Path, env: dict[str, str], log: Path) -> None:
    # Private logs are local evidence; never copy their contents into public gaps.
    started = time.monotonic()
    print(f"[vm] START {log.name}", flush=True)
    with log.open("xb") as stream:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdout=stream, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            while True:
                try:
                    code = process.wait(timeout=30)
                    break
                except subprocess.TimeoutExpired:
                    print(f"[vm] WAIT {log.name} elapsed={int(time.monotonic()-started)}s", flush=True)
        except BaseException:
            os.killpg(process.pid, __import__("signal").SIGTERM)
            process.wait()
            raise
    print(f"[vm] EXIT {log.name} code={code}", flush=True)
    COMMAND_RESULTS.append({"argv": argv, "exit_code": code,
                            "duration_seconds": round(time.monotonic()-started, 3),
                            "private_log": log.name})
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        pass
    else:
        UNVERIFIED_GROUPS.append(process.pid)
        raise Refusal("workload descendants remain; preserve the owned root for reconciliation")
    if code:
        raise Refusal(f"{argv[0]} failed with exit {code}; inspect private {log.name}")


def binding(request: dict, job: str, lease: int, uuid: str) -> dict:
    return {
        "job_id": job, "installation_id": request["haepari"]["installation_id"],
        "lease_generation": lease, "guest_hardware_uuid": uuid,
        "candidate_commit": request["candidate"]["source_commit"],
        "candidate_binary_sha256": request["candidate"]["binary_sha256"],
        "skill_tree_git_object": request["candidate"]["skill_tree_git_object"],
        "profile_id": request["profiles"]["target_profile_id"],
        "profile_digest": request["profiles"]["target_profile_sha256"].removeprefix("sha256:"),
    }


def inventory(identity: dict, roots: list[Path]) -> dict:
    live_pids = []
    if UNVERIFIED_GROUPS:
        probe = subprocess.run(["/bin/ps", "-axo", "pid=,pgid="], check=True, capture_output=True, text=True)
        for line in probe.stdout.splitlines():
            pid, group = map(int, line.split())
            if group in UNVERIFIED_GROUPS:
                live_pids.append(pid)
    return dict(identity, schema="mulgae.vm-guest-inventory/v1",
                remaining_owned_roots=[str(path) for path in roots if path.exists()],
                remaining_helper_pids=live_pids, unverified_process_groups=list(UNVERIFIED_GROUPS))


def cleanup(work: Path, results: Path, identity: dict) -> None:
    # The workload owns precisely this mkdtemp root. Controllers and children
    # must already have been waited by the driver before removal.
    if not work.name.startswith("mulgae-vm-") or work.parent != Path("/private/tmp"):
        raise Refusal("cleanup root is outside the owned physical temporary namespace")
    info = work.lstat()
    owner = json.loads(regular_bytes(work/"consumer-owner.json"))
    if (info.st_uid != os.getuid() or info.st_mode & 0o777 != 0o700
            or owner != dict(identity, root_dev=info.st_dev, root_ino=info.st_ino)):
        raise Refusal("owned temporary fixture identity changed; cleanup is refused")
    if UNVERIFIED_GROUPS:
        raise Refusal("owned process-group drain is unverified; cleanup is refused")
    probe = subprocess.run(["/usr/sbin/lsof", "-n", "-P", "-t", "+D", str(work)],
                           capture_output=True, text=True, check=False)
    if probe.returncode not in (0, 1) or probe.stdout.strip() or probe.stderr.strip():
        raise Refusal("owned root has open handles or an unreadable process inventory; cleanup is refused")
    remove_owned_tree(work)
    after = inventory(identity, [work])
    write_json(results/"post-cleanup-inventory.json", after)
    write_json(results/"consumer-cleanup.json", dict(
        identity, schema="mulgae.vm-consumer-cleanup/v1", status="clean",
        post_cleanup_inventory_sha256=digest(results/"post-cleanup-inventory.json"),
    ))


def run(suite: str, mode: str, job: str, lease: int, uuid: str, bundle: Path, results: Path) -> int:
    manifest = verify_sealed_bundle(bundle)
    request = json.loads(regular_bytes(bundle/"profiles/execution-request.json"))
    identity = binding(request, job, lease, uuid)
    prepared = json.loads(regular_bytes(bundle/"artifacts/candidate.json"))
    for field in ("source_commit", "binary_sha256", "skill_tree_git_object"):
        if prepared[field] != request["candidate"][field]:
            raise Refusal("prepared candidate identity does not match the execution request")
    if "sha256:"+hashlib.sha256(candidate_binary_bytes(bundle)).hexdigest() != prepared["binary_sha256"]:
        raise Refusal("candidate binary digest mismatch")
    go = os.environ.get("MULGAE_VM_GO_EXECUTABLE") or shutil.which("go")
    if not go or not Path(go).is_absolute() or not os.access(go, os.X_OK):
        raise Refusal("the admitted guest profile lacks Go; provisioning is a separate effect")
    observed_go = subprocess.run([go, "version"], env=dict(os.environ, GOTOOLCHAIN="local", GOENV="off", GOWORK="off"),
                                 check=True, capture_output=True, text=True).stdout
    if request["prior_release"]["go_toolchain"] not in observed_go.split():
        raise Refusal("guest Go toolchain differs from the admitted prior-release toolchain")
    # GOENV/GOTOOLCHAIN prevent ambient config or a downloaded compiler from
    # silently changing the selected guest toolchain.
    work = Path(tempfile.mkdtemp(prefix="mulgae-vm-", dir="/private/tmp")).resolve()
    roots = [work]
    info = work.stat()
    write_json(work/"consumer-owner.json", dict(identity, root_dev=info.st_dev, root_ino=info.st_ino))
    write_json(results/"inventory-before.json", inventory(identity, roots))
    status, gaps = "fail", []
    try:
        for name in ("bin", "prior-bin", "home", "cache", "modules", "runtime"):
            (work/name).mkdir(mode=0o700)
        candidate = work/"bin/mulgae"
        candidate.write_bytes(candidate_binary_bytes(bundle))
        if digest(candidate) != request["candidate"]["binary_sha256"]:
            raise Refusal("expanded candidate differs from the admitted executable")
        candidate.chmod(0o700)
        native_source = bundle/"artifacts/haepari"
        native = None
        if native_source.is_file():
            if digest(native_source) != request["haepari"]["executable_sha256"]:
                raise Refusal("staged Haepari does not match the admitted released unit")
            native = str(work/"bin/haepari")
            shutil.copyfile(native_source, native)
            Path(native).chmod(0o700)
        else:
            native = shutil.which("haepari")
        if not native or digest(Path(native).resolve()) != request["haepari"]["executable_sha256"]:
            raise Refusal("guest Haepari executable differs from the admitted released unit")
        skills = work/"skills/use-mulgae"
        shutil.copytree(bundle/"skills/use-mulgae", skills)
        env = dict(os.environ, GOTOOLCHAIN="local", GOENV="off", GOWORK="off",
                   HOME=str(work/"home"), GOCACHE=str(work/"cache"),
                   GOMODCACHE=str(work/"modules"), TMPDIR=str(work/"runtime"),
                   GOPROXY=request["prior_release"]["goproxy"])
        env.pop("HAEPARI_LOCK_GRANT", None)
        # ParentChain remains inherited unchanged. Never reacquire the outer VM.
        installed_version = subprocess.run([str(candidate), "version", "--json"], env=env,
                                          check=True, capture_output=True, text=True).stdout
        write_json(results/"candidate-install.json", dict(
            identity, schema="mulgae.vm-candidate-install/v1", status="pass",
            installed_path=str(candidate), actual_binary_sha256=digest(candidate),
            version_output=json.loads(installed_version),
            skill_files={name: manifest["files"][name] for name in manifest["files"] if name.startswith("skills/use-mulgae/")},
        ))
        if suite in {"guest-qualification", "manual-qualification"}:
            old_env = dict(env, GOBIN=str(work/"prior-bin"))
            prior = request["prior_release"]
            downloaded = subprocess.run([go, "mod", "download", "-json", prior["install_target"]],
                                        cwd=work, env=old_env, check=False, capture_output=True, text=True)
            (results/"prior-module.json").write_text(downloaded.stdout)
            (results/"prior-module.stderr.log").write_text(downloaded.stderr)
            if downloaded.returncode:
                raise Refusal(f"prior module download failed with exit {downloaded.returncode}; inspect private prior-module logs")
            module_download = json.loads(downloaded.stdout)
            if (module_download.get("Path") != "github.com/irootkernel/mulgae"
                    or module_download.get("Version") != "v0.1.26" or module_download.get("Error")):
                raise Refusal("prior module download identity mismatch")
            prior_inputs = json.loads(regular_bytes(bundle/"artifacts/prior-inputs.json"))
            if prior_inputs.get("schema") != "mulgae.vm-prior-build-inputs/v1" or prior_inputs.get("source_commit") != prior["tag_commit"]:
                raise Refusal("prior build input provenance mismatch")
            from haepari_inputs import regular_file
            module_root = Path(module_download["Dir"])
            for name, expected in prior_inputs["files"].items():
                _, path = regular_file(module_root, name)
                if digest(path) != expected:
                    raise Refusal("downloaded prior module differs from the pinned Git build inputs")
            execute([go, "install", "-trimpath", "-ldflags",
                     "-X main.buildVersion=v0.1.26 -X main.buildRevision="+prior["tag_commit"],
                     prior["install_target"]], work, old_env, results/"prior-build.log")
            old_binary = work/"prior-bin/mulgae"
            old_version = subprocess.run([str(old_binary), "version", "--json"], env=env,
                                         check=True, capture_output=True, text=True).stdout
            if "v0.1.26" not in old_version:
                raise Refusal("rebuilt prior CLI did not report v0.1.26")
            module = subprocess.run([go, "version", "-m", str(old_binary)], env=env,
                                    check=True, capture_output=True, text=True).stdout
            if "github.com/irootkernel/mulgae\tv0.1.26" not in module:
                raise Refusal("prior binary module identity differs from the pinned old release")
            write_json(results/"prior-release-baseline.json", dict(
                identity, schema="mulgae.vm-prior-release-baseline/v1",
                source=prior, binary_sha256=digest(old_binary),
                version_output=json.loads(old_version), module_identity=module,
                provenance="tag-pinned Go rebuild; official release has no binary assets",
            ))
            controller_root = Path(request["review_controller_home"])
            if os.path.lexists(controller_root):
                raise Refusal("admitted isolated review controller home already exists")
            roots.append(controller_root)
            driver_root = work/"driver"
            driver_root.mkdir(mode=0o700)
            env.update(MULGAE_E2E_BINARY=str(candidate), MULGAE_VM_PRIOR_BINARY=str(old_binary),
                       MULGAE_VM_HAEPARI_BINARY=str(Path(native).resolve()),
                       MULGAE_VM_WORK_ROOT=str(driver_root), MULGAE_VM_REVIEW_HOME=request["review_controller_home"])
            try:
                execute([go, "test", "-v", "-count=1", "-timeout=25m", "-tags=vm_qualification",
                         "-run", "^TestVMQualificationNative$", "./test/e2e"],
                        bundle/"source", env, results/"native-driver.log")
            finally:
                # Preserve observations completed before a later case failed.
                # Missing outputs stay missing; no success record is fabricated.
                for source, target in (("native-result.json", "transport-qualification.json"),
                                       ("prior-state.json", "prior-state.json")):
                    if (driver_root/source).is_file():
                        shutil.copyfile(driver_root/source, results/target)
                case_files = sorted(driver_root.glob("*-result.json")) + sorted(driver_root.glob("*-queued.json"))
                write_json(results/"native-evidence.json", dict(
                    identity, schema="mulgae.vm-native-case-evidence/v1",
                    files=[{"name": path.name, "sha256": digest(path), "utf8_content": regular_bytes(path).decode("utf-8")}
                           for path in case_files],
                ))
            required_cases = (
                "borrower-result.json", "compatibility-zero-call-result.json",
                "partial-fifo-result.json", "loss-scenarios-result.json",
                "response-loss-result.json", "prior-active-result.json",
                "cancel-observed-queued.json", "cancel_race-observed-queued.json",
            )
            if any(not (driver_root/name).is_file() for name in required_cases):
                raise Refusal("native driver omitted a required original case observation")
            native_result = json.loads(regular_bytes(driver_root/"native-result.json"))
            if native_result.get("status") != "pass":
                raise Refusal("native driver has no post-cleanup qualification success")
            write_json(results/"coordination-scenarios.json", dict(
                identity, schema="mulgae.vm-coordination-scenarios/v1",
                observed=native_result, status="pass",
                limits=[
                    "Running-owner reserve guards retain separate deterministic evidence.",
                    "Manual, live-provider and released qualification remain separate.",
                ],
            ))
        elif suite == "live-providers":
            live = request.get("live_accounts")
            if not isinstance(live, dict):
                raise Refusal("live suite lacks admitted guest account aliases")
            controller = Path(request["review_controller_home"])
            controller.mkdir(mode=0o700)  # Never adopt another run's root.
            roots.append(controller)
            controller_identity = controller.stat()
            daemon = None
            targets = []
            try:
                env.update(HAEPARI_HOME=str(controller), MULGAE_TEST_INSTALLED_BINARY=str(candidate),
                           MULGAE_TEST_SOURCE_COMMIT=request["candidate"]["source_commit"],
                           MULGAE_TEST_PREPARED_MANIFEST=str(bundle/"artifacts/candidate.json"),
                           MULGAE_E2E_ZCODE_APP_BUNDLE=live["zcode"]["app_bundle"],
                           MULGAE_E2E_GROK_EXECUTABLE=live["grok"]["executable"],
                           MULGAE_E2E_CURSOR_EXECUTABLE=live["cursor"]["executable"],
                           MULGAE_E2E_AGY_EXECUTABLE=live["agy"]["executable"],
                           MULGAE_E2E_CODEX_EXECUTABLE=live["codex"]["executable"],
                           MULGAE_E2E_CODEX_PRIMARY_HOME=live["codex"]["primary_home"],
                           MULGAE_MCP_CODEX_BINARY=live["mcp_clients"]["codex_binary"],
                           MULGAE_MCP_CLAUDE_BINARY=live["mcp_clients"]["claude_binary"])
                token_name = live["cursor"]["token_env_var"]
                if token_name != "CURSOR_AUTH_TOKEN" or not os.environ.get(token_name):
                    raise Refusal("the guest invoking process lacks the admitted Cursor token")
                # Pin declared executable paths before the first live call. No sign-in,
                # profile, launcher or account configuration is performed here.
                for path in (live["grok"]["executable"], live["cursor"]["executable"],
                             live["agy"]["executable"], live["codex"]["executable"],
                             live["mcp_clients"]["codex_binary"], live["mcp_clients"]["claude_binary"]):
                    if not Path(path).is_absolute() or not os.access(path, os.X_OK):
                        raise Refusal("an admitted guest client executable is unavailable")
                for path in (live["codex"]["primary_home"], live["zcode"]["app_bundle"]):
                    if not Path(path).is_absolute() or not Path(path).is_dir():
                        raise Refusal("an admitted guest account/app directory is unavailable")
                import time
                with (results/"live-controller.log").open("xb") as log:
                    daemon = subprocess.Popen([native, "daemon", "run", "--root", str(controller)],
                                              env=env, stdout=log, stderr=subprocess.STDOUT,
                                              start_new_session=True)
                    deadline = time.monotonic()+20
                    while not (controller/"control.sock").exists():
                        if daemon.poll() is not None or time.monotonic() >= deadline:
                            raise Refusal("isolated live review controller did not become ready")
                        time.sleep(0.05)
                    resource = work/"review-resource.json"
                    write_json(resource, {"schema":"haepari.resource/v1","id":"mulgae-review","kind":"lock","capacity":1})
                    execute([native, "resource", "register", "--file", str(resource), "--json"],
                            work, env, results/"live-resource.log")
                    for target in ("test-e2e", "test-grok", "test-cursor", "test-agy",
                                   "test-e2e-opt-in", "test-mcp-requirements-clients"):
                        target_env = dict(env, MULGAE_E2E_OPT_IN="1")
                        execute(["make", target], bundle/"source", target_env, results/(target+".log"))
                        targets.append({"target": target, "exit_code": 0})
            finally:
                if daemon is not None:
                    daemon.terminate()
                    try:
                        daemon.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        UNVERIFIED_GROUPS.append(daemon.pid)
                if not UNVERIFIED_GROUPS and controller.exists() and (controller.stat().st_dev, controller.stat().st_ino) == (controller_identity.st_dev, controller_identity.st_ino):
                    remove_owned_tree(controller)
                else:
                    UNVERIFIED_GROUPS.append(daemon.pid if daemon is not None else os.getpid())
                write_json(results/"live-providers-summary.json", dict(
                    identity, schema="mulgae.vm-live-providers-summary/v1", serial_execution=True,
                    targets=targets, status="pass" if len(targets) == 6 else "fail",
                ))
        else:
            raise Refusal("unsupported guest suite")
        status = "incomplete" if gaps else "pass"
    except (Refusal, OSError, subprocess.SubprocessError, ValueError, KeyError) as exc:
        gaps.append(str(exc))
    finally:
        write_json(results/"inventory-after.json", inventory(identity, roots))
        if mode == "manual":
            # Keep the real installed project/history/skill until the operator's
            # observations and explicit guest finalization; smoke is not PASS.
            write_json(results/"manual-staging.json", dict(
                identity, schema="mulgae.vm-manual-staging/v1", status="awaiting_observation",
                owned_root=str(work), results_dir=str(results), bundle=str(bundle),
                automatic_status=status, gaps=gaps, unverified_process_groups=list(UNVERIFIED_GROUPS),
                remaining_controller_roots=[str(path) for path in roots[1:] if path.exists()],
                instructions="test/vm/scenarios.md",
            ))
        else:
            try:
                if any(path.exists() for path in roots[1:]):
                    raise Refusal("owned review controller root remains; cleanup is unverified")
                cleanup(work, results, identity)
            except (Refusal, OSError) as exc:
                status = "fail"
                gaps.append(str(exc))
                write_json(results/"post-cleanup-inventory.json", inventory(identity, roots))
                write_json(results/"consumer-cleanup.json", dict(identity, schema="mulgae.vm-consumer-cleanup/v1", status="unverified"))
        write_json(results/"result.json", dict(
            identity, schema="mulgae.vm-suite-result/v1", suite=suite, mode=mode,
            status=status, gaps=gaps, command_results=COMMAND_RESULTS,
            limits="Manual, live and released qualification are distinct.",
        ))
    return 0 if mode == "manual" else (0 if status == "pass" else 3)


def main() -> int:
    try:
        return run(sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5],
                   Path(sys.argv[6]).resolve(), Path(sys.argv[7]).resolve())
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("refused: "+str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
