#!/usr/bin/env python3
"""VM-free contract test suite for Mulgae's Haepari host adapter, input sealer, and guest recipe.

All CLI stand-ins in this file are explicitly labeled:
    evidence_kind = "scripted_cli_host_contract_only"
They verify host/guest contract guards without substituting for real UTM macOS guest or live-provider execution.
"""

from __future__ import annotations

import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

sys.dont_write_bytecode = True

TEST_VM_DIR = Path(__file__).resolve().parent
REPO_ROOT = TEST_VM_DIR.parents[1]
if str(TEST_VM_DIR) not in sys.path:
    sys.path.insert(0, str(TEST_VM_DIR))

import haepari_inputs  # noqa: E402
import host  # noqa: E402
import guest  # noqa: E402
import gui  # noqa: E402


EVIDENCE_KIND = "scripted_cli_host_contract_only"
SAMPLE_GUEST_UUID = "11111111-2222-3333-4444-555555555555"
SAMPLE_CANDIDATE_COMMIT = "df287e959010b8cef2b6a54b67067c19154ba2b2"
SAMPLE_SKILL_TREE_SHA = "874e4f007a518502889281fbcf20b433931b6395"


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


class GUIWorkerLifecycleTests(unittest.TestCase):
    def test_real_worker_exit_and_caller_loss(self) -> None:
        # Real subprocesses and sockets; no launchd, VM, provider or credentials.
        driver = """
import json, os, socket, sys
from pathlib import Path
import gui
with socket.socket(fileno=int(sys.argv[1])) as lifeline:
    with Path(sys.argv[3]).open("wb") as log:
        result = gui.run_command(
            [sys.executable, "-c", sys.argv[4]], Path.cwd(), dict(os.environ),
            log, lifeline)
    Path(sys.argv[2]).write_text(json.dumps(result))
"""
        for action in ("success", "nonzero", "cancel", "caller_loss"):
            with self.subTest(action=action), tempfile.TemporaryDirectory(
                    prefix="mulgae-gui-contract-", dir="/private/tmp") as raw:
                root = Path(raw)
                parent, child = socket.socketpair()
                parent.settimeout(10)
                sleep = "30" if action in ("cancel", "caller_loss") else "0.2"
                code = 7 if action == "nonzero" else 0
                command = f"import time; print('worker started', flush=True); time.sleep({sleep}); raise SystemExit({code})"
                helper = subprocess.Popen(
                    [sys.executable, "-B", "-c", driver, str(child.fileno()),
                     str(root / "result.json"), str(root / "worker.log"), command],
                    cwd=TEST_VM_DIR, pass_fds=(child.fileno(),),
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                )
                child.close()
                pid = None
                try:
                    pid = int(gui.receive(parent)["guest_pid"])
                    if action == "cancel":
                        parent.sendall(b"!")
                    elif action == "caller_loss":
                        parent.close()
                    _, stderr = helper.communicate(timeout=15)
                    self.assertEqual(helper.returncode, 0, stderr.decode())
                    result = json.loads((root / "result.json").read_bytes())
                    self.assertTrue(result["guest_group_drained"])
                    self.assertEqual(result["cancelled"], action in ("cancel", "caller_loss"))
                    if action in ("success", "nonzero"):
                        self.assertEqual(result["exit_code"], code)
                    with self.assertRaises(ProcessLookupError):
                        os.kill(pid, 0)
                    with self.assertRaises(ProcessLookupError):
                        os.killpg(pid, 0)
                finally:
                    parent.close()
                    if helper.poll() is None:
                        helper.kill()
                        helper.wait()
                    if pid is not None:
                        try:
                            os.killpg(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass


class HaepariVMContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="mulgae-vm-contract-", dir="/private/tmp")
        self.tmp_root = Path(self._tmp.name).resolve()

        self.start_profile = self.tmp_root / "profile-v0.2.14.json"
        self.start_profile_bytes = b'{"profile_id": "mulgae-guest-v0.2.14", "version": "v0.2.14"}\n'
        self.start_profile.write_bytes(self.start_profile_bytes)

        self.target_profile = self.tmp_root / "profile-v0.2.16.json"
        self.target_profile_bytes = b'{"profile_id": "mulgae-guest-v0.2.16", "version": "v0.2.16"}\n'
        self.target_profile.write_bytes(self.target_profile_bytes)

        self.fake_haepari = self.tmp_root / "fake-haepari"
        self._write_fake_haepari()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _write_fake_haepari(self) -> None:
        # Envelopes/Receipt/Result fields come from frozen Haepari v0.1.0,
        # not from this adapter's parser. No controller or Job is started.
        script = r"""#!/usr/bin/env python3
import json
import os
import re
import sys
from pathlib import Path

args = sys.argv[1:]
log_path = os.environ.get("FAKE_HAEPARI_LOG", "")
if log_path:
    with open(log_path, "a", encoding="utf-8") as out:
        out.write(json.dumps({"argv": args, "evidence_kind": "scripted_cli_host_contract_only"}) + "\n")

def emit(data, code=0, ok=True):
    result = {"schema": "haepari.envelope/v1", "operation": ".".join(args[:2]) if args[0] == "manual" else args[0], "ok": ok}
    result["data" if ok else "error"] = data
    print(json.dumps(result))
    sys.exit(code)

inst = os.environ.get("FAKE_HAEPARI_INSTALLATION_ID", "inst-contract-001")
resource = os.environ.get("FAKE_HAEPARI_RESOURCE_ID", "mulgae-qual-vm")
revision = int(os.environ.get("FAKE_HAEPARI_CONFIG_REV", "1"))
job = os.environ.get("FAKE_HAEPARI_JOB_ID", "job-contract-101")
receipt = {"job_id": job, "job_revision": 1, "job_state": "queued", "resource_id": resource,
           "resource_config_revision": revision, "lease_generation": 1}

if args[0] == "doctor":
    ready = os.environ.get("FAKE_HAEPARI_DOCTOR_STATUS", "ready") == "ready"
    emit({"schema": "haepari.doctor/v1", "installation_id": inst, "resource_id": resource,
          "resource": {"resource_id": resource, "kind": "utm-macos", "config_revision": revision,
                       "configuration_digest": "c" * 64, "capacity": 1},
          "ready": ready, "gaps": []}, int(os.environ.get("FAKE_HAEPARI_DOCTOR_EXIT", "0")))

if args[0] == "submit":
    try:
        assert len(args) == 6 and args[1] == "--spec" and args[3] == "--request-key" and args[5] == "--json"
        spec = json.loads(Path(args[2]).read_text())
        required = {"schema", "execution_mode", "resource_id", "mode", "suite", "input",
                    "environment", "workload", "deadlines", "effects", "provenance"}
        assert set(spec) in (required, required | {"manual"})
        assert spec["schema"] == "haepari.job/v2" and spec["execution_mode"] == "managed"
        assert spec["resource_id"] == resource
        assert set(spec["input"]) == {"root", "inventory_digest", "selected_files"}
        assert set(spec["workload"]) == {"argv", "cwd", "environment", "required_outputs"}
        assert spec["workload"]["cwd"] == "bundle"
        assert (Path(spec["input"]["root"]) / "bundle" / spec["workload"]["argv"][1]).is_file()
        assert set(spec["environment"]) == {"profile_id", "profile_digest"}
        assert set(spec["effects"]) == {"mode", "authorization_reference"}
        assert all(type(v) is int and v > 0 for v in spec["deadlines"].values())
        for value in [spec["input"]["inventory_digest"], spec["environment"]["profile_digest"],
                      spec["provenance"]["candidate_digest"], spec["provenance"]["tests_digest"]]:
            assert re.fullmatch("[0-9a-f]{64}", value)
        if spec["mode"] == "manual":
            assert set(spec["manual"]) == {"scenario_document", "required_scenarios"}
    except (AssertionError, KeyError, ValueError):
        emit({"code": "INVALID_REQUEST", "message": "unsupported native Job shape", "retry": "none"}, 2, False)
    emit(receipt, int(os.environ.get("FAKE_HAEPARI_SUBMIT_EXIT", "0")))

if args[0] == "inspect":
    emit({"receipt": dict(receipt, job_revision=2,
                         job_state=os.environ.get("FAKE_HAEPARI_INSPECT_STATE", "awaiting_manual"))})

if args[0] == "wait":
    code = int(os.environ.get("FAKE_HAEPARI_WAIT_EXIT", "0"))
    if os.environ.get("FAKE_HAEPARI_WAIT_MALFORMED") == "1":
        print("not-json")
        sys.exit(code)
    if code == 5:
        emit({"code": "WAIT_TIMEOUT", "message": "scripted observer timeout", "retry": "none"}, 5, False)
    verdict = os.environ.get("FAKE_HAEPARI_WAIT_VERDICT", "PASS")
    emit({"schema": "haepari.result/v2", "job_id": args[1], "resource_id": resource,
          "resource_revision": revision, "lease_generation": 1, "job_state": "finished",
          "resource_availability": "available", "final_verdict": verdict,
          "workload_outcome": {"PASS": "pass", "FAIL": "fail", "CANCELLED": "cancelled"}.get(verdict, "inconclusive"),
          "evidence_completeness": "complete" if verdict != "INCOMPLETE" else "partial",
          "cleanup_outcome": "verified" if verdict != "INCOMPLETE" else "unknown"}, code)

if args[:2] == ["manual", "complete"]:
    emit(dict(receipt, job_revision=3, job_state="collecting"))

emit({"code": "INVALID_REQUEST", "message": "unsupported scripted command", "retry": "none"}, 2, False)
"""
        self.fake_haepari.write_text(script, encoding="utf-8")
        self.fake_haepari.chmod(0o700)
        self.fake_haepari_sha = _sha256_bytes(self.fake_haepari.read_bytes())

    def _base_request(self, include_live: bool = False) -> dict:
        req = {
            "schema": "mulgae.haepari-vm-request/v1",
            "haepari": {
                "executable": str(self.fake_haepari),
                "executable_sha256": self.fake_haepari_sha,
                "installation_root": str(self.tmp_root / "haepari-home"),
                "installation_id": "inst-contract-001",
            },
            "resource": {
                "id": "mulgae-qual-vm",
                "kind": "utm-macos",
                "configuration_revision": 1,
            },
            "guest": {
                "expected_hardware_uuid": SAMPLE_GUEST_UUID,
            },
            "profiles": {
                "starting_profile_id": "mulgae-guest-v0.2.14",
                "starting_profile_file": str(self.start_profile),
                "starting_profile_sha256": _sha256_bytes(self.start_profile_bytes),
                "target_profile_id": "mulgae-guest-v0.2.16",
                "target_profile_file": str(self.target_profile),
                "target_profile_sha256": _sha256_bytes(self.target_profile_bytes),
            },
            "candidate": {
                "source_commit": SAMPLE_CANDIDATE_COMMIT,
                "binary_sha256": "sha256:" + ("a" * 64),
                "skill_tree_git_object": SAMPLE_SKILL_TREE_SHA,
                "authorization_reference": "EPIC-016/TASK-080",
            },
            "prior_release": {
                "version": "v0.1.26",
                "tag_commit": "c422590155f62380709c8f6fd08c9ad423badaaa",
                "install_target": "github.com/irootkernel/mulgae@v0.1.26",
                "go_toolchain": "go1.27.1",
                "goproxy": "https://proxy.golang.org,direct",
                "network_exposure": "guest-nat-outbound-https-only",
            },
            "review_controller_home": "/tmp/mulgae-guest-review-haepari-home",
        }
        if include_live:
            req["live_accounts"] = {
                "zcode": {"app_bundle": "/Applications/ZCode.app", "account_alias": "guest-zcode"},
                "grok": {"executable": "/usr/local/bin/grok", "account_alias": "guest-grok"},
                "cursor": {
                    "executable": "/usr/local/bin/cursor-agent",
                    "account_alias": "guest-cursor",
                    "token_env_var": "CURSOR_AUTH_TOKEN",
                },
                "agy": {"executable": "/usr/local/bin/agy", "account_alias": "guest-agy"},
                "codex": {
                    "executable": "/usr/local/bin/codex",
                    "primary_home": "/Users/guest/.codex-primary",
                    "primary_account_alias": "guest-codex-1",
                },
                "mcp_clients": {
                    "codex_binary": "/usr/local/bin/codex",
                    "claude_binary": "/usr/local/bin/claude",
                    "claude_account_alias": "guest-claude",
                },
            }
        return req

    def _write_request_file(self, payload: dict, name: str = "request.json") -> Path:
        path = self.tmp_root / name
        path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path


    def test_owned_guest_cleanup_refuses_foreign_identity_and_open_handles(self) -> None:
        # Pure ownership policy with a scripted lsof result; no guest workload,
        # controller, Go installation or real process probe is executed.
        with tempfile.TemporaryDirectory(prefix="mulgae-vm-", dir="/private/tmp") as raw:
            work = Path(raw)
            results = self.tmp_root / "cleanup-results"
            results.mkdir()
            identity = guest.binding(self._base_request(), "job-cleanup-1", 1, SAMPLE_GUEST_UUID)
            info = work.stat()
            owner = dict(identity, root_dev=info.st_dev, root_ino=info.st_ino)
            guest.write_json(work / "consumer-owner.json", dict(owner, job_id="foreign-job"))
            with self.assertRaises(haepari_inputs.Refusal):
                guest.cleanup(work, results, identity)
            self.assertTrue(work.exists())
            guest.write_json(work / "consumer-owner.json", owner)
            with mock.patch("guest.subprocess.run", return_value=subprocess.CompletedProcess([], 0, "123\n", "")):
                with self.assertRaises(haepari_inputs.Refusal):
                    guest.cleanup(work, results, identity)
            self.assertTrue(work.exists())
            cache = work / "readonly-go-module"
            cache.mkdir()
            (cache / "source.go").write_bytes(b"package fixture\n")
            cache.chmod(0o555)
            with mock.patch("guest.subprocess.run", return_value=subprocess.CompletedProcess([], 1, "", "")):
                guest.cleanup(work, results, identity)
            self.assertFalse(work.exists())
            cleanup = json.loads((results / "consumer-cleanup.json").read_bytes())
            self.assertEqual(cleanup["job_id"], identity["job_id"])
            self.assertEqual(cleanup["post_cleanup_inventory_sha256"],
                             _sha256_bytes((results / "post-cleanup-inventory.json").read_bytes()))

    def test_declared_guest_tool_paths_are_carried_into_native_environment(self) -> None:
        request = self._base_request()
        request["guest"].update(go_executable="/Users/guest/.local/bin/go", python_executable="/Users/guest/.local/bin/python3")
        validated = haepari_inputs.validate_execution_request(
            request, REPO_ROOT, "guest-qualification", haepari_inputs.DEFAULT_SUITES["guest-qualification"],
        )
        self.assertEqual(validated["guest"], request["guest"])
        request["guest"]["go_executable"] = "../untrusted/go"
        with self.assertRaises(haepari_inputs.Refusal):
            haepari_inputs.validate_execution_request(
                request, REPO_ROOT, "guest-qualification", haepari_inputs.DEFAULT_SUITES["guest-qualification"],
            )

    def test_prepared_artifact_binding(self) -> None:
        root = self.tmp_root / "prepared"
        artifacts = root / "artifacts"
        artifacts.mkdir(parents=True, mode=0o700)
        binary = artifacts / "mulgae"
        binary.write_bytes(b"synthetic artifact; never executed")
        binary.chmod(0o700)
        candidate = dict(self._base_request()["candidate"])
        candidate["binary_sha256"] = _sha256_bytes(binary.read_bytes())
        receipt = {
            "schema": "mulgae.vm-prepared-candidate/v1",
            **{key: candidate[key] for key in ("source_commit", "binary_sha256", "skill_tree_git_object")},
            "files": {"artifacts/mulgae": candidate["binary_sha256"]},
        }
        (artifacts / "candidate.json").write_text(json.dumps(receipt))
        request = {"candidate": candidate}
        self.assertEqual(haepari_inputs.verify_prepared_candidate(root, request), receipt)
        native = artifacts / "haepari"
        native.write_bytes(self.fake_haepari.read_bytes())
        receipt["files"]["artifacts/haepari"] = self.fake_haepari_sha
        receipt["native_controller_sha256"] = self.fake_haepari_sha
        (artifacts / "candidate.json").write_text(json.dumps(receipt))
        request["haepari"] = {"executable_sha256": self.fake_haepari_sha}
        haepari_inputs.verify_prepared_candidate(root, request)
        request["haepari"]["executable_sha256"] = "sha256:"+"f"*64
        with self.assertRaises(haepari_inputs.Refusal):
            haepari_inputs.verify_prepared_candidate(root, request)
        request["haepari"]["executable_sha256"] = self.fake_haepari_sha
        other = {"candidate": dict(candidate, source_commit="f"*40)}
        with self.assertRaises(haepari_inputs.Refusal):
            haepari_inputs.verify_prepared_candidate(root, other)
        binary.write_bytes(b"changed bytes")
        with self.assertRaises(haepari_inputs.Refusal):
            haepari_inputs.verify_prepared_candidate(root, request)

    def test_compressed_candidate_preserves_executable_identity(self) -> None:
        import gzip
        root = self.tmp_root / "compressed-prepared"
        artifacts = root / "artifacts"
        artifacts.mkdir(parents=True, mode=0o700)
        payload = b"synthetic executable identity"
        packed = artifacts / "mulgae.gz"
        packed.write_bytes(gzip.compress(payload, mtime=0))
        candidate = dict(self._base_request()["candidate"], binary_sha256=_sha256_bytes(payload))
        receipt = {
            "schema": "mulgae.vm-prepared-candidate/v1",
            **{key: candidate[key] for key in ("source_commit", "binary_sha256", "skill_tree_git_object")},
            "files": {"artifacts/mulgae.gz": _sha256_bytes(packed.read_bytes())},
        }
        (artifacts / "candidate.json").write_text(json.dumps(receipt))
        self.assertEqual(haepari_inputs.verify_prepared_candidate(root, {"candidate": candidate}), receipt)
        self.assertEqual(haepari_inputs.candidate_binary_bytes(root), payload)
        (artifacts / "mulgae").write_bytes(payload)
        with self.assertRaises(haepari_inputs.Refusal):
            haepari_inputs.verify_prepared_candidate(root, {"candidate": candidate})
        (artifacts / "mulgae").unlink()
        packed.write_bytes(gzip.compress(b"other executable", mtime=0))
        receipt["files"]["artifacts/mulgae.gz"] = _sha256_bytes(packed.read_bytes())
        (artifacts / "candidate.json").write_text(json.dumps(receipt))
        with self.assertRaises(haepari_inputs.Refusal):
            haepari_inputs.verify_prepared_candidate(root, {"candidate": candidate})

    def test_selected_file_sealing_and_tamper_refusal(self) -> None:
        req = haepari_inputs.validate_execution_request(
            self._base_request(),
            REPO_ROOT,
            "guest-qualification",
            haepari_inputs.DEFAULT_SUITES["guest-qualification"],
        )
        run_dir = self.tmp_root / "seal-run"
        run_dir.mkdir(mode=0o700)
        digests = haepari_inputs.capture_inputs(
            REPO_ROOT,
            run_dir,
            haepari_inputs.DEFAULT_SELECTED_FILES,
            req,
        )
        self.assertEqual(digests["candidate_digest"], req["candidate"]["binary_sha256"])
        self.assertEqual(digests["profile_digest"], req["profiles"]["target_profile_sha256"])
        manifest = haepari_inputs.verify_sealed_bundle(run_dir / "bundle", run_dir / "bundle-manifest.json")
        self.assertEqual(manifest["digests"], digests)

        # Tamper with a sealed skill file and verify refusal.
        skill_file = run_dir / "bundle" / "skills" / "use-mulgae" / "SKILL.md"
        skill_file.write_bytes(skill_file.read_bytes() + b"\n<!-- tampered -->\n")
        with self.assertRaises(haepari_inputs.Refusal) as ctx:
            haepari_inputs.verify_sealed_bundle(run_dir / "bundle", run_dir / "bundle-manifest.json")
        self.assertIn("tampered", str(ctx.exception))

    def test_symlink_and_credential_filename_refusal(self) -> None:
        fake_repo = self.tmp_root / "fake-repo"
        fake_repo.mkdir(mode=0o700)
        (fake_repo / "local.yaml").write_text("secret: true\n", encoding="utf-8")
        with self.assertRaises(haepari_inputs.Refusal) as ctx:
            haepari_inputs.validate_paths(fake_repo, ["local.yaml"])
        self.assertIn("credential-like input path is forbidden", str(ctx.exception))

        target = fake_repo / "real.txt"
        target.write_text("ok\n", encoding="utf-8")
        link = fake_repo / "link.txt"
        link.symlink_to(target)
        with self.assertRaises(haepari_inputs.Refusal) as ctx2:
            haepari_inputs.validate_paths(fake_repo, ["link.txt"])

    def test_execution_request_refuses_secrets_profile_relabeling_and_missing_live_accounts(self) -> None:
        # 1. Embedded secret field refused.
        bad_secret = self._base_request()
        bad_secret["cursor_auth_token"] = "raw-secret-value"
        with self.assertRaises(haepari_inputs.Refusal) as ctx:
            haepari_inputs.validate_execution_request(
                bad_secret,
                REPO_ROOT,
                "guest-qualification",
                haepari_inputs.DEFAULT_SUITES["guest-qualification"],
            )
        self.assertIn("forbidden", str(ctx.exception))

        # 2. Relabeling v0.2.14 as v0.2.16 refused.
        relabeled = self._base_request()
        relabeled["profiles"]["target_profile_file"] = str(self.start_profile)
        relabeled["profiles"]["target_profile_sha256"] = _sha256_bytes(self.start_profile_bytes)
        with self.assertRaises(haepari_inputs.Refusal) as ctx2:
            haepari_inputs.validate_execution_request(
                relabeled,
                REPO_ROOT,
                "guest-qualification",
                haepari_inputs.DEFAULT_SUITES["guest-qualification"],
            )
        self.assertIn("profile relabeling is forbidden", str(ctx2.exception))

        # 3. Missing live_accounts for live-providers suite refused.
        with self.assertRaises(haepari_inputs.Refusal) as ctx3:
            haepari_inputs.validate_execution_request(
                self._base_request(include_live=False),
                REPO_ROOT,
                "live-providers",
                haepari_inputs.DEFAULT_SUITES["live-providers"],
            )
        self.assertIn("requires request.live_accounts", str(ctx3.exception))

        # 4. Main-only Codex live_accounts accepted; secondary Codex fields refused.
        valid_live = haepari_inputs.validate_execution_request(
            self._base_request(include_live=True),
            REPO_ROOT,
            "live-providers",
            haepari_inputs.DEFAULT_SUITES["live-providers"],
        )
        self.assertEqual(
            valid_live["live_accounts"]["codex"],
            {
                "executable": "/usr/local/bin/codex",
                "primary_home": "/Users/guest/.codex-primary",
                "primary_account_alias": "guest-codex-1",
            },
        )
        for forbidden_key in ("secondary_home", "secondary_account_alias"):
            with_secondary = self._base_request(include_live=True)
            with_secondary["live_accounts"]["codex"][forbidden_key] = "retired-secondary"
            with self.assertRaises(haepari_inputs.Refusal):
                haepari_inputs.validate_execution_request(
                    with_secondary,
                    REPO_ROOT,
                    "live-providers",
                    haepari_inputs.DEFAULT_SUITES["live-providers"],
                )

    def test_request_refuses_unsupported_local_toolchain(self) -> None:
        request = self._base_request()
        request["prior_release"]["go_toolchain"] = "go1.26.1"
        with self.assertRaises(haepari_inputs.Refusal):
            haepari_inputs.validate_execution_request(
                request, REPO_ROOT, "guest-qualification",
                haepari_inputs.DEFAULT_SUITES["guest-qualification"],
            )

    def test_host_parent_context_guard(self) -> None:
        req_file = self._write_request_file(self._base_request())
        old = os.environ.get("HAEPARI_PARENT_CONTEXT")
        os.environ["HAEPARI_PARENT_CONTEXT"] = '{"job_id":"j1","lease_generation":1,"nonce":"' + ("a" * 64) + '"}'
        try:
            with self.assertRaises(haepari_inputs.Refusal) as ctx:
                host.run(["--request", str(req_file), "--resource", "mulgae-qual-vm"])
            self.assertIn("host submission is forbidden inside a managed guest", str(ctx.exception))
        finally:
            if old is None:
                os.environ.pop("HAEPARI_PARENT_CONTEXT", None)
            else:
                os.environ["HAEPARI_PARENT_CONTEXT"] = old

    def test_host_submit_replay_and_conflict_refusal(self) -> None:
        req_file = self._write_request_file(self._base_request())
        run_dir = self.tmp_root / "run-replay"
        log_file = self.tmp_root / "cli-log.jsonl"
        old_log = os.environ.get("FAKE_HAEPARI_LOG")
        os.environ["FAKE_HAEPARI_LOG"] = str(log_file)
        try:
            code1 = host.run(
                [
                    "--haepari",
                    str(self.fake_haepari),
                    "--request",
                    str(req_file),
                    "--resource",
                    "mulgae-qual-vm",
                    "--suite",
                    "guest-qualification",
                    "--mode",
                    "auto",
                    "--run-dir",
                    str(run_dir),
                ]
            )
            self.assertEqual(code1, 0)
            saved1 = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            req_key1 = saved1["entries"][0]["request_key"]
            self.assertEqual(saved1["entries"][0]["job_id"], "job-contract-101")

            # Reconnect with identical parameters reuses the same request_key and spec_sha256.
            code2 = host.run(
                [
                    "--haepari",
                    str(self.fake_haepari),
                    "--request",
                    str(req_file),
                    "--resource",
                    "mulgae-qual-vm",
                    "--suite",
                    "guest-qualification",
                    "--mode",
                    "auto",
                    "--run-dir",
                    str(run_dir),
                ]
            )
            self.assertEqual(code2, 0)
            saved2 = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(saved2["entries"][0]["request_key"], req_key1)

            # Verify exact native submit grammar in log.
            logged = [json.loads(line) for line in log_file.read_text(encoding="utf-8").splitlines()]
            submit_calls = [entry["argv"] for entry in logged if entry["argv"][0] == "submit"]
            self.assertEqual(len(submit_calls), 2)
            self.assertIn("--spec", submit_calls[0])
            self.assertIn("--request-key", submit_calls[0])
            self.assertIn(req_key1, submit_calls[0])

            # Conflict on suite selection with the same run_dir is refused.
            with self.assertRaises(haepari_inputs.Refusal) as ctx_conflict:
                host.run(
                    [
                        "--haepari",
                        str(self.fake_haepari),
                        "--request",
                        str(req_file),
                        "--resource",
                        "mulgae-qual-vm",
                        "--suite",
                        "manual-qualification",
                        "--mode",
                        "auto",
                        "--run-dir",
                        str(run_dir),
                    ]
                )
            self.assertIn("different resource, suite, or mode", str(ctx_conflict.exception))

            # Installation mismatch on reconnect is refused.
            bad_inst_req = self._base_request()
            bad_inst_req["haepari"]["installation_id"] = "inst-different-999"
            bad_req_file = self._write_request_file(bad_inst_req, "bad-inst.json")
            os.environ["FAKE_HAEPARI_INSTALLATION_ID"] = "inst-different-999"
            with self.assertRaises(haepari_inputs.Refusal) as ctx_inst:
                host.run(
                    [
                        "--haepari",
                        str(self.fake_haepari),
                        "--request",
                        str(bad_req_file),
                        "--resource",
                        "mulgae-qual-vm",
                        "--suite",
                        "guest-qualification",
                        "--mode",
                        "auto",
                        "--run-dir",
                        str(run_dir),
                    ]
                )
            self.assertIn("installation_id", str(ctx_inst.exception))
        finally:
            os.environ.pop("FAKE_HAEPARI_INSTALLATION_ID", None)
            if old_log is None:
                os.environ.pop("FAKE_HAEPARI_LOG", None)
            else:
                os.environ["FAKE_HAEPARI_LOG"] = old_log

    def test_host_truthful_exit_and_timeout_mappings(self) -> None:
        req_file = self._write_request_file(self._base_request())
        cases = [
            ("0", "PASS", 0),
            ("1", "FAIL", 1),
            ("3", "INCOMPLETE", 3),
            ("4", "CANCELLED", 4),
            ("5", "PENDING", 5),
        ]
        for idx, (wait_exit, verdict, expected_code) in enumerate(cases):
            run_dir = self.tmp_root / f"run-map-{idx}"
            os.environ["FAKE_HAEPARI_WAIT_EXIT"] = wait_exit
            os.environ["FAKE_HAEPARI_WAIT_VERDICT"] = verdict
            try:
                code = host.run(
                    [
                        "--haepari",
                        str(self.fake_haepari),
                        "--request",
                        str(req_file),
                        "--resource",
                        "mulgae-qual-vm",
                        "--suite",
                        "guest-qualification",
                        "--mode",
                        "auto",
                        "--run-dir",
                        str(run_dir),
                    ]
                )
                self.assertEqual(code, expected_code)
            finally:
                os.environ.pop("FAKE_HAEPARI_WAIT_EXIT", None)
                os.environ.pop("FAKE_HAEPARI_WAIT_VERDICT", None)

        # Malformed wait output maps to UNKNOWN (exit code 2).
        run_dir_unknown = self.tmp_root / "run-unknown"
        os.environ["FAKE_HAEPARI_WAIT_EXIT"] = "7"
        os.environ["FAKE_HAEPARI_WAIT_MALFORMED"] = "1"
        try:
            code_unk = host.main(
                [
                    "--haepari",
                    str(self.fake_haepari),
                    "--request",
                    str(req_file),
                    "--resource",
                    "mulgae-qual-vm",
                    "--suite",
                    "guest-qualification",
                    "--mode",
                    "auto",
                    "--run-dir",
                    str(run_dir_unknown),
                ]
            )
            self.assertEqual(code_unk, 2)
        finally:
            os.environ.pop("FAKE_HAEPARI_WAIT_EXIT", None)
            os.environ.pop("FAKE_HAEPARI_WAIT_MALFORMED", None)

    def test_manual_cleanup_before_completion_ordering(self) -> None:
        request = self._base_request()
        request_file = self._write_request_file(request)
        run_dir = self.tmp_root / "run-manual"
        args = ["--haepari", str(self.fake_haepari), "--request", str(request_file),
                "--resource", "mulgae-qual-vm", "--suite", "manual-qualification",
                "--mode", "manual", "--run-dir", str(run_dir)]
        os.environ["FAKE_HAEPARI_WAIT_EXIT"] = "5"
        try:
            self.assertEqual(host.run(args), 5)
        finally:
            os.environ.pop("FAKE_HAEPARI_WAIT_EXIT", None)
        manual_path = self.tmp_root / "manual-result.json"
        references = ["results/manual-qualification/manual-observations.json"]
        manual = {
            "schema": "haepari.manual-result/v1", "job_id": "job-contract-101",
            "installation_id": "inst-contract-001",
            "profile_id": request["profiles"]["target_profile_id"],
            "profile_digest": request["profiles"]["target_profile_sha256"].removeprefix("sha256:"),
            "expected_revision": 2, "observer": "scripted-fixture-operator",
            "scenarios": [{"id": name, "status": "pass", "evidence_references": references}
                          for name in haepari_inputs.MANUAL_SCENARIO_IDS],
        }
        manual_path.write_text(json.dumps(manual))
        complete_args = args + ["--manual-complete-input", str(manual_path), "--expected-revision", "2"]
        with self.assertRaisesRegex(haepari_inputs.Refusal, "consumer-cleanup.json"):
            host.run(complete_args)
        results = run_dir / "results/manual-qualification"
        results.mkdir(parents=True)
        (run_dir / references[0]).write_text(json.dumps({"evidence_kind": EVIDENCE_KIND}))
        identity = {
            "job_id": "job-contract-101", "installation_id": "inst-contract-001",
            "lease_generation": 1, "guest_hardware_uuid": SAMPLE_GUEST_UUID,
            "candidate_commit": request["candidate"]["source_commit"],
            "candidate_binary_sha256": request["candidate"]["binary_sha256"],
            "skill_tree_git_object": request["candidate"]["skill_tree_git_object"],
            "profile_id": manual["profile_id"], "profile_digest": manual["profile_digest"],
        }
        inventory = dict(identity, schema="mulgae.vm-guest-inventory/v1",
                         remaining_owned_roots=[], remaining_helper_pids=[])
        inventory_path = results / "post-cleanup-inventory.json"
        inventory_path.write_text(json.dumps(inventory))
        cleanup = dict(identity, schema="mulgae.vm-consumer-cleanup/v1", status="clean",
                       post_cleanup_inventory_sha256=haepari_inputs.file_digest(inventory_path))
        (results / "consumer-cleanup.json").write_text(json.dumps(cleanup))
        inventory_path.write_text(json.dumps(dict(inventory, job_id="foreign-job")))
        with self.assertRaisesRegex(haepari_inputs.Refusal, "does not match"):
            host.run(complete_args)
        inventory_path.write_text(json.dumps(inventory))
        manual_path.write_text(json.dumps(dict(manual, cleanup_completed_before_manual_complete=True)))
        with self.assertRaisesRegex(haepari_inputs.Refusal, "closed native"):
            host.run(complete_args)
        manual_path.write_text(json.dumps(manual))
        os.environ["FAKE_HAEPARI_INSPECT_STATE"] = "running"
        try:
            with self.assertRaisesRegex(haepari_inputs.Refusal, "state/revision changed"):
                host.run(complete_args)
        finally:
            os.environ.pop("FAKE_HAEPARI_INSPECT_STATE", None)
        self.assertEqual(host.run(complete_args), 0)

    def test_native_tree_digest_matches_frozen_reference(self) -> None:
        # Generated once by the frozen upstream example's tree_digest on these exact bytes/mode.
        sample = self.tmp_root / "sample.txt"
        sample.write_bytes(b"opaque\n")
        sample.chmod(0o600)
        expected = "sha256:3cc083c64420b9745134b2abd63d62e708ad8d0cf010097aa12b219d4c527615"
        self.assertEqual(haepari_inputs.tree_digest([("sample.txt", sample)]), expected)
        sample.chmod(0o700)
        self.assertNotEqual(haepari_inputs.tree_digest([("sample.txt", sample)]), expected)

    def test_native_parent_chain_and_guest_identity_policy(self) -> None:
        entry = {"installation_id": "inst-contract-001", "job_id": "job-guest-001",
                 "lease_generation": 1, "nonce": "b" * 64}
        chain = [dict(entry, installation_id="foreign-installation"), entry]
        observed = haepari_inputs.validate_guest_identity(
            json.dumps(chain), "Darwin", "1", SAMPLE_GUEST_UUID, SAMPLE_GUEST_UUID, "inst-contract-001"
        )
        self.assertEqual(observed["job_id"], "job-guest-001")
        self.assertNotIn("nonce", observed)
        invalid = [entry, [], [dict(entry, lease_generation=True)], [dict(entry, nonce="short")],
                   [dict(entry, extra=True)], [dict(entry, installation_id="wrong")], chain * 17]
        for value in invalid:
            with self.subTest(context=value), self.assertRaises(haepari_inputs.Refusal):
                haepari_inputs.validate_guest_identity(
                    json.dumps(value), "Darwin", "1", SAMPLE_GUEST_UUID, SAMPLE_GUEST_UUID, "inst-contract-001"
                )
        for platform_name, hypervisor, hardware in [
            ("Darwin", "0", SAMPLE_GUEST_UUID), ("Linux", "1", SAMPLE_GUEST_UUID),
            ("Darwin", "1", "99999999-9999-9999-9999-999999999999"),
        ]:
            with self.subTest(platform=platform_name, hypervisor=hypervisor), self.assertRaises(haepari_inputs.Refusal):
                haepari_inputs.validate_guest_identity(
                    json.dumps(chain), platform_name, hypervisor, hardware, SAMPLE_GUEST_UUID, "inst-contract-001"
                )

    def test_guest_entrypoint_refuses_missing_native_parent(self) -> None:
        # No positive guest execution is simulated on the host. Actual guest work remains a separate gate.
        env = {key: value for key, value in os.environ.items() if key != "HAEPARI_PARENT_CONTEXT"}
        proc = subprocess.run(
            ["/bin/sh", str(TEST_VM_DIR / "run.sh"), "manual-qualification"],
            cwd=self.tmp_root, env=env, text=True, capture_output=True, check=False, timeout=5,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("missing HAEPARI_PARENT_CONTEXT", proc.stderr)

if __name__ == "__main__":
    unittest.main()
