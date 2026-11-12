#!/usr/bin/env python3
"""Finalize only an owned manual guest fixture before native manual completion."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

from guest import cleanup
from haepari_inputs import check_python_entrypoint
from haepari_inputs import Refusal, regular_bytes, verify_sealed_bundle


def finalize(stage_path: Path) -> None:
    stage = json.loads(regular_bytes(stage_path))
    if stage.get("schema") != "mulgae.vm-manual-staging/v1":
        raise Refusal("unsupported manual staging record")
    if subprocess.run(["/usr/bin/uname", "-s"], check=True, capture_output=True, text=True).stdout.strip() != "Darwin":
        raise Refusal("manual finalization requires the admitted Darwin guest")
    hv = subprocess.run(["/usr/sbin/sysctl", "-n", "kern.hv_vmm_present"], check=True, capture_output=True, text=True).stdout.strip()
    hardware = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                              check=True, capture_output=True, text=True).stdout
    import re
    uuid = re.search(r'"IOPlatformUUID"\s*=\s*"([^"]+)"', hardware)
    if hv != "1" or not uuid or uuid[1].upper() != stage["guest_hardware_uuid"]:
        raise Refusal("manual finalization guest identity mismatch")
    bundle, results = Path(stage["bundle"]), Path(stage["results_dir"])
    if bundle.resolve() != bundle or results.resolve() != results or stage_path.resolve() != results/"manual-staging.json":
        raise Refusal("manual staging path is not its sealed guest result location")
    verify_sealed_bundle(bundle)
    request = json.loads(regular_bytes(bundle/"profiles/execution-request.json"))
    expected = {
        "installation_id": request["haepari"]["installation_id"],
        "candidate_commit": request["candidate"]["source_commit"],
        "candidate_binary_sha256": request["candidate"]["binary_sha256"],
        "skill_tree_git_object": request["candidate"]["skill_tree_git_object"],
        "profile_id": request["profiles"]["target_profile_id"],
        "profile_digest": request["profiles"]["target_profile_sha256"].removeprefix("sha256:"),
    }
    if any(stage.get(key) != value for key, value in expected.items()):
        raise Refusal("manual fixture candidate/profile identity mismatch")
    keys = tuple(expected)+("job_id", "lease_generation", "guest_hardware_uuid")
    identity = {key: stage[key] for key in keys}
    for group in stage.get("unverified_process_groups", []):
        if type(group) is not int or group <= 1:
            raise Refusal("invalid owned process-group identity")
        try:
            __import__("os").killpg(group, 0)
        except ProcessLookupError:
            pass
        else:
            raise Refusal("an originally unverified owned process group still exists")
    if any(Path(path).exists() for path in stage.get("remaining_controller_roots", [])):
        raise Refusal("an originally retained review controller root still exists")
    cleanup(Path(stage["owned_root"]), results, identity)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stage", required=True)
    args = parser.parse_args()
    try:
        finalize(Path(args.stage))
    except (Refusal, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("refused: "+str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    check_python_entrypoint()
    raise SystemExit(main())
