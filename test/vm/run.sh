#!/bin/sh
# Guest-side workload entrypoint for Mulgae VM qualification and live-provider suites.
#
# Provenance:
# - Adapted from Haepari v0.1.0 (`800da97b7e2ca84a15d4ee5921702ec57bbc7d61`,
#   build revision `fc3b975f8a99cacb96aecc988d3adbc04dda7309`)
#   `examples/project-test/tests/vm/run.sh`.
# - Adapted for Mulgae `TASK-080` (`EPIC-016`, `aquarium/EPIC-032/TASK-092/mulgae-rollout/v1`).

set -eu

SUITE="${1:-${MULGAE_VM_SUITE:-${HAEPARI_TEST_SUITE:-guest-qualification}}}"
MODE="${MULGAE_VM_MODE:-${HAEPARI_TEST_MODE:-auto}}"
export PYTHONDONTWRITEBYTECODE=1

case "$SUITE" in
  guest-qualification|live-providers|manual-qualification) ;;
  *) echo "unsupported Mulgae VM suite: $SUITE" >&2; exit 2 ;;
esac
case "$MODE" in
  auto|manual) ;;
  *) echo "unsupported Mulgae VM mode: $MODE" >&2; exit 2 ;;
esac

if [ -z "${HAEPARI_PARENT_CONTEXT:-}" ]; then
  echo "refused: missing HAEPARI_PARENT_CONTEXT" >&2
  exit 2
fi
OS_NAME=$(/usr/bin/uname -s)
HV_PRESENT=$(/usr/sbin/sysctl -n kern.hv_vmm_present 2>/dev/null || true)
if [ "$OS_NAME" != "Darwin" ] || [ "$HV_PRESENT" != "1" ]; then
  echo "refused: physical host execution is forbidden; a Darwin virtual guest is required" >&2
  exit 2
fi

PYTHON_BIN="${PYTHON:?an explicit admitted Python executable is required}"
BUNDLE_ROOT="."
"$PYTHON_BIN" -B "$BUNDLE_ROOT/test/vm/haepari_inputs.py" \
  --verify-bundle --bundle "$BUNDLE_ROOT" >/dev/null

ACTUAL_UUID=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice \
  | /usr/bin/awk -F\" '/IOPlatformUUID/{print $(NF-1); exit}')
NATIVE_IDENTITY=$("$PYTHON_BIN" -B - "$BUNDLE_ROOT" "$OS_NAME" "$HV_PRESENT" "$ACTUAL_UUID" <<'GUARD_PY'
import json
import os
from pathlib import Path
import sys

bundle = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(bundle / "test/vm"))
from haepari_inputs import Refusal, regular_bytes, validate_guest_identity

try:
    request = json.loads(regular_bytes(bundle / "profiles/execution-request.json"))
    identity = validate_guest_identity(
        os.environ["HAEPARI_PARENT_CONTEXT"], sys.argv[2], sys.argv[3], sys.argv[4],
        request["guest"]["expected_hardware_uuid"], request["haepari"]["installation_id"],
    )
except (Refusal, ValueError, KeyError, OSError) as exc:
    print("refused: " + str(exc), file=sys.stderr)
    sys.exit(2)
print(identity["job_id"] + " " + str(identity["lease_generation"]))
GUARD_PY
) || exit 2
JOB_ID=${NATIVE_IDENTITY% *}
LEASE_GENERATION=${NATIVE_IDENTITY##* }
ACTUAL_UUID_UPPER=$(printf '%s' "$ACTUAL_UUID" | /usr/bin/tr '[:lower:]' '[:upper:]')
RESULTS_DIR="../results/$SUITE"
mkdir -p "$RESULTS_DIR"

GUEST_RUNNER="$BUNDLE_ROOT/test/vm/guest.py"
if [ "$SUITE" = "live-providers" ]; then
  GUEST_RUNNER="$BUNDLE_ROOT/test/vm/gui.py"
fi
exec "$PYTHON_BIN" -B "$GUEST_RUNNER" \
  "$SUITE" "$MODE" "$JOB_ID" "$LEASE_GENERATION" "$ACTUAL_UUID_UPPER" "$BUNDLE_ROOT" "$RESULTS_DIR"
