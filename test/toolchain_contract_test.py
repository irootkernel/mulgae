"""Behavior checks for development toolchain selection; no real installation."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ToolchainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mulgae-toolchain-", dir="/tmp")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve() / "project with spaces"
        (self.root / "tools").mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        shutil.copyfile(ROOT / "tools/toolchains.env", self.root / "tools/toolchains.env")
        shutil.copyfile(ROOT / "tools/mise.toml", self.root / "tools/mise.toml")
        shutil.copyfile(ROOT / "dev", self.root / "dev")
        (self.root / "dev").chmod(0o700)
        self.bin = self.root / "runtime/bin"
        self.bin.mkdir(parents=True)
        self.versions = dict(line.split("=", 1) for line in (self.root / "tools/toolchains.env").read_text().splitlines()
                             if line and not line.startswith("#"))
        self.go = self.script("go", '''case "$1" in
version)
  if [ "${2:-}" = -m ]; then
    printf '%s: go%s\\n' "$3" "${FAKE_FMT_VERSION:-__GO_PIN__}"
  else
    printf 'go version go%s darwin/arm64\\n' "${FAKE_GO_VERSION:-__GO_PIN__}"
  fi ;;
env) printf '%s\\n' "${0%/bin/go}" ;;
*) printf '%s|%s|%s|%s\\n' "$GOTOOLCHAIN" "$GOENV" "$GOWORK" "$PATH" ;;
esac'''.replace("__GO_PIN__", self.versions["GO_VERSION"]))
        self.python = self.script("python3", 'printf "Python %s\\n" "${FAKE_PYTHON_VERSION:-__PY_PIN__}"'.replace("__PY_PIN__", self.versions["PYTHON_VERSION"]))
        self.script("gofmt", "exit 0")
        prior_bin = self.root / "prior/bin"
        prior_bin.mkdir(parents=True)
        prior_go = prior_bin / "go"
        prior_go.write_text(self.go.read_text().replace(self.versions["GO_VERSION"], self.versions["PRIOR_GO_VERSION"]))
        prior_go.chmod(0o700)
        self.env = dict(os.environ, MULGAE_GO_EXECUTABLE=str(self.go),
                        MULGAE_PRIOR_GO_EXECUTABLE=str(prior_go),
                        MULGAE_PYTHON_EXECUTABLE=str(self.python))

    def script(self, name, body):
        p = self.bin / name
        p.write_text("#!/bin/sh\n" + body + "\n")
        p.chmod(0o700)
        return p

    def run_dev(self, *args, env=None):
        return subprocess.run([str(self.root / "dev"), *args], env=env or self.env,
                              text=True, capture_output=True, timeout=20)

    def test_exact_versions_paths_and_child_environment(self):
        result = self.run_dev("check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("declared=" + self.versions["GO_VERSION"], result.stdout)
        self.assertIn("real=" + str(self.go), result.stdout)
        result = self.run_dev("go", "child")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("local|off|off|" + str(self.bin)))

    def test_mismatch_and_missing_do_not_fallback(self):
        for extra in ({"FAKE_GO_VERSION": "999.0.1"},
                      {"MULGAE_GO_EXECUTABLE": str(self.bin / "missing")},
                      {"MULGAE_GO_EXECUTABLE": "go"}):
            result = self.run_dev("go", "child", env=dict(self.env, **extra))
            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn("local|off|off|", result.stdout)
        result = self.run_dev("python", "--version", env=dict(self.env, FAKE_PYTHON_VERSION="999.0.1"))
        self.assertNotEqual(result.returncode, 0)

    def test_missing_manager_never_runs_path_go_or_installs(self):
        self.script("mise", 'printf "unexpected mise invocation\\n" >&2; exit 71')
        env = dict(self.env, PATH=str(self.bin) + ":/usr/bin:/bin")
        env.pop("MULGAE_GO_EXECUTABLE")
        result = self.run_dev("go", "child", env=env)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("local|off|off|", result.stdout)

    def test_managed_lookup_selects_exact_distribution_without_ambient_config(self):
        self.script("mise", '''test "$MISE_AUTO_INSTALL" = 0 || exit 70
test -f "$MISE_GLOBAL_CONFIG_FILE" || exit 70
test "$MISE_GLOBAL_CONFIG_FILE" = "$MISE_SYSTEM_CONFIG_FILE" || exit 70
test -z "${MISE_ENV:-}" || exit 70
test "$1" = where || exit 71
case "$2" in
'''+f'''core:go@{self.versions['GO_VERSION']}|core:python@{self.versions['PYTHON_VERSION']})
  printf '%s\\n' "{self.bin.parent}" ;;
core:go@{self.versions['PRIOR_GO_VERSION']})
  printf '%s\\n' "{self.root / 'prior'}" ;;
*) exit 72 ;;
esac''')
        env = dict(self.env, PATH=str(self.bin) + ":/usr/bin:/bin", MISE_ENV="hostile")
        for key in ("MULGAE_GO_EXECUTABLE", "MULGAE_PYTHON_EXECUTABLE", "MULGAE_PRIOR_GO_EXECUTABLE"):
            env.pop(key)
        result = self.run_dev("check", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("real=" + str(self.go), result.stdout)

    def test_pin_change_and_invalid_declarations(self):
        pin = self.root / "tools/toolchains.env"
        original = pin.read_text()
        pin.write_text(original.replace("GO_VERSION=" + self.versions["GO_VERSION"], "GO_VERSION=999.0.1", 1))
        result = self.run_dev("go", "version", env=dict(self.env, FAKE_GO_VERSION="999.0.1"))
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_dev("prior-go", "version", env=dict(self.env, FAKE_GO_VERSION="999.0.1"))
        self.assertNotEqual(result.returncode, 0)
        for contents in ("", original + "GO_VERSION=999.0.1\n", original.replace(self.versions["GO_VERSION"], "latest")):
            pin.write_text(contents)
            self.assertNotEqual(self.run_dev("go", "version").returncode, 0)

    def test_explicit_installer_is_isolated_and_does_not_edit_pins(self):
        log = self.root / "mise.log"
        self.script("mise", '''printf '%s\\n' "$*" > "$INSTALL_LOG"
test "$MISE_AUTO_INSTALL" = 0 && test "$MISE_NO_HOOKS" = 1 &&
test -f "$MISE_GLOBAL_CONFIG_FILE" && test "$MISE_PYTHON_COMPILE" = 0
'''.replace('"$INSTALL_LOG"', '"' + str(log) + '"'))
        pin = self.root / "tools/toolchains.env"
        original = pin.read_bytes()
        result = self.run_dev("install", env=dict(self.env, PATH=str(self.bin) + ":/usr/bin:/bin"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().strip(),
                         f"install core:go@{self.versions['GO_VERSION']} core:go@{self.versions['PRIOR_GO_VERSION']} core:python@{self.versions['PYTHON_VERSION']}")
        self.assertEqual(pin.read_bytes(), original)

    def test_hung_version_probe_fails_with_timeout(self):
        self.go.write_text("#!/bin/sh\nexec /bin/sleep 30\n")
        result = self.run_dev("go", "version")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("timed out", result.stderr)

    def test_symlink_and_exec_children_use_physical_distribution(self):
        alias = self.root / "go-link"
        alias.symlink_to(self.go)
        result = self.run_dev("check", env=dict(self.env, MULGAE_GO_EXECUTABLE=str(alias)))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("selected=" + str(alias), result.stdout)
        self.assertIn("real=" + str(self.go), result.stdout)
        result = self.run_dev("exec", "--", "/bin/sh", "-c", "command -v go; command -v python3")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [str(self.go), str(self.python)])

    def test_make_help_and_formatter_failure_propagation(self):
        shutil.copyfile(ROOT / "Makefile", self.root / "Makefile")
        result = subprocess.run(["make", "help"], cwd=self.root,
                                env=dict(self.env, MULGAE_GO_EXECUTABLE="/missing"),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        (self.root / "fixture.go").write_text("package fixture\n")
        for target in ("fmt", "fmt-check"):
            for extra in ({"FAKE_GO_VERSION": "999.0.1"}, {"FAKE_FMT_VERSION": "999.0.1"}):
                result = subprocess.run(["make", target], cwd=self.root,
                                        env=dict(self.env, **extra), capture_output=True,
                                        text=True, timeout=20)
                self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_recursive_make_preserves_validated_legacy_environment_paths(self):
        shutil.copyfile(ROOT / "Makefile", self.root / "Makefile")
        result = subprocess.run(["make", "test-offline"], cwd=self.root,
                                env=dict(self.env, GO=str(self.go), PYTHON=str(self.python)),
                                capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("[test-offline] completed", result.stdout)

    def test_prepare_formats_generated_go_before_static_checks(self):
        real_go = subprocess.check_output([str(ROOT / "dev"), "path", "go"],
                                          text=True, timeout=30).strip()
        shutil.copyfile(ROOT / "Makefile", self.root / "Makefile")
        # Stop at mod verify, after formatting, without running the real suites.
        with (self.root / "Makefile").open("a") as probe:
            probe.write("\noverride GO := /usr/bin/false\n"
                        "test-toolchain:\n\t@:\n"
                        "generate:\n\t@printf 'package fixture\\n\\nfunc f( ){ }\\n' > fixture.go\n")
        env = dict(self.env, MULGAE_GO_EXECUTABLE=real_go)
        original = "package fixture\n\nfunc f( ){ }\n"
        (self.root / ".gitignore").write_text("ignored/\n")
        for directory in ("ignored", "vendor"):
            folder = self.root / directory
            folder.mkdir()
            (folder / "untouched.go").write_text(original)
        result = subprocess.run(["make", "test-prepare"],
                                cwd=self.root, env=env, capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        fixture = self.root / "fixture.go"
        self.assertEqual(fixture.read_text(), "package fixture\n\nfunc f() {}\n")
        for directory in ("ignored", "vendor"):
            self.assertEqual((self.root / directory / "untouched.go").read_text(), original)
        result = subprocess.run(["make", "fmt-check"], cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        fixture.write_text(original)
        result = subprocess.run(["make", "fmt-check"], cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(fixture.read_text(), original)
        result = subprocess.run(["make", "fmt"], cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fixture.read_text(), "package fixture\n\nfunc f() {}\n")
        before = fixture.read_bytes()
        result = subprocess.run(["make", "fmt"], cwd=self.root, env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fixture.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
