//go:build darwin && arm64

package mulgae

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/environment"
	"github.com/irootkernel/mulgae/internal/app"
	"github.com/irootkernel/mulgae/internal/app/doctor"
	"github.com/irootkernel/mulgae/internal/ports"
)

func assertRejectedNativeHome(t *testing.T, result doctor.LocalDoctorResult) {
	t.Helper()
	if err := result.Validate(); err != nil {
		t.Fatal(err)
	}
	if result.Config.Status != "unsafe" || result.Config.NativeHomeIdentity != "mismatch" || !reflect.DeepEqual(result.Config.ReasonCodes, []string{"native_home_mismatch"}) || len(result.ConfiguredProviderIDs) != 0 || result.Assignment != (doctor.LocalAssignmentProjection{State: "not_observed", Resilience: "not_observed"}) {
		t.Fatalf("incomplete native-home rejection: %+v", result)
	}
	for _, row := range result.ProviderInventory {
		if row.Configured || row.State != "not_observed" || row.Reason != "config_not_ready" || !reflect.DeepEqual(row.ReferencedByRoles, []string{}) || row.BinaryAvailable.Status != "not_applicable" || row.CLICompatible.Status != "not_applicable" || row.CLICompatible.Eligibility != "not_evaluated" || row.CLICompatible.Compatibility != "not_observed" || row.ApplicationCompatible.Status != "not_applicable" {
			t.Fatalf("observed rejected row: %+v", row)
		}
	}
	for _, readiness := range []doctor.LocalReadiness{result.Readiness, result.ConfiguredReadiness, result.RoleRouteReadiness} {
		if readiness.State != "unsafe" || readiness.ExitCode != 8 || !reflect.DeepEqual(readiness.ReasonCodes, []string{"native_home_mismatch"}) {
			t.Fatalf("inconsistent readiness: %+v", readiness)
		}
	}
}

func TestDoctorProvidersNativeHomeReplacementRegression(t *testing.T) {
	for _, cause := range []string{"replacement", "identity_error"} {
		t.Run(cause+"/model", func(t *testing.T) {
			f := newDoctorBeforeFixture(t, "grok")
			f.spy.replaceNative = cause == "replacement"
			if cause == "identity_error" {
				f.spy.nativeErrors = map[int]error{2: errors.New("native home changed")}
			}
			root, _ := ports.NewAnchoredRoot(f.root)
			result, err := f.application.diagnoseLocalDoctor(context.Background(), root)
			if err != nil {
				t.Fatalf("native-home rejection must remain a valid diagnosis: %v", err)
			}
			assertRejectedNativeHome(t, result)
			raw, _ := json.Marshal(result)
			schema, _ := ports.ParseAssetID(doctorResultSchema)
			if err := f.validator.Validate(context.Background(), schema, raw); err != nil {
				t.Fatal(err)
			}
		})
		for _, command := range []string{"doctor", "providers"} {
			for _, format := range []string{"json", "human"} {
				for _, include := range []bool{false, true} {
					if command == "doctor" && include {
						continue
					}
					t.Run(fmt.Sprintf("%s/%s/%s/include=%t", cause, command, format, include), func(t *testing.T) {
						f := newDoctorBeforeFixture(t, "grok")
						f.spy.replaceNative = cause == "replacement"
						if cause == "identity_error" {
							f.spy.nativeErrors = map[int]error{2: errors.New("native home changed")}
						}
						f.application.evidenceReader = &doctorBeforeEvidence{spy: f.spy}
						argv := []string{command}
						if include {
							argv = append(argv, "--include-unverified")
						}
						argv = append(argv, "--output", format)
						got := doctorBeforeCapture(t, f, context.Background(), argv...)
						raw, _ := json.Marshal(got)
						t.Logf("PUBLIC Q1 %s %s include=%t %s", cause, command, include, raw)
						if got.Exit != app.ExitCodeSecurity {
							t.Fatalf("want security exit 8, got %d: %s %s", got.Exit, got.Stdout, got.Stderr)
						}
						expected := []string{"attest.1", "locality.1", "locality.2", "native.1", "binary.grok", "version.grok", "native.2"}
						if command == "providers" {
							expected = append(expected, "platform", "permission", "evidence.zcode", "evidence.grok", "evidence.codex", "evidence.cursor", "evidence.agy", "evidence.platform", "evidence.tools")
						}
						if !reflect.DeepEqual(got.Trace, expected) {
							t.Fatalf("effects=%v want=%v", got.Trace, expected)
						}
						if format == "json" {
							var envelope struct {
								Result struct {
									Doctor  *doctor.LocalDoctorResult `json:"doctor"`
									Offline int                       `json:"offline_ready_provider_count"`
									Static  int                       `json:"static_evidence_ready_provider_count"`
								} `json:"result"`
							}
							if err := json.Unmarshal([]byte(got.Stdout), &envelope); err != nil {
								t.Fatal(err)
							}
							if command == "doctor" {
								if envelope.Result.Doctor == nil {
									t.Fatal("missing inline diagnosis")
								}
								assertRejectedNativeHome(t, *envelope.Result.Doctor)
							} else if envelope.Result.Offline != 0 || envelope.Result.Static != 4 {
								t.Fatalf("independent counts: %+v", envelope.Result)
							}
							if !strings.Contains(got.Stdout, `"code":"security_rejected"`) {
								t.Fatalf("missing security diagnostic: %s", got.Stdout)
							}
						} else if command == "doctor" && !strings.HasPrefix(got.Stdout, "Readiness: unsafe\nConfiguration: unsafe\nProviders:\n") {
							t.Fatalf("human diagnosis=%q", got.Stdout)
						}
					})
				}
			}
		}
	}
}

func TestDoctorProvidersNativeHomeCancellationProjection(t *testing.T) {
	for _, command := range []string{"doctor", "providers"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			for _, observation := range []int{1, 2} {
				for _, format := range []string{"json", "human"} {
					t.Run(fmt.Sprintf("%s/%s/observation=%d/%s", command, cause, observation, format), func(t *testing.T) {
						f := newDoctorBeforeFixture(t, "grok")
						f.spy.nativeErrors = map[int]error{observation: cause}
						f.application.evidenceReader = &doctorBeforeEvidence{spy: f.spy}
						got := doctorBeforeCapture(t, f, context.Background(), command, "--output", format)
						wantExit := app.ExitCodeCancellation
						if command == "providers" {
							// Providers' frozen command envelope does not permit exit 9.
							wantExit = app.ExitCodeArtifact
						}
						if got.Exit != wantExit {
							t.Fatalf("cancellation projection: exit %d, want %d: %s %s", got.Exit, wantExit, got.Stdout, got.Stderr)
						}
						wantTrace := []string{"attest.1", "locality.1", "locality.2", "native.1"}
						if observation == 2 {
							wantTrace = append(wantTrace, "binary.grok", "version.grok", "native.2")
						}
						if !reflect.DeepEqual(got.Trace, wantTrace) {
							t.Fatalf("cancellation effects: %v, want %v", got.Trace, wantTrace)
						}
						raw, err := json.Marshal(got)
						if err != nil {
							t.Fatal(err)
						}
						t.Logf("PUBLIC CANCELLATION %s", raw)
					})
				}
			}
		}
	}
}

func cursorCorrectionFixture(t *testing.T, version string) (*doctorBeforeFixture, string) {
	return cursorCorrectionFixtureForFamilies(t, version, "cursor")
}

func cursorCorrectionFixtureForFamilies(t *testing.T, version, families string) (*doctorBeforeFixture, string) {
	t.Helper()
	f := newDoctorBeforeFixture(t, families)
	runtimeParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", runtimeParent)
	path := filepath.Join(f.root, "cursor")
	marker := filepath.Join(f.root, "launches")
	script := "#!/bin/sh\n[ \"$#\" = 1 ] && [ \"$1\" = --version ] || exit 91\n[ \"$PWD\" = \"$HOME\" ] && [ \"$HOME\" = \"$TMPDIR\" ] || exit 92\n[ -z \"$(/bin/ls -A \"$HOME\")\" ] || exit 93\n[ -z \"${CURSOR_AUTH_TOKEN+x}${OPENAI_API_KEY+x}\" ] || exit 94\nprintf x >> '" + marker + "'\nprintf '" + version + "\\n'\n"
	doctorBeforeWrite(t, path, []byte(script))
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatal(err)
	}
	doctorBeforeEdit(t, filepath.Join(f.root, ".mulgae", "local.yaml"), func(b []byte) []byte { return bytes.Replace(b, []byte("/synthetic/cursor"), []byte(path), 1) })
	f.spy.realExecutable = true
	f.application.versionObserver = environment.NewProviderVersionObserver()
	return f, marker
}

func TestDoctorProvidersProductionCursorCompatibility(t *testing.T) {
	for _, command := range []string{"doctor", "providers"} {
		for _, format := range []string{"json", "human"} {
			for _, include := range []bool{false, true} {
				if command == "doctor" && include {
					continue
				}
				t.Run(fmt.Sprintf("%s/%s/include=%t", command, format, include), func(t *testing.T) {
					t.Setenv("CURSOR_AUTH_TOKEN", "synthetic-not-for-child")
					t.Setenv("OPENAI_API_KEY", "synthetic-not-for-child")
					f, marker := cursorCorrectionFixture(t, "2026.10.14-0f9edde")
					argv := []string{command}
					if include {
						argv = append(argv, "--include-unverified")
					}
					argv = append(argv, "--output", format)
					got := doctorBeforeCapture(t, f, context.Background(), argv...)
					raw, _ := json.Marshal(got)
					t.Logf("PUBLIC Q3 %s include=%t %s", command, include, raw)
					if got.Exit != 0 {
						t.Fatalf("Cursor supported tuple should be ready: exit=%d %s %s", got.Exit, got.Stdout, got.Stderr)
					}
					launches, err := os.ReadFile(marker)
					if err != nil || string(launches) != "x" {
						t.Fatalf("version launches=%q err=%v", launches, err)
					}
					if format == "json" {
						if command == "doctor" && (!strings.Contains(got.Stdout, `"observed_version":"2026.10.14-0f9edde"`) || !strings.Contains(got.Stdout, `"reason_code":"provider_cli_version_supported"`)) {
							t.Fatalf("tuple lost: %s", got.Stdout)
						}
						if command == "providers" && !strings.Contains(got.Stdout, `"offline_ready_provider_count":1`) {
							t.Fatalf("missing offline count: %s", got.Stdout)
						}
					}
				})
			}
		}
	}
}

// Separate fixed expectations preserve the complete predecessor bytes and permit
// only the decision record's Q1/Q3 changes. No update mode reads runtime output.
func assertDoctorCorrected(t *testing.T, key string, actual doctorBefore) {
	t.Helper()
	if !strings.HasPrefix(key, "q1/") && !strings.HasPrefix(key, "q3/") {
		t.Fatalf("unapproved correction key %q", key)
	}
	raw, err := os.ReadFile("testdata/task063-doctor-corrected.json")
	if err != nil {
		t.Fatal(err)
	}
	var expected map[string]doctorBefore
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatal(err)
	}
	want, found := expected[key]
	want = currentDoctorTransportExpectation(want)
	if !found || !reflect.DeepEqual(actual, want) {
		t.Fatalf("corrected %s differs: got=%+v want=%+v", key, actual, want)
	}
}

func TestDoctorCursorProductionVersionPolicy(t *testing.T) {
	for _, test := range []struct {
		name, version, reason, observed string
		exit                            app.ExitCode
	}{
		{"same day different hash", "2026.10.14-deadbeef", "provider_cli_version_newer_than_verified", "2026.10.14-deadbeef", 0},
		{"future date", "2026.10.15-abc", "provider_cli_version_newer_than_verified", "2026.10.15-abc", 0},
		{"below minimum", "2026.10.13-abc", "provider_cli_version_below_minimum", "2026.10.13-abc", 4},
		{"invalid calendar", "2026.02.30-abc", "provider_cli_version_malformed", "2026.02.30-abc", 4},
		{"unpadded date", "2026.1.2-abc", "provider_cli_version_malformed", "", 4},
		{"empty hash", "2026.10.14-", "provider_cli_version_malformed", "", 4},
		{"uppercase hash", "2026.10.14-0F9edde", "provider_cli_version_malformed", "", 4},
		{"nonhex hash", "2026.10.14-xyz", "provider_cli_version_malformed", "", 4},
		{"ambiguous", "2026.10.14-abc 2026.10.15-def", "provider_cli_version_malformed", "", 4},
		{"embedded", "x2026.10.14-abc", "provider_cli_version_malformed", "", 4},
	} {
		t.Run(test.name, func(t *testing.T) {
			f, marker := cursorCorrectionFixture(t, test.version)
			got := doctorBeforeCapture(t, f, context.Background(), "doctor", "--output", "json")
			var envelope struct {
				Result struct {
					Doctor doctor.LocalDoctorResult `json:"doctor"`
				} `json:"result"`
			}
			if err := json.Unmarshal([]byte(got.Stdout), &envelope); err != nil {
				t.Fatal(err)
			}
			row := envelope.Result.Doctor.ProviderInventory[3]
			if got.Exit != test.exit || row.CLICompatible.ReasonCode != test.reason || row.CLICompatible.ObservedVersion != test.observed {
				t.Fatalf("Cursor policy exit=%d row=%+v", got.Exit, row)
			}
			launches, err := os.ReadFile(marker)
			if err != nil || string(launches) != "x" {
				t.Fatalf("launches=%q err=%v", launches, err)
			}
		})
	}
	for _, unsafe := range []bool{false, true} {
		for _, command := range []string{"doctor", "providers"} {
			t.Run(fmt.Sprintf("mixed/%s/unsafe=%t", command, unsafe), func(t *testing.T) {
				f, marker := cursorCorrectionFixtureForFamilies(t, "2026.10.14-0f9edde", "grok,cursor")
				want := app.ExitCodeReadiness
				if unsafe {
					f.application.inspector = cursorMixedUnsafeInspector{f.spy}
					want = app.ExitCodeSecurity
				}
				got := doctorBeforeCapture(t, f, context.Background(), command, "--output", "json")
				if got.Exit != want {
					t.Fatalf("mixed exit=%d want=%d %s", got.Exit, want, got.Stdout)
				}
				if command == "doctor" && (!strings.Contains(got.Stdout, `"observed_version":"2026.10.14-0f9edde"`) || !strings.Contains(got.Stdout, `"reason":"provider_cli_version_supported"`)) {
					t.Fatalf("safe Cursor lost: %s", got.Stdout)
				}
				if command == "providers" && !strings.Contains(got.Stdout, `"offline_ready_provider_count":1`) {
					t.Fatalf("mixed offline count: %s", got.Stdout)
				}
				launches, err := os.ReadFile(marker)
				if err != nil || string(launches) != "x" {
					t.Fatalf("launches=%q err=%v", launches, err)
				}
			})
		}
	}
}

type cursorMixedUnsafeInspector struct{ *doctorBeforeSpy }

func (inspector cursorMixedUnsafeInspector) ObserveExecutableIdentity(ctx context.Context, path string) (ports.ExecutableObservation, error) {
	if filepath.Base(path) == "grok" {
		inspector.record("binary.grok")
		return ports.ExecutableObservation{}, ports.NewIdentityObservationError(ports.IdentityObservationSecurity, "synthetic unsafe Grok")
	}
	return inspector.doctorBeforeSpy.ObserveExecutableIdentity(ctx, path)
}
