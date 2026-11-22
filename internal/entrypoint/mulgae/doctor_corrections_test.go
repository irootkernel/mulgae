//go:build darwin && arm64

package mulgae

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

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
							expected = append(expected, "platform", "permission", "evidence.zcode", "evidence.grok", "evidence.codex", "evidence.agy", "evidence.platform", "evidence.tools")
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
							} else if envelope.Result.Offline != 0 || envelope.Result.Static != 3 {
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

// Separate fixed expectations preserve the complete predecessor bytes and permit
// only the decision record's Q1 changes. No update mode reads runtime output.
func assertDoctorCorrected(t *testing.T, key string, actual doctorBefore) {
	t.Helper()
	if !strings.HasPrefix(key, "q1/") {
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
	want = currentDoctorPortfolioExpectation(currentDoctorTransportExpectation(want))
	if !found || !reflect.DeepEqual(actual, want) {
		t.Fatalf("corrected %s differs: got=%+v want=%+v", key, actual, want)
	}
}
