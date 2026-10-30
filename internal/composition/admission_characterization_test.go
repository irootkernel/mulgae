//go:build darwin && arm64

package composition

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/providercli"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// The concrete source is deliberately real. Mutations inside the attestor prove
// which source confirmations surround the observable locality callbacks.
type beforeReviewLocality struct {
	ports.TrustedProjectReader
	trace    []string
	rechecks int
	onCheck  func(int)
}

func (reader *beforeReviewLocality) Attest(_ context.Context, request ports.ConfigLocalityRequest) (ports.ConfigLocalityContext, error) {
	reader.trace = append(reader.trace, "attest")
	device, inode, uid, mode := request.Config().RootIdentity()
	return ports.NewConfigLocalityContext("before-review", device, inode, uid, mode, "", "", "sha256:"+strings.Repeat("b", 64), 0, false, nil, request.Config(), ports.ParsedTargetProof{SHA256: "sha256:" + strings.Repeat("c", 64), PrivatePathFree: true})
}

func (reader *beforeReviewLocality) Revalidate(_ context.Context, _ ports.ConfigLocalityRequest, _ ports.ConfigLocalityContext) error {
	reader.trace = append(reader.trace, "locality")
	reader.rechecks++
	if reader.onCheck != nil {
		reader.onCheck(reader.rechecks)
	}
	return nil
}

func TestReviewAdmissionSequenceCharacterization(t *testing.T) {
	for _, mutation := range []string{"none", "same-byte-replacement", "credential"} {
		t.Run(mutation, func(t *testing.T) {
			rootPath := canonicalTestTempDir(t)
			for _, name := range []string{".git", ".mulgae"} {
				if err := os.Mkdir(filepath.Join(rootPath, name), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			project := []byte(compositionProjectConfig)
			if mutation == "credential" {
				project = append(project, []byte("api_key: synthetic-do-not-emit\n")...)
			}
			path := filepath.Join(rootPath, ".mulgae", "config.yaml")
			if err := os.WriteFile(path, project, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(rootPath, ".mulgae", "local.yaml"), []byte(compositionLocalConfig), 0o600); err != nil {
				t.Fatal(err)
			}
			root, _ := ports.NewAnchoredRoot(rootPath)
			reader := &beforeReviewLocality{}
			if mutation == "same-byte-replacement" {
				reader.onCheck = func(n int) {
					if n != 1 {
						return
					}
					if err := os.Rename(path, path+".held"); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, project, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			policy, err := resolveProductionRunPolicy(context.Background(), root, reader)
			if mutation != "none" {
				var failure *domain.Failure
				if !errors.As(err, &failure) || failure.Class() != domain.FailureSecurityPolicy || !reflect.DeepEqual(reader.trace, []string{"attest", "locality"}) {
					t.Fatalf("%s failure=%v trace=%v", mutation, err, reader.trace)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(reader.trace, []string{"attest", "locality", "locality"}) {
				t.Fatalf("static admission: %v %v", err, reader.trace)
			}
			reader.trace = nil
			// Preflight composition admits the configured /Users/test home without
			// performing the normal runtime graph's installed-account check.
			catalog, _ := mustSharedCompositionTestAssets(t)
			if _, err := composeReviewPreflight(context.Background(), catalog, root, reader); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reader.trace, []string{"attest", "locality", "locality"}) {
				t.Fatalf("preflight admission: %v", reader.trace)
			}
			reader.trace = nil
			bound, err := bindProductionLocality(context.Background(), policy.source, reader, policy.localityRequest, policy.locality, policy.config, nil, nil)
			if err != nil || !reflect.DeepEqual(reader.trace, []string{"locality", "attest", "locality"}) {
				t.Fatalf("target admission: %v %v", err, reader.trace)
			}
			reader.trace = nil
			inner := &recordingReviewSpawnVerifier{}
			verifier := localitySpawnVerifier{inner: inner, source: bound.source, attestor: reader, request: bound.request, expected: bound.expected}
			if err := verifier.VerifyProviderSpawn(context.Background(), providercli.RuntimeDefinition{}); err != nil || !inner.called || !reflect.DeepEqual(reader.trace, []string{"locality"}) {
				t.Fatalf("spawn confirmation: %v inner=%t trace=%v", err, inner.called, reader.trace)
			}
		})
	}
}
