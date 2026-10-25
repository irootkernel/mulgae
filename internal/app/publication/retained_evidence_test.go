package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

type retainedRecordingSchema struct {
	validator *jsonschema.Validator
	ids       []ports.AssetID
}

func retainedSchema(t *testing.T) *retainedRecordingSchema {
	t.Helper()
	validator, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	return &retainedRecordingSchema{validator: validator}
}

func (validator *retainedRecordingSchema) Validate(ctx context.Context, id ports.AssetID, raw []byte) error {
	validator.ids = append(validator.ids, id)
	return validator.validator.Validate(ctx, id, raw)
}

func assertNoRetiredSupport(t *testing.T, bundle PublicationBundle) {
	t.Helper()
	for _, artifact := range bundle.SupportArtifacts() {
		for _, prefix := range []string{"/target/", "/prompts/", "/support/sources/"} {
			if strings.Contains(artifact.Path().String(), prefix) {
				t.Fatalf("live support contains retired member %s", artifact.Path())
			}
		}
	}
}

func TestPreparedEvidenceCanonicalizationPreservesEveryTuple(t *testing.T) {
	for _, count := range []int{1, 2, 20} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			items := make([]preparedEvidence, count)
			for i := range items {
				items[i] = preparedEvidence{sourceSessionID: "session", sourceRunID: "run", sourceReviewID: "review", sourceFindingID: "F007", sourceTargetSHA256: "source-target", sourceExcerptSHA256: "source-excerpt", targetSHA256: "current-target", currentExcerptSHA256: "current-excerpt", side: evidence.SideHead, path: fmt.Sprintf("src/%02d.go", count-i-1), lineStart: 1, lineEnd: 1, quote: "line one\n", excerpt: []byte("line one\n")}
			}
			before := append([]preparedEvidence(nil), items...)
			if err := canonicalizePreparedEvidence(items); err != nil {
				t.Fatal(err)
			}
			for i := range items {
				if !reflect.DeepEqual(items[i], before[count-i-1]) {
					t.Fatal("canonicalization changed source/current authority or bytes")
				}
			}
			for _, list := range []string{"outcome", "finding"} {
				t.Run(list+" duplicate", func(t *testing.T) {
					duplicate := []preparedEvidence{items[0], items[0]}
					if err := canonicalizePreparedEvidence(duplicate); err == nil || !strings.Contains(err.Error(), "evidence tuple is duplicated") {
						t.Fatalf("duplicate bypassed tuple guard: %v", err)
					}
				})
			}
		})
	}
}

func TestNormalizedFindingUsesOriginalSourceTuple(t *testing.T) {
	session, err := domain.ParseSessionID("s_019f596a-cf80-7c67-b265-f37053d51ccf")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f596a-cfe4-7c9c-b82e-7149158243bb")
	if err != nil {
		t.Fatal(err)
	}
	issued := publicationIssuedReviewID(t)
	source := sourceEvidenceWire{SessionID: session.String(), RunID: "r_019f596a-cfe4-7c9c-b82e-7149158243ba", ReviewID: "019f596a-d175-7321-b920-c2d312c82cc2", FindingID: "F007", SourceTargetSHA256: "source-target", SourceExcerptSHA256: "source-excerpt"}
	item := preparedEvidence{sourceSessionID: source.SessionID, sourceRunID: source.RunID, sourceReviewID: source.ReviewID, sourceFindingID: source.FindingID, sourceTargetSHA256: source.SourceTargetSHA256, sourceExcerptSHA256: source.SourceExcerptSHA256, targetSHA256: "current-target", currentExcerptSHA256: "current-excerpt", side: evidence.SideHead, path: "src/a.go", lineStart: 1, lineEnd: 1, quote: "line one\n"}
	candidate := PreparedCandidate{sessionID: session, runID: run, target: preparedTarget{sha256: "current-target"}, findings: []preparedFinding{{id: "F001", evidence: []preparedEvidence{item}}}}
	dir := session.String() + "/" + run.String() + "/excerpts"
	artifacts, err := candidate.buildNormalizedFindingExcerpts(dir, issued)
	if err != nil || len(artifacts) != 1 {
		t.Fatalf("normalized findings: %v", err)
	}
	var got finalFindingWire
	if err := json.Unmarshal(artifacts[0].Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Evidence) != 1 || got.Evidence[0].Source != source || got.Evidence[0].Source.ReviewID == issued.String() || got.Evidence[0].Source.RunID == run.String() || got.Evidence[0].Current.Quote != item.quote || got.Evidence[0].Current.CurrentExcerptSHA256 != item.currentExcerptSHA256 {
		t.Fatal("encoder replaced retained source authority with current publication")
	}
	// Exercise the default branch separately: current publication owns source
	// only when no historical source tuple is present.
	candidate.findings[0].evidence[0].sourceSessionID = ""
	current := candidate.finalFindings(issued)[0].Evidence[0]
	if current.Source.RunID != run.String() || current.Source.ReviewID != issued.String() || current.Source.FindingID != "F001" {
		t.Fatal("ordinary source ownership changed")
	}
}

func TestRetainedRoleReportEncodingAndZeroAttemptOmission(t *testing.T) {
	candidate := retainedLiveCandidate(t, false)
	candidate.roles[0].attempts = nil
	// Direct helper input: this does not claim admission of an invalid live run.
	reports, err := candidate.buildRoleReports()
	if err != nil || len(reports) != 2 {
		t.Fatalf("report emission: %v", err)
	}
	identities := candidate.roleReportIdentities(reports)
	got := candidate.manifestRoleReportsFromIdentities(identities)
	if len(got) != 1 || got[0].Role != "security" || len(candidate.manifestRoleReports()) != 1 {
		t.Fatal("zero-attempt report entered manifest authority")
	}
	if reports[0].SHA256() != sha256Identifier(candidate.roles[0].reportMarkdown) || !bytes.Equal(reports[0].Bytes(), candidate.roles[0].reportMarkdown) {
		t.Fatal("report identity or bytes changed")
	}
	index, err := buildRunSupportIndex(mustPublicationPath(candidate.sessionID.String()+"/"+candidate.runID.String()+"/support/index.json"), reports)
	if err != nil {
		t.Fatal(err)
	}
	var wire runSupportIndexWire
	if err := json.Unmarshal(index.Bytes(), &wire); err != nil || len(wire.Artifacts) != 2 {
		t.Fatalf("report indexing: %v", err)
	}
}

func TestLiveCandidateHashBindsRetainedProvenanceAndAttemptBytes(t *testing.T) {
	for name, mutate := range map[string]func(*PreparedCandidate){
		"build": func(c *PreparedCandidate) { c.mulgae.commit = "other"; c.target.live.provenance.BuildCommit = "other" },
		"build version": func(c *PreparedCandidate) {
			c.mulgae.version = "0.2.0"
			c.target.live.provenance.BuildVersion = "0.2.0"
		},
		"family":           func(c *PreparedCandidate) { c.target.live.provenance.Providers[0].Family = "aaa" },
		"instance":         func(c *PreparedCandidate) { c.target.live.provenance.Providers[0].Instance = "agy-other" },
		"provider version": func(c *PreparedCandidate) { c.target.live.provenance.Providers[0].Version = "2.0.0" },
		"executable":       func(c *PreparedCandidate) { c.target.live.provenance.Providers[0].Executable = "/private/bin/other" },
		"launcher": func(c *PreparedCandidate) {
			c.target.live.provenance.Providers[0].Launcher = "/private/bin/other-launcher"
		},
		"launcher digest": func(c *PreparedCandidate) {
			c.target.live.provenance.Providers[0].LauncherSHA256 = sha256Identifier([]byte("other launcher"))
		},
		"profile generation": func(c *PreparedCandidate) { c.target.live.provenance.Providers[0].ProfileGeneration = "generation-2" },
		"adapter profile":    func(c *PreparedCandidate) { c.target.live.provenance.Providers[0].AdapterProfile = "other-profile" },
		"source closure": func(c *PreparedCandidate) {
			c.target.live.provenance.SourceTerminalReceipt = "source-terminal:v1:" + sha256Identifier([]byte("different closure"))
		},
		"objective": func(c *PreparedCandidate) {
			c.target.live.provenance.HasObjective = true
			c.target.live.provenance.ObjectiveSHA256 = sha256Identifier([]byte("objective"))
		},
		"provider executable": func(c *PreparedCandidate) {
			c.target.live.provenance.Providers[0].ExecutableSHA256 = sha256Identifier([]byte("other executable"))
		},
		"qualification": func(c *PreparedCandidate) {
			c.target.live.provenance.Providers[0].QualificationReceiptIDs = []string{sha256Identifier([]byte("other qualification"))}
		},
		"packet transport": func(c *PreparedCandidate) {
			c.target.live.provenance.Providers[0].PacketTransportReceiptIDs = []string{sha256Identifier([]byte("other packet"))}
		},
		"namespace": func(c *PreparedCandidate) {
			c.target.live.provenance.Providers[0].NamespaceTerminalReceipt = sha256Identifier([]byte("other terminal"))
		},
		"stdout": func(c *PreparedCandidate) {
			c.roles[0].attempts[0].invocations[0].artifacts = []preparedAttemptArtifact{{kind: ports.AttemptArtifactStdout, bytes: []byte("different stdout")}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			original := retainedLiveCandidate(t, false)
			candidate := retainedLiveCandidate(t, false)
			mutate(&candidate)
			if !candidate.Valid() || candidate.ValidatedCandidateSHA256() == "" || candidate.ValidatedCandidateSHA256() == original.ValidatedCandidateSHA256() {
				t.Fatal("retained identity input omitted from candidate hash")
			}
		})
	}
}

func TestLiveProvenanceBuildProductAndObjectiveAuthority(t *testing.T) {
	candidate := retainedLiveCandidate(t, false)
	candidate.target.live.provenance.BuildProduct = "other-mulgae"
	if candidate.Valid() {
		t.Fatal("live provenance accepted a foreign build product")
	}
	base := retainedLiveCandidate(t, false)
	base.target.live.provenance.HasObjective = true
	base.target.live.provenance.ObjectiveSHA256 = sha256Identifier([]byte("objective"))
	changed := retainedLiveCandidate(t, false)
	changed.target.live.provenance.HasObjective = true
	changed.target.live.provenance.ObjectiveSHA256 = sha256Identifier([]byte("other objective"))
	if !base.Valid() || !changed.Valid() || base.ValidatedCandidateSHA256() == changed.ValidatedCandidateSHA256() {
		t.Fatal("live objective digest did not bind candidate identity")
	}
}

func TestLiveSupportContainsNoRetiredCaptureOrPromptMembers(t *testing.T) {
	for _, finding := range []bool{false, true} {
		candidate := PreparedLiveCandidate{candidate: retainedLiveCandidate(t, finding)}
		bundle, err := candidate.Build(context.Background(), retainedSchema(t), publicationIssuedReviewID(t), publicationTestTime(), 1)
		if err != nil {
			t.Fatal(err)
		}
		assertNoRetiredSupport(t, bundle)
	}
}

func TestLiveAttemptIdentityHashRetainsEveryBoundInput(t *testing.T) {
	appendRepair := func(c *PreparedCandidate) {
		c.roles[0].repaired = true
		c.roles[0].attempts[0].validationState = domain.ValidationRepairedValid
		c.roles[0].attempts[0].invocations = append(c.roles[0].attempts[0].invocations, preparedInvocation{sequence: 2, purpose: domain.InvocationRepair, state: domain.InvocationSucceeded, artifacts: []preparedAttemptArtifact{{kind: ports.AttemptArtifactRepairedCandidate, bytes: []byte("repaired capture")}}})
	}
	for name, mutate := range map[string]func(*PreparedCandidate){
		"run": func(c *PreparedCandidate) {
			id, err := domain.ParseRunID("r_019f596a-dfe4-7c9c-b82e-7149158243ba")
			if err != nil {
				t.Fatal(err)
			}
			c.runID = id
		},
		"attempt": func(c *PreparedCandidate) {
			id, err := domain.ParseAttemptID("a_019f596a-e048-79e7-b2b7-59822f012273")
			if err != nil {
				t.Fatal(err)
			}
			c.roles[0].attempts[0].id = id
		},
		"role": func(c *PreparedCandidate) {
			role := clonePreparedRoles(c.roles[:1])[0]
			role.role = domain.RoleMaintainability
			role.required = false
			id, err := domain.ParseAttemptID("a_019f596a-e0ac-7c12-8b68-0bd73e911b2e")
			if err != nil {
				t.Fatal(err)
			}
			role.attempts[0].id = id
			// Same qualified provider is permitted to serve another role; no
			// captured runtime inventory or new provider authority is invented.
			c.roles = append(c.roles, role)
		},
		"sequence purpose and capture kind": appendRepair,
		"capture bytes": func(c *PreparedCandidate) {
			c.roles[0].attempts[0].invocations[0].artifacts[0].bytes = []byte("other capture")
		},
		"capture security flag and bytes": func(c *PreparedCandidate) {
			a := &c.roles[0].attempts[0].invocations[0].artifacts[0]
			a.securityRejected = true
			a.bytes = nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			base := retainedLiveCandidate(t, false)
			base.roles[0].attempts[0].invocations[0].artifacts = []preparedAttemptArtifact{{kind: ports.AttemptArtifactInitialCandidate, bytes: []byte("captured candidate")}}
			candidate := retainedLiveCandidate(t, false)
			candidate.roles[0].attempts[0].invocations[0].artifacts = []preparedAttemptArtifact{{kind: ports.AttemptArtifactInitialCandidate, bytes: []byte("captured candidate")}}
			mutate(&candidate)
			if !candidate.Valid() || candidate.ValidatedCandidateSHA256() == "" || candidate.ValidatedCandidateSHA256() == base.ValidatedCandidateSHA256() {
				t.Fatal("live attempt/capture identity input was lost")
			}
		})
	}
}
