package query

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func queryRecoveryFixture(t *testing.T) (recovery.Document, map[string][]byte) {
	t.Helper()
	session, err := domain.ParseSessionID("s_019f5a09-5eec-7001-8001-000000000010")
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID("r_019f5a09-5eec-7001-8001-000000000011")
	if err != nil {
		t.Fatal(err)
	}
	target, err := ports.NewCapturedReviewPatchTarget([]byte("immutable target"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := ports.NewWorkspaceSnapshotRequest(nil, "recovery-test")
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := ports.NewCapturedTargetEvidence(map[ports.CapturedEvidenceSide][]ports.WorkspaceSnapshotFile{ports.CapturedEvidenceHead: nil})
	if err != nil {
		t.Fatal(err)
	}
	material, err := ports.NewCapturedReviewMaterialWithEvidence(target, request, nil, evidence)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := ports.MarshalCapturedReviewMaterial(material)
	if err != nil {
		t.Fatal(err)
	}
	blobs := map[string][]byte{}
	document := recovery.Document{SchemaVersion: recovery.SchemaVersion, SessionID: session.String(), RunID: run.String(), RunType: domain.RunTypeReview, RunState: domain.RunFailed, Threshold: domain.SeverityHigh, SnapshotManifestSHA256: "sha256:" + strings.Repeat("a", 64), WorkspaceTerminalReceipt: "workspace-terminal:v1:sha256:" + strings.Repeat("b", 64), Findings: []recovery.Finding{}}
	document.Target = recovery.Target{Kind: target.Identity().Kind(), SHA256: "sha256:" + target.Identity().SHA256(), Bytes: recovery.AddBlob(blobs, target.Bytes()), CapturedArchive: recovery.AddBlob(blobs, archive)}
	for index, role := range []domain.Role{domain.RoleLogic, domain.RoleSecurity} {
		suffix := "000000000021"
		if index == 1 {
			suffix = "000000000022"
		}
		attemptID, err := domain.ParseAttemptID("a_019f5a09-5eec-7001-8001-" + suffix)
		if err != nil {
			t.Fatal(err)
		}
		roleTaskID, err := prompt.ParseRoleTaskID("rt_019f5a09-5eec-7001-8001-" + suffix)
		if err != nil {
			t.Fatal(err)
		}
		coordinates, err := prompt.NewScopeCoordinates(session, run, roleTaskID, attemptID)
		if err != nil {
			t.Fatal(err)
		}
		template, err := prompt.NewTrustedTemplate("recovery-test", "v1", []byte("Return a review."))
		if err != nil {
			t.Fatal(err)
		}
		compiler, err := prompt.NewCompiler(template, recoveryIssuer{suffix})
		if err != nil {
			t.Fatal(err)
		}
		compiled, err := compiler.Compile(prompt.CompileInput{Scope: coordinates, ReviewTarget: prompt.NewPayload(target.Bytes())})
		if err != nil {
			t.Fatal(err)
		}
		input := recovery.Prompt{Stdin: recovery.AddBlob(blobs, compiled.Stdin()), SourceInvocationID: compiled.Scope().SourceInvocationID().String(), ExecutionInvocationID: compiled.Scope().ExecutionInvocationID().String(), TemplateID: template.ID(), TemplateVersion: template.Version(), TemplateSHA256: "sha256:" + template.SHA256(), AdapterProfile: "test", AdapterParameters: map[string]string{}, Scope: compiled.Scope().FrameScope().String()}
		attempt := recovery.Attempt{AttemptID: attemptID.String(), Role: role, ProviderInstance: "test.provider", State: domain.AttemptSucceeded, InitialPrompt: input}
		outcome := recovery.Role{Role: role, Required: true, Outcome: "completed", AttemptID: attemptID.String(), ProviderInstance: attempt.ProviderInstance, FindingIDs: []string{}}
		if index == 0 {
			report := recovery.AddBlob(blobs, []byte("Accepted logic report."))
			outcome.Report = &report
		} else {
			attempt.State = domain.AttemptCancelled
			attempt.FailureClass = domain.FailureCancelled
			attempt.ReasonCode = "cancelled"
			outcome.Outcome = "failed"
		}
		document.Attempts = append(document.Attempts, attempt)
		document.Roles = append(document.Roles, outcome)
	}
	return document, blobs
}

type recoveryIssuer struct{ suffix string }

func (issuer recoveryIssuer) NewSourceInvocationID() (prompt.SourceInvocationID, error) {
	return prompt.ParseSourceInvocationID("i_019f5a09-5eec-7001-8001-" + issuer.suffix)
}
func (issuer recoveryIssuer) NewExecutionInvocationID() (prompt.ExecutionInvocationID, error) {
	return prompt.ParseExecutionInvocationID("019f5a09-5eec-7002-8001-" + issuer.suffix)
}
func queryRecoveryJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func installQueryRecovery(t *testing.T, store *queryStore, root ports.AnchoredRoot, document recovery.Document, blobs map[string][]byte) ports.PublicationRun {
	t.Helper()
	session, _ := domain.ParseSessionID(document.SessionID)
	id, _ := domain.ParseRunID(document.RunID)
	run, err := ports.NewPublicationRun(root, session, id)
	if err != nil {
		t.Fatal(err)
	}
	retained := map[string][]byte{}
	for _, blob := range document.Blobs() {
		retained[blob.SHA256] = blobs[blob.SHA256]
	}
	raw := queryRecoveryJSON(t, document)
	if _, err := recovery.Restore(context.Background(), raw, retained); err != nil {
		t.Fatal(err)
	}
	manifest, _ := recovery.ManifestPath(run)
	artifact, err := ports.NewImmutablePublicationArtifact(manifest, recovery.Digest(raw), raw)
	if err != nil {
		t.Fatal(err)
	}
	if store.auxiliaryArtifacts == nil {
		store.auxiliaryArtifacts = map[string]ports.ImmutablePublicationArtifact{}
	}
	store.auxiliaryArtifacts[manifest.String()] = artifact
	for _, blob := range document.Blobs() {
		path, _ := recovery.BlobPath(run, blob)
		artifact, err := ports.NewImmutablePublicationArtifact(path, blob.SHA256, blobs[blob.SHA256])
		if err != nil {
			t.Fatal(err)
		}
		store.auxiliaryArtifacts[path.String()] = artifact
	}
	return run
}

func queryCanonicalReplayPrompt(t *testing.T, run ports.PublicationRun, attempt domain.AttemptID, target []byte) prompt.CompiledPrompt {
	t.Helper()
	task, _ := prompt.ParseRoleTaskID("rt_019f5a09-5eec-7001-8001-000000000001")
	scope, err := prompt.NewScopeCoordinates(run.SessionID(), run.RunID(), task, attempt)
	if err != nil {
		t.Fatal(err)
	}
	template, err := prompt.NewTrustedTemplate("recovery-test", "v1", []byte("Return a review."))
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := prompt.NewCompiler(template, recoveryIssuer{"000000000002"})
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := compiler.Compile(prompt.CompileInput{Scope: scope, ReviewTarget: prompt.NewPayload(target)})
	if err != nil {
		t.Fatal(err)
	}
	return compiled
}

type queryRuntimeFixtureEntry struct {
	bytes       []byte
	previousSHA string
}

func queryRekeyRuntimeFixture(
	t *testing.T,
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
	artifacts map[string]ports.ImmutablePublicationArtifact,
	paths map[string]string,
	newRunID string,
	attempt domain.AttemptID,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact, map[string]string, domain.AttemptID) {
	t.Helper()
	newID, err := domain.ParseRunID(newRunID)
	if err != nil {
		t.Fatal(err)
	}
	newRun, err := ports.NewPublicationRun(run.Root(), run.SessionID(), newID)
	if err != nil {
		t.Fatal(err)
	}
	oldRunID := run.RunID().String()
	pathTransform := func(value string) string { return strings.ReplaceAll(value, oldRunID, newRunID) }
	byteTransform := func(value []byte) []byte { return bytes.ReplaceAll(value, []byte(oldRunID), []byte(newRunID)) }
	entries := queryRuntimeFixtureEntries(t, snapshot, artifacts, pathTransform, byteTransform)
	queryConvergeRuntimeFixtureDigests(t, entries)
	newPaths := make(map[string]string, len(paths))
	for key, value := range paths {
		newPaths[key] = pathTransform(value)
	}
	return queryBuildRuntimeFixture(t, newRun, snapshot, artifacts, entries, newPaths, pathTransform, attempt)
}

func queryRebindRuntimePrompt(
	t *testing.T,
	run ports.PublicationRun,
	snapshot ports.CommittedPublicationSnapshot,
	artifacts map[string]ports.ImmutablePublicationArtifact,
	paths map[string]string,
	sourcePrompt ports.ImmutablePublicationArtifact,
	sourceStdin ports.ImmutablePublicationArtifact,
	attempt domain.AttemptID,
) (ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact) {
	t.Helper()
	identity := func(value string) string { return value }
	copyBytes := func(value []byte) []byte { return append([]byte(nil), value...) }
	entries := queryRuntimeFixtureEntries(t, snapshot, artifacts, identity, copyBytes)
	promptEntry := entries[paths["prompt-manifest"]]
	stdinEntry := entries[paths["stdin"]]
	if promptEntry == nil || stdinEntry == nil {
		t.Fatal("runtime prompt fixture entries are absent")
	}
	var wire runtimePromptManifestDTO
	if err := json.Unmarshal(sourcePrompt.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	wire.Target.Path = paths["target"]
	wire.Stdin.Path = paths["stdin"]
	if target, ok := artifacts[paths["target"]]; ok {
		wire.Target.SHA256 = target.SHA256()
	} else {
		t.Fatal("runtime target fixture entry is absent")
	}
	wire.Stdin.SHA256 = sourceStdin.SHA256()
	wire.CompleteStdinSHA256 = prompt.CompleteStdinSHA256(sourceStdin.Bytes())
	promptBytes, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	promptEntry.bytes = promptBytes
	stdinEntry.bytes = sourceStdin.Bytes()
	queryConvergeRuntimeFixtureDigests(t, entries)
	_, reboundSnapshot, reboundObservation, reboundArtifacts, _, _ := queryBuildRuntimeFixture(t, run, snapshot, artifacts, entries, paths, identity, attempt)
	return reboundSnapshot, reboundObservation, reboundArtifacts
}

func queryRuntimeFixtureEntries(
	t *testing.T,
	snapshot ports.CommittedPublicationSnapshot,
	artifacts map[string]ports.ImmutablePublicationArtifact,
	pathTransform func(string) string,
	byteTransform func([]byte) []byte,
) map[string]*queryRuntimeFixtureEntry {
	t.Helper()
	entries := make(map[string]*queryRuntimeFixtureEntry)
	add := func(path ports.SafeRelativePath, value []byte, sha string) {
		transformedPath, err := ports.NewSafeRelativePath(pathTransform(path.String()))
		if err != nil {
			t.Fatal(err)
		}
		entries[transformedPath.String()] = &queryRuntimeFixtureEntry{bytes: byteTransform(value), previousSHA: sha}
	}
	add(snapshot.Final().Identity().Path(), snapshot.Final().Bytes(), snapshot.Final().Identity().SHA256())
	add(snapshot.Manifest().Path(), snapshot.Manifest().Bytes(), snapshot.Manifest().SHA256())
	add(snapshot.LineageEdge().Path(), snapshot.LineageEdge().Bytes(), snapshot.LineageEdge().SHA256())
	add(snapshot.Epoch().Record().Path(), snapshot.Epoch().Record().Bytes(), snapshot.Epoch().Record().SHA256())
	for _, artifact := range artifacts {
		add(artifact.Path(), artifact.Bytes(), artifact.SHA256())
	}
	return entries
}

func queryConvergeRuntimeFixtureDigests(t *testing.T, entries map[string]*queryRuntimeFixtureEntry) {
	t.Helper()
	for pass := 0; pass < 32; pass++ {
		current := make(map[string]string, len(entries))
		for path, entry := range entries {
			current[path] = querySHA(entry.bytes)
		}
		changed := false
		for _, entry := range entries {
			updated := entry.bytes
			for path, replacement := range current {
				previous := entries[path].previousSHA
				if previous == "" || previous == replacement {
					continue
				}
				updated = bytes.ReplaceAll(updated, []byte(previous), []byte(replacement))
			}
			if !bytes.Equal(updated, entry.bytes) {
				entry.bytes = updated
				changed = true
			}
		}
		for path, digest := range current {
			entries[path].previousSHA = digest
		}
		if !changed {
			return
		}
	}
	t.Fatal("runtime fixture digest references did not converge")
}

func queryBuildRuntimeFixture(
	t *testing.T,
	run ports.PublicationRun,
	baseSnapshot ports.CommittedPublicationSnapshot,
	baseArtifacts map[string]ports.ImmutablePublicationArtifact,
	entries map[string]*queryRuntimeFixtureEntry,
	paths map[string]string,
	pathTransform func(string) string,
	attempt domain.AttemptID,
) (ports.PublicationRun, ports.CommittedPublicationSnapshot, ports.PublicationObservation, map[string]ports.ImmutablePublicationArtifact, map[string]string, domain.AttemptID) {
	t.Helper()
	finalPath, err := ports.NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/review_" + baseSnapshot.Final().Identity().ReviewID().String() + ".json")
	if err != nil {
		t.Fatal(err)
	}
	manifestPath, err := ports.NewSafeRelativePath(run.SessionID().String() + "/" + run.RunID().String() + "/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	finalEntry := entries[finalPath.String()]
	manifestEntry := entries[manifestPath.String()]
	if finalEntry == nil || manifestEntry == nil {
		t.Fatalf("runtime fixture final or manifest is absent: %s %s", finalPath, manifestPath)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(baseSnapshot.Final().Identity().ReviewID(), finalPath, querySHA(finalEntry.bytes))
	if err != nil {
		t.Fatal(err)
	}
	final, err := ports.NewFinalReviewArtifact(finalIdentity, finalEntry.bytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ports.NewImmutablePublicationArtifact(manifestPath, querySHA(manifestEntry.bytes), manifestEntry.bytes)
	if err != nil {
		t.Fatal(err)
	}
	edgePath := baseSnapshot.LineageEdge().Path()
	edgeEntry := entries[edgePath.String()]
	if edgeEntry == nil {
		t.Fatal("runtime fixture lineage edge is absent")
	}
	edge, err := ports.NewImmutablePublicationArtifact(edgePath, querySHA(edgeEntry.bytes), edgeEntry.bytes)
	if err != nil {
		t.Fatal(err)
	}
	epochPath := baseSnapshot.Epoch().Record().Path()
	epochEntry := entries[epochPath.String()]
	if epochEntry == nil {
		t.Fatal("runtime fixture epoch is absent")
	}
	epochRecord, err := ports.NewImmutablePublicationArtifact(epochPath, querySHA(epochEntry.bytes), epochEntry.bytes)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := ports.NewPublicationEpoch(baseSnapshot.Epoch().Value(), epochRecord)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ports.NewCommittedPublicationSnapshot(final, manifest, edge, epoch)
	if err != nil {
		t.Fatal(err)
	}
	artifacts := make(map[string]ports.ImmutablePublicationArtifact, len(baseArtifacts))
	for _, artifact := range baseArtifacts {
		path, err := ports.NewSafeRelativePath(pathTransform(artifact.Path().String()))
		if err != nil {
			t.Fatal(err)
		}
		entry := entries[path.String()]
		if entry == nil {
			t.Fatalf("runtime fixture artifact is absent: %s", path)
		}
		artifacts[path.String()], err = ports.NewImmutablePublicationArtifact(path, querySHA(entry.bytes), entry.bytes)
		if err != nil {
			t.Fatal(err)
		}
	}
	observation := queryP2Observation(t, run, snapshot, domain.JournalCompleted, domain.ExitCommittedCIRejected, 1)
	return run, snapshot, observation, artifacts, paths, attempt
}

func querySetExactRerunLineage(
	t *testing.T,
	snapshot ports.CommittedPublicationSnapshot,
	parentRunID domain.RunID,
	sourceRunID domain.RunID,
	sourceReviewID domain.ReviewID,
	sourceAttemptID domain.AttemptID,
) ports.CommittedPublicationSnapshot {
	t.Helper()
	parent, source, review, attempt, mode := parentRunID.String(), sourceRunID.String(), sourceReviewID.String(), sourceAttemptID.String(), string(ReplayModeExact)
	lineage := lineageDTO{ParentRunID: &parent, SourceRunID: &source, SourceReviewID: &review, SourceAttemptID: &attempt, ReplayMode: &mode, LineageEdgePath: snapshot.LineageEdge().Path().String(), LineageEdgeSHA: snapshot.LineageEdge().SHA256()}
	final, err := decodeFinalDTO(snapshot.Final().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	final.RunType = string(domain.RunTypeRerun)
	final.ImmutableLineage = lineage
	finalBytes, err := json.Marshal(final)
	if err != nil {
		t.Fatal(err)
	}
	finalIdentity, err := ports.NewFinalReviewIdentity(snapshot.Final().Identity().ReviewID(), snapshot.Final().Identity().Path(), querySHA(finalBytes))
	if err != nil {
		t.Fatal(err)
	}
	finalArtifact, err := ports.NewFinalReviewArtifact(finalIdentity, finalBytes)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeManifestDTO(snapshot.Manifest().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	manifest.RunType = string(domain.RunTypeRerun)
	manifest.ImmutableLineage = lineage
	if manifest.FinalReview == nil || manifest.RecoveryJournal.ExpectedFinal == nil {
		t.Fatal("runtime fixture final identity bindings are absent")
	}
	manifest.FinalReview.SHA256 = finalIdentity.SHA256()
	manifest.RecoveryJournal.ExpectedFinal.SHA256 = finalIdentity.SHA256()
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestArtifact, err := ports.NewImmutablePublicationArtifact(snapshot.Manifest().Path(), querySHA(manifestBytes), manifestBytes)
	if err != nil {
		t.Fatal(err)
	}
	updated, err := ports.NewCommittedPublicationSnapshot(finalArtifact, manifestArtifact, snapshot.LineageEdge(), snapshot.Epoch())
	if err != nil {
		t.Fatal(err)
	}
	return updated
}

type recoveryParentStore struct {
	*queryStore
	parent domain.RunID
	p0     ports.PublicationObservation
}

func (store *recoveryParentStore) ObserveRun(ctx context.Context, request ports.ObserveRunRequest) (ports.PublicationObservation, error) {
	if request.Run().RunID() != store.parent {
		return store.p0, nil
	}
	return store.queryStore.ObserveRun(ctx, request)
}
