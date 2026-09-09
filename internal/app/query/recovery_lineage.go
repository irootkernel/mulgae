package query

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/irootkernel/mulgae/internal/app/prompt"
	"github.com/irootkernel/mulgae/internal/app/recovery"
	"github.com/irootkernel/mulgae/internal/app/review"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

// Every exact edge must retain its parent's input. Execution invocation IDs are
// deliberately excluded: a retry executes again while preserving source scope.
func (service *Service) verifyRecoveryReplay(ctx context.Context, run ports.PublicationRun, snapshot recovery.Snapshot) error {
	document := snapshot.Document()
	source := document.Source
	if source == nil || source.ReplayMode != "exact" {
		return nil
	}
	expected := document.Attempts[0]
	expectedStdin := snapshot.Blob(expected.InitialPrompt.Stdin)
	seen := map[string]bool{document.RunID: true}
	for depth := 0; source != nil && source.ReplayMode == "exact"; depth++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth >= 128 || seen[source.RunID] {
			return fmt.Errorf("recovery replay lineage exceeds bound or cycles")
		}
		seen[source.RunID] = true
		reference, err := source.Reference()
		if err != nil {
			return err
		}
		parent, err := ports.NewPublicationRun(run.Root(), run.SessionID(), reference.RunID())
		if err != nil {
			return err
		}
		attemptID, err := domain.ParseAttemptID(source.AttemptID)
		if err != nil {
			return err
		}
		if source.Kind == "failed_run_recovery" {
			ancestor, err := recovery.Read(ctx, service.store, service.validator, parent, service.maxReadBytes)
			if errors.Is(err, recovery.ErrUnavailable) {
				return fmt.Errorf("recovery ancestor is absent")
			}
			if err != nil {
				return err
			}
			if recovery.Digest(ancestor.Manifest()) != reference.RecoveryManifestSHA256() {
				return fmt.Errorf("recovery ancestor manifest changed")
			}
			observed, err := service.observe(ctx, parent, "query.read_recovery")
			if err != nil {
				return err
			}
			if observed.decision.Status() != domain.PublicationNotPublished {
				return fmt.Errorf("recovery ancestor conflicts with publication")
			}
			ancestorDocument := ancestor.Document()
			var selected *recovery.Attempt
			for i := range ancestorDocument.Attempts {
				if ancestorDocument.Attempts[i].AttemptID == attemptID.String() {
					selected = &ancestorDocument.Attempts[i]
				}
			}
			if selected == nil || selected.State == domain.AttemptSucceeded || ancestorDocument.Target != document.Target || !sameRecoveryReplayInput(expected, *selected, expectedStdin, ancestor.Blob(selected.InitialPrompt.Stdin)) {
				return fmt.Errorf("recovery input differs from exact ancestor")
			}
			source = ancestorDocument.Source
			continue
		}
		ancestor, err := service.ReadCommittedAttempt(ctx, parent, attemptID)
		if err != nil {
			return err
		}
		input := ancestor.prompt
		selected := recovery.Attempt{Role: ancestor.role, ProviderInstance: ancestor.provider, InitialPrompt: recovery.Prompt{
			Stdin:              recovery.Blob{SHA256: recovery.Digest(input.stdin), ByteLength: int64(len(input.stdin))},
			SourceInvocationID: input.sourceInvocationID, TemplateID: input.templateID, TemplateVersion: input.templateVersion,
			TemplateSHA256: "sha256:" + strings.TrimPrefix(input.templateSHA256, "sha256:"), AdapterProfile: input.adapterProfile,
			AdapterParameters: input.adapterParameters, Scope: input.scope,
		}}
		target, err := document.Target.Identity()
		if err != nil {
			return err
		}
		if ancestor.sessionID != run.SessionID() || ancestor.reviewID != reference.ReviewID() || ancestor.target.identity != target ||
			recovery.Digest(ancestor.target.bytes) != document.Target.Bytes.SHA256 || recovery.Digest(ancestor.target.capturedArchive) != document.Target.CapturedArchive.SHA256 ||
			!sameRecoveryReplayInput(expected, selected, expectedStdin, input.stdin) {
			return fmt.Errorf("recovery input differs from committed ancestor")
		}
		lineage := ancestor.lineage
		mode, exact := lineage.ReplayMode()
		if !exact || mode != ReplayModeExact {
			boundary := bytes.Index(input.stdin, []byte("\nMulgae-FRAMES/1\n"))
			if boundary <= 0 {
				return fmt.Errorf("recovery original prompt is invalid")
			}
			template, err := prompt.NewTrustedTemplate(input.templateID, input.templateVersion, input.stdin[:boundary])
			if err != nil {
				return err
			}
			parsed, err := prompt.ParseStdin(template, input.stdin)
			if err != nil {
				return err
			}
			scope := parsed.Scope()
			if scope.String() != input.scope || "sha256:"+template.SHA256() != selected.InitialPrompt.TemplateSHA256 || scope.SessionID() != parent.SessionID() || scope.RunID() != parent.RunID() || scope.AttemptID() != attemptID {
				return fmt.Errorf("recovery original prompt scope is foreign")
			}
			return nil
		}
		parentID, ok := lineage.SourceRunID()
		if !ok {
			return fmt.Errorf("recovery ancestor has no source run")
		}
		selectedID, ok := lineage.SourceAttemptID()
		if !ok {
			return fmt.Errorf("recovery ancestor has no exact source attempt")
		}
		source = &recovery.Source{RunID: parentID.String(), AttemptID: selectedID.String(), ReplayMode: "exact"}
		if lineage.sourceRecoveryManifestSHA256 != nil {
			source.Kind = "failed_run_recovery"
			source.RecoveryManifestSHA256 = lineage.sourceRecoveryManifestSHA256
		} else if reviewID, ok := lineage.SourceReviewID(); ok {
			id := reviewID.String()
			source.Kind = "published_review"
			source.ReviewID = &id
		} else {
			return fmt.Errorf("recovery ancestor has no source identity")
		}
	}
	return nil
}

func sameRecoveryReplayInput(left, right recovery.Attempt, leftStdin, rightStdin []byte) bool {
	a, b := left.InitialPrompt, right.InitialPrompt
	if left.Role != right.Role || left.ProviderInstance != right.ProviderInstance || a.SourceInvocationID != b.SourceInvocationID ||
		a.TemplateID != b.TemplateID || a.TemplateVersion != b.TemplateVersion || a.AdapterProfile != b.AdapterProfile || a.Scope != b.Scope {
		return false
	}
	if a.Stdin == b.Stdin && a.TemplateSHA256 == b.TemplateSHA256 && maps.Equal(a.AdapterParameters, b.AdapterParameters) {
		return true
	}
	leftParameters, rightParameters := maps.Clone(a.AdapterParameters), maps.Clone(b.AdapterParameters)
	delete(leftParameters, prompt.TrustedLayerManifestAdapterParameter)
	delete(rightParameters, prompt.TrustedLayerManifestAdapterParameter)
	if !maps.Equal(leftParameters, rightParameters) {
		return false
	}
	leftTemplate, leftFrames, err := recoveryStagedReplayTemplate(a, leftStdin)
	if err != nil {
		return false
	}
	rightTemplate, rightFrames, err := recoveryStagedReplayTemplate(b, rightStdin)
	if err != nil {
		return false
	}
	leftLayers, rightLayers := leftTemplate.TrustedLayerManifest(), rightTemplate.TrustedLayerManifest()
	leftBase := leftTemplate.Bytes()[:leftTemplate.ByteLength()-leftLayers[len(leftLayers)-1].ByteLength()]
	rightBase := rightTemplate.Bytes()[:rightTemplate.ByteLength()-rightLayers[len(rightLayers)-1].ByteLength()]
	return bytes.Equal(leftFrames, rightFrames) && bytes.Equal(leftBase, rightBase) &&
		slices.Equal(leftLayers[:len(leftLayers)-1], rightLayers[:len(rightLayers)-1])
}

// A staged exact replay may replace only the canonical final destination layer.
// Validate its full constructor-owned text before excluding it from comparison.
func recoveryStagedReplayTemplate(input recovery.Prompt, stdin []byte) (prompt.TrustedTemplate, []byte, error) {
	invalid := fmt.Errorf("recovery staged replay template is invalid")
	boundary := bytes.Index(stdin, []byte("\nMulgae-FRAMES/1\n"))
	if boundary <= 0 {
		return prompt.TrustedTemplate{}, nil, invalid
	}
	template, err := prompt.NewTrustedTemplate(input.TemplateID, input.TemplateVersion, stdin[:boundary])
	if err != nil || "sha256:"+template.SHA256() != input.TemplateSHA256 {
		return prompt.TrustedTemplate{}, nil, invalid
	}
	if _, err := prompt.ParseStdin(template, stdin); err != nil {
		return prompt.TrustedTemplate{}, nil, invalid
	}
	template, err = prompt.RestoreTrustedLayerManifest(template, input.AdapterParameters[prompt.TrustedLayerManifestAdapterParameter])
	if err != nil {
		return prompt.TrustedTemplate{}, nil, invalid
	}
	layers := template.TrustedLayerManifest()
	last := layers[len(layers)-1]
	body := stdin[boundary-last.ByteLength() : boundary]
	lines := strings.Split(string(body), "\n")
	if last.ID() != review.OutputDestinationTrustedLayerID || len(lines) != 6 {
		return prompt.TrustedTemplate{}, nil, invalid
	}
	destination, err := ports.NewStagedOutputDestination(filepath.Dir(lines[2]), filepath.Base(lines[2]))
	if err != nil {
		return prompt.TrustedTemplate{}, nil, invalid
	}
	canonical, err := review.OutputDestinationTrustedLayer(destination)
	if err != nil || last.Version() != canonical.Version() || !bytes.Equal(body, canonical.Bytes()) {
		return prompt.TrustedTemplate{}, nil, invalid
	}
	return template, stdin[boundary:], nil
}
