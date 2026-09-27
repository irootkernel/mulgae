package compositesupport

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func TestCompositeSupportExampleRequiresCopiedVerificationMaterial(t *testing.T) {
	raw, err := os.ReadFile("../../builtin/assets/examples/composite-support.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var example Document
	if err := json.Unmarshal(raw, &example); err != nil {
		t.Fatal(err)
	}
	canonical, err := json.Marshal(example)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Sources) != 2 || len(doc.Findings) != 1 || len(doc.Findings[0].Evidence) != 1 {
		t.Fatal("paired example lost its published/recovery/evidence cases")
	}
	published, recovered := doc.Sources[0], doc.Sources[1]
	if published.ReviewID == "" || published.Epoch == 0 || published.RecoveryManifestSHA256 != "" {
		t.Fatal("published source receipt is incomplete")
	}
	if recovered.RecoveryManifestSHA256 == "" || recovered.ReviewID != "" || recovered.Epoch != 0 || recovered.FinalSHA256 != "" || recovered.ManifestSHA256 != "" || recovered.SupportSHA256 != "" || recovered.LineageSHA256 != "" {
		t.Fatal("recovery source fabricates a publication receipt")
	}
	if doc.CommonCapture() != "" {
		t.Fatal("unavailable recovery source was excluded from common capture calculation")
	}
	finding := doc.Findings[0]
	if finding.ID == finding.SourceFindingID || finding.Role != published.Role || finding.Evidence[0].Index != 0 || finding.Evidence[0].TargetSHA256 != published.TargetSHA256 {
		t.Fatal("paired example loses finding remapping or evidence identity")
	}
	session, err := domain.ParseSessionID(published.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	run, err := domain.ParseRunID(published.RunID)
	if err != nil {
		t.Fatal(err)
	}
	path := session.String() + "/" + run.String() + "/" + DocumentPath
	artifacts := map[string]ports.ImmutablePublicationArtifact{}
	replaceArtifact(t, artifacts, path, canonical)
	if _, err := Verify(session, run, published.TargetSHA256, artifacts); err == nil {
		t.Fatal("metadata-only example improperly proves its claimed copied evidence/capture")
	}
}

func TestCompositeSupportDecodeRejectsNoncanonicalFields(t *testing.T) {
	session, run, material, _ := supportFixture(t, false)
	artifacts := supportArtifacts(t, session, run, material)
	canonical := string(artifacts[session.String()+"/"+run.String()+"/"+DocumentPath].Bytes())
	cases := map[string]string{
		"unknown":   strings.Replace(canonical, `"schema_version":`, `"unexpected":true,"schema_version":`, 1),
		"duplicate": strings.Replace(canonical, `"schema_version":`, `"schema_version":"mulgae-composite-support.v1","schema_version":`, 1),
		"reordered": strings.Replace(canonical, `"index":0,"availability":"verified"`, `"availability":"verified","index":0`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if raw == canonical {
				t.Fatal("fixture mutation missed its target")
			}
			if _, err := Decode([]byte(raw)); err == nil {
				t.Fatal("accepted noncanonical fields")
			}
		})
	}
}
