package ports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/irootkernel/mulgae/internal/artifactwire"
)

func publicationPathCompatibilityOutputs(t *testing.T) map[string]string {
	t.Helper()
	out := map[string]string{}
	run := publicationTestRun(t)
	final := publicationTestFinal(t, []byte("{}"))
	put := func(name string, path SafeRelativePath, err error) {
		if err != nil {
			t.Fatal(err)
		}
		out[name] = path.String()
	}
	p, e := ValidatedCandidatePath(run)
	put("validated", p, e)
	p, e = validatedCandidatePathForFinal(final)
	put("validated-for-final", p, e)
	p, e = canonicalStagedFinalPath(run, final)
	put("staged", p, e)
	p, e = canonicalStagedFinalPathForFinal(final)
	put("staged-for-final", p, e)
	out["final"] = final.Path().String()
	for _, document := range []MutablePublicationDocument{MutablePublicationStatus, MutablePublicationJournal} {
		p, e = canonicalMutablePublicationPath(run, document)
		put("mutable/"+string(document), p, e)
		p, e = canonicalMutablePublicationPathForFinal(final, document)
		put("mutable-for-final/"+string(document), p, e)
	}
	for _, epoch := range []uint64{1, 42, 1000, ^uint64(0)} {
		m, l, p, e := canonicalCompositePaths(run, final, epoch)
		if e != nil {
			t.Fatal(e)
		}
		out[fmt.Sprintf("composite/%d/manifest", epoch)] = m.String()
		out[fmt.Sprintf("composite/%d/lineage", epoch)] = l.String()
		out[fmt.Sprintf("composite/%d/epoch", epoch)] = p.String()
		p, e = canonicalCorruptionDiagnosticPath(run, epoch)
		put(fmt.Sprintf("diagnostic/%d", epoch), p, e)
	}
	m, l, p, e := canonicalPreparedCompositePaths(run)
	if e != nil {
		t.Fatal(e)
	}
	out["prepared/manifest"], out["prepared/lineage"], out["prepared/epoch"] = m.String(), l.String(), p.String()
	for _, name := range []string{"", "0", "00", "000", "001", "010", "100", "1000", "0001", "1", "01", "a", "-1", "１", "12/3", "001-initial", "001-retry", "001-repair", "001-extract", "000-initial", "0001-repair", "001-unknown", "F001.json", "F0.json", "F001_1.md", "F001_0.md", "F001_01.md", "F001_1.json", "F001.md", "F001_1.md/x", "../F001.json"} {
		out["decimal/"+name] = fmt.Sprint(decimalIdentifier(name, 3))
		out["digits/"+name] = fmt.Sprint(artifactwire.DecimalDigits(name, 1))
		out["invocation/"+name] = fmt.Sprint(canonicalInvocationDirectory(name))
		out["excerpt/"+name] = fmt.Sprint(canonicalExcerptName(name))
	}
	return out
}
func TestPublicationPathContractCompatibility(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "m2-publication-paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]string
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if got := publicationPathCompatibilityOutputs(t); !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v;want %+v", got, want)
	}
}
