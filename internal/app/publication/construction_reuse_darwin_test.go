//go:build darwin && arm64

package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/irootkernel/mulgae/internal/adapters/filesystem"
	"github.com/irootkernel/mulgae/internal/adapters/gittarget"
	"github.com/irootkernel/mulgae/internal/adapters/jsonschema"
	"github.com/irootkernel/mulgae/internal/app/evidence"
	"github.com/irootkernel/mulgae/internal/builtin"
	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

func livePublicationChangedFixture(t *testing.T) PreparedLiveCandidate {
	t.Helper()
	rootPath := t.TempDir()
	for path, data := range map[string][]byte{
		"source.go":   []byte("observed\n"),
		"diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0},
	} {
		if err := os.WriteFile(filepath.Join(rootPath, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	source, err := opener.OpenLiveSource(context.Background(), root, selector)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	input, _ := livePublicationChangedInput(t, source, schema)
	candidate, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	return candidate
}

type publicationIssueCountingStore struct {
	*filesystem.PublicationStore
	issueCalls int
}

func (store *publicationIssueCountingStore) IssueReviewID(ctx context.Context, request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	store.issueCalls++
	return store.PublicationStore.IssueReviewID(ctx, request)
}

// publicationLiveGoldenBundle builds one family bundle with the fixed issued
// review ID so golden vectors stay comparable across the refactor.
func publicationLiveGoldenBundle(t *testing.T, candidate PreparedLiveCandidate) PublicationBundle {
	t.Helper()
	bundle, err := candidate.Build(context.Background(), &publicationTestValidator{}, publicationIssuedReviewID(t), publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func publicationGoldenVectorLines(t *testing.T, bundle PublicationBundle) []string {
	t.Helper()
	lines := []string{
		"final " + bundle.Final().Identity().Path().String() + " " + bundle.Final().Identity().SHA256(),
		"manifest " + bundle.Manifest().Path().String() + " " + bundle.Manifest().SHA256(),
		"lineage " + bundle.LineageEdge().Path().String() + " " + bundle.LineageEdge().SHA256(),
		"epoch " + bundle.Epoch().Record().Path().String() + " " + bundle.Epoch().Record().SHA256(),
		"staged " + bundle.StagedFinal().Path().String() + " " + bundle.StagedFinal().SHA256(),
		"journal " + bundle.Journal().Path().String() + " " + bundle.Journal().SHA256(),
		"status " + bundle.Status().Path().String() + " " + bundle.Status().SHA256(),
	}
	for _, artifact := range bundle.SupportArtifacts() {
		lines = append(lines, "support "+artifact.Path().String()+" "+artifact.SHA256())
	}
	return lines
}

// publicationGoldenVectors freezes the old builder's exact member vectors at
// the TASK-054 baseline. The constants are recorded once from the builder at
// HEAD and must never be regenerated; any byte drift in the construction
// refactor turns this test red.
var publicationGoldenVectors = map[string][]string{
	"live-changed-with-attempts": {
		`final s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:e9e59191f13d33cdfedb2ffe7459e2b25470ba044b89ed8e44863fcc773fcfbb`,
		`manifest s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/manifest.json sha256:efa61a7ffc2b969d033dd2cc0b463261ff965268eca49b27201da8eb4cc0a349`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:cc72d0ffe74a9facf60a39fb8017c2a3e55fbc1e17d55d6884cb26daaf16b906`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:e122dccc361ea5d799188b84a7506e89aad619ead7d3b962a769916ad158dfd3`,
		`staged s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:e9e59191f13d33cdfedb2ffe7459e2b25470ba044b89ed8e44863fcc773fcfbb`,
		`journal s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/publication/journal.json sha256:229dfba7ef0d0b27d9add65abeddc625a51791a34567cca4ebdfe01b75d76610`,
		`status s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/status.json sha256:6784afdaa334033ebdd9036461a7997ae533c62d6dcc1a8f839c85061706d631`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/excerpts/F001_1.md sha256:08cfb1f08c9a2b3985853df5336808a27d616d731c6e944ff0a4e8e74dde5e5f`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/excerpts/F001.json sha256:071883237a7870c9325801e6f7c3ae8d15f4e395a44114146173acb700e6a995`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/attempts/a_019f5a09-5eec-7001-8001-000000000003/invocations/001-initial/stdout.raw sha256:0e257bf8603787434bc514a59596d4c90a7bbf7d6469c2d4522c3aeece5785fc`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/attempts/a_019f5a09-5eec-7001-8001-000000000003/candidate.initial.json sha256:c8c91fe713b7a56f96d5d8df479d59ff5a9acf336727854d28f2cf07e39e3f14`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/attempts/a_019f5a09-5eec-7001-8001-000000000003/status.json sha256:93d8f7bbc4f01912052a84adae78f63e32f12c12a82f7cc272e4d949f79bf204`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/attempts/a_019f5a09-5eec-7001-8001-000000000004/invocations/001-initial/stdout.raw sha256:92cef8d53774f2cb01082540556f1fca41f4eaad24cb14b6ee4166d481adc306`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/attempts/a_019f5a09-5eec-7001-8001-000000000004/candidate.initial.json sha256:5337a7909fa5bfa71a87d36db82187900bdc9c70747cb4858a4f73e7ff6e93b1`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/attempts/a_019f5a09-5eec-7001-8001-000000000004/status.json sha256:a232f27271e00e25851fbad19eef76c0cebf94410d1fc0aa9ec2384c0fec1f8d`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/role-reports/logic.md sha256:7cca1a7e3a6b9dcfc1ae9299f41c6d8a80811d070045d73c71b32d77105a3f42`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/role-reports/security.md sha256:b037f897bdebe29a3ec642bd6dc2f84a3673171bda3b5a801da7c8b2ef456844`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/source/source.json sha256:87baffbf5aebb20121d9176136272bf300e23b78c4203c0061f9b64e819a750f`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/evidence/images/sha256-843ac23b1736b4487ec81cf7c07ddd9bb46ae5b7818c2c3843d99d62fa75f3c9.png sha256:843ac23b1736b4487ec81cf7c07ddd9bb46ae5b7818c2c3843d99d62fa75f3c9`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/support/index.json sha256:f07b5590ff2b86207aa659f829dde7cd39ec58199c73f0a651d1a27458b59932`,
	},
	"live-changed": {
		`final s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:e9e59191f13d33cdfedb2ffe7459e2b25470ba044b89ed8e44863fcc773fcfbb`,
		`manifest s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/manifest.json sha256:d182484899676c233086857afbfa9da4dca3a036479a4e72fda98d57e84e7501`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:cc72d0ffe74a9facf60a39fb8017c2a3e55fbc1e17d55d6884cb26daaf16b906`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:6591fe4ed381b14889cbe834c4e338fac405754cf35958a39e2421e8afca5d56`,
		`staged s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:e9e59191f13d33cdfedb2ffe7459e2b25470ba044b89ed8e44863fcc773fcfbb`,
		`journal s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/publication/journal.json sha256:0f1555d5992c61aff9bf132a35d6256f5e86d17f3fafc21ae981a50f78c18b95`,
		`status s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/status.json sha256:8dfd4af6061f201634ad09d4083da6c2f357efe88e27bd55ae6fec7b595345b3`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/excerpts/F001_1.md sha256:08cfb1f08c9a2b3985853df5336808a27d616d731c6e944ff0a4e8e74dde5e5f`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/excerpts/F001.json sha256:071883237a7870c9325801e6f7c3ae8d15f4e395a44114146173acb700e6a995`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/role-reports/logic.md sha256:7cca1a7e3a6b9dcfc1ae9299f41c6d8a80811d070045d73c71b32d77105a3f42`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/role-reports/security.md sha256:b037f897bdebe29a3ec642bd6dc2f84a3673171bda3b5a801da7c8b2ef456844`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/source/source.json sha256:87baffbf5aebb20121d9176136272bf300e23b78c4203c0061f9b64e819a750f`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/evidence/images/sha256-843ac23b1736b4487ec81cf7c07ddd9bb46ae5b7818c2c3843d99d62fa75f3c9.png sha256:843ac23b1736b4487ec81cf7c07ddd9bb46ae5b7818c2c3843d99d62fa75f3c9`,
		`support s_019f5a09-5eec-7001-8001-000000000001/r_019f5a09-5eec-7001-8001-000000000002/support/index.json sha256:d5dbea0d86e13a121cf6865b6a893590c02a3e400512a5932ec729b90d492d83`,
	},
	"live-no-change": {
		`final s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:e42c5c3bc0c457495a3275481b436667bef857fb8a8a7ee599f9793d297bb5b2`,
		`manifest s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/manifest.json sha256:dd218c899b5797c3c1371c1d1df1bd04c8a2d46edb69d3bd62f184f626a6cc5d`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:caf8d02afae37724a20c1ee1b1cf136792ab04add7fac64c187ee899f01f749b`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:125ba98f920f7adf12c318519a5df55e9920d641e9448c1c86d5cb1e0c8bc4ff`,
		`staged s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:e42c5c3bc0c457495a3275481b436667bef857fb8a8a7ee599f9793d297bb5b2`,
		`journal s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/journal.json sha256:2e72947fbf19619debbf08ce5a9f48df5d4eb21d7c01dc104fb84eb848f302b7`,
		`status s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/status.json sha256:f83d926865090d167b2d90257aea9bac7128d1b65ef3e5ea2f86cb3d85d34e06`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/source/source.json sha256:87baffbf5aebb20121d9176136272bf300e23b78c4203c0061f9b64e819a750f`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json sha256:dc958f680fd7e7254dcf3730eeefbc1f6ed00583a04017b5278dddbd65ac5385`,
	},
	"captured": {
		`final s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:225adad5e8e28515dd00aa91c3969fb7303f7bb72caf7f69c97b83a75c0d805e`,
		`manifest s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/manifest.json sha256:9969f0000214127107065127349e9f660b1b2bd8df4c9f692cd667efc015cd90`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:caf8d02afae37724a20c1ee1b1cf136792ab04add7fac64c187ee899f01f749b`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:f9c83c39ba06cca7afc85e324e56ec28251e31156cb52991330f24027a53f249`,
		`staged s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:225adad5e8e28515dd00aa91c3969fb7303f7bb72caf7f69c97b83a75c0d805e`,
		`journal s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/journal.json sha256:ad0e401fa8ec97991144fe79a194cdfb3586a387a9f5e56e2fd9247f4c6101a6`,
		`status s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/status.json sha256:86ecbf47e6f8711454ef56ea8ac9df3eec0ddcd515645122750fcfc9719c2ad0`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/excerpts/F001_1.md sha256:cfd126680b3411bb472378d2dc0177b6faf13ed46da4d50176f57408e4ad3d2c`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/excerpts/F001.json sha256:4f562bf26951edf223ee81dab58c2d8c79d69233aa88338bca492606035dcca0`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/logic.md sha256:7cca1a7e3a6b9dcfc1ae9299f41c6d8a80811d070045d73c71b32d77105a3f42`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/security.md sha256:b037f897bdebe29a3ec642bd6dc2f84a3673171bda3b5a801da7c8b2ef456844`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json sha256:5a675650fbcdf02f60998c794b76a35bd1a2ddce51f3c0a5539c4f23d7060188`,
	},
	"captured-no-change": {
		`final s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:8332843f3435d11125dde20b53f44362343ac6ebc7ab50b7b1292ed3630e657f`,
		`manifest s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/manifest.json sha256:04c819b99d37180a2a0efc4454072a7366bb25e9b6f2b40229f02f3b17868cea`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:caf8d02afae37724a20c1ee1b1cf136792ab04add7fac64c187ee899f01f749b`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:29cb7f48378f213bea00ddfde351a79b06e68a03c6a1670830b59f28d41cff87`,
		`staged s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:8332843f3435d11125dde20b53f44362343ac6ebc7ab50b7b1292ed3630e657f`,
		`journal s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/journal.json sha256:a76e93ec961517d7c79f3525474cecba16390cc3f56b7b7bc272f450c0157187`,
		`status s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/status.json sha256:824c3dfb2c7c337a237634bc425ae27a33041551059bb743dc1b7327d5e314ff`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json sha256:bcc7f3688edf490eaab4b7c409701611f33401c985916d49dbf15ff43bb9dd4b`,
	},
	"runtime": {
		`final s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:1e60be4b222cdc205967dd6f2ea641b97d9d268707579aed5f443a1e4281e9b8`,
		`manifest s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/manifest.json sha256:5b20a9dda1115f572c42cec7f9f90c44a15ed404daa8bb17b6bd3fdbeead8fa4`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:caf8d02afae37724a20c1ee1b1cf136792ab04add7fac64c187ee899f01f749b`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:bb755ca4cb7cb3c4323a8a92a93934911323638136e68f63dada904671998de3`,
		`staged s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:1e60be4b222cdc205967dd6f2ea641b97d9d268707579aed5f443a1e4281e9b8`,
		`journal s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/publication/journal.json sha256:1cec96c109223378ad466e29bd84e2679ccf2cd2331283ff0020401c0fc4e7c5`,
		`status s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/status.json sha256:c2afa0bdf93cc32b23e3f6a263606fec9c2da977e30138e833f5c57d89b99409`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/candidate.initial.json sha256:cf3f7d07d46be05c1a1a58ed5c00f69ea0da00ad66f69b0265eae5eddce68ebe`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/status.json sha256:e0b5d5da84778d926de7d6a3b13d433bc38bad59f4761bac07aad611701eee94`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/attempts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/candidate.initial.json sha256:cf3f7d07d46be05c1a1a58ed5c00f69ea0da00ad66f69b0265eae5eddce68ebe`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/attempts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/status.json sha256:1609b5d70f763dd4c5a989ce9d8bced6ae334123df9d9b2324fdf1803eb75132`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/target/target.bytes sha256:cfd126680b3411bb472378d2dc0177b6faf13ed46da4d50176f57408e4ad3d2c`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.stdin sha256:10b9112662887d841f3c4cc43b9a10b23d45928fecb3a73f59c78a71d98a6e79`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.manifest.json sha256:56dad72f74a40e6da38f53f129703559e1eefc4f658c2603ee8533f992a5630c`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/001-initial.stdin sha256:10b9112662887d841f3c4cc43b9a10b23d45928fecb3a73f59c78a71d98a6e79`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/prompts/a_019f596a-d0ac-7c12-8b68-0bd73e911b2e/001-initial.manifest.json sha256:17be124358d93c9b11adc68a2277f81300e177e37f7791738f2df5753c0457b8`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/target/target-manifest.json sha256:803d2db729ce1fb6eed42381128d0aa38205b27e6d572793d068d380d40b4c28`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/logic.md sha256:7cca1a7e3a6b9dcfc1ae9299f41c6d8a80811d070045d73c71b32d77105a3f42`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/role-reports/security.md sha256:b037f897bdebe29a3ec642bd6dc2f84a3673171bda3b5a801da7c8b2ef456844`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe4-7c9c-b82e-7149158243ba/support/index.json sha256:73a82bcb373c71a3c8eb6329decb2b72bb4e68dd28ebd5c977f2f7c214d7ccc1`,
	},
	"followup": {
		`final s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:2495c8c09e3b2ffb196b46363530512c7642dc3971d7572f6321718cdfe942b3`,
		`manifest s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/manifest.json sha256:e956f69739799724be650b185c41c8c6b28c3835971d0661843e5c0444f894ea`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:5f7e0e11f1fdfb8beed836fa2f1002ac17d5ed55be0fa52e7e9a706bd16ed04f`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:68a3a10157ac26555e047f8f2f17a5fce4f7757c2244e4eec2fec49bd2637531`,
		`staged s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:2495c8c09e3b2ffb196b46363530512c7642dc3971d7572f6321718cdfe942b3`,
		`journal s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/publication/journal.json sha256:8b2b23aae9e9801eefbb96060260e8183f208c08e44d5a64a2eeaa6452c5a955`,
		`status s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/status.json sha256:82d6b8e67b144beada8bd3c8124b541bfc371fdde9ba004b79704aa1a6649375`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/excerpts/F001_1.md sha256:29cecbc78c021415a2f486b0e795fff51891f90328cc8581ebc5d10e0e05aef6`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/excerpts/F001.json sha256:a2c10850a8e35265be500e78d164791fee5ca0df2b68575a58ea1ba33b57d1ad`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/candidate.initial.json sha256:b0cbcdc8254ccc2cf40e1eefc48e390e017c980c174c9c7d5d51113f4430ddbe`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/invocations/001-initial/stdout.raw sha256:9e4a87c11aef21665a9ecd78a39b58f99289a8396e8e7872700891efa03a5bd9`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/attempts/a_019f596a-d048-79e7-b2b7-59822f012273/status.json sha256:04eb6ade9c76df03e16abf4943f8ce3dbc59404e2c2dea8f60c769a1bb7f4222`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/target/target.bytes sha256:29cecbc78c021415a2f486b0e795fff51891f90328cc8581ebc5d10e0e05aef6`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.stdin sha256:01a2b6c70c711d3b7ac79afcd7de50b6f833a622e0dea594beb7b0b0c821b5cb`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/prompts/a_019f596a-d048-79e7-b2b7-59822f012273/001-initial.manifest.json sha256:e68fabb242a00a5a1efec96af65494a61b7fd88222b353425daff884fa5e5689`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/target/target-manifest.json sha256:f145514d8e203f8e847433ef6aec960f83ac5e7ae1bedc203296d36b1de93f01`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/role-reports/logic.md sha256:9e4a87c11aef21665a9ecd78a39b58f99289a8396e8e7872700891efa03a5bd9`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_019f596a-cfe9-7c9c-b82e-7149158243ba/support/index.json sha256:d823e10c82c88d579d5b13d28198f782d53f4db09b60d0c793df5a227917fdeb`,
	},
	"composite": {
		`final s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/review_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:67dc144cad1c663b056287e6074fc85328a06d6d02231ffa1cb015c68e76de85`,
		`manifest s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/manifest.json sha256:0d7f5fd64484aad31caee3bfa89934d874b9dde2ce7d34c0dacc25234582cf6a`,
		`lineage store/lineage-edges/e_019f596a-cf80-7c67-b265-f37053d51ccf.json sha256:66a868caa371e08ff6dd54fd4ea95b504bbf0cd3ceeac6546744d75842c33b73`,
		`epoch store/epochs/epoch_00000000000000000001.json sha256:cfce54d4da002f84cad85d42899b5bdf4cef1ef23508a88f79fc05547c3a45d7`,
		`staged s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/publication/staged/review_019f596a-cf80-7c67-b265-f37053d51ccf.json.tmp sha256:67dc144cad1c663b056287e6074fc85328a06d6d02231ffa1cb015c68e76de85`,
		`journal s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/publication/journal.json sha256:eff248c0b32a45b4f4bf5881dc5eed033cb6b626df86380ffabd2a4189fbf741`,
		`status s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/status.json sha256:2fe18361d6f88c33c9f1c2166db178ae5d408f453323d70bc267e8ed840ac7d9`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/target/target.bytes sha256:5c7f970ed608861857c192b4980ae15da74b648be991b3250e9a0657d2b87599`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/target/target-manifest.json sha256:3d8646d5ae908b521b2aeaaf51b9fe4c17700f45f79e33527da6f309829138a2`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/role-reports/logic.md sha256:f17dfb2f45b63372247fba1f4a9e7a5d7ba64c27b4bc3dd36ece8b5cab6fc586`,
		`support s_019f596a-cf80-7c67-b265-f37053d51ccf/r_f91fb28d-a22d-7ef4-86b9-852c353c70a1/support/index.json sha256:f71d8ff9e3500165e4af54f49d37f3342b8f6bfebb6c202a619d0a43e590a151`,
	},
}

// publicationLiveBaselineConstructionCounts records the shared support
// constructions of one live publication through publishCandidate. The
// pre-refactor baseline at HEAD was two per member (two full Build calls:
// changed {2,0,0,4,4,0}, no-change {0,0,0,0,2,0}); the wired two-phase
// builder constructs each shared member once. The live no-change candidate
// shares exactly one member, the source metadata artifact: it carries no
// findings, attempts, runtime inventory, role reports or binary receipts, so
// its role-report digest delta is zero by construction.
var publicationLiveBaselineConstructionCounts = map[string]publicationEstablishedConstructionCounts{
	"changed":   {evidenceExcerpts: 1, attemptArtifacts: 0, roleReports: 2, liveSupport: 2},
	"no-change": {evidenceExcerpts: 0, attemptArtifacts: 0, roleReports: 0, liveSupport: 1},
	// The with-attempts fixture binds a stdout stream and the initial
	// candidate to each of its two primary attempts, so buildAttemptArtifacts
	// constructs two capture artifacts and one status artifact per attempt:
	// six per construction. The pre-wiring baseline (two full Build calls)
	// is therefore twelve; the wired builder constructs them once.
	"changed-with-attempts": {evidenceExcerpts: 1, attemptArtifacts: 6, roleReports: 2, liveSupport: 2},
}

// publicationLiveBaselineDigestTotals records the publication digest-helper
// total of one live publication. The establishing run at HEAD measured 72
// (changed) and 56 (no-change); the wired two-phase builder measured 63 and
// 55. The deltas are exactly the shared-member pre-digests the second binding
// no longer performs (changed: one evidence excerpt, two role reports, the
// source metadata and one binary image; no-change: the source metadata) plus
// the two role-report re-hashes manifestRoleReports() performed per binding
// (changed: 2 reports x 2 bindings). The historical Build keeps that re-hash,
// so the whole delta comes from the live path. Constructor verification in
// internal/ports is deliberately out of view here.
// The totals also include fixture-preparation digests because counting starts
// before fixture.candidate(t); only the deltas are the reuse evidence.
// TASK-065 removes four fixture-only digests from changed setup (the captured
// target, objective, snapshot and workspace receipt) and three from no-change
// setup (the live fixture retains its workspace receipt). Publication work and
// the counting boundary are unchanged, yielding 63-4 and 55-3 below.
var publicationLiveBaselineDigestTotals = map[string]int64{
	"changed":   59,
	"no-change": 52,
}

// publicationEstablishedConstructionCounts records the per-family shared
// support constructions of one live publication through publishCandidate at
// the pre-refactor baseline (two full Build calls per publication). TASK-054
// flips these to the reuse counts after wiring the two-phase builder.
type publicationEstablishedConstructionCounts struct {
	evidenceExcerpts int64
	attemptArtifacts int64
	roleReports      int64
	liveSupport      int64
}

func publicationPublishLiveCandidateThroughRealStore(t *testing.T, candidate PreparedLiveCandidate) (PublicationResult, *publicationIssueCountingStore) {
	t.Helper()
	ctx := context.Background()
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(rootPath, "artifacts")
	if err := os.MkdirAll(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: publicationTestTime()}
	store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{reviewID: publicationIssuedReviewID(t)}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	counting := &publicationIssueCountingStore{PublicationStore: store}
	service, err := NewService(counting, schema, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.PublishLiveNext(ctx, root, candidate)
	if err != nil {
		t.Fatalf("live publication failed: %v", err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("live publication authority = %q, want P2", result.Decision().Authority())
	}
	if counting.issueCalls != 1 {
		t.Fatalf("IssueReviewID calls = %d, want 1", counting.issueCalls)
	}
	return result, counting
}

// TestLivePublicationConstructsSharedSupportOnce counts newly constructed
// review-independent support artifacts per live publication. The frozen
// expectations record the pre-refactor baseline and flip to the reuse counts
// with the wired two-phase builder; sequential because the seam counters are
// process-global.
func TestLivePublicationConstructsSharedSupportOnce(t *testing.T) {
	fixtures := []struct {
		name      string
		candidate func(t *testing.T) PreparedLiveCandidate
		want      publicationEstablishedConstructionCounts
	}{
		{name: "changed", candidate: livePublicationChangedFixture, want: publicationLiveBaselineConstructionCounts["changed"]},
		{name: "changed-with-attempts", candidate: livePublicationChangedWithAttemptsFixture, want: publicationLiveBaselineConstructionCounts["changed-with-attempts"]},
		{name: "no-change", candidate: livePublicationNoChange, want: publicationLiveBaselineConstructionCounts["no-change"]},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			scope := beginPublicationCounting(t)
			publicationPublishLiveCandidateThroughRealStore(t, fixture.candidate(t))
			got := publicationEstablishedConstructionCounts{
				evidenceExcerpts: scope.evidenceExcerpts(),
				attemptArtifacts: scope.attemptArtifacts(),
				roleReports:      scope.roleReports(),
				liveSupport:      scope.liveSupport(),
			}
			if got != fixture.want {
				t.Fatalf("construction counts = %+v, want %+v", got, fixture.want)
			}
		})
	}
}

// TestLivePublicationDigestHelperCounts records the publication digest-helper
// total of one live publication. The frozen total is derived from the
// pre-refactor baseline run only and flips with the reuse wiring; sequential
// because the seam counters are process-global.
func TestLivePublicationDigestHelperCounts(t *testing.T) {
	fixtures := []struct {
		name      string
		candidate func(t *testing.T) PreparedLiveCandidate
		want      int64
	}{
		{name: "changed", candidate: livePublicationChangedFixture, want: publicationLiveBaselineDigestTotals["changed"]},
		{name: "no-change", candidate: livePublicationNoChange, want: publicationLiveBaselineDigestTotals["no-change"]},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			scope := beginPublicationCounting(t)
			publicationPublishLiveCandidateThroughRealStore(t, fixture.candidate(t))
			if got := scope.digests(); got != fixture.want {
				t.Fatalf("digest helper calls = %d, want %d", got, fixture.want)
			}
		})
	}
}

type publicationCountingSchemaValidator struct {
	inner publicationTestValidator
	calls int
}

func (validator *publicationCountingSchemaValidator) Validate(ctx context.Context, id ports.AssetID, value []byte) error {
	validator.calls++
	return validator.inner.Validate(ctx, id, value)
}

// TestLivePublicationSchemaValidationRunsPerBinding proves the preflight and
// issued bindings each schema-validate the final and manifest bytes: four
// validations per live publication, before and after the construction reuse.
func TestLivePublicationSchemaValidationRunsPerBinding(t *testing.T) {
	ctx := context.Background()
	candidate := livePublicationNoChange(t)
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(rootPath, "artifacts")
	if err := os.MkdirAll(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: publicationTestTime()}
	store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{reviewID: publicationIssuedReviewID(t)}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	counting := &publicationCountingSchemaValidator{}
	service, err := NewService(store, counting, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.PublishLiveNext(ctx, root, candidate); err != nil {
		t.Fatalf("live publication failed: %v", err)
	}
	if counting.calls != 4 {
		t.Fatalf("schema validations = %d, want 4 (preflight final+manifest, issued final+manifest)", counting.calls)
	}
}

// TestPublishLiveRejectsPreflightFailureBeforeIDIssuance proves preflight
// rejection paths of the live publication leave the review ID unissued. The
// zero-receipt leg keeps the candidate valid while forcing a live support
// construction failure.
func TestPublishLiveRejectsPreflightFailureBeforeIDIssuance(t *testing.T) {
	ctx := context.Background()
	publish := func(t *testing.T, candidate PreparedLiveCandidate, validator SchemaValidator, maxBytes int64) (*publicationIssueCountingStore, error) {
		t.Helper()
		rootPath, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		artifactPath := filepath.Join(rootPath, "artifacts")
		if err := os.MkdirAll(artifactPath, 0o700); err != nil {
			t.Fatal(err)
		}
		root, err := ports.NewAnchoredRoot(artifactPath)
		if err != nil {
			t.Fatal(err)
		}
		schema, err := jsonschema.New(ctx, builtin.NewCatalog())
		if err != nil {
			t.Fatal(err)
		}
		clock := publicationServiceClock{now: publicationTestTime()}
		store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{reviewID: publicationIssuedReviewID(t)}, filesystem.NewSecureWriter())
		if err != nil {
			t.Fatal(err)
		}
		counting := &publicationIssueCountingStore{PublicationStore: store}
		if validator == nil {
			validator = schema
		}
		service, err := NewService(counting, validator, clock, maxBytes)
		if err != nil {
			t.Fatal(err)
		}
		_, err = service.PublishLiveNext(ctx, root, candidate)
		return counting, err
	}

	t.Run("schema failure", func(t *testing.T) {
		counting, err := publish(t, livePublicationNoChange(t), publicationServiceFailingValidator{}, 8<<20)
		if err == nil {
			t.Fatal("live publication accepted a preflight schema failure")
		}
		publicationRequireFailureStage(t, err, "publish.build", "publication bundle build failed")
		publicationRequireDiagnostic(t, err, domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSchemaFailed)
		if counting.issueCalls != 0 {
			t.Fatalf("IssueReviewID calls = %d, want 0", counting.issueCalls)
		}
	})

	t.Run("oversize preflight", func(t *testing.T) {
		counting, err := publish(t, livePublicationNoChange(t), nil, 8)
		if err == nil {
			t.Fatal("live publication accepted an oversize preflight bundle")
		}
		publicationRequireFailureStage(t, err, "publish.preflight", "publication bundle exceeds configured byte limits")
		if counting.issueCalls != 0 {
			t.Fatalf("IssueReviewID calls = %d, want 0", counting.issueCalls)
		}
	})

	t.Run("zero receipt support failure", func(t *testing.T) {
		candidate := livePublicationNoChange(t)
		candidate.candidate.target.live.binary = []evidence.LiveBinaryReceipt{{}}
		if !candidate.Valid() {
			t.Fatal("zero-receipt fixture is invalid")
		}
		counting, err := publish(t, candidate, nil, 8<<20)
		if err == nil {
			t.Fatal("live publication accepted an inconsistent binary receipt")
		}
		if !strings.Contains(publicationErrorChainText(err), "unsupported source image media type") {
			t.Fatalf("zero-receipt error chain = %q, want the zero-receipt media-type rejection", publicationErrorChainText(err))
		}
		// The unwrapped live-support error is classified by the publish.build
		// stage: final-review phase, serialization cause.
		publicationRequireFailureStage(t, err, "publish.build", "publication bundle build failed")
		publicationRequireDiagnostic(t, err, domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSerializationFailed)
		if counting.issueCalls != 0 {
			t.Fatalf("IssueReviewID calls = %d, want 0", counting.issueCalls)
		}
	})
}

func publicationRequireFailureStage(t *testing.T, err error, stage, reason string) {
	t.Helper()
	var failure *domain.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error %v carries no typed failure", err)
	}
	if failure.Stage() != stage || failure.Reason() != reason {
		t.Fatalf("failure stage/reason = %q/%q, want %q/%q", failure.Stage(), failure.Reason(), stage, reason)
	}
}

func publicationRequireDiagnostic(t *testing.T, err error, phase domain.RuntimeDiagnosticPhase, cause domain.RuntimeDiagnosticCause) {
	t.Helper()
	diagnostic, ok := FailureDiagnosticFromError(err)
	if !ok || diagnostic.Phase() != phase || diagnostic.Cause() != cause {
		t.Fatalf("diagnostic = %#v (%t), want phase %q cause %q", diagnostic, ok, phase, cause)
	}
}

// TestLivePublishIssuedBindingFailureAfterIssuance fails only the issued
// (second) binding: the preflight binding passes, the review ID is issued
// exactly once, the failure carries the build classification, and nothing is
// persisted or installed.
func TestLivePublishIssuedBindingFailureAfterIssuance(t *testing.T) {
	ctx := context.Background()
	candidate := livePublicationNoChange(t)
	rootPath, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	artifactPath := filepath.Join(rootPath, "artifacts")
	if err := os.MkdirAll(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	clock := publicationServiceClock{now: publicationTestTime()}
	issued := publicationIssuedReviewID(t)
	store, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{reviewID: issued}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	counting := &publicationIssueCountingStore{PublicationStore: store}
	validator := &publicationServiceFailAfterPreflightValidator{}
	service, err := NewService(counting, validator, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.PublishLiveNext(ctx, root, candidate)
	if err == nil {
		t.Fatal("live publication succeeded although the issued binding was rejected")
	}
	if validator.calls != 3 {
		t.Fatalf("schema validations = %d, want 3 (preflight final+manifest, issued final rejected)", validator.calls)
	}
	if counting.issueCalls != 1 {
		t.Fatalf("IssueReviewID calls = %d, want exactly 1", counting.issueCalls)
	}
	publicationRequireFailureStage(t, err, "publish.build", "publication bundle build failed")
	publicationRequireDiagnostic(t, err, domain.DiagnosticPhasePublicationFinalReview, domain.DiagnosticCausePublicationSchemaFailed)
	bundle, err := candidate.Build(ctx, &publicationTestValidator{}, issued, publicationTestTime(), 1)
	if err != nil {
		t.Fatal(err)
	}
	run, err := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}
	candidatePath, err := ports.ValidatedCandidatePath(run)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{bundle.Final().Identity().Path().String(), candidatePath.String(), bundle.Manifest().Path().String()} {
		if _, statErr := os.Stat(filepath.Join(artifactPath, relative)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("issued-binding failure left %q on disk (stat error %v)", relative, statErr)
		}
	}
}

// TestIntegrationLivePublishResumeRebindsPersistedCandidateIdentity
// interrupts a live publication after candidate persistence, then republishes
// the same candidate with an advanced clock and a different ID generator: the
// resumed publication reuses the persisted creation time and review ID, never
// reissues, and commits byte-identical final bytes.
func TestIntegrationLivePublishResumeRebindsPersistedCandidateIdentity(t *testing.T) {
	ctx := context.Background()
	fixtureRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sourceRoot := filepath.Join(fixtureRoot, "source")
	if err := os.Mkdir(sourceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, data := range map[string][]byte{"source.go": []byte("observed\n"), "diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0}} {
		if err := os.WriteFile(filepath.Join(sourceRoot, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sourceAnchored, err := ports.NewAnchoredRoot(sourceRoot)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	source, err := opener.OpenLiveSource(ctx, sourceAnchored, selector)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(ctx, builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	input, _ := livePublicationChangedInput(t, source, schema)
	candidate, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}

	artifactPath := filepath.Join(fixtureRoot, "artifacts")
	if err := os.MkdirAll(artifactPath, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := ports.NewAnchoredRoot(artifactPath)
	if err != nil {
		t.Fatal(err)
	}
	firstReviewID := publicationIssuedReviewID(t)
	firstTime := publicationTestTime()
	clock := publicationServiceClock{now: firstTime}
	firstStore, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{reviewID: firstReviewID}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	resumeStore := &publicationResumeInterruptStore{PublicationStore: firstStore}
	firstService, err := NewService(resumeStore, schema, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstService.PublishLiveNext(ctx, root, candidate); err == nil {
		t.Fatal("interrupted live publication succeeded")
	}
	if resumeStore.issueCalls != 1 {
		t.Fatalf("first attempt IssueReviewID calls = %d, want 1", resumeStore.issueCalls)
	}
	firstBundle, err := candidate.Build(ctx, schema, firstReviewID, firstTime, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondTime := firstTime.Add(time.Hour)
	secondBundle, err := candidate.Build(ctx, schema, firstReviewID, secondTime, 1)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(firstBundle.Final().Bytes(), secondBundle.Final().Bytes()) {
		t.Fatal("fixture final bytes do not depend on the creation time")
	}
	run, err := ports.NewPublicationRun(root, candidate.SessionID(), candidate.RunID())
	if err != nil {
		t.Fatal(err)
	}
	candidatePath, err := ports.ValidatedCandidatePath(run)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := os.ReadFile(filepath.Join(artifactPath, candidatePath.String()))
	if err != nil {
		t.Fatalf("persisted candidate: %v", err)
	}
	if !bytes.Equal(persisted, firstBundle.Final().Bytes()) {
		t.Fatal("persisted candidate bytes differ from the first-attempt final")
	}

	changed := candidate
	changedSource := *candidate.candidate.target.live
	changedSource.provenance.SourceTerminalReceipt = "source-terminal:v1:sha256:" + strings.Repeat("c", 64)
	changed.candidate.target.live = &changedSource
	if !changed.Valid() || changed.ValidatedCandidateSHA256() == candidate.ValidatedCandidateSHA256() {
		t.Fatal("changed candidate fixture is invalid or shares the candidate identity")
	}
	// An unjournaled persisted candidate is rebound through the resumed
	// equality guard rather than the journaled binding check.
	if _, err := firstService.PublishLiveNext(ctx, root, changed); err == nil ||
		!strings.Contains(publicationErrorChainText(err), "persisted candidate differs from composition inputs") {
		t.Fatalf("resume accepted a changed candidate: %v", err)
	}

	clock.now = secondTime
	nextReviewID, err := domain.ParseReviewID("019f596a-d177-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	secondStore, err := filesystem.NewPublicationStore(schema, clock, compositeTestIDs{reviewID: nextReviewID}, filesystem.NewSecureWriter())
	if err != nil {
		t.Fatal(err)
	}
	secondCounting := &publicationIssueCountingStore{PublicationStore: secondStore}
	secondService, err := NewService(secondCounting, schema, clock, 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	result, err := secondService.PublishLiveNext(ctx, root, candidate)
	if err != nil {
		t.Fatalf("resumed live publication failed: %v", err)
	}
	if result.Decision().Authority() != domain.PublicationAuthorityP2 {
		t.Fatalf("resumed authority = %q, want P2", result.Decision().Authority())
	}
	if secondCounting.issueCalls != 0 {
		t.Fatalf("resume reissued the review ID: %d additional calls", secondCounting.issueCalls)
	}
	final, ok := result.Final()
	if !ok || final.ReviewID() != firstReviewID || final.Path() != firstBundle.Final().Identity().Path() {
		t.Fatalf("resumed final identity = %#v, want the persisted first-attempt identity", final)
	}
	if final.SHA256() != firstBundle.Final().Identity().SHA256() {
		t.Fatal("resumed final digest differs from the first-attempt final")
	}
	installed, err := os.ReadFile(filepath.Join(artifactPath, final.Path().String()))
	if err != nil {
		t.Fatalf("installed final: %v", err)
	}
	if !bytes.Equal(installed, firstBundle.Final().Bytes()) || bytes.Equal(installed, secondBundle.Final().Bytes()) {
		t.Fatal("resumed final bytes did not reuse the persisted creation time")
	}
}

type publicationResumeInterruptStore struct {
	*filesystem.PublicationStore
	issueCalls     int
	persistedCheck bool
}

func (store *publicationResumeInterruptStore) IssueReviewID(ctx context.Context, request ports.IssueReviewIDRequest) (ports.IssuedReviewID, error) {
	store.issueCalls++
	return store.PublicationStore.IssueReviewID(ctx, request)
}

func (store *publicationResumeInterruptStore) PersistValidatedCandidate(ctx context.Context, request ports.PersistValidatedCandidateRequest) (ports.PersistValidatedCandidateResult, error) {
	result, err := store.PublicationStore.PersistValidatedCandidate(ctx, request)
	if err == nil && !store.persistedCheck {
		store.persistedCheck = true
		return ports.PersistValidatedCandidateResult{}, errors.New("interrupted after candidate installation")
	}
	return result, err
}

func publicationRequireBundleEqual(t *testing.T, got, want PublicationBundle) {
	t.Helper()
	if !got.Final().Equal(want.Final()) {
		t.Fatal("final members differ")
	}
	if !got.Manifest().Equal(want.Manifest()) {
		t.Fatal("manifest members differ")
	}
	if !got.LineageEdge().Equal(want.LineageEdge()) {
		t.Fatal("lineage edge members differ")
	}
	if got.Epoch().Value() != want.Epoch().Value() || !got.Epoch().Record().Equal(want.Epoch().Record()) {
		t.Fatal("epoch members differ")
	}
	if !got.StagedFinal().Equal(want.StagedFinal()) {
		t.Fatal("staged members differ")
	}
	if got.Journal().Path() != want.Journal().Path() || !bytes.Equal(got.Journal().Bytes(), want.Journal().Bytes()) {
		t.Fatal("journal members differ")
	}
	if got.Status().Path() != want.Status().Path() || !bytes.Equal(got.Status().Bytes(), want.Status().Bytes()) {
		t.Fatal("status members differ")
	}
	gotSupport, wantSupport := got.SupportArtifacts(), want.SupportArtifacts()
	if len(gotSupport) != len(wantSupport) {
		t.Fatalf("support artifact count = %d, want %d", len(gotSupport), len(wantSupport))
	}
	for index := range wantSupport {
		if !gotSupport[index].Equal(wantSupport[index]) {
			t.Fatalf("support artifact %d (%s) differs from %s", index, gotSupport[index].Path(), wantSupport[index].Path())
		}
	}
}

// TestLiveTwoPhaseBundleEqualsBuildWithIssuedID is the differential oracle:
// the first binding equals Build with the dummy ID, and the second binding,
// which reuses the retained support shares, equals Build with the distinct
// issued ID member by member in the same support order.
func TestLiveTwoPhaseBundleEqualsBuildWithIssuedID(t *testing.T) {
	ctx := context.Background()
	dummy, err := domain.ParseReviewID(publicationPreflightDummyID)
	if err != nil {
		t.Fatal(err)
	}
	issued := publicationIssuedReviewID(t)
	fixtures := []struct {
		name      string
		candidate func(t *testing.T) PreparedLiveCandidate
	}{
		{"changed", livePublicationChangedFixture},
		{"changed-with-attempts", livePublicationChangedWithAttemptsFixture},
		{"no-change", livePublicationNoChange},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			candidate := fixture.candidate(t)
			builder, err := newLivePublicationBuilder(candidate)
			if err != nil {
				t.Fatal(err)
			}
			preflight, err := builder.bind(ctx, &publicationTestValidator{}, dummy, publicationTestTime(), 7)
			if err != nil {
				t.Fatalf("first binding: %v", err)
			}
			wantPreflight, err := candidate.Build(ctx, &publicationTestValidator{}, dummy, publicationTestTime(), 7)
			if err != nil {
				t.Fatal(err)
			}
			publicationRequireBundleEqual(t, preflight, wantPreflight)
			bound, err := builder.bind(ctx, &publicationTestValidator{}, issued, publicationTestTime(), 7)
			if err != nil {
				t.Fatalf("second binding: %v", err)
			}
			want, err := candidate.Build(ctx, &publicationTestValidator{}, issued, publicationTestTime(), 7)
			if err != nil {
				t.Fatal(err)
			}
			publicationRequireBundleEqual(t, bound, want)
			if bound.Final().Identity().ReviewID() != issued || preflight.Final().Identity().ReviewID() != dummy {
				t.Fatal("bindings did not bind their own review IDs")
			}
		})
	}
}

// publicationAttemptSupportPaths returns the attempt capture and status
// artifact paths present in bundle, in support order.
func publicationAttemptSupportPaths(bundle PublicationBundle, prefix string) []string {
	var paths []string
	for _, artifact := range bundle.SupportArtifacts() {
		if strings.HasPrefix(artifact.Path().String(), prefix+"attempts/") {
			paths = append(paths, artifact.Path().String())
		}
	}
	return paths
}

// TestLiveBuilderBoundMembersCarryIssuedIDNotDummy proves, for live fixtures
// with and without bound attempt artifacts, that the reused second binding
// rebinds every review-ID-dependent member to the issued ID, retains the
// attempt artifacts in support order, and no member still carries the
// preflight dummy ID. The Build legs pin the same bindings on the historical
// builder.
func TestLiveBuilderBoundMembersCarryIssuedIDNotDummy(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dummy, err := domain.ParseReviewID(publicationPreflightDummyID)
	if err != nil {
		t.Fatal(err)
	}
	issued := publicationIssuedReviewID(t)
	other, err := domain.ParseReviewID("019f596a-d175-7321-b920-c2d312c82cc2")
	if err != nil {
		t.Fatal(err)
	}
	fixtures := []struct {
		name         string
		candidate    func(t *testing.T) PreparedLiveCandidate
		wantAttempts int
	}{
		{"changed", livePublicationChangedFixture, 0},
		{"changed-with-attempts", livePublicationChangedWithAttemptsFixture, 6},
	}
	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			t.Parallel()
			candidate := fixture.candidate(t)
			prefix := candidate.SessionID().String() + "/" + candidate.RunID().String() + "/"
			requireIssuedBindings := func(t *testing.T, bundle PublicationBundle, reference PublicationBundle, label string) {
				t.Helper()
				if bundle.Final().Identity().ReviewID() != issued || bundle.LineageEdge().Path().String() != "store/lineage-edges/e_"+issued.String()+".json" {
					t.Fatalf("%s: final or lineage identity does not bind the issued review ID", label)
				}
				var normalized []byte
				var boundIndex, referenceIndex ports.ImmutablePublicationArtifact
				for _, artifact := range bundle.SupportArtifacts() {
					switch artifact.Path().String() {
					case prefix + "excerpts/F001.json":
						normalized = artifact.Bytes()
					case prefix + "support/index.json":
						boundIndex = artifact
					}
				}
				for _, artifact := range reference.SupportArtifacts() {
					if artifact.Path().String() == prefix+"support/index.json" {
						referenceIndex = artifact
					}
				}
				if normalized == nil {
					t.Fatalf("%s: bundle lacks the normalized finding", label)
				}
				var finding finalFindingWire
				if err := json.Unmarshal(normalized, &finding); err != nil {
					t.Fatal(err)
				}
				if len(finding.Evidence) == 0 || finding.Evidence[0].Source.ReviewID != issued.String() {
					t.Fatalf("%s: normalized evidence source review ID = %q, want issued", label, finding.Evidence[0].Source.ReviewID)
				}
				if !boundIndex.Valid() || !referenceIndex.Valid() || boundIndex.SHA256() == referenceIndex.SHA256() {
					t.Fatalf("%s: support index digests did not bind the issued review ID", label)
				}
				attempts := publicationAttemptSupportPaths(bundle, prefix)
				if len(attempts) != fixture.wantAttempts {
					t.Fatalf("%s: attempt support artifacts = %v, want %d", label, attempts, fixture.wantAttempts)
				}
				var index runSupportIndexWire
				if err := json.Unmarshal(boundIndex.Bytes(), &index); err != nil {
					t.Fatal(err)
				}
				indexed := map[string]bool{}
				for _, identity := range index.Artifacts {
					indexed[identity.Path] = true
				}
				for _, path := range attempts {
					if !indexed[path] {
						t.Fatalf("%s: support index omitted attempt artifact %q", label, path)
					}
				}
				var journal publicationJournalWire
				if err := json.Unmarshal(bundle.Journal().Bytes(), &journal); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(journal.ExpectedFinal.Path, issued.String()) || !strings.Contains(journal.ExpectedStaged.Path, issued.String()) {
					t.Fatalf("%s: journal expected identities do not bind the issued review ID", label)
				}
			}

			t.Run("builder", func(t *testing.T) {
				builder, err := newLivePublicationBuilder(candidate)
				if err != nil {
					t.Fatal(err)
				}
				preflight, err := builder.bind(ctx, &publicationTestValidator{}, dummy, publicationTestTime(), 1)
				if err != nil {
					t.Fatal(err)
				}
				bound, err := builder.bind(ctx, &publicationTestValidator{}, issued, publicationTestTime(), 1)
				if err != nil {
					t.Fatal(err)
				}
				members := [][]byte{
					bound.Final().Bytes(), bound.Manifest().Bytes(), bound.LineageEdge().Bytes(),
					bound.Epoch().Record().Bytes(), bound.Journal().Bytes(), bound.Status().Bytes(),
				}
				for _, artifact := range bound.SupportArtifacts() {
					members = append(members, artifact.Bytes())
				}
				for index, data := range members {
					if bytes.Contains(data, []byte(publicationPreflightDummyID)) {
						t.Fatalf("bound member %d carries the preflight dummy review ID", index)
					}
				}
				requireIssuedBindings(t, bound, preflight, "builder")
				if !reflect.DeepEqual(publicationAttemptSupportPaths(bound, prefix), publicationAttemptSupportPaths(preflight, prefix)) {
					t.Fatal("reused attempt artifacts changed position or identity between bindings")
				}
			})

			t.Run("build", func(t *testing.T) {
				bundle, err := candidate.Build(ctx, &publicationTestValidator{}, issued, publicationTestTime(), 1)
				if err != nil {
					t.Fatal(err)
				}
				reference, err := candidate.Build(ctx, &publicationTestValidator{}, other, publicationTestTime(), 1)
				if err != nil {
					t.Fatal(err)
				}
				requireIssuedBindings(t, bundle, reference, "build")
			})
		})
	}
}

func publicationRequireSameFailure(t *testing.T, got, want error) {
	t.Helper()
	if (got == nil) != (want == nil) {
		t.Fatalf("binding error = %v, Build error = %v", got, want)
	}
	if got == nil {
		return
	}
	if got.Error() != want.Error() {
		t.Fatalf("binding error text %q differs from Build error text %q", got.Error(), want.Error())
	}
	if publicationErrorChainText(got) != publicationErrorChainText(want) {
		t.Fatalf("binding error chain %q differs from Build chain %q", publicationErrorChainText(got), publicationErrorChainText(want))
	}
	gotDiagnostic, gotOK := FailureDiagnosticFromError(got)
	wantDiagnostic, wantOK := FailureDiagnosticFromError(want)
	if gotOK != wantOK || gotDiagnostic != wantDiagnostic {
		t.Fatalf("binding diagnostic %#v (%t) differs from Build diagnostic %#v (%t)", gotDiagnostic, gotOK, wantDiagnostic, wantOK)
	}
}

// TestLiveFirstBindingProloguePrecedenceMatchesBuild proves the first live
// binding runs the complete Build prologue before any member: each invalid
// prologue input, combined with the constructible zero-receipt support
// failure, selects the same error text and classification as Build.
func TestLiveFirstBindingProloguePrecedenceMatchesBuild(t *testing.T) {
	t.Parallel()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	validator := &publicationTestValidator{}
	type binding struct {
		ctx       context.Context
		validator SchemaValidator
		reviewID  domain.ReviewID
		createdAt time.Time
		epoch     uint64
	}
	nominal := binding{ctx: context.Background(), validator: validator, reviewID: publicationIssuedReviewID(t), createdAt: publicationTestTime(), epoch: 1}
	legs := []struct {
		name   string
		mutate func(binding) binding
	}{
		{"invalid review ID", func(b binding) binding { b.reviewID = domain.ReviewID{}; return b }},
		{"zero time", func(b binding) binding { b.createdAt = time.Time{}; return b }},
		{"zero epoch", func(b binding) binding { b.epoch = 0; return b }},
		{"cancelled context", func(b binding) binding { b.ctx = cancelled; return b }},
		{"nil validator", func(b binding) binding { b.validator = nil; return b }},
		{"nil context before invalid review ID", func(b binding) binding { b.ctx = nil; b.reviewID = domain.ReviewID{}; return b }},
		{"support failure alone", func(b binding) binding { return b }},
	}
	for _, leg := range legs {
		leg := leg
		t.Run(leg.name, func(t *testing.T) {
			t.Parallel()
			candidate := livePublicationNoChange(t)
			candidate.candidate.target.live.binary = []evidence.LiveBinaryReceipt{{}}
			if !candidate.Valid() {
				t.Fatal("zero-receipt fixture is invalid")
			}
			input := leg.mutate(nominal)
			_, wantErr := candidate.Build(input.ctx, input.validator, input.reviewID, input.createdAt, input.epoch)
			if wantErr == nil {
				t.Fatal("Build accepted the defective binding")
			}
			builder, err := newLivePublicationBuilder(candidate)
			if err != nil {
				t.Fatal(err)
			}
			_, gotErr := builder.bind(input.ctx, input.validator, input.reviewID, input.createdAt, input.epoch)
			publicationRequireSameFailure(t, gotErr, wantErr)
			if leg.name == "support failure alone" && !strings.Contains(publicationErrorChainText(gotErr), "unsupported source image media type") {
				t.Fatalf("support failure chain = %q, want the zero-receipt media-type rejection", publicationErrorChainText(gotErr))
			}
		})
	}

	t.Run("invalid candidate", func(t *testing.T) {
		t.Parallel()
		candidate := livePublicationNoChange(t)
		candidate.candidate.capturedArchive = []byte("retired capture")
		if candidate.Valid() {
			t.Fatal("captured archive did not invalidate the live candidate")
		}
		_, wantErr := candidate.Build(context.Background(), validator, publicationIssuedReviewID(t), publicationTestTime(), 1)
		_, gotErr := newLivePublicationBuilder(candidate)
		publicationRequireSameFailure(t, gotErr, wantErr)
	})
}

type publicationSchemaRejectingValidator struct {
	rejectFinal    bool
	rejectManifest bool
}

func (validator publicationSchemaRejectingValidator) Validate(_ context.Context, id ports.AssetID, _ []byte) error {
	if validator.rejectFinal && strings.Contains(id.String(), "review-artifact") {
		return errors.New("schema rejected final review")
	}
	if validator.rejectManifest && strings.Contains(id.String(), "run-manifest") {
		return errors.New("schema rejected run manifest")
	}
	return nil
}

// TestLiveBindingMemberPrecedenceMatchesBuild proves the constructible dual
// member failure selects the same error on both paths: with both schema
// rejections armed, the final-review rejection wins before manifest
// validation; single rejections classify as their own member.
func TestLiveBindingMemberPrecedenceMatchesBuild(t *testing.T) {
	t.Parallel()
	legs := []struct {
		name      string
		validator publicationSchemaRejectingValidator
		phase     domain.RuntimeDiagnosticPhase
		text      string
	}{
		{"final rejected", publicationSchemaRejectingValidator{rejectFinal: true}, domain.DiagnosticPhasePublicationFinalReview, "schema rejected final review"},
		{"manifest rejected", publicationSchemaRejectingValidator{rejectManifest: true}, domain.DiagnosticPhasePublicationManifest, "schema rejected run manifest"},
		{"both rejected selects final", publicationSchemaRejectingValidator{rejectFinal: true, rejectManifest: true}, domain.DiagnosticPhasePublicationFinalReview, "schema rejected final review"},
	}
	for _, leg := range legs {
		leg := leg
		t.Run(leg.name, func(t *testing.T) {
			t.Parallel()
			candidate := livePublicationNoChange(t)
			_, wantErr := candidate.Build(context.Background(), leg.validator, publicationIssuedReviewID(t), publicationTestTime(), 1)
			builder, err := newLivePublicationBuilder(candidate)
			if err != nil {
				t.Fatal(err)
			}
			_, gotErr := builder.bind(context.Background(), leg.validator, publicationIssuedReviewID(t), publicationTestTime(), 1)
			publicationRequireSameFailure(t, gotErr, wantErr)
			diagnostic, ok := FailureDiagnosticFromError(gotErr)
			if !ok || diagnostic.Phase() != leg.phase || diagnostic.Cause() != domain.DiagnosticCausePublicationSchemaFailed {
				t.Fatalf("diagnostic = %#v (%t), want phase %q schema failure", diagnostic, ok, leg.phase)
			}
			chain := publicationErrorChainText(gotErr)
			if !strings.Contains(chain, leg.text) {
				t.Fatalf("error chain = %q, want %q", chain, leg.text)
			}
			if leg.name == "both rejected selects final" && strings.Contains(chain, "schema rejected run manifest") {
				t.Fatal("dual rejection reported the manifest before the final review")
			}
		})
	}
}

// livePublicationChangedWithAttemptsFixture binds attempt artifacts the way
// production does (LiveCandidateInput.AttemptArtifacts, one input per captured
// artifact): a stdout stream and the initial candidate for each role's primary
// attempt. The attempt identities come from the same coordinator result.
func livePublicationChangedWithAttemptsFixture(t *testing.T) PreparedLiveCandidate {
	t.Helper()
	rootPath := t.TempDir()
	for path, data := range map[string][]byte{
		"source.go":   []byte("observed\n"),
		"diagram.png": {137, 80, 78, 71, 13, 10, 26, 10, 0},
	} {
		if err := os.WriteFile(filepath.Join(rootPath, path), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := ports.NewAnchoredRoot(rootPath)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := gittarget.NewLiveSourceAdapter(gittarget.ExecRunner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	selector, err := ports.NewLiveSourceSelector(domain.LiveSourceWorkspace, "")
	if err != nil {
		t.Fatal(err)
	}
	source, err := opener.OpenLiveSource(context.Background(), root, selector)
	if err != nil {
		t.Fatal(err)
	}
	schema, err := jsonschema.New(context.Background(), builtin.NewCatalog())
	if err != nil {
		t.Fatal(err)
	}
	input, _ := livePublicationChangedInput(t, source, schema)
	base, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	var attempts []AttemptArtifactInput
	for _, role := range base.candidate.roles {
		for _, attempt := range role.attempts {
			for _, invocation := range attempt.invocations {
				stdout, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactStdout, []byte("provider stdout for "+string(role.role)+"\n"), false)
				if err != nil {
					t.Fatal(err)
				}
				attempts = append(attempts, AttemptArtifactInput{AttemptID: attempt.id, InvocationSequence: invocation.sequence, Artifact: stdout})
				if invocation.purpose == domain.InvocationInitial {
					initial, err := ports.NewCapturedAttemptArtifact(ports.AttemptArtifactInitialCandidate, []byte(`{"candidate":"`+string(role.role)+`"}`), false)
					if err != nil {
						t.Fatal(err)
					}
					attempts = append(attempts, AttemptArtifactInput{AttemptID: attempt.id, InvocationSequence: invocation.sequence, Artifact: initial})
				}
			}
		}
	}
	if len(attempts) == 0 {
		t.Fatal("live fixture produced no attempt invocations to bind")
	}
	input.AttemptArtifacts = attempts
	candidate, err := PrepareLiveCandidate(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	return candidate
}
