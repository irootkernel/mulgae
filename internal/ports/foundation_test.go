package ports

import (
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"path"
	"strings"
	"testing"
)

func TestAnchoredRootAndSafeRelativePathValidation(t *testing.T) {
	t.Parallel()

	rootTests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "root", value: "/", valid: true},
		{name: "canonical absolute", value: "/tmp/mulgae", valid: true},
		{name: "empty", value: ""},
		{name: "relative", value: "tmp/mulgae"},
		{name: "NUL", value: "/tmp/mulgae\x00blocked"},
		{name: "backslash", value: "/tmp\\mulgae"},
		{name: "dot", value: "/tmp/."},
		{name: "dotdot", value: "/tmp/../mulgae"},
		{name: "trailing separator", value: "/tmp/mulgae/"},
	}
	for _, test := range rootTests {
		t.Run("root/"+test.name, func(t *testing.T) {
			root, err := NewAnchoredRoot(test.value)
			if test.valid {
				if err != nil {
					t.Fatalf("NewAnchoredRoot(%q): %v", test.value, err)
				}
				if root.String() != test.value || !root.Valid() {
					t.Fatalf("root = %q, valid = %v", root.String(), root.Valid())
				}
				return
			}
			if err == nil {
				t.Fatalf("NewAnchoredRoot(%q) succeeded", test.value)
			}
		})
	}

	pathTests := []struct {
		name  string
		value string
		valid bool
	}{
		{name: "one component", value: "manifest.json", valid: true},
		{name: "nested", value: "runs/current/manifest.json", valid: true},
		{name: "empty", value: ""},
		{name: "absolute", value: "/tmp/mulgae"},
		{name: "NUL", value: "run\x00/manifest"},
		{name: "backslash", value: "run\\manifest"},
		{name: "dot", value: "."},
		{name: "dotdot", value: ".."},
		{name: "nested dot", value: "run/./manifest"},
		{name: "nested dotdot", value: "run/../manifest"},
		{name: "duplicate separator", value: "run//manifest"},
		{name: "trailing separator", value: "run/"},
	}
	for _, test := range pathTests {
		t.Run("path/"+test.name, func(t *testing.T) {
			relative, err := NewSafeRelativePath(test.value)
			if test.valid {
				if err != nil {
					t.Fatalf("NewSafeRelativePath(%q): %v", test.value, err)
				}
				if relative.String() != test.value || !relative.Valid() {
					t.Fatalf("path = %q, valid = %v", relative.String(), relative.Valid())
				}
				return
			}
			if err == nil {
				t.Fatalf("NewSafeRelativePath(%q) succeeded", test.value)
			}
		})
	}
}

func TestSafeRelativePathSeededTraversalProperty(t *testing.T) {
	t.Parallel()

	random := rand.New(rand.NewSource(0x4b415250415448))
	for iteration := 0; iteration < 512; iteration++ {
		value := seededSafeRelativePath(random)
		relative, err := NewSafeRelativePath(value)
		if err != nil {
			t.Fatalf("iteration %d rejected generated canonical path %q: %v", iteration, value, err)
		}
		if !relative.Valid() || relative.String() != value || path.Clean(relative.String()) != relative.String() {
			t.Fatalf("iteration %d did not preserve canonical path %q", iteration, value)
		}
		for _, hostile := range []string{
			"/" + value,
			"../" + value,
			value + "/../escape",
			value + "//tail",
			value + "/./tail",
			value + "\\tail",
			value + "\x00tail",
		} {
			if accepted, err := NewSafeRelativePath(hostile); err == nil {
				t.Fatalf("iteration %d accepted hostile path %q as %q", iteration, hostile, accepted.String())
			}
		}
	}
}

func seededSafeRelativePath(random *rand.Rand) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
	components := make([]string, 1+random.Intn(8))
	for componentIndex := range components {
		component := make([]byte, 1+random.Intn(24))
		for index := range component {
			component[index] = alphabet[random.Intn(len(alphabet))]
		}
		components[componentIndex] = string(component)
	}
	return strings.Join(components, "/")
}

func TestContractValuesAndWriteRequestsDefensivelyOwnMutableInputs(t *testing.T) {
	t.Parallel()

	assetID, err := ParseAssetID("builtin:schemas/command-result@1")
	if err != nil {
		t.Fatal(err)
	}
	assetSource, err := NewSafeRelativePath("schemas/mulgae-command-result.v2.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := NewAssetMetadata(
		assetID,
		AssetKindSchema,
		assetSource,
		"application/schema+json",
		"sha256:"+strings.Repeat("a", sha256.Size*2),
		42,
	)
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ID() != assetID || metadata.Kind() != AssetKindSchema ||
		metadata.Source() != assetSource || metadata.MediaType() != "application/schema+json" ||
		metadata.ByteLength() != 42 {
		t.Fatalf("metadata = %#v", metadata)
	}

	root, err := NewAnchoredRoot("/tmp/mulgae")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := NewSafeRelativePath("raw/provider.stdout")
	if err != nil {
		t.Fatal(err)
	}
	sourceIDs := []string{"provider:stdout"}
	aborted := false
	request, err := NewSecureWriteRequest(
		root,
		destination,
		"provider_stdout",
		strings.NewReader("untrusted bytes"),
		1024,
		sourceIDs,
		func(error) { aborted = true },
	)
	if err != nil {
		t.Fatal(err)
	}
	if request.Source() == nil || request.MaxBytes() != 1024 {
		t.Fatalf("source = %v, max bytes = %d", request.Source(), request.MaxBytes())
	}
	request.Abort()(nil)
	if !aborted {
		t.Fatal("request abort was not retained")
	}
	sourceIDs[0] = "mutated"
	if got := request.SourceIDs()[0]; got != "provider:stdout" {
		t.Fatalf("request source after input mutation = %q", got)
	}
	returnedSources := request.SourceIDs()
	returnedSources[0] = "mutated"
	if got := request.SourceIDs()[0]; got != "provider:stdout" {
		t.Fatalf("request source after return mutation = %q", got)
	}

	dropSources := []string{"provider:stdout"}
	drop, err := NewDropMetadata("provider_stdout", "credential_scanner", 1, dropSources)
	if err != nil {
		t.Fatal(err)
	}
	dropSources[0] = "mutated"
	if got := drop.SourceIDs()[0]; got != "provider:stdout" {
		t.Fatalf("drop source after input mutation = %q", got)
	}
	returnedDropSources := drop.SourceIDs()
	returnedDropSources[0] = "mutated"
	if got := drop.SourceIDs()[0]; got != "provider:stdout" {
		t.Fatalf("drop source after return mutation = %q", got)
	}
}
func TestAssetMetadataRequiresCanonicalSourceAndMediaType(t *testing.T) {
	t.Parallel()

	id, err := ParseAssetID("builtin:help/security@1")
	if err != nil {
		t.Fatal(err)
	}
	source, err := NewSafeRelativePath("help/security.md")
	if err != nil {
		t.Fatal(err)
	}
	hash := "sha256:" + strings.Repeat("a", sha256.Size*2)
	tests := []struct {
		name      string
		source    SafeRelativePath
		mediaType string
	}{
		{name: "zero source", mediaType: "text/markdown"},
		{name: "invalid media type", source: source, mediaType: "text/markdown; charset=utf-8"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewAssetMetadata(id, AssetKindHelp, test.source, test.mediaType, hash, 1); err == nil {
				t.Fatal("NewAssetMetadata succeeded")
			}
		})
	}
}
func TestSecureWriteRequestRequiresStreamCapSourceIDsAndAbort(t *testing.T) {
	t.Parallel()

	root, err := NewAnchoredRoot("/tmp/mulgae")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := NewSafeRelativePath("raw/provider.stdout")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		source    *strings.Reader
		maxBytes  int64
		sourceIDs []string
		abort     func(error)
	}{
		{name: "nil source", maxBytes: 1, sourceIDs: []string{"provider:stdout"}, abort: func(error) {}},
		{name: "zero cap", source: strings.NewReader("input"), sourceIDs: []string{"provider:stdout"}, abort: func(error) {}},
		{name: "missing source IDs", source: strings.NewReader("input"), maxBytes: 1, abort: func(error) {}},
		{name: "nil abort", source: strings.NewReader("input"), maxBytes: 1, sourceIDs: []string{"provider:stdout"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewSecureWriteRequest(
				root,
				destination,
				"provider_stdout",
				test.source,
				test.maxBytes,
				test.sourceIDs,
				test.abort,
			); err == nil {
				t.Fatal("NewSecureWriteRequest succeeded")
			}
		})
	}
}
func TestSecureWriteReceiptBindsExactRootAndLineage(t *testing.T) {
	t.Parallel()

	root, err := NewAnchoredRoot("/tmp/mulgae")
	if err != nil {
		t.Fatal(err)
	}
	destination, err := NewSafeRelativePath("raw/provider.stdout")
	if err != nil {
		t.Fatal(err)
	}
	sourceIDs := []string{"provider:stdout"}
	receipt, err := NewSecureWriteReceipt(
		root,
		destination,
		"sha256:"+strings.Repeat("a", sha256.Size*2),
		42,
		"provider_stdout",
		sourceIDs,
	)
	if err != nil {
		t.Fatalf("NewSecureWriteReceipt() error = %v", err)
	}
	if receipt.Root() != root || receipt.Destination() != destination ||
		receipt.SHA256() != "sha256:"+strings.Repeat("a", sha256.Size*2) ||
		receipt.ByteLength() != 42 || receipt.Channel() != "provider_stdout" {
		t.Fatalf("receipt = %#v", receipt)
	}
	sourceIDs[0] = "mutated"
	if got := receipt.SourceIDs(); len(got) != 1 || got[0] != "provider:stdout" {
		t.Fatalf("receipt source IDs after input mutation = %q", got)
	}
	if _, err := NewSecureWriteReceipt(
		AnchoredRoot{},
		destination,
		"sha256:"+strings.Repeat("a", sha256.Size*2),
		42,
		"provider_stdout",
		[]string{"provider:stdout"},
	); err == nil {
		t.Fatal("NewSecureWriteReceipt() accepted an invalid root")
	}
}
func TestAuditTokensRejectWhitespaceAndControls(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"", " ", " token", "token ", "token\tvalue", "token\u001bvalue", string([]byte{0xff})} {
		if err := validateAuditToken(value, 256); err == nil {
			t.Errorf("validateAuditToken(%q) succeeded", value)
		}
		if err := validateSourceIDs([]string{value}); err == nil {
			t.Errorf("validateSourceIDs(%q) succeeded", value)
		}
	}
	for _, value := range []string{
		"provider_stdout",
		"git-project-config:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:policy/project.yaml",
	} {
		if err := validateAuditToken(value, 256); err != nil {
			t.Errorf("validateAuditToken(%q) error = %v", value, err)
		}
	}
}

func TestCapturedGitTargetDefensivelyOwnsCapturedBytes(t *testing.T) {
	t.Parallel()

	objectID, err := ParseGitObjectID(strings.Repeat("a", 40))
	if err != nil {
		t.Fatal(err)
	}
	indexID, err := ParseGitObjectID(strings.Repeat("b", 40))
	if err != nil {
		t.Fatal(err)
	}
	bytes := []byte("canonical target")
	target, err := NewCapturedGitTarget("repository:example", objectID, objectID, objectID, &indexID, bytes)
	if err != nil {
		t.Fatal(err)
	}
	bytes[0] = 'X'
	if got := string(target.Bytes()); got != "canonical target" {
		t.Fatalf("target bytes after input mutation = %q", got)
	}
	returned := target.Bytes()
	returned[0] = 'Y'
	if got := string(target.Bytes()); got != "canonical target" {
		t.Fatalf("target bytes after return mutation = %q", got)
	}

	sum := sha256.Sum256([]byte("canonical target"))
	wantHash := "sha256:" + hex.EncodeToString(sum[:])
	if target.SHA256() != wantHash {
		t.Fatalf("target SHA256 = %q, want %q", target.SHA256(), wantHash)
	}
	gotIndex, ok := target.IndexTreeID()
	if !ok || gotIndex != indexID {
		t.Fatalf("index tree = %q, present = %v", gotIndex.String(), ok)
	}
}
