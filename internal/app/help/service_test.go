package help

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/irootkernel/mulgae/internal/ports"
)

func TestTopicsReturnsExactlyRequiredHelpMetadataInAssetIDOrder(t *testing.T) {
	catalog := completeCatalog(t, nil)
	nonHelp := testAssetMetadata(t, "schema:ignored", ports.AssetKindSchema, []byte("{}"))
	catalog.listing = append(catalog.listing, nonHelp)
	service := newTestService(t, catalog)

	topics, err := service.Topics(context.Background())
	if err != nil {
		t.Fatalf("Topics: %v", err)
	}

	wantIDs := []string{
		"help:artifacts",
		"help:ci",
		"help:config",
		"help:exit-codes",
		"help:prompts",
		"help:providers",
		"help:quickstart",
		"help:role-paths",
		"help:security",
		"help:validation",
		"help:workflows",
	}
	if len(topics) != len(wantIDs) {
		t.Fatalf("Topics count = %d, want %d", len(topics), len(wantIDs))
	}
	for index, topic := range topics {
		if topic.Kind() != ports.AssetKindHelp {
			t.Errorf("Topics[%d].Kind() = %q, want help", index, topic.Kind())
		}
		if got := topic.ID().String(); got != wantIDs[index] {
			t.Errorf("Topics[%d].ID() = %q, want %q", index, got, wantIDs[index])
		}
	}
}

func TestRenderPreservesExactAuthoritativeBytes(t *testing.T) {
	quickstart := []byte("quickstart ends with a newline\n")
	config := []byte("config deliberately has no trailing newline")
	catalog := completeCatalog(t, map[string][]byte{
		TopicQuickstart: quickstart,
		TopicConfig:     config,
	})
	service := newTestService(t, catalog)

	for _, test := range []struct {
		topic string
		want  []byte
	}{
		{topic: TopicQuickstart, want: quickstart},
		{topic: TopicConfig, want: config},
	} {
		t.Run(test.topic, func(t *testing.T) {
			got, err := service.Render(context.Background(), test.topic)
			if err != nil {
				t.Fatalf("Render(%q): %v", test.topic, err)
			}
			if !bytes.Equal(got, test.want) {
				t.Errorf("Render(%q) = %q, want exact bytes %q", test.topic, got, test.want)
			}
			if gotTrailingNewline, wantTrailingNewline := hasTrailingNewline(got), hasTrailingNewline(test.want); gotTrailingNewline != wantTrailingNewline {
				t.Errorf("Render(%q) trailing newline = %t, want %t", test.topic, gotTrailingNewline, wantTrailingNewline)
			}
		})
	}
}

func TestRenderReturnsDefensiveBytes(t *testing.T) {
	contents := []byte("authoritative help bytes\n")
	catalog := completeCatalog(t, map[string][]byte{TopicQuickstart: contents})
	catalog.returnSharedContents = true
	service := newTestService(t, catalog)

	first, err := service.Render(context.Background(), TopicQuickstart)
	if err != nil {
		t.Fatalf("first Render: %v", err)
	}
	first[0] = 'X'
	if got := catalog.assets["help:quickstart"].contents[0]; got != 'a' {
		t.Fatalf("mutating Render result modified catalog bytes: got %q, want %q", got, 'a')
	}

	second, err := service.Render(context.Background(), TopicQuickstart)
	if err != nil {
		t.Fatalf("second Render: %v", err)
	}
	if !bytes.Equal(second, contents) {
		t.Errorf("second Render = %q, want unmodified exact bytes %q", second, contents)
	}
	if len(second) > 0 && &first[0] == &second[0] {
		t.Error("Render returned aliased byte slices")
	}
}
func TestRenderRejectsSameLengthContentSubstitution(t *testing.T) {
	catalog := completeCatalog(t, map[string][]byte{TopicQuickstart: []byte("alpha")})
	asset := catalog.assets["help:quickstart"]
	asset.contents = []byte("bravo")
	catalog.assets["help:quickstart"] = asset
	service := newTestService(t, catalog)

	if _, err := service.Render(context.Background(), TopicQuickstart); !errors.Is(err, ErrCatalogInconsistent) {
		t.Fatalf("Render() error = %v, want ErrCatalogInconsistent", err)
	}
}

func TestTopicsRejectsOutOfOrderCatalog(t *testing.T) {
	catalog := completeCatalog(t, nil)
	catalog.listing[0], catalog.listing[1] = catalog.listing[1], catalog.listing[0]
	service := newTestService(t, catalog)
	if _, err := service.Topics(context.Background()); !errors.Is(err, ErrCatalogInconsistent) {
		t.Fatalf("Topics() error = %v, want ErrCatalogInconsistent", err)
	}
}

func TestTopicsAndRenderRejectIncompleteHelpCatalog(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testCatalog, *testing.T)
		want   error
	}{
		{
			name: "missing",
			mutate: func(catalog *testCatalog, _ *testing.T) {
				catalog.listing = catalog.listing[1:]
			},
			want: ErrCatalogIncomplete,
		},
		{
			name: "duplicate",
			mutate: func(catalog *testCatalog, _ *testing.T) {
				catalog.listing = append(catalog.listing, catalog.listing[0])
			},
			want: ErrCatalogInconsistent,
		},
		{
			name: "unexpected",
			mutate: func(catalog *testCatalog, t *testing.T) {
				catalog.listing = append(catalog.listing, testAssetMetadata(t, "help:unexpected", ports.AssetKindHelp, []byte("unexpected")))
			},
			want: ErrCatalogIncomplete,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := completeCatalog(t, nil)
			test.mutate(catalog, t)
			sort.Slice(catalog.listing, func(left, right int) bool {
				return catalog.listing[left].ID().String() < catalog.listing[right].ID().String()
			})
			service := newTestService(t, catalog)

			if _, err := service.Topics(context.Background()); !errors.Is(err, test.want) {
				t.Fatalf("Topics error = %v, want %v", err, test.want)
			}
			if _, err := service.Render(context.Background(), TopicQuickstart); !errors.Is(err, test.want) {
				t.Fatalf("Render error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRenderRejectsEmptyUnsafeAndUnknownTopicsWithoutFallback(t *testing.T) {
	for _, test := range []struct {
		name  string
		topic string
		want  error
	}{
		{name: "empty", topic: "", want: ErrEmptyTopic},
		{name: "path traversal", topic: "../quickstart", want: ErrUnsafeTopic},
		{name: "embedded asset identifier", topic: "help:quickstart", want: ErrUnsafeTopic},
		{name: "unknown", topic: "unknown", want: ErrUnknownTopic},
	} {
		t.Run(test.name, func(t *testing.T) {
			catalog := completeCatalog(t, nil)
			service := newTestService(t, catalog)

			got, err := service.Render(context.Background(), test.topic)
			if got != nil {
				t.Errorf("Render(%q) bytes = %q, want nil", test.topic, got)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("Render(%q) error = %v, want %v", test.topic, err, test.want)
			}
			if catalog.listCalls != 0 || catalog.readCalls != 0 {
				t.Fatalf("Render(%q) accessed catalog (list=%d read=%d), indicating fallback lookup", test.topic, catalog.listCalls, catalog.readCalls)
			}
		})
	}
}

func TestTopicsAndRenderRespectCancelledContext(t *testing.T) {
	catalog := completeCatalog(t, nil)
	service := newTestService(t, catalog)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := service.Topics(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Topics cancelled error = %v, want context.Canceled", err)
	}
	if _, err := service.Render(ctx, TopicQuickstart); !errors.Is(err, context.Canceled) {
		t.Fatalf("Render cancelled error = %v, want context.Canceled", err)
	}
	if catalog.listCalls != 0 || catalog.readCalls != 0 {
		t.Fatalf("cancelled calls accessed catalog (list=%d read=%d)", catalog.listCalls, catalog.readCalls)
	}
}

func TestNewServiceRejectsNilCatalog(t *testing.T) {
	service, err := NewService(nil)
	if service != nil {
		t.Fatal("NewService(nil) returned a service")
	}
	if !errors.Is(err, ErrNilCatalog) {
		t.Fatalf("NewService(nil) error = %v, want ErrNilCatalog", err)
	}
}

type testCatalog struct {
	listing              []ports.AssetMetadata
	assets               map[string]testCatalogAsset
	returnSharedContents bool
	listCalls            int
	readCalls            int
}

type testCatalogAsset struct {
	metadata ports.AssetMetadata
	contents []byte
}

func (catalog *testCatalog) List(ctx context.Context) ([]ports.AssetMetadata, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	catalog.listCalls++
	return append([]ports.AssetMetadata(nil), catalog.listing...), nil
}

func (catalog *testCatalog) Read(ctx context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	if err := ctx.Err(); err != nil {
		return ports.AssetMetadata{}, nil, err
	}
	catalog.readCalls++
	asset, ok := catalog.assets[id.String()]
	if !ok {
		return ports.AssetMetadata{}, nil, fmt.Errorf("unknown asset %q", id.String())
	}
	if catalog.returnSharedContents {
		return asset.metadata, asset.contents, nil
	}
	return asset.metadata, append([]byte(nil), asset.contents...), nil
}

func completeCatalog(t *testing.T, contentsByTopic map[string][]byte) *testCatalog {
	t.Helper()

	catalog := &testCatalog{assets: make(map[string]testCatalogAsset)}
	for _, topic := range requiredHelpTopics() {
		contents, present := contentsByTopic[topic]
		if !present {
			contents = []byte("help for " + topic + "\n")
		}
		contents = append([]byte(nil), contents...)
		id := "help:" + topic
		metadata := testAssetMetadata(t, id, ports.AssetKindHelp, contents)
		catalog.listing = append(catalog.listing, metadata)
		catalog.assets[id] = testCatalogAsset{metadata: metadata, contents: contents}
	}
	sort.Slice(catalog.listing, func(left, right int) bool {
		return catalog.listing[left].ID().String() < catalog.listing[right].ID().String()
	})
	return catalog
}

func testAssetMetadata(t *testing.T, rawID string, kind ports.AssetKind, contents []byte) ports.AssetMetadata {
	t.Helper()

	id, err := ports.ParseAssetID(rawID)
	if err != nil {
		t.Fatalf("ParseAssetID(%q): %v", rawID, err)
	}
	source, err := ports.NewSafeRelativePath("test-assets/" + rawID + ".md")
	if err != nil {
		t.Fatalf("NewSafeRelativePath(%q): %v", rawID, err)
	}
	digest := sha256.Sum256(contents)
	metadata, err := ports.NewAssetMetadata(
		id,
		kind,
		source,
		"text/markdown",
		"sha256:"+hex.EncodeToString(digest[:]),
		int64(len(contents)),
	)
	if err != nil {
		t.Fatalf("NewAssetMetadata(%q): %v", rawID, err)
	}
	return metadata
}

func newTestService(t *testing.T, catalog ports.ContractCatalog) *Service {
	t.Helper()
	service, err := NewService(catalog)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return service
}

func hasTrailingNewline(contents []byte) bool {
	return len(contents) > 0 && contents[len(contents)-1] == '\n'
}
