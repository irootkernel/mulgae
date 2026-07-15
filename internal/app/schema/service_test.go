package schema

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"testing"

	"github.com/irootkernel/kkachi-agent-review/internal/domain"
	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

type catalogAsset struct {
	metadata ports.AssetMetadata
	contents []byte
}

type fakeCatalog struct {
	assets  map[string]catalogAsset
	listed  []ports.AssetMetadata
	listErr error
	readErr error
	reads   int
}

func (catalog *fakeCatalog) List(context.Context) ([]ports.AssetMetadata, error) {
	if catalog.listErr != nil {
		return nil, catalog.listErr
	}
	return append([]ports.AssetMetadata(nil), catalog.listed...), nil
}

func (catalog *fakeCatalog) Read(_ context.Context, id ports.AssetID) (ports.AssetMetadata, []byte, error) {
	catalog.reads++
	if catalog.readErr != nil {
		return ports.AssetMetadata{}, nil, catalog.readErr
	}
	asset, found := catalog.assets[id.String()]
	if !found {
		return ports.AssetMetadata{}, nil, errors.New("asset not found")
	}
	return asset.metadata, asset.contents, nil
}

type fakeWriter struct {
	write func(context.Context, ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error)
}

func (writer fakeWriter) EnsurePrivateDir(ports.AnchoredRoot, ports.SafeRelativePath) error {
	return errors.New("EnsurePrivateDir must not be called for a single secure write")
}

func (writer fakeWriter) Write(ctx context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
	return writer.write(ctx, request)
}

func TestListFiltersOrderedSchemaMetadata(t *testing.T) {
	first := testAsset(t, "https://kar.local/schemas/a.schema.json", ports.AssetKindSchema, "schemas/a.schema.json", []byte(`{"a":1}`))
	second := testAsset(t, "https://kar.local/schemas/b.schema.json", ports.AssetKindSchema, "schemas/b.schema.json", []byte(`{"b":2}`))
	help := testAsset(t, "help:quickstart", ports.AssetKindHelp, "docs/help.md", []byte("help\n"))
	catalog := &fakeCatalog{
		assets: map[string]catalogAsset{
			first.metadata.ID().String():  first,
			second.metadata.ID().String(): second,
			help.metadata.ID().String():   help,
		},
		listed: []ports.AssetMetadata{help.metadata, first.metadata, second.metadata},
	}

	listed, err := NewService(catalog, nil).List(context.Background())
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if got, want := schemaIDs(listed), []string{first.metadata.ID().String(), second.metadata.ID().String()}; !reflect.DeepEqual(got, want) {
		t.Fatalf("List() IDs = %q, want %q", got, want)
	}
}
func TestListRejectsOutOfOrderCatalog(t *testing.T) {
	first := testAsset(t, "https://kar.local/schemas/a.schema.json", ports.AssetKindSchema, "schemas/a.schema.json", []byte(`{"a":1}`))
	second := testAsset(t, "https://kar.local/schemas/b.schema.json", ports.AssetKindSchema, "schemas/b.schema.json", []byte(`{"b":2}`))
	catalog := &fakeCatalog{
		assets: map[string]catalogAsset{
			first.metadata.ID().String():  first,
			second.metadata.ID().String(): second,
		},
		listed: []ports.AssetMetadata{second.metadata, first.metadata},
	}
	_, err := NewService(catalog, nil).List(context.Background())
	assertFailureClass(t, err, domain.FailureArtifact)
}

func TestShowReturnsExactDefensiveBytes(t *testing.T) {
	asset := testAsset(t, "https://kar.local/schemas/example.schema.json", ports.AssetKindSchema, "schemas/example.schema.json", []byte("{\r\n  \"exact\": true\r\n}\n"))
	catalog := &fakeCatalog{
		assets: map[string]catalogAsset{asset.metadata.ID().String(): asset},
		listed: []ports.AssetMetadata{asset.metadata},
	}
	service := NewService(catalog, nil)

	metadata, shown, err := service.Show(context.Background(), asset.metadata.ID())
	if err != nil {
		t.Fatalf("Show() error = %v", err)
	}
	if metadata != asset.metadata {
		t.Fatalf("Show() metadata = %#v, want %#v", metadata, asset.metadata)
	}
	if !bytes.Equal(shown, asset.contents) {
		t.Fatalf("Show() bytes = %q, want exact %q", shown, asset.contents)
	}
	shown[0] = '!'
	if !bytes.Equal(catalog.assets[asset.metadata.ID().String()].contents, asset.contents) {
		t.Fatal("Show() exposed catalog-owned bytes")
	}

	_, shownAgain, err := service.Show(context.Background(), asset.metadata.ID())
	if err != nil {
		t.Fatalf("second Show() error = %v", err)
	}
	if !bytes.Equal(shownAgain, asset.contents) {
		t.Fatalf("second Show() bytes = %q, want exact %q", shownAgain, asset.contents)
	}
}

func TestShowRejectsUnknownAndNonSchemaIDs(t *testing.T) {
	schemaAsset := testAsset(t, "https://kar.local/schemas/example.schema.json", ports.AssetKindSchema, "schemas/example.schema.json", []byte(`{"schema":true}`))
	helpAsset := testAsset(t, "help:quickstart", ports.AssetKindHelp, "docs/help.md", []byte("help\n"))
	catalog := &fakeCatalog{
		assets: map[string]catalogAsset{
			schemaAsset.metadata.ID().String(): schemaAsset,
			helpAsset.metadata.ID().String():   helpAsset,
		},
		listed: []ports.AssetMetadata{helpAsset.metadata, schemaAsset.metadata},
	}
	service := NewService(catalog, nil)
	unknown := mustAssetID(t, "https://kar.local/schemas/missing.schema.json")

	for name, id := range map[string]ports.AssetID{
		"unknown":    unknown,
		"non-schema": helpAsset.metadata.ID(),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := service.Show(context.Background(), id)
			assertFailureClass(t, err, domain.FailureConfiguration)
		})
	}
	if catalog.reads != 0 {
		t.Fatalf("Show() read catalog %d times for rejected IDs, want 0", catalog.reads)
	}
}

func TestExportStreamsExactRequestAndBindsReceipt(t *testing.T) {
	asset := testAsset(t, "https://kar.local/schemas/export.schema.json", ports.AssetKindSchema, "schemas/export.schema.json", []byte("{\n  \"preserve\": [1, 2, 3]\n}\n"))
	catalog := &fakeCatalog{
		assets: map[string]catalogAsset{asset.metadata.ID().String(): asset},
		listed: []ports.AssetMetadata{asset.metadata},
	}
	root := mustRoot(t, "/private/schema-export")
	destination := mustRelativePath(t, "schemas/export.schema.json")
	writer := fakeWriter{write: func(_ context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
		if request.Root() != root || request.Destination() != destination {
			t.Fatalf("request target = %q/%q, want %q/%q", request.Root(), request.Destination(), root, destination)
		}
		if request.Channel() != exportChannel {
			t.Fatalf("request channel = %q, want %q", request.Channel(), exportChannel)
		}
		if request.MaxBytes() != asset.metadata.ByteLength() {
			t.Fatalf("request cap = %d, want %d", request.MaxBytes(), asset.metadata.ByteLength())
		}
		if got, want := request.SourceIDs(), []string{asset.metadata.ID().String()}; !reflect.DeepEqual(got, want) {
			t.Fatalf("request source IDs = %q, want %q", got, want)
		}
		if request.Abort() == nil {
			t.Fatal("request abort callback is nil")
		}
		streamed, err := io.ReadAll(request.Source())
		if err != nil {
			t.Fatalf("read request source: %v", err)
		}
		if !bytes.Equal(streamed, asset.contents) {
			t.Fatalf("request source bytes = %q, want exact %q", streamed, asset.contents)
		}
		receipt, err := ports.NewSecureWriteReceipt(root, destination, asset.metadata.SHA256(), asset.metadata.ByteLength(), exportChannel, []string{asset.metadata.ID().String()})
		if err != nil {
			t.Fatalf("NewSecureWriteReceipt() error = %v", err)
		}
		return receipt, nil, nil
	}}

	receipt, err := NewService(catalog, writer).Export(context.Background(), asset.metadata.ID(), root, destination)
	if err != nil {
		t.Fatalf("Export() error = %v", err)
	}
	if receipt.Destination() != destination || receipt.SHA256() != asset.metadata.SHA256() || receipt.ByteLength() != asset.metadata.ByteLength() {
		t.Fatalf("Export() receipt = %#v, does not bind destination/hash/size", receipt)
	}
}

func TestExportFailsWithoutWriter(t *testing.T) {
	asset := testAsset(t, "https://kar.local/schemas/example.schema.json", ports.AssetKindSchema, "schemas/example.schema.json", []byte(`{"schema":true}`))
	catalog := &fakeCatalog{
		assets: map[string]catalogAsset{asset.metadata.ID().String(): asset},
		listed: []ports.AssetMetadata{asset.metadata},
	}

	_, err := NewService(catalog, nil).Export(context.Background(), asset.metadata.ID(), mustRoot(t, "/private/schema-export"), mustRelativePath(t, "schemas/example.schema.json"))
	assertFailureClass(t, err, domain.FailureArtifact)
}

func TestExportRejectsBlockedWrite(t *testing.T) {
	asset := testAsset(t, "https://kar.local/schemas/example.schema.json", ports.AssetKindSchema, "schemas/example.schema.json", []byte(`{"schema":true}`))
	catalog := &fakeCatalog{
		assets: map[string]catalogAsset{asset.metadata.ID().String(): asset},
		listed: []ports.AssetMetadata{asset.metadata},
	}
	root := mustRoot(t, "/private/schema-export")
	destination := mustRelativePath(t, "schemas/example.schema.json")
	writer := fakeWriter{write: func(_ context.Context, request ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
		blocked := errors.New("credential detected")
		request.Abort()(blocked)
		drop, err := ports.NewDropMetadata(request.Channel(), "credential_assignment", 1, request.SourceIDs())
		if err != nil {
			t.Fatalf("NewDropMetadata() error = %v", err)
		}
		receipt, err := ports.NewSecureWriteReceipt(root, destination, asset.metadata.SHA256(), asset.metadata.ByteLength(), exportChannel, []string{asset.metadata.ID().String()})
		if err != nil {
			t.Fatalf("NewSecureWriteReceipt() error = %v", err)
		}
		return receipt, &drop, blocked
	}}

	receipt, err := NewService(catalog, writer).Export(context.Background(), asset.metadata.ID(), root, destination)
	if !zeroReceipt(receipt) {
		t.Fatalf("Export() returned blocked receipt %#v", receipt)
	}
	assertFailureClass(t, err, domain.FailureSecurityPolicy)
}

func TestExportRejectsReceiptThatDoesNotBindAuthoritativeBytes(t *testing.T) {
	asset := testAsset(t, "https://kar.local/schemas/example.schema.json", ports.AssetKindSchema, "schemas/example.schema.json", []byte(`{"schema":true}`))
	root := mustRoot(t, "/private/schema-export")
	destination := mustRelativePath(t, "schemas/example.schema.json")
	otherDestination := mustRelativePath(t, "schemas/other.schema.json")
	wrongSHA256 := "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0}, sha256.Size))

	cases := []struct {
		name    string
		receipt func(*testing.T) ports.SecureWriteReceipt
	}{
		{
			name: "destination",
			receipt: func(t *testing.T) ports.SecureWriteReceipt {
				return mustReceipt(t, otherDestination, asset.metadata.SHA256(), asset.metadata.ByteLength())
			},
		},
		{
			name: "sha256",
			receipt: func(t *testing.T) ports.SecureWriteReceipt {
				return mustReceipt(t, destination, wrongSHA256, asset.metadata.ByteLength())
			},
		},
		{
			name: "byte length",
			receipt: func(t *testing.T) ports.SecureWriteReceipt {
				return mustReceipt(t, destination, asset.metadata.SHA256(), asset.metadata.ByteLength()+1)
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			catalog := &fakeCatalog{
				assets: map[string]catalogAsset{asset.metadata.ID().String(): asset},
				listed: []ports.AssetMetadata{asset.metadata},
			}
			writer := fakeWriter{write: func(context.Context, ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
				return test.receipt(t), nil, nil
			}}

			receipt, err := NewService(catalog, writer).Export(context.Background(), asset.metadata.ID(), root, destination)
			if !zeroReceipt(receipt) {
				t.Fatalf("Export() receipt = %#v, want zero receipt", receipt)
			}
			assertFailureClass(t, err, domain.FailureArtifact)
		})
	}
}
func TestCatalogAndWriterErrorsRemainTyped(t *testing.T) {
	asset := testAsset(t, "https://kar.local/schemas/example.schema.json", ports.AssetKindSchema, "schemas/example.schema.json", []byte(`{"schema":true}`))
	root := mustRoot(t, "/private/schema-export")
	destination := mustRelativePath(t, "schemas/example.schema.json")

	t.Run("catalog", func(t *testing.T) {
		catalog := &fakeCatalog{listErr: errors.New("catalog checksum mismatch")}

		_, err := NewService(catalog, nil).List(context.Background())
		assertFailureClass(t, err, domain.FailureArtifact)
	})

	t.Run("writer", func(t *testing.T) {
		catalog := &fakeCatalog{
			assets: map[string]catalogAsset{asset.metadata.ID().String(): asset},
			listed: []ports.AssetMetadata{asset.metadata},
		}
		writer := fakeWriter{write: func(context.Context, ports.SecureWriteRequest) (ports.SecureWriteReceipt, *ports.DropMetadata, error) {
			return ports.SecureWriteReceipt{}, nil, errors.New("destination already exists")
		}}

		_, err := NewService(catalog, writer).Export(context.Background(), asset.metadata.ID(), root, destination)
		assertFailureClass(t, err, domain.FailureArtifact)
	})
}

func testAsset(t *testing.T, id string, kind ports.AssetKind, source string, contents []byte) catalogAsset {
	t.Helper()
	assetID := mustAssetID(t, id)
	assetSource := mustRelativePath(t, source)
	sum := sha256.Sum256(contents)
	metadata, err := ports.NewAssetMetadata(assetID, kind, assetSource, "application/schema+json", "sha256:"+hex.EncodeToString(sum[:]), int64(len(contents)))
	if err != nil {
		t.Fatalf("NewAssetMetadata() error = %v", err)
	}
	return catalogAsset{metadata: metadata, contents: append([]byte(nil), contents...)}
}

func mustAssetID(t *testing.T, value string) ports.AssetID {
	t.Helper()
	id, err := ports.ParseAssetID(value)
	if err != nil {
		t.Fatalf("ParseAssetID(%q) error = %v", value, err)
	}
	return id
}

func mustRoot(t *testing.T, value string) ports.AnchoredRoot {
	t.Helper()
	root, err := ports.NewAnchoredRoot(value)
	if err != nil {
		t.Fatalf("NewAnchoredRoot(%q) error = %v", value, err)
	}
	return root
}

func mustRelativePath(t *testing.T, value string) ports.SafeRelativePath {
	t.Helper()
	path, err := ports.NewSafeRelativePath(value)
	if err != nil {
		t.Fatalf("NewSafeRelativePath(%q) error = %v", value, err)
	}
	return path
}

func mustReceipt(t *testing.T, destination ports.SafeRelativePath, sha256 string, size int64) ports.SecureWriteReceipt {
	t.Helper()
	receipt, err := ports.NewSecureWriteReceipt(mustRoot(t, "/private/schema-export"), destination, sha256, size, exportChannel, []string{"https://kar.local/schemas/example.schema.json"})
	if err != nil {
		t.Fatalf("NewSecureWriteReceipt() error = %v", err)
	}
	return receipt
}

func zeroReceipt(receipt ports.SecureWriteReceipt) bool {
	return !receipt.Destination().Valid() &&
		receipt.SHA256() == "" &&
		receipt.ByteLength() == 0 &&
		receipt.Channel() == "" &&
		len(receipt.SourceIDs()) == 0
}
func schemaIDs(metadata []ports.AssetMetadata) []string {
	ids := make([]string, len(metadata))
	for index, asset := range metadata {
		ids[index] = asset.ID().String()
	}
	return ids
}

func assertFailureClass(t *testing.T, err error, want domain.FailureClass) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil")
	}
	var failure *domain.Failure
	if !errors.As(err, &failure) {
		t.Fatalf("error %v is not a typed domain failure", err)
	}
	if failure.Class() != want {
		t.Fatalf("failure class = %q, want %q", failure.Class(), want)
	}
}
