package query

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestReadContractExamplesBindPublicationAndCursor(t *testing.T) {
	data, err := os.ReadFile("../../builtin/assets/examples/publication-receipt.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := DecodeInspectionReceipt(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		bytes.Replace(data, []byte(`"lineage_sha256": "",`), nil, 1),
		append([]byte(`{"epoch":1,`), data[1:]...),
		bytes.Replace(data, []byte(`"epoch": 1`), []byte(`"epoch": 1.0`), 1),
	} {
		if _, err := DecodeInspectionReceipt(bad); err == nil {
			t.Fatal("noncanonical publication receipt accepted")
		}
	}
	identity, err := receipt.Identity()
	if err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile("../../builtin/assets/examples/finding-cursor.v1.valid.json")
	if err != nil {
		t.Fatal(err)
	}
	var cursor findingCursor
	if err := decodeStrictDTO(data, &cursor); err != nil {
		t.Fatal(err)
	}
	if cursor.Scope.PublicationReceipt != identity.String() {
		t.Fatal("independent receipt fixture diverged")
	}
	canonical, err := json.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(canonical) + "." + strings.TrimPrefix(readContractDigest(FindingCursorVersion, canonical), "sha256:")
	if got, err := DecodeFindingCursor(encoded, cursor.Scope); err != nil || got != cursor.Offset {
		t.Fatalf("cursor fixture: %d/%v", got, err)
	}
	receipt.Epoch = 0
	if _, err := receipt.Identity(); err == nil {
		t.Fatal("missing observed epoch accepted")
	}
	cursor.Offset = 101
	canonical, err = json.Marshal(cursor)
	if err != nil {
		t.Fatal(err)
	}
	encoded = base64.RawURLEncoding.EncodeToString(canonical) + "." + strings.TrimPrefix(readContractDigest(FindingCursorVersion, canonical), "sha256:")
	if _, err := DecodeFindingCursor(encoded, cursor.Scope); err == nil {
		t.Fatal("invalid fixture boundary accepted")
	}
}
