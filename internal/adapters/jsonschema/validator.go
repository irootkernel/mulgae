package jsonschema

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dlclark/regexp2"
	jschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/irootkernel/kkachi-agent-review/internal/ports"
)

const (
	draft2020URI           = "https://json-schema.org/draft/2020-12/schema"
	g0FileCatalogExampleID = "example:g0-file-catalog.v1.valid.json"
	authoritativePairCount = 25
	regexpMatchTimeout     = 100 * time.Millisecond
	maxJSONDepth           = 256
)

type ecmaRegexp regexp2.Regexp

type regexpExecutionPanic struct{}

func (regexp *ecmaRegexp) MatchString(value string) bool {
	matched, err := (*regexp2.Regexp)(regexp).MatchString(value)
	if err != nil {
		panic(regexpExecutionPanic{})
	}
	return matched
}

func (regexp *ecmaRegexp) String() string {
	return (*regexp2.Regexp)(regexp).String()
}

func compileECMARegexp(expression string) (jschema.Regexp, error) {
	compiled, err := regexp2.Compile(expression, regexp2.ECMAScript)
	if err != nil {
		return nil, err
	}
	compiled.MatchTimeout = regexpMatchTimeout
	return (*ecmaRegexp)(compiled), nil
}

type denyURLLoader struct{}

func (denyURLLoader) Load(string) (any, error) {
	return nil, errors.New("external schema loading is disabled")
}

func newSchemaCompiler() *jschema.Compiler {
	compiler := jschema.NewCompiler()
	compiler.DefaultDraft(jschema.Draft2020)
	compiler.UseLoader(denyURLLoader{})
	compiler.UseRegexpEngine(compileECMARegexp)
	compiler.AssertFormat()
	return compiler
}

// Stage identifies the adapter boundary at which processing failed.
type Stage string

const (
	StageCatalog    Stage = "catalog"
	StageCompile    Stage = "compile"
	StageContext    Stage = "context"
	StageDecode     Stage = "decode"
	StageSchema     Stage = "schema"
	StageRuntime    Stage = "runtime"
	StageValidation Stage = "validation"
)

// Diagnostic is a redacted, typed failure produced at the JSON Schema adapter
// boundary. Path is a JSON Pointer-like location. It deliberately retains no
// implementation cause, so validation input cannot escape through error chains.
type Diagnostic struct {
	Stage    Stage
	Path     string
	SchemaID ports.AssetID
}

// DocumentViolation reports whether this diagnostic was caused by provider
// document bytes rather than validator configuration or runtime state.
func (diagnostic *Diagnostic) DocumentViolation() bool {
	return diagnostic != nil && (diagnostic.Stage == StageDecode || diagnostic.Stage == StageValidation)
}

// Error implements error without rendering untrusted input or the underlying
// error text, which may be more detailed than this boundary should expose.
func (diagnostic *Diagnostic) Error() string {
	if diagnostic == nil {
		return "json schema diagnostic"
	}
	if diagnostic.SchemaID.Valid() {
		return fmt.Sprintf("json schema %s failure for %s at %s", diagnostic.Stage, diagnostic.SchemaID.String(), diagnostic.Path)
	}
	return fmt.Sprintf("json schema %s failure at %s", diagnostic.Stage, diagnostic.Path)
}

// Validator is an immutable, compiled set of catalog JSON schemas and copied
// JSON examples. It does not retain caller-provided validation bytes.
type Validator struct {
	schemas  map[string]*jschema.Schema
	examples map[string]catalogExample
	pairs    map[string]string
}

type catalogExample struct {
	metadata ports.AssetMetadata
	raw      []byte
}

// New loads, verifies, and compiles every schema in catalog. Compilation is
// fail-closed: schemas must be draft 2020-12 resources whose JSON $id exactly
// matches the catalog AssetID, references must be local fragments, and the
// compiler's loader always denies external resources.
func New(ctx context.Context, catalog ports.ContractCatalog) (*Validator, error) {
	if err := contextError(ctx); err != nil {
		return nil, diagnostic(StageContext, "catalog", ports.AssetID{}, err)
	}
	if isNilCatalog(catalog) {
		return nil, diagnostic(StageCatalog, "catalog", ports.AssetID{}, errors.New("nil catalog"))
	}

	metadata, err := catalog.List(ctx)
	if err != nil {
		return nil, diagnostic(StageCatalog, "catalog/list", ports.AssetID{}, err)
	}
	if len(metadata) == 0 {
		return nil, diagnostic(StageCatalog, "catalog/list", ports.AssetID{}, errors.New("empty catalog"))
	}

	compiler := newSchemaCompiler()

	validator := &Validator{
		schemas:  make(map[string]*jschema.Schema),
		examples: make(map[string]catalogExample),
		pairs:    make(map[string]string),
	}
	schemas := make([]ports.AssetID, 0)
	seen := make(map[string]struct{}, len(metadata))
	schemaSources := make(map[string]string)
	previousID := ""

	for _, listed := range metadata {
		if err := contextError(ctx); err != nil {
			return nil, diagnostic(StageContext, "catalog/read", listed.ID(), err)
		}
		if err := validateListedMetadata(listed, previousID); err != nil {
			return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), err)
		}
		id := listed.ID().String()
		if _, exists := seen[id]; exists {
			return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), errors.New("duplicate asset ID"))
		}
		seen[id] = struct{}{}
		previousID = id

		readMetadata, raw, err := catalog.Read(ctx, listed.ID())
		if err != nil {
			return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), err)
		}
		if readMetadata != listed {
			return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), errors.New("read metadata differs from listed metadata"))
		}
		raw = cloneBytes(raw)
		if err := verifyAssetBytes(listed, raw); err != nil {
			return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), err)
		}

		switch listed.Kind() {
		case ports.AssetKindSchema:
			doc, err := decodeJSON(raw)
			if err != nil {
				return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), err)
			}
			if err := verifySchemaDocument(listed.ID(), doc); err != nil {
				return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), err)
			}
			if err := compiler.AddResource(listed.ID().String(), doc); err != nil {
				return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), err)
			}
			schemas = append(schemas, listed.ID())
			schemaSources[listed.ID().String()] = listed.Source().String()
		case ports.AssetKindExample:
			if listed.MediaType() == "application/json" {
				if _, err := decodeJSON(raw); err != nil {
					return nil, diagnostic(StageCatalog, listed.Source().String(), listed.ID(), err)
				}
				validator.examples[listed.ID().String()] = catalogExample{
					metadata: listed,
					raw:      raw,
				}
			}
		}
	}
	if len(schemas) == 0 {
		return nil, diagnostic(StageCatalog, "catalog/list", ports.AssetID{}, errors.New("catalog has no schemas"))
	}
	pairs, err := buildPairs(validator.examples, schemaSources)
	if err != nil {
		return nil, diagnostic(StageCatalog, "examples/g0-file-catalog.v1.valid.json", ports.AssetID{}, err)
	}
	validator.pairs = pairs

	for _, schemaID := range schemas {
		if err := contextError(ctx); err != nil {
			return nil, diagnostic(StageContext, schemaID.String(), schemaID, err)
		}
		compiled, err := compiler.Compile(schemaID.String())
		if err != nil {
			return nil, diagnostic(StageCompile, schemaID.String(), schemaID, err)
		}
		validator.schemas[schemaID.String()] = compiled
	}
	return validator, nil
}

// Validate strictly decodes raw as exactly one JSON value before applying the
// compiled schema identified by schemaID.
func (validator *Validator) Validate(ctx context.Context, schemaID ports.AssetID, raw []byte) (result error) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		if _, regexpFailure := recovered.(regexpExecutionPanic); regexpFailure {
			result = diagnostic(StageRuntime, "$", schemaID, errors.New("ECMA regular expression execution failed"))
			return
		}
		panic(recovered)
	}()
	if err := contextError(ctx); err != nil {
		return diagnostic(StageContext, "$", schemaID, err)
	}
	if validator == nil {
		return diagnostic(StageSchema, "schema", schemaID, errors.New("nil validator"))
	}
	if !schemaID.Valid() {
		return diagnostic(StageSchema, "schema", schemaID, errors.New("invalid schema ID"))
	}
	schema, exists := validator.schemas[schemaID.String()]
	if !exists {
		return diagnostic(StageSchema, "schema", schemaID, errors.New("unknown schema ID or kind"))
	}
	if len(raw) > MaxInputBytes {
		return diagnostic(StageDecode, "$", schemaID, errors.New("input exceeds maximum size"))
	}

	value, err := decodeJSON(cloneBytes(raw))
	if err != nil {
		return diagnostic(StageDecode, "$", schemaID, err)
	}
	if err := contextError(ctx); err != nil {
		return diagnostic(StageContext, "$", schemaID, err)
	}
	if err := schema.Validate(value); err != nil {
		return diagnostic(StageValidation, validationPath(err), schemaID, err)
	}
	if err := contextError(ctx); err != nil {
		return diagnostic(StageContext, "$", schemaID, err)
	}
	return nil
}

// ValidatePair validates the one catalog example paired with schemaID by the
// authoritative G0 file catalog. Both IDs must name the compiled schema and
// copied JSON example captured when the validator was constructed.
func (validator *Validator) ValidatePair(ctx context.Context, schemaID, exampleID ports.AssetID) error {
	if err := contextError(ctx); err != nil {
		return diagnostic(StageContext, "$", schemaID, err)
	}
	if validator == nil {
		return diagnostic(StageSchema, "schema", schemaID, errors.New("nil validator"))
	}
	if !schemaID.Valid() || validator.schemas[schemaID.String()] == nil {
		return diagnostic(StageSchema, "schema", schemaID, errors.New("unknown schema ID or kind"))
	}
	if !exampleID.Valid() {
		return diagnostic(StageCatalog, "example", schemaID, errors.New("invalid example ID"))
	}
	expectedExampleID, paired := validator.pairs[schemaID.String()]
	if !paired || expectedExampleID != exampleID.String() {
		return diagnostic(StageCatalog, "pair", schemaID, errors.New("example is not paired with schema ID"))
	}
	example, exists := validator.examples[exampleID.String()]
	if !exists || example.metadata.Kind() != ports.AssetKindExample {
		return diagnostic(StageCatalog, "example", schemaID, errors.New("unknown example ID or kind"))
	}
	return validator.Validate(ctx, schemaID, cloneBytes(example.raw))
}

func validateListedMetadata(metadata ports.AssetMetadata, previousID string) error {
	if !metadata.ID().Valid() || !metadata.Kind().Valid() || !metadata.Source().Valid() {
		return errors.New("invalid asset metadata")
	}
	if previousID != "" && metadata.ID().String() <= previousID {
		return errors.New("asset IDs are not strictly ascending")
	}
	if metadata.ByteLength() < 0 {
		return errors.New("asset byte length must not be negative")
	}
	if !strings.HasPrefix(metadata.SHA256(), "sha256:") || len(metadata.SHA256()) != len("sha256:")+sha256.Size*2 {
		return errors.New("invalid asset integrity metadata")
	}
	switch metadata.Kind() {
	case ports.AssetKindSchema:
		if !strings.HasPrefix(metadata.Source().String(), "schemas/") || !strings.HasSuffix(metadata.Source().String(), ".schema.json") {
			return errors.New("schema has a non-schema source")
		}
		if metadata.MediaType() != "application/schema+json" {
			return errors.New("schema has an invalid media type")
		}
	case ports.AssetKindExample:
		if !strings.HasPrefix(metadata.Source().String(), "examples/") {
			return errors.New("example has a non-example source")
		}
		if strings.HasSuffix(metadata.Source().String(), ".json") && metadata.MediaType() != "application/json" {
			return errors.New("JSON example has an invalid media type")
		}
	}
	return nil
}

func verifyAssetBytes(metadata ports.AssetMetadata, raw []byte) error {
	if int64(len(raw)) != metadata.ByteLength() {
		return errors.New("asset byte length does not match metadata")
	}
	sum := sha256.Sum256(raw)
	if metadata.SHA256() != "sha256:"+hex.EncodeToString(sum[:]) {
		return errors.New("asset sha256 does not match metadata")
	}
	return nil
}

func verifySchemaDocument(id ports.AssetID, doc any) error {
	schema, ok := doc.(map[string]any)
	if !ok {
		return errors.New("schema is not a JSON object")
	}
	schemaID, ok := schema["$id"].(string)
	if !ok || schemaID == "" {
		return errors.New("schema has no string $id")
	}
	if schemaID != id.String() {
		return errors.New("schema $id does not match asset ID")
	}
	draft, ok := schema["$schema"].(string)
	if !ok || draft != draft2020URI {
		return errors.New("schema is not draft 2020-12")
	}
	if err := verifySchemaReferences(schema, true); err != nil {
		return err
	}
	if err := verifySupportedFormats(doc); err != nil {
		return err
	}
	return nil
}
func verifySchemaReferences(value any, root bool) error {
	switch value := value.(type) {
	case map[string]any:
		for key, nested := range value {
			if key == "$id" && !root {
				return errors.New("schema has a nested $id")
			}
			if key == "$ref" || key == "$dynamicRef" {
				reference, ok := nested.(string)
				if !ok || !strings.HasPrefix(reference, "#") {
					return errors.New("schema has a non-fragment reference")
				}
			}
			if err := verifySchemaReferences(nested, false); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range value {
			if err := verifySchemaReferences(nested, false); err != nil {
				return err
			}
		}
	}
	return nil
}
func verifySupportedFormats(value any) error {
	switch value := value.(type) {
	case map[string]any:
		for key, nested := range value {
			if key == "format" {
				format, ok := nested.(string)
				if !ok {
					return errors.New("schema format is not a string")
				}
				if !supportedFormat(format) {
					return errors.New("schema uses an unsupported format")
				}
			}
			if err := verifySupportedFormats(nested); err != nil {
				return err
			}
		}
	case []any:
		for _, nested := range value {
			if err := verifySupportedFormats(nested); err != nil {
				return err
			}
		}
	}
	return nil
}
func supportedFormat(format string) bool {
	switch format {
	case "date", "date-time", "duration", "email", "hostname", "ipv4", "ipv6",
		"iri", "iri-reference", "json-pointer", "period", "regex",
		"relative-json-pointer", "semver", "time", "uri", "uri-reference",
		"uri-template", "uuid":
		return true
	default:
		return false
	}
}
func buildPairs(examples map[string]catalogExample, schemaSources map[string]string) (map[string]string, error) {
	if len(schemaSources) != authoritativePairCount {
		return nil, errors.New("catalog does not contain the authoritative schema count")
	}
	if len(examples) != authoritativePairCount {
		return nil, errors.New("catalog does not contain the authoritative JSON example count")
	}

	g0, exists := examples[g0FileCatalogExampleID]
	if !exists {
		return nil, errors.New("catalog has no G0 file catalog example")
	}
	document, err := decodeJSON(g0.raw)
	if err != nil {
		return nil, errors.New("G0 file catalog is not valid JSON")
	}
	root, ok := document.(map[string]any)
	if !ok {
		return nil, errors.New("G0 file catalog is not a JSON object")
	}
	files, ok := root["files"].([]any)
	if !ok {
		return nil, errors.New("G0 file catalog has no files array")
	}

	examplesBySource := make(map[string]string, len(examples))
	for id, example := range examples {
		source := example.metadata.Source().String()
		if _, duplicate := examplesBySource[source]; duplicate {
			return nil, errors.New("multiple JSON examples share one source")
		}
		examplesBySource[source] = id
	}
	schemasBySource := make(map[string]string, len(schemaSources))
	for id, source := range schemaSources {
		if _, duplicate := schemasBySource[source]; duplicate {
			return nil, errors.New("multiple schemas share one source")
		}
		schemasBySource[source] = id
	}

	pairs := make(map[string]string, authoritativePairCount)
	reversePairs := make(map[string]string, authoritativePairCount)
	exampleSources := make(map[string]struct{}, authoritativePairCount)
	schemaRecordSources := make(map[string]struct{}, authoritativePairCount)
	exampleTargets := make(map[string]string, authoritativePairCount)
	reverseExampleTargets := make(map[string]string, authoritativePairCount)

	for _, value := range files {
		file, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("G0 file catalog has a non-object file record")
		}
		source, ok := file["path"].(string)
		if !ok {
			return nil, errors.New("G0 file catalog file record has no path")
		}
		schemaID, schemaOK := file["schema_id"].(string)
		pairSource, pairOK := file["pair"].(string)

		switch {
		case strings.HasPrefix(source, "sot/examples/"):
			if !schemaOK && !pairOK {
				if _, known := examplesBySource[strings.TrimPrefix(source, "sot/")]; known {
					return nil, errors.New("G0 file catalog leaves a JSON example unpaired")
				}
				continue
			}
			if !schemaOK || !pairOK || !strings.HasPrefix(pairSource, "sot/schemas/") {
				return nil, errors.New("G0 example record has an invalid schema pair")
			}
			if _, duplicate := exampleSources[source]; duplicate {
				return nil, errors.New("G0 file catalog duplicates an example source")
			}
			exampleSources[source] = struct{}{}

			expectedSchemaSource, exists := schemaSources[schemaID]
			if !exists {
				return nil, errors.New("G0 file catalog references an unknown schema")
			}
			if pairSource != "sot/"+expectedSchemaSource {
				return nil, errors.New("G0 file catalog pair path does not match schema ID")
			}
			exampleID, exists := examplesBySource[strings.TrimPrefix(source, "sot/")]
			if !exists {
				return nil, errors.New("G0 file catalog references an unknown example")
			}
			if _, duplicate := pairs[schemaID]; duplicate {
				return nil, errors.New("G0 file catalog duplicates a schema pair")
			}
			if _, duplicate := exampleTargets[exampleID]; duplicate {
				return nil, errors.New("G0 file catalog duplicates an example target")
			}
			pairs[schemaID] = exampleID
			exampleTargets[exampleID] = schemaID

		case strings.HasPrefix(source, "sot/schemas/"):
			if !schemaOK && !pairOK {
				if _, known := schemasBySource[strings.TrimPrefix(source, "sot/")]; known {
					return nil, errors.New("G0 file catalog leaves a schema unpaired")
				}
				continue
			}
			if !schemaOK || !pairOK || !strings.HasPrefix(pairSource, "sot/examples/") {
				return nil, errors.New("G0 schema record has an invalid example pair")
			}
			if _, duplicate := schemaRecordSources[source]; duplicate {
				return nil, errors.New("G0 file catalog duplicates a schema source")
			}
			schemaRecordSources[source] = struct{}{}

			expectedSchemaSource, exists := schemaSources[schemaID]
			if !exists || source != "sot/"+expectedSchemaSource {
				return nil, errors.New("G0 schema record does not match schema ID")
			}
			exampleID, exists := examplesBySource[strings.TrimPrefix(pairSource, "sot/")]
			if !exists {
				return nil, errors.New("G0 schema record references an unknown example")
			}
			if _, duplicate := reversePairs[schemaID]; duplicate {
				return nil, errors.New("G0 file catalog duplicates a reverse schema pair")
			}
			if _, duplicate := reverseExampleTargets[exampleID]; duplicate {
				return nil, errors.New("G0 file catalog duplicates a reverse example target")
			}
			reversePairs[schemaID] = exampleID
			reverseExampleTargets[exampleID] = schemaID
		}
	}
	if len(pairs) != authoritativePairCount || len(exampleTargets) != authoritativePairCount {
		return nil, errors.New("G0 file catalog does not exactly pair every schema")
	}
	if len(reversePairs) != authoritativePairCount || len(reverseExampleTargets) != authoritativePairCount {
		return nil, errors.New("G0 file catalog does not exactly reverse-pair every schema")
	}
	if len(exampleSources) != authoritativePairCount || len(schemaRecordSources) != authoritativePairCount {
		return nil, errors.New("G0 file catalog does not contain exactly one record per pair direction")
	}
	for schemaID, exampleID := range pairs {
		if reversePairs[schemaID] != exampleID {
			return nil, errors.New("G0 file catalog pair directions disagree")
		}
	}
	if len(examplesBySource) != len(pairs) {
		return nil, errors.New("G0 file catalog leaves JSON examples unpaired")
	}
	return pairs, nil
}

func decodeJSON(raw []byte) (any, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	if err := validateUnicodeEscapes(raw); err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err == io.EOF {
		return value, nil
	} else if err == nil {
		return nil, errors.New("multiple top-level JSON values")
	}
	return nil, errors.New("invalid data after top-level JSON value")
}

func decodeJSONValue(decoder *json.Decoder, depth int) (any, error) {
	if depth >= maxJSONDepth {
		return nil, errors.New("JSON exceeds maximum nesting depth")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch token := token.(type) {
	case json.Delim:
		switch token {
		case '{':
			return decodeJSONObject(decoder, depth+1)
		case '[':
			return decodeJSONArray(decoder, depth+1)
		default:
			return nil, errors.New("unexpected JSON delimiter")
		}
	case json.Number:
		if !validJSONNumber(token.String()) {
			return nil, errors.New("invalid JSON number")
		}
		return token, nil
	case string, bool, nil:
		return token, nil
	default:
		return nil, errors.New("invalid JSON value")
	}
}

func decodeJSONObject(decoder *json.Decoder, depth int) (map[string]any, error) {
	object := make(map[string]any)
	keys := make(map[string]struct{})
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("JSON object key is not a string")
		}
		if _, duplicate := keys[key]; duplicate {
			return nil, errors.New("JSON object has a duplicate key")
		}
		value, err := decodeJSONValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		keys[key] = struct{}{}
		object[key] = value
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != '}' {
		return nil, errors.New("JSON object is not closed")
	}
	return object, nil
}

func decodeJSONArray(decoder *json.Decoder, depth int) ([]any, error) {
	array := make([]any, 0)
	for decoder.More() {
		value, err := decodeJSONValue(decoder, depth)
		if err != nil {
			return nil, err
		}
		array = append(array, value)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	if delimiter, ok := token.(json.Delim); !ok || delimiter != ']' {
		return nil, errors.New("JSON array is not closed")
	}
	return array, nil
}

func validJSONNumber(value string) bool {
	if value == "" {
		return false
	}
	index := 0
	if value[index] == '-' {
		index++
		if index == len(value) {
			return false
		}
	}
	switch {
	case value[index] == '0':
		index++
	case value[index] >= '1' && value[index] <= '9':
		index++
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
		}
	default:
		return false
	}
	if index < len(value) && value[index] == '.' {
		index++
		start := index
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
		}
		if index == start {
			return false
		}
	}
	if index < len(value) && (value[index] == 'e' || value[index] == 'E') {
		index++
		if index < len(value) && (value[index] == '+' || value[index] == '-') {
			index++
		}
		start := index
		for index < len(value) && value[index] >= '0' && value[index] <= '9' {
			index++
		}
		if index == start {
			return false
		}
	}
	return index == len(value)
}

func validateUnicodeEscapes(raw []byte) error {
	inString := false
	for index := 0; index < len(raw); index++ {
		switch raw[index] {
		case '"':
			if inString {
				inString = false
			} else {
				inString = true
			}
		case '\\':
			if !inString {
				continue
			}
			if index+1 >= len(raw) {
				return errors.New("JSON string has an incomplete escape")
			}
			if raw[index+1] != 'u' {
				index++
				continue
			}
			if index+5 >= len(raw) {
				return errors.New("JSON string has an incomplete Unicode escape")
			}
			codeUnit, valid := decodeHexCodeUnit(raw[index+2 : index+6])
			if !valid {
				return errors.New("JSON string has an invalid Unicode escape")
			}
			switch {
			case codeUnit >= 0xD800 && codeUnit <= 0xDBFF:
				if index+11 >= len(raw) || raw[index+6] != '\\' || raw[index+7] != 'u' {
					return errors.New("JSON string has an unpaired high surrogate")
				}
				lowSurrogate, valid := decodeHexCodeUnit(raw[index+8 : index+12])
				if !valid || lowSurrogate < 0xDC00 || lowSurrogate > 0xDFFF {
					return errors.New("JSON string has an unpaired high surrogate")
				}
				index += 11
			case codeUnit >= 0xDC00 && codeUnit <= 0xDFFF:
				return errors.New("JSON string has an unpaired low surrogate")
			default:
				index += 5
			}
		}
	}
	return nil
}

func decodeHexCodeUnit(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var codeUnit uint16
	for _, digit := range value {
		codeUnit <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			codeUnit |= uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			codeUnit |= uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			codeUnit |= uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return codeUnit, true
}

func validationPath(err error) string {
	var validationError *jschema.ValidationError
	if !errors.As(err, &validationError) {
		return "$"
	}
	for len(validationError.Causes) > 0 {
		validationError = validationError.Causes[0]
	}
	if len(validationError.InstanceLocation) == 0 {
		return "$"
	}
	const maximumPathDepth = 16
	var path strings.Builder
	path.WriteByte('$')
	for index := range validationError.InstanceLocation {
		if index == maximumPathDepth {
			path.WriteString("/...")
			break
		}
		path.WriteString("/<redacted>")
	}
	return path.String()
}

func diagnostic(stage Stage, path string, schemaID ports.AssetID, _ error) *Diagnostic {
	return &Diagnostic{Stage: stage, Path: path, SchemaID: schemaID}
}

func contextError(ctx context.Context) error {
	if ctx == nil {
		return errors.New("nil context")
	}
	return ctx.Err()
}

func isNilCatalog(catalog ports.ContractCatalog) bool {
	if catalog == nil {
		return true
	}
	value := reflect.ValueOf(catalog)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func cloneBytes(raw []byte) []byte {
	return append([]byte(nil), raw...)
}
