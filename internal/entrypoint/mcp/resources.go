package mcpentry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/irootkernel/mulgae/internal/domain"
	"github.com/irootkernel/mulgae/internal/ports"
)

const (
	reportResourceTemplate   = "mulgae://runs/{run_id}/report{?offset}"
	evidenceResourceTemplate = "mulgae://runs/{run_id}/findings/{finding_id}/evidence{?target_sha256,offset}"
	// MaxResourceChunkBytes bounds every report and evidence resource read.
	MaxResourceChunkBytes = 16 << 10
)

var errInvalidResourceURI = errors.New("invalid MCP resource URI")

// ResourceKind is one closed verified MCP resource family.
type ResourceKind string

const (
	ResourceReport   ResourceKind = "report"
	ResourceEvidence ResourceKind = "evidence"
)

// ResourceRequest is one canonical project-confined resource selector parsed by
// the MCP entrypoint. Accessors expose only values needed by the backend query.
type ResourceRequest struct {
	rawURI       string
	kind         ResourceKind
	runID        string
	findingID    string
	targetSHA256 string
	offset       int
}

// URI returns the canonical resource URI supplied by the client.
func (request ResourceRequest) URI() string { return request.rawURI }

// Kind returns the admitted resource family.
func (request ResourceRequest) Kind() ResourceKind { return request.kind }

// RunID returns the admitted run identity.
func (request ResourceRequest) RunID() string { return request.runID }

// FindingID returns the admitted finding identity for evidence resources.
func (request ResourceRequest) FindingID() string { return request.findingID }

// TargetSHA256 returns the admitted target digest for evidence resources.
func (request ResourceRequest) TargetSHA256() string { return request.targetSHA256 }

// Offset returns the canonical chunk boundary requested by the client.
func (request ResourceRequest) Offset() int { return request.offset }

// ResourceContent is verified full content returned by the project-confined
// backend before MCP-owned chunk projection.
type ResourceContent struct {
	MIMEType string
	Bytes    []byte
	Text     bool
}

// ResourceResult is one verified bounded resource chunk and its continuation
// metadata. Exactly one of Text and Blob is populated.
type ResourceResult struct {
	URI      string
	MIMEType string
	Text     string
	Blob     []byte
	Meta     map[string]any
}

func registerResources(server *mcpsdk.Server, backend Backend) {
	if server == nil || backend == nil {
		return
	}
	annotations := &mcpsdk.Annotations{Audience: []mcpsdk.Role{mcpsdk.Role("assistant")}, Priority: 0.8}
	handler := func(ctx context.Context, request *mcpsdk.ReadResourceRequest) (*mcpsdk.ReadResourceResult, error) {
		selector, err := ParseResourceURI(request.Params.URI)
		if err != nil {
			return nil, publicResourceError(errInvalidResourceURI)
		}
		content, err := backend.ReadResource(ctx, selector)
		if err != nil {
			return nil, publicResourceError(err)
		}
		result, err := projectResource(selector, content)
		if err != nil {
			return nil, publicResourceError(err)
		}
		if err := result.validate(request.Params.URI); err != nil {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "Mulgae resource result is unavailable"}
		}
		return &mcpsdk.ReadResourceResult{Contents: []*mcpsdk.ResourceContents{{
			URI: result.URI, MIMEType: result.MIMEType, Text: result.Text,
			Blob: append([]byte(nil), result.Blob...), Meta: cloneMap(result.Meta),
		}}}, nil
	}
	server.AddResourceTemplate(&mcpsdk.ResourceTemplate{
		Name: "verified_review_report", Title: "Verified Mulgae review report",
		Description: "Read a verified committed review report in bounded UTF-8 chunks.",
		MIMEType:    "text/markdown", URITemplate: reportResourceTemplate, Annotations: annotations,
	}, handler)
	server.AddResourceTemplate(&mcpsdk.ResourceTemplate{
		Name: "verified_finding_evidence", Title: "Verified Mulgae finding evidence",
		Description: "Read one current-target-verified finding excerpt in bounded binary chunks.",
		MIMEType:    "application/octet-stream", URITemplate: evidenceResourceTemplate, Annotations: annotations,
	}, handler)
}

// NewReportResourceURI returns the canonical first report resource URI.
func NewReportResourceURI(runID string) (string, error) {
	if _, err := domain.ParseRunID(runID); err != nil {
		return "", fmt.Errorf("report resource URI: invalid run ID")
	}
	return reportResourceURI(runID, 0), nil
}

// NewEvidenceResourceURI returns the canonical first evidence resource URI.
func NewEvidenceResourceURI(runID, findingID, targetSHA256 string) (string, error) {
	if _, err := domain.ParseRunID(runID); err != nil || !validFindingID(findingID) || !validSHA256(targetSHA256) {
		return "", fmt.Errorf("evidence resource URI: invalid identity")
	}
	return evidenceResourceURI(runID, findingID, targetSHA256, 0), nil
}

// ParseResourceURI admits one canonical MCP resource selector.
func ParseResourceURI(raw string) (ResourceRequest, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return ResourceRequest{}, fmt.Errorf("resource URI length is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "mulgae" || parsed.Host != "runs" || parsed.User != nil || parsed.Fragment != "" {
		return ResourceRequest{}, fmt.Errorf("resource URI authority is invalid")
	}
	segments := strings.Split(strings.TrimPrefix(parsed.EscapedPath(), "/"), "/")
	if len(segments) != 2 && len(segments) != 4 {
		return ResourceRequest{}, fmt.Errorf("resource URI path is invalid")
	}
	for index, segment := range segments {
		decoded, decodeErr := url.PathUnescape(segment)
		if decodeErr != nil || decoded != segment {
			return ResourceRequest{}, fmt.Errorf("resource URI path encoding is invalid")
		}
		segments[index] = decoded
	}
	if _, err := domain.ParseRunID(segments[0]); err != nil {
		return ResourceRequest{}, fmt.Errorf("resource run ID is invalid")
	}
	query, err := url.ParseQuery(parsed.RawQuery)
	if err != nil {
		return ResourceRequest{}, fmt.Errorf("resource URI query is invalid")
	}
	offset, err := parseResourceOffset(query)
	if err != nil {
		return ResourceRequest{}, err
	}
	request := ResourceRequest{rawURI: raw, runID: segments[0], offset: offset}
	switch {
	case len(segments) == 2 && segments[1] == "report":
		if len(query) > 1 || query.Has("target_sha256") {
			return ResourceRequest{}, fmt.Errorf("report resource query is invalid")
		}
		request.kind = ResourceReport
		if raw != reportResourceURI(request.runID, request.offset) {
			return ResourceRequest{}, fmt.Errorf("report resource URI is not canonical")
		}
	case len(segments) == 4 && segments[1] == "findings" && segments[3] == "evidence":
		if !validFindingID(segments[2]) || len(query) > 2 || len(query["target_sha256"]) != 1 ||
			!validSHA256(query.Get("target_sha256")) {
			return ResourceRequest{}, fmt.Errorf("evidence resource query is invalid")
		}
		request.kind, request.findingID, request.targetSHA256 = ResourceEvidence, segments[2], query.Get("target_sha256")
		if raw != evidenceResourceURI(request.runID, request.findingID, request.targetSHA256, request.offset) {
			return ResourceRequest{}, fmt.Errorf("evidence resource URI is not canonical")
		}
	default:
		return ResourceRequest{}, fmt.Errorf("resource URI path is invalid")
	}
	return request, nil
}

func parseResourceOffset(query url.Values) (int, error) {
	values, present := query["offset"]
	if !present {
		return 0, nil
	}
	if len(values) != 1 || values[0] == "" || len(values[0]) > 8 {
		return 0, fmt.Errorf("resource offset is invalid")
	}
	offset, err := strconv.Atoi(values[0])
	if err != nil || offset < 0 || int64(offset) > ports.PublicationStoreMaxReadBytes {
		return 0, fmt.Errorf("resource offset is invalid")
	}
	return offset, nil
}

func reportResourceURI(runID string, offset int) string {
	uri := "mulgae://runs/" + runID + "/report"
	if offset != 0 {
		uri += "?offset=" + strconv.Itoa(offset)
	}
	return uri
}

func evidenceResourceURI(runID, findingID, targetSHA256 string, offset int) string {
	uri := "mulgae://runs/" + runID + "/findings/" + findingID + "/evidence?target_sha256=" + url.QueryEscape(targetSHA256)
	if offset != 0 {
		uri += "&offset=" + strconv.Itoa(offset)
	}
	return uri
}

func projectResource(request ResourceRequest, content ResourceContent) (ResourceResult, error) {
	if content.MIMEType == "" || len(content.Bytes) == 0 || content.Text && !utf8.Valid(content.Bytes) {
		return ResourceResult{}, fmt.Errorf("MCP resource content is invalid")
	}
	if !canonicalResourceOffset(content.Bytes, content.Text, request.offset) {
		return ResourceResult{}, errInvalidResourceURI
	}
	end := resourceChunkEnd(content.Bytes, content.Text, request.offset)
	chunk := append([]byte(nil), content.Bytes[request.offset:end]...)
	digest := sha256.Sum256(content.Bytes)
	var nextURI any
	if end < len(content.Bytes) {
		if request.kind == ResourceReport {
			nextURI = reportResourceURI(request.runID, end)
		} else {
			nextURI = evidenceResourceURI(request.runID, request.findingID, request.targetSHA256, end)
		}
	}
	result := ResourceResult{
		URI: request.rawURI, MIMEType: content.MIMEType,
		Meta: map[string]any{
			"io.mulgae/sha256": "sha256:" + hex.EncodeToString(digest[:]),
			"io.mulgae/offset": request.offset, "io.mulgae/chunkBytes": len(chunk),
			"io.mulgae/totalBytes": len(content.Bytes), "io.mulgae/complete": end == len(content.Bytes),
			"io.mulgae/nextURI": nextURI,
		},
	}
	if content.Text {
		result.Text = string(chunk)
	} else {
		result.Blob = chunk
	}
	return result, nil
}

func canonicalResourceOffset(contents []byte, text bool, offset int) bool {
	if offset < 0 || offset >= len(contents) {
		return false
	}
	for current := 0; current < len(contents); current = resourceChunkEnd(contents, text, current) {
		if current == offset {
			return true
		}
		if current > offset {
			return false
		}
	}
	return false
}

func resourceChunkEnd(contents []byte, text bool, offset int) int {
	end := offset + MaxResourceChunkBytes
	if end > len(contents) {
		end = len(contents)
	}
	if text {
		for end < len(contents) && end > offset && !utf8.RuneStart(contents[end]) {
			end--
		}
	}
	return end
}

func validFindingID(value string) bool {
	if len(value) < 4 || len(value) > 5 || value[0] != 'F' {
		return false
	}
	for _, character := range value[1:] {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func (result ResourceResult) validate(requestURI string) error {
	if result.URI != requestURI || result.MIMEType == "" || len(result.Meta) == 0 {
		return errInvalidToolArguments
	}
	textPresent := result.Text != ""
	blobPresent := len(result.Blob) != 0
	if textPresent == blobPresent {
		return errInvalidToolArguments
	}
	if textPresent && (!utf8.ValidString(result.Text) || len(result.Text) > MaxResourceChunkBytes) {
		return errInvalidToolArguments
	}
	if blobPresent && len(result.Blob) > MaxResourceChunkBytes {
		return errInvalidToolArguments
	}
	return nil
}

func publicResourceError(err error) error {
	failure := ToolError{
		Class: "usage", Code: "configuration_rejected", Stage: "admission",
		Message: "The project configuration or request is invalid.", Retryable: false,
	}
	if !errors.Is(err, errInvalidResourceURI) {
		failure = publicToolError(err, "resource")
	}
	code := int64(jsonrpc.CodeInternalError)
	if failure.Class == "usage" || failure.Class == "artifact" || failure.Class == "security" {
		code = jsonrpc.CodeInvalidParams
	}
	data, marshalErr := json.Marshal(failure)
	if marshalErr != nil {
		return &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "Mulgae resource is unavailable"}
	}
	return &jsonrpc.Error{Code: code, Message: failure.Message, Data: data}
}
