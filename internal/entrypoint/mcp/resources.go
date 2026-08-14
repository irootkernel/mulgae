package mcpentry

import (
	"context"
	"encoding/json"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const (
	reportResourceTemplate   = "mulgae://runs/{run_id}/report{?offset}"
	evidenceResourceTemplate = "mulgae://runs/{run_id}/findings/{finding_id}/evidence{?target_sha256,offset}"
	// MaxResourceChunkBytes bounds every report and evidence resource read.
	MaxResourceChunkBytes = 16 << 10
)

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
		result, err := backend.ReadResource(ctx, request.Params.URI)
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
	failure := publicToolError(err, "resource")
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
