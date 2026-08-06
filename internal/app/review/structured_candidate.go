package review

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

var errStructuredCandidateMissing = errors.New("structured review candidate missing")

// AssistantContentClass separates free-form prose from structured candidates.
type AssistantContentClass int

const (
	AssistantContentFreeForm AssistantContentClass = iota
	AssistantContentStructuredLike
	AssistantContentStructured
)

type assistantContentClass = AssistantContentClass

const (
	assistantContentFreeForm       = AssistantContentFreeForm
	assistantContentStructuredLike = AssistantContentStructuredLike
	assistantContentStructured     = AssistantContentStructured
)

// ClassifyAssistantContent separates free-form prose from structured or
// structured-like candidates before validation. Trusted structured content is
// exactly one JSON object (unique fence payload or whole body). Structured-like
// content is a unique fence payload or whole `{...` attempt that may be
// malformed and therefore repair-eligible. Ambiguous multi-fence and trailing
// JSON values stay free-form/untrusted.
func ClassifyAssistantContent(content []byte) (AssistantContentClass, []byte) {
	return classifyAssistantContent(content)
}

func classifyAssistantContent(content []byte) (assistantContentClass, []byte) {
	trimmed := bytes.TrimSpace(content)
	if len(trimmed) == 0 {
		return assistantContentFreeForm, nil
	}
	if bytes.Contains(trimmed, []byte("```json")) {
		payload, err := extractUniqueJSONFencePayload(trimmed)
		if err != nil {
			return assistantContentFreeForm, nil
		}
		if object, ok := decodeExactJSONObject(payload); ok {
			return assistantContentStructured, object
		}
		return assistantContentStructuredLike, payload
	}
	if trimmed[0] != '{' {
		return assistantContentFreeForm, nil
	}
	if object, ok := decodeExactJSONObject(trimmed); ok {
		return assistantContentStructured, object
	}
	if hasTrailingJSONValue(trimmed) {
		return assistantContentFreeForm, nil
	}
	return assistantContentStructuredLike, append([]byte(nil), trimmed...)
}

// extractStructuredReviewCandidate returns a trusted structured JSON object
// candidate when classification succeeds as structured.
func extractStructuredReviewCandidate(content []byte) ([]byte, bool) {
	class, candidate := classifyAssistantContent(content)
	if class != assistantContentStructured {
		return nil, false
	}
	return candidate, true
}

func extractUniqueJSONFencePayload(output []byte) ([]byte, error) {
	const (
		fenceStart = "```json\n"
		fenceEnd   = "\n```"
	)
	start := bytes.Index(output, []byte(fenceStart))
	if start < 0 || (start > 0 && output[start-1] != '\n') {
		return nil, errStructuredCandidateMissing
	}
	contentStart := start + len(fenceStart)
	if bytes.Contains(output[contentStart:], []byte(fenceStart)) {
		return nil, errStructuredCandidateMissing
	}
	endOffset := bytes.Index(output[contentStart:], []byte(fenceEnd))
	if endOffset < 0 {
		return nil, errStructuredCandidateMissing
	}
	candidate := bytes.TrimSpace(output[contentStart : contentStart+endOffset])
	if len(candidate) == 0 {
		return nil, errStructuredCandidateMissing
	}
	return append([]byte(nil), candidate...), nil
}

func decodeExactJSONObject(payload []byte) ([]byte, bool) {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, false
	}
	object := bytes.TrimSpace(raw)
	if len(object) == 0 || object[0] != '{' {
		return nil, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(object, &fields); err != nil {
		return nil, false
	}
	return append([]byte(nil), object...), true
}

func hasTrailingJSONValue(payload []byte) bool {
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return false
	}
	var trailing json.RawMessage
	err := decoder.Decode(&trailing)
	return !errors.Is(err, io.EOF)
}
