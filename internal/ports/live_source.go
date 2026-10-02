package ports

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/irootkernel/mulgae/internal/domain"
)

// LiveSourceSelector is independent of the existing capture selectors.
type LiveSourceSelector struct {
	scope domain.LiveSourceScope
	value string
}

func NewLiveSourceSelector(scope domain.LiveSourceScope, value string) (LiveSourceSelector, error) {
	if !scope.Valid() || len(value) > 4096 {
		return LiveSourceSelector{}, fmt.Errorf("live source selector: invalid selector")
	}
	switch scope {
	case domain.LiveSourceWorkspace, domain.LiveSourceStage, domain.LiveSourceHead:
		if value != "" {
			return LiveSourceSelector{}, fmt.Errorf("live source selector: unexpected operand")
		}
	case domain.LiveSourceCommit:
		if validateGitReference(value) != nil || !utf8.ValidString(value) {
			return LiveSourceSelector{}, fmt.Errorf("live source selector: invalid revision")
		}
	case domain.LiveSourceDiff:
		left, right, _ := liveRangeOperands(value)
		if validateGitReference(left) != nil || validateGitReference(right) != nil || !utf8.ValidString(value) {
			return LiveSourceSelector{}, fmt.Errorf("live source selector: invalid range")
		}
	}
	return LiveSourceSelector{scope: scope, value: value}, nil
}

func (selector LiveSourceSelector) Scope() domain.LiveSourceScope { return selector.scope }
func (selector LiveSourceSelector) Value() string                 { return selector.value }
func (selector LiveSourceSelector) RangeOperands() (string, string, string) {
	return liveRangeOperands(selector.value)
}
func (selector LiveSourceSelector) Valid() bool {
	_, err := NewLiveSourceSelector(selector.scope, selector.value)
	return err == nil
}

func liveRangeOperands(value string) (string, string, string) {
	operator := ".."
	if strings.Contains(value, "...") {
		operator = "..."
	}
	left, right, ok := strings.Cut(value, operator)
	if !ok || strings.Contains(left, "..") || strings.Contains(right, "..") ||
		strings.HasSuffix(left, ".") || strings.HasPrefix(right, ".") {
		return "", "", ""
	}
	return left, right, operator
}

// LiveSourceChange preserves both paths of a rename and deletion-side evidence.
type LiveSourceChange struct {
	Kind   string
	Before SafeRelativePath
	After  SafeRelativePath
}

func (change LiveSourceChange) Valid() bool {
	switch change.Kind {
	case "included", "added":
		return !change.Before.Valid() && change.After.Valid()
	case "deleted":
		return change.Before.Valid() && !change.After.Valid()
	case "modified":
		return change.Before.Valid() && change.After == change.Before
	case "renamed":
		return change.Before.Valid() && change.After.Valid() && change.Before != change.After
	default:
		return false
	}
}

// LiveSourceTarget records selection and resolved operands, never a content
// digest for mutable workspace/index state. Root identity is bound separately.
type LiveSourceTarget struct {
	selector   LiveSourceSelector
	base, head GitObjectID
	emptyBase  bool
	changes    []LiveSourceChange
}

func NewLiveSourceTarget(selector LiveSourceSelector, base, head GitObjectID, emptyBase bool, changes []LiveSourceChange) (LiveSourceTarget, error) {
	if !selector.Valid() {
		return LiveSourceTarget{}, fmt.Errorf("live source target: invalid selector")
	}
	switch selector.Scope() {
	case domain.LiveSourceWorkspace:
		if base.Valid() || head.Valid() || emptyBase {
			return LiveSourceTarget{}, fmt.Errorf("live source target: unexpected Git operands")
		}
	case domain.LiveSourceHead:
		if !head.Valid() || base.Valid() || emptyBase {
			return LiveSourceTarget{}, fmt.Errorf("live source target: invalid head operand")
		}
	case domain.LiveSourceStage:
		if head.Valid() || base.Valid() == emptyBase {
			return LiveSourceTarget{}, fmt.Errorf("live source target: invalid index base")
		}
	case domain.LiveSourceCommit, domain.LiveSourceDiff:
		if !head.Valid() || base.Valid() == emptyBase || selector.Scope() == domain.LiveSourceDiff && emptyBase {
			return LiveSourceTarget{}, fmt.Errorf("live source target: invalid transition operands")
		}
	}
	for _, change := range changes {
		wholeTree := selector.Scope() == domain.LiveSourceWorkspace || selector.Scope() == domain.LiveSourceHead
		if !change.Valid() || (change.Kind == "included") != wholeTree {
			return LiveSourceTarget{}, fmt.Errorf("live source target: invalid candidate change")
		}
	}
	return LiveSourceTarget{selector: selector, base: base, head: head, emptyBase: emptyBase, changes: append([]LiveSourceChange(nil), changes...)}, nil
}

func (target LiveSourceTarget) Selector() LiveSourceSelector { return target.selector }
func (target LiveSourceTarget) Base() GitObjectID            { return target.base }
func (target LiveSourceTarget) Head() GitObjectID            { return target.head }
func (target LiveSourceTarget) EmptyBase() bool              { return target.emptyBase }
func (target LiveSourceTarget) Changes() []LiveSourceChange {
	return append([]LiveSourceChange(nil), target.changes...)
}
func (target LiveSourceTarget) NoChange() bool { return len(target.changes) == 0 }

// LiveSourceFile is one observed file, not a source snapshot or replay receipt.
type LiveSourceFile struct {
	path      SafeRelativePath
	bytes     []byte
	mediaType string
	sha256    string
}

func NewLiveSourceFile(path SafeRelativePath, data []byte, mediaType string) (LiveSourceFile, error) {
	if !path.Valid() || mediaType != "text/plain" && mediaType != "application/octet-stream" && !validRasterBytes(data, mediaType) ||
		mediaType == "text/plain" && (!utf8.Valid(data) || strings.IndexByte(string(data), 0) >= 0) {
		return LiveSourceFile{}, fmt.Errorf("live source file: invalid path or content")
	}
	digest := sha256.Sum256(data)
	return LiveSourceFile{path: path, bytes: append([]byte(nil), data...), mediaType: mediaType, sha256: "sha256:" + hex.EncodeToString(digest[:])}, nil
}
func (file LiveSourceFile) Path() SafeRelativePath { return file.path }
func (file LiveSourceFile) Bytes() []byte          { return append([]byte(nil), file.bytes...) }
func (file LiveSourceFile) MediaType() string      { return file.mediaType }
func (file LiveSourceFile) SHA256() string         { return file.sha256 }
func (file LiveSourceFile) IsText() bool           { return file.mediaType == "text/plain" }

type LiveSourceErrorCode string

const (
	LiveSourceInvalid     LiveSourceErrorCode = "invalid_source"
	LiveSourceUnsafe      LiveSourceErrorCode = "unsafe_source"
	LiveSourceConflict    LiveSourceErrorCode = "conflicted_index"
	LiveSourceRevision    LiveSourceErrorCode = "revision_unavailable"
	LiveSourceNoMergeBase LiveSourceErrorCode = "merge_base_unavailable"
	LiveSourceUnavailable LiveSourceErrorCode = "source_unavailable"
	LiveSourceUnsupported LiveSourceErrorCode = "unsupported_content"
)

// LiveSourceError exposes only a typed code; native paths and Git diagnostics
// remain in the private wrapped cause.
type LiveSourceError struct {
	code  LiveSourceErrorCode
	cause error
}

func NewLiveSourceError(code LiveSourceErrorCode, cause error) *LiveSourceError {
	return &LiveSourceError{code: code, cause: cause}
}
func (err *LiveSourceError) Error() string             { return "live source: " + string(err.code) }
func (err *LiveSourceError) Code() LiveSourceErrorCode { return err.code }
func (err *LiveSourceError) Unwrap() error             { return err.cause }

// LiveSourceReader owns a root lease. List and Read observe live workspace/index
// state or fixed committed objects. Callers keep mutable state unchanged during
// a review; this port supplies no atomic tree observation or drift monitor.
type LiveSourceReader interface {
	Root() AnchoredRoot
	Target() LiveSourceTarget
	List(context.Context, domain.LiveSourceSide) ([]SafeRelativePath, error)
	Read(context.Context, domain.LiveSourceSide, SafeRelativePath) (LiveSourceFile, error)
	Close() error
}

type LiveSourceOpener interface {
	OpenLiveSource(context.Context, AnchoredRoot, LiveSourceSelector) (LiveSourceReader, error)
}
