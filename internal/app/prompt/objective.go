package prompt

import (
	"bytes"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxObjectiveBytes is the fixed maximum objective length. It is a byte
	// limit rather than a rune limit because objective provenance is byte exact.
	MaxObjectiveBytes = 12000
)

// ObjectiveConflictClass is a frozen deterministic preflight category. It is
// deliberately not configurable: a lower-trust objective cannot redefine the
// constraints it is checked against.
type ObjectiveConflictClass string

const (
	ObjectiveRoleConflict        ObjectiveConflictClass = "role_conflict"
	ObjectiveRunTypeConflict     ObjectiveConflictClass = "run_type_conflict"
	ObjectiveSchemaConflict      ObjectiveConflictClass = "schema_conflict"
	ObjectiveSafetyConflict      ObjectiveConflictClass = "safety_conflict"
	ObjectiveAuthorityConflict   ObjectiveConflictClass = "authority_conflict"
	ObjectiveInstructionOverride ObjectiveConflictClass = "instruction_override"
	ObjectiveOversize            ObjectiveConflictClass = "oversize"
	ObjectiveInvalidEncoding     ObjectiveConflictClass = "invalid_encoding"
)

func (class ObjectiveConflictClass) Valid() bool {
	switch class {
	case ObjectiveRoleConflict, ObjectiveRunTypeConflict, ObjectiveSchemaConflict,
		ObjectiveSafetyConflict, ObjectiveAuthorityConflict, ObjectiveInstructionOverride,
		ObjectiveOversize, ObjectiveInvalidEncoding:
		return true
	default:
		return false
	}
}

// Objective is an immutable limited-trust instruction. It is linted before it
// can be incorporated into a compiler-owned trusted layer.
type Objective struct{ bytes []byte }

func NewObjective(content []byte) Objective { return Objective{bytes: cloneBytes(content)} }

func (objective Objective) Bytes() []byte             { return cloneBytes(objective.bytes) }
func (objective Objective) ByteLength() int           { return len(objective.bytes) }
func (objective Objective) Lint() ObjectiveLintResult { return LintObjective(objective.bytes) }

// ObjectiveDiagnostic identifies one deterministic conflict and gives a
// stable, actionable rewrite direction.
type ObjectiveDiagnostic struct {
	class   ObjectiveConflictClass
	message string
}

func (diagnostic ObjectiveDiagnostic) Class() ObjectiveConflictClass { return diagnostic.class }
func (diagnostic ObjectiveDiagnostic) Message() string               { return diagnostic.message }

// ObjectiveLintResult reports all applicable frozen classes in canonical
// order. Its getter returns a new slice so callers cannot mutate the result.
type ObjectiveLintResult struct{ diagnostics []ObjectiveDiagnostic }

func (result ObjectiveLintResult) Accepted() bool { return len(result.diagnostics) == 0 }

func (result ObjectiveLintResult) Diagnostics() []ObjectiveDiagnostic {
	return append([]ObjectiveDiagnostic(nil), result.diagnostics...)
}

func (result ObjectiveLintResult) ConflictClasses() []ObjectiveConflictClass {
	classes := make([]ObjectiveConflictClass, len(result.diagnostics))
	for index, diagnostic := range result.diagnostics {
		classes[index] = diagnostic.class
	}
	return classes
}

// Err returns nil for an accepted objective and otherwise an actionable,
// deterministic summary suitable for preflight reporting.
func (result ObjectiveLintResult) Err() error {
	if result.Accepted() {
		return nil
	}
	classes := result.ConflictClasses()
	values := make([]string, len(classes))
	for index, class := range classes {
		values[index] = string(class)
	}
	return fmt.Errorf("objective rejected (%s): rewrite the objective so it only narrows review focus without changing Mulgae constraints", strings.Join(values, ", "))
}

// LintObjective applies the frozen byte cap, UTF-8 check, and conservative
// ASCII phrase rules. It is intentionally deterministic rather than an LLM
// judgment, so a user can rewrite an objective from the exact diagnostics.
func LintObjective(content []byte) ObjectiveLintResult {
	diagnostics := make([]ObjectiveDiagnostic, 0, len(objectivePhraseRules)+2)
	oversized := len(content) > MaxObjectiveBytes
	if !utf8.Valid(content) {
		if oversized {
			diagnostics = append(diagnostics, objectiveDiagnostic(ObjectiveOversize))
		}
		diagnostics = append(diagnostics, objectiveDiagnostic(ObjectiveInvalidEncoding))
		return ObjectiveLintResult{diagnostics: diagnostics}
	}
	folded := normalizeObjectiveForLint(content)
	for _, rule := range objectivePhraseRules {
		if containsAny(folded, rule.phrases) {
			diagnostics = append(diagnostics, objectiveDiagnostic(rule.class))
		}
	}
	if oversized {
		diagnostics = append(diagnostics, objectiveDiagnostic(ObjectiveOversize))
	}
	return ObjectiveLintResult{diagnostics: diagnostics}
}

type objectivePhraseRule struct {
	class   ObjectiveConflictClass
	phrases [][]byte
}

// objectivePhraseRules order is part of the lint contract. Each list contains
// only explicit constraint-changing requests, leaving legitimate domain words
// such as "release notes" and "security schema" available to objectives.
var objectivePhraseRules = [...]objectivePhraseRule{
	{
		class: ObjectiveRoleConflict,
		phrases: [][]byte{
			[]byte("change the role"),
			[]byte("switch the role"),
			[]byte("switch roles"),
			[]byte("act as a different role"),
			[]byte("ignore the selected role"),
			[]byte("ignore your role"),
			[]byte("replace the selected role"),
		},
	},
	{
		class: ObjectiveRunTypeConflict,
		phrases: [][]byte{
			[]byte("change the run type"),
			[]byte("switch the run type"),
			[]byte("switch run type"),
			[]byte("treat this as a new review"),
			[]byte("treat this as a followup"),
			[]byte("treat this as a delta review"),
			[]byte("treat this as a rerun"),
		},
	},
	{
		class: ObjectiveSchemaConflict,
		phrases: [][]byte{
			[]byte("ignore the schema"),
			[]byte("ignore schema"),
			[]byte("do not return json"),
			[]byte("return markdown"),
			[]byte("return yaml"),
			[]byte("return plain text"),
			[]byte("omit mandatory values"),
		},
	},
	{
		class: ObjectiveSafetyConflict,
		phrases: [][]byte{
			[]byte("reveal secret"),
			[]byte("disclose secret"),
			[]byte("modify files"),
			[]byte("write files"),
			[]byte("invoke tools"),
			[]byte("run commands"),
			[]byte("execute commands"),
		},
	},
	{
		class: ObjectiveAuthorityConflict,
		phrases: [][]byte{
			[]byte("grant approval"),
			[]byte("approve this"),
			[]byte("approve the change"),
			[]byte("waive the requirement"),
			[]byte("authorize merge"),
			[]byte("merge this"),
			[]byte("authorize release"),
			[]byte("release this"),
			[]byte("deploy this"),
		},
	},
	{
		class: ObjectiveInstructionOverride,
		phrases: [][]byte{
			[]byte("ignore previous instructions"),
			[]byte("ignore earlier instructions"),
			[]byte("ignore all instructions"),
			[]byte("disregard previous instructions"),
			[]byte("override previous instructions"),
			[]byte("override all instructions"),
			[]byte("supersede previous instructions"),
		},
	},
}

func containsAny(content []byte, phrases [][]byte) bool {
	quoted := objectiveQuotedRanges(content)
	for _, phrase := range phrases {
		if containsUnnegatedUnquotedPhrase(content, phrase, quoted) {
			return true
		}
	}
	return false
}

type objectiveRange struct {
	start int
	end   int
}

func normalizeObjectiveForLint(content []byte) []byte {
	normalized := make([]byte, 0, len(content))
	previousWhitespace := false
	for len(content) > 0 {
		runeValue, width := utf8.DecodeRune(content)
		content = content[width:]
		if unicode.IsSpace(runeValue) {
			if len(normalized) > 0 && !previousWhitespace {
				normalized = append(normalized, ' ')
				previousWhitespace = true
			}
			continue
		}
		normalized = append(normalized, string(unicode.ToLower(runeValue))...)
		previousWhitespace = false
	}
	return normalized
}

func containsUnnegatedUnquotedPhrase(content, phrase []byte, quoted []objectiveRange) bool {
	for offset := 0; offset < len(content); {
		relative := bytes.Index(content[offset:], phrase)
		if relative < 0 {
			return false
		}
		start := offset + relative
		end := start + len(phrase)
		if !hasObjectiveTokenBefore(content, start) &&
			!hasObjectiveTokenAfter(content, end) &&
			!objectiveRangeContains(quoted, start, end) &&
			!negatesObjectivePhrase(content, start) {
			return true
		}
		offset = start + 1
	}
	return false
}

func objectiveQuotedRanges(content []byte) []objectiveRange {
	ranges := make([]objectiveRange, 0, 1)
	for start := 0; start < len(content); start++ {
		quote := content[start]
		if quote != '"' && quote != '\'' {
			continue
		}
		if quote == '\'' && hasObjectiveTokenBefore(content, start) {
			continue
		}
		relativeEnd := bytes.IndexByte(content[start+1:], quote)
		if relativeEnd < 0 {
			continue
		}
		end := start + 1 + relativeEnd
		ranges = append(ranges, objectiveRange{start: start + 1, end: end})
		start = end
	}
	return ranges
}

func objectiveRangeContains(ranges []objectiveRange, start, end int) bool {
	for _, quoted := range ranges {
		if quoted.start <= start && end <= quoted.end {
			return true
		}
	}
	return false
}

var objectiveNegations = [...][]byte{
	[]byte("do not "),
	[]byte("don't "),
	[]byte("never "),
	[]byte("must not "),
}

func negatesObjectivePhrase(content []byte, start int) bool {
	for _, negation := range objectiveNegations {
		if len(negation) <= start &&
			bytes.Equal(content[start-len(negation):start], negation) &&
			!hasObjectiveTokenBefore(content, start-len(negation)) {
			return true
		}
	}

	prefix := content[:start]
	var connector []byte
	switch {
	case bytes.HasSuffix(prefix, []byte(" or ")):
		connector = []byte(" or ")
	case bytes.HasSuffix(prefix, []byte(" and ")):
		connector = []byte(" and ")
	default:
		return false
	}
	clause := prefix[:len(prefix)-len(connector)]
	if boundary := bytes.LastIndexAny(clause, ".;!?\n"); boundary >= 0 {
		clause = clause[boundary+1:]
	}
	for _, contrast := range [][]byte{[]byte(" but "), []byte(" then "), []byte(" however ")} {
		if boundary := bytes.LastIndex(clause, contrast); boundary >= 0 {
			clause = clause[boundary+len(contrast):]
		}
	}
	for _, negation := range objectiveNegations {
		for offset := 0; offset < len(clause); {
			relative := bytes.Index(clause[offset:], negation)
			if relative < 0 {
				break
			}
			position := offset + relative
			if !hasObjectiveTokenBefore(clause, position) {
				return true
			}
			offset = position + 1
		}
	}
	return false
}

func hasObjectiveTokenBefore(content []byte, offset int) bool {
	if offset == 0 {
		return false
	}
	runeValue, _ := utf8.DecodeLastRune(content[:offset])
	return isObjectiveTokenRune(runeValue)
}

func hasObjectiveTokenAfter(content []byte, offset int) bool {
	if offset == len(content) {
		return false
	}
	runeValue, _ := utf8.DecodeRune(content[offset:])
	return isObjectiveTokenRune(runeValue)
}

func isObjectiveTokenRune(runeValue rune) bool {
	return runeValue == '_' || unicode.IsLetter(runeValue) || unicode.IsDigit(runeValue)
}

func objectiveDiagnostic(class ObjectiveConflictClass) ObjectiveDiagnostic {
	switch class {
	case ObjectiveRoleConflict:
		return ObjectiveDiagnostic{class: class, message: "remove the request to change or ignore the selected role"}
	case ObjectiveRunTypeConflict:
		return ObjectiveDiagnostic{class: class, message: "remove the request to change the selected run type"}
	case ObjectiveSchemaConflict:
		return ObjectiveDiagnostic{class: class, message: "keep the required JSON schema and mandatory values"}
	case ObjectiveSafetyConflict:
		return ObjectiveDiagnostic{class: class, message: "remove requests for secrets, file mutation, tools, or commands"}
	case ObjectiveAuthorityConflict:
		return ObjectiveDiagnostic{class: class, message: "remove approval, waiver, merge, release, or deployment authority requests"}
	case ObjectiveInstructionOverride:
		return ObjectiveDiagnostic{class: class, message: "remove requests to ignore, override, or supersede earlier instructions"}
	case ObjectiveOversize:
		return ObjectiveDiagnostic{class: class, message: fmt.Sprintf("shorten the objective to at most %d bytes", MaxObjectiveBytes)}
	case ObjectiveInvalidEncoding:
		return ObjectiveDiagnostic{class: class, message: "provide valid UTF-8 objective bytes"}
	default:
		return ObjectiveDiagnostic{class: class, message: "rewrite the objective to preserve Mulgae constraints"}
	}
}
