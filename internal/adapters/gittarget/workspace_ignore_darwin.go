//go:build darwin && arm64

package gittarget

import (
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"
)

type workspaceIgnoreRule struct {
	base          string
	components    []*regexp.Regexp
	anchored      bool
	directoryOnly bool
	negate        bool
}

func compileWorkspaceIgnore(data []byte, base string) ([]workspaceIgnoreRule, error) {
	var rules []workspaceIgnoreRule
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		for strings.HasSuffix(line, " ") {
			backslashes := 0
			for index := len(line) - 2; index >= 0 && line[index] == '\\'; index-- {
				backslashes++
			}
			if backslashes%2 == 1 {
				break
			}
			line = line[:len(line)-1]
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		negate := strings.HasPrefix(line, "!")
		if negate {
			line = line[1:]
		}
		anchored := strings.HasPrefix(line, "/")
		line = strings.TrimPrefix(line, "/")
		directoryOnly := strings.HasSuffix(line, "/")
		line = strings.TrimSuffix(line, "/")
		if line == "" {
			continue
		}
		rule := workspaceIgnoreRule{base: filepath.ToSlash(base), anchored: anchored || strings.Contains(line, "/"), directoryOnly: directoryOnly, negate: negate}
		valid := true
		components := strings.Split(line, "/")
		for index, component := range components {
			// An escaped interior separator still separates Git pattern components.
			// Preserve paired backslashes and the final component's escape semantics.
			backslashes := len(component) - len(strings.TrimRight(component, `\`))
			if index < len(components)-1 && backslashes%2 == 1 {
				component = component[:len(component)-1]
			}
			if len(component) >= 2 && strings.Trim(component, "*") == "" {
				// A complete ** component crosses zero or more directories.
				rule.components = append(rule.components, nil)
				continue
			}
			expression, ok := workspaceIgnoreRegexp(component)
			if !ok {
				valid = false
				break
			}
			pattern, err := regexp.Compile(expression)
			if err != nil {
				valid = false
				break
			}
			rule.components = append(rule.components, pattern)
		}
		// Git's invalid glob patterns never select a path.
		if valid {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func workspaceIgnoreRegexp(pattern string) (string, bool) {
	var expression strings.Builder
	expression.WriteString("(?s)^")
	characters := []rune(workspaceIgnoreBytes(pattern))
	for index := 0; index < len(characters); index++ {
		switch characters[index] {
		case '*':
			expression.WriteString(".*")
		case '?':
			expression.WriteString(".")
		case '\\':
			index++
			if index == len(characters) {
				return "", false
			}
			expression.WriteString(regexp.QuoteMeta(string(characters[index])))
		case '[':
			expression.WriteRune('[')
			index++
			if index < len(characters) && (characters[index] == '!' || characters[index] == '^') {
				expression.WriteRune('^')
				index++
			}
			if index < len(characters) && characters[index] == ']' {
				expression.WriteString(`\]`)
				index++
			}
			closed := false
			for ; index < len(characters); index++ {
				character := characters[index]
				if character == ']' {
					expression.WriteRune(']')
					closed = true
					break
				}
				if character == '[' && index+1 < len(characters) && characters[index+1] == ':' {
					end := index + 2
					for end+1 < len(characters) && !(characters[end] == ':' && characters[end+1] == ']') {
						end++
					}
					if end+1 == len(characters) {
						return "", false
					}
					expression.WriteString(string(characters[index : end+2]))
					index = end + 1
				} else if character == '\\' {
					index++
					if index == len(characters) {
						return "", false
					}
					escaped := regexp.QuoteMeta(string(characters[index]))
					if characters[index] == '-' {
						escaped = `\-`
					}
					expression.WriteString(escaped)
				} else if character == '[' || character == '^' {
					expression.WriteString(`\` + string(character))
				} else {
					expression.WriteRune(character)
				}
			}
			if !closed {
				return "", false
			}
		default:
			expression.WriteString(regexp.QuoteMeta(string(characters[index])))
		}
	}
	expression.WriteString("$")
	return expression.String(), true
}

// Git wildmatch treats ? and bracket classes as byte patterns. Encoding each
// byte as one rune keeps regexp matching consistent for UTF-8 filenames.
func workspaceIgnoreBytes(value string) string {
	var encoded strings.Builder
	for index := 0; index < len(value); index++ {
		encoded.WriteRune(rune(value[index]))
	}
	return encoded.String()
}

func workspaceIgnored(path string, directory bool, rules []workspaceIgnoreRule) bool {
	ignored := false
	for _, rule := range rules {
		if rule.directoryOnly && !directory {
			continue
		}
		relative := path
		if rule.base != "" {
			prefix := rule.base + "/"
			if !strings.HasPrefix(path, prefix) {
				continue
			}
			relative = strings.TrimPrefix(path, prefix)
		}
		parts := strings.Split(workspaceIgnoreBytes(relative), "/")
		if !rule.anchored {
			parts = parts[len(parts)-1:]
		}
		matched := make([]bool, len(parts)+1)
		matched[0] = true
		for index, component := range rule.components {
			next := make([]bool, len(parts)+1)
			if component == nil {
				// A trailing /** selects contents, never the directory itself.
				contents := index == len(rule.components)-1 && index > 0
				for part := 0; part <= len(parts); part++ {
					if !contents {
						next[part] = matched[part]
					}
					if part > 0 {
						next[part] = next[part] || next[part-1] || (contents && matched[part-1])
					}
				}
			} else {
				for part := 1; part <= len(parts); part++ {
					next[part] = matched[part-1] && component.MatchString(parts[part-1])
				}
			}
			matched = next
		}
		if matched[len(parts)] {
			ignored = !rule.negate
		}
	}
	return ignored
}

func rasterMediaType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".webp":
		return "image/webp"
	default:
		return ""
	}
}

func sameStableFile(left, right unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino && left.Size == right.Size && left.Mtim == right.Mtim && left.Ctim == right.Ctim
}
