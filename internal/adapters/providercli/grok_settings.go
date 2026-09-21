package providercli

import (
	"crypto/sha256"
	"encoding/hex"
	"path"
	"regexp"
	"strings"
)

var (
	grokModelPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$`)
	grokEffortPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
)

type grokInvocationSettings struct {
	model           string
	reasoningEffort string
}

func newGrokInvocationSettings(model, reasoningEffort string) (grokInvocationSettings, error) {
	if !validGrokSettings(model, reasoningEffort) {
		return grokInvocationSettings{}, errInvalidGrokSettings
	}
	return grokInvocationSettings{model: model, reasoningEffort: reasoningEffort}, nil
}

func (settings grokInvocationSettings) configured() bool {
	return settings.model != "" || settings.reasoningEffort != ""
}

func validGrokSettings(model, reasoningEffort string) bool {
	return (model == "" || validGrokModel(model)) && (reasoningEffort == "" || grokEffortPattern.MatchString(reasoningEffort))
}

func validGrokModel(value string) bool {
	if !grokModelPattern.MatchString(value) || path.IsAbs(value) || strings.Contains(value, "//") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return false
		}
	}
	return true
}

func grokSettingsIdentity(model, reasoningEffort string) string {
	sum := sha256.Sum256([]byte("Mulgae-GROK-SETTINGS/1\x00model\x00" + model + "\x00reasoning-effort\x00" + reasoningEffort))
	return "sha256:" + hex.EncodeToString(sum[:])
}

type grokSettingsError struct{}

func (grokSettingsError) Error() string { return "invalid Grok settings" }

var errInvalidGrokSettings error = grokSettingsError{}
