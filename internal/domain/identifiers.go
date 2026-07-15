package domain

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SessionID identifies one immutable review lineage. Its representation is
// opaque so callers cannot bypass UUIDv7 validation with a type conversion.
type SessionID struct{ value string }

// RunID identifies one immutable execution in a session.
type RunID struct{ value string }

// AttemptID identifies one logical provider attempt.
type AttemptID struct{ value string }

// ReviewID identifies one final review artifact. Unlike directory identifiers,
// it is not prefixed.
type ReviewID struct{ value string }

func ParseSessionID(value string) (SessionID, error) {
	if err := validatePrefixedUUIDv7(value, "s_"); err != nil {
		return SessionID{}, fmt.Errorf("session id: %w", err)
	}
	return SessionID{value: value}, nil
}

func ParseRunID(value string) (RunID, error) {
	if err := validatePrefixedUUIDv7(value, "r_"); err != nil {
		return RunID{}, fmt.Errorf("run id: %w", err)
	}
	return RunID{value: value}, nil
}

func ParseAttemptID(value string) (AttemptID, error) {
	if err := validatePrefixedUUIDv7(value, "a_"); err != nil {
		return AttemptID{}, fmt.Errorf("attempt id: %w", err)
	}
	return AttemptID{value: value}, nil
}

func ParseReviewID(value string) (ReviewID, error) {
	if err := validateUUIDv7(value); err != nil {
		return ReviewID{}, fmt.Errorf("review id: %w", err)
	}
	return ReviewID{value: value}, nil
}

func (id SessionID) String() string { return id.value }
func (id RunID) String() string     { return id.value }
func (id AttemptID) String() string { return id.value }
func (id ReviewID) String() string  { return id.value }

func (id SessionID) MarshalText() ([]byte, error) { return marshalID(id.value, "s_") }
func (id RunID) MarshalText() ([]byte, error)     { return marshalID(id.value, "r_") }
func (id AttemptID) MarshalText() ([]byte, error) { return marshalID(id.value, "a_") }
func (id ReviewID) MarshalText() ([]byte, error) {
	if err := validateUUIDv7(id.value); err != nil {
		return nil, fmt.Errorf("review id: %w", err)
	}
	return []byte(id.value), nil
}
func (id *SessionID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return fmt.Errorf("session id: nil destination")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("session id: JSON string: %w", err)
	}
	parsed, err := ParseSessionID(value)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *RunID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return fmt.Errorf("run id: nil destination")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("run id: JSON string: %w", err)
	}
	parsed, err := ParseRunID(value)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *AttemptID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return fmt.Errorf("attempt id: nil destination")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("attempt id: JSON string: %w", err)
	}
	parsed, err := ParseAttemptID(value)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *ReviewID) UnmarshalJSON(data []byte) error {
	if id == nil {
		return fmt.Errorf("review id: nil destination")
	}
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("review id: JSON string: %w", err)
	}
	parsed, err := ParseReviewID(value)
	if err != nil {
		return err
	}
	*id = parsed
	return nil
}

func (id *SessionID) UnmarshalText(text []byte) error {
	parsed, err := ParseSessionID(string(text))
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("session id: nil destination")
	}
	*id = parsed
	return nil
}

func (id *RunID) UnmarshalText(text []byte) error {
	parsed, err := ParseRunID(string(text))
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("run id: nil destination")
	}
	*id = parsed
	return nil
}

func (id *AttemptID) UnmarshalText(text []byte) error {
	parsed, err := ParseAttemptID(string(text))
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("attempt id: nil destination")
	}
	*id = parsed
	return nil
}

func (id *ReviewID) UnmarshalText(text []byte) error {
	parsed, err := ParseReviewID(string(text))
	if err != nil {
		return err
	}
	if id == nil {
		return fmt.Errorf("review id: nil destination")
	}
	*id = parsed
	return nil
}

func marshalID(value, prefix string) ([]byte, error) {
	if err := validatePrefixedUUIDv7(value, prefix); err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func validatePrefixedUUIDv7(value, prefix string) error {
	if !strings.HasPrefix(value, prefix) {
		return fmt.Errorf("must start with %q", prefix)
	}
	return validateUUIDv7(strings.TrimPrefix(value, prefix))
}

func validateUUIDv7(value string) error {
	if len(value) != 36 {
		return fmt.Errorf("must contain 36 canonical UUID characters")
	}
	for index, char := range value {
		switch index {
		case 8, 13, 18, 23:
			if char != '-' {
				return fmt.Errorf("hyphen at byte %d is missing", index)
			}
		default:
			if !isLowerHex(char) {
				return fmt.Errorf("byte %d is not lowercase hexadecimal", index)
			}
		}
	}
	if value[14] != '7' {
		return fmt.Errorf("version nibble is not 7")
	}
	if !strings.ContainsRune("89ab", rune(value[19])) {
		return fmt.Errorf("variant nibble is not RFC 9562")
	}
	if value == "00000000-0000-7000-8000-000000000000" {
		return fmt.Errorf("zero-form UUIDv7 is not an issued identifier")
	}
	return nil
}

func isLowerHex(char rune) bool {
	return char >= '0' && char <= '9' || char >= 'a' && char <= 'f'
}
