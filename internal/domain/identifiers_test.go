package domain

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"testing"
)

const testUUIDv7 = "019f596a-cf80-7c67-b265-f37053d51ccf"

func TestIdentifierParsing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		parse func(string) error
		value string
	}{
		{"session", func(value string) error { _, err := ParseSessionID(value); return err }, "s_" + testUUIDv7},
		{"run", func(value string) error { _, err := ParseRunID(value); return err }, "r_" + testUUIDv7},
		{"attempt", func(value string) error { _, err := ParseAttemptID(value); return err }, "a_" + testUUIDv7},
		{"review", func(value string) error { _, err := ParseReviewID(value); return err }, testUUIDv7},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if err := test.parse(test.value); err != nil {
				t.Fatalf("parse valid ID: %v", err)
			}
		})
	}
	for _, variant := range []byte{'8', '9', 'a', 'b'} {
		value := []byte(testUUIDv7)
		value[19] = variant
		if _, err := ParseReviewID(string(value)); err != nil {
			t.Errorf("valid RFC 9562 variant %q rejected: %v", variant, err)
		}
	}
}

func TestIdentifierTextAndJSONRoundTrip(t *testing.T) {
	t.Parallel()

	session, err := ParseSessionID("s_" + testUUIDv7)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != `"s_`+testUUIDv7+`"` {
		t.Fatalf("JSON ID = %s", encoded)
	}
	var decoded SessionID
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded != session {
		t.Fatalf("round trip = %q, want %q", decoded.String(), session.String())
	}
	if err := json.Unmarshal([]byte(`"r_`+testUUIDv7+`"`), &decoded); err == nil {
		t.Error("session ID accepted run prefix during unmarshal")
	}
	if _, err := (SessionID{}).MarshalText(); err == nil {
		t.Error("zero session ID serialized")
	}
}

func TestIdentifierJSONRejectsNonStringsWithoutMutation(t *testing.T) {
	t.Parallel()

	type identifierCase struct {
		name  string
		fresh func([]byte) error
		stale func([]byte) (string, error)
		want  string
	}
	cases := []identifierCase{
		{
			name: "session",
			fresh: func(data []byte) error {
				var id SessionID
				return json.Unmarshal(data, &id)
			},
			stale: func(data []byte) (string, error) {
				id, err := ParseSessionID("s_" + testUUIDv7)
				if err != nil {
					return "", err
				}
				err = json.Unmarshal(data, &id)
				return id.String(), err
			},
			want: "s_" + testUUIDv7,
		},
		{
			name: "run",
			fresh: func(data []byte) error {
				var id RunID
				return json.Unmarshal(data, &id)
			},
			stale: func(data []byte) (string, error) {
				id, err := ParseRunID("r_" + testUUIDv7)
				if err != nil {
					return "", err
				}
				err = json.Unmarshal(data, &id)
				return id.String(), err
			},
			want: "r_" + testUUIDv7,
		},
		{
			name: "attempt",
			fresh: func(data []byte) error {
				var id AttemptID
				return json.Unmarshal(data, &id)
			},
			stale: func(data []byte) (string, error) {
				id, err := ParseAttemptID("a_" + testUUIDv7)
				if err != nil {
					return "", err
				}
				err = json.Unmarshal(data, &id)
				return id.String(), err
			},
			want: "a_" + testUUIDv7,
		},
		{
			name: "review",
			fresh: func(data []byte) error {
				var id ReviewID
				return json.Unmarshal(data, &id)
			},
			stale: func(data []byte) (string, error) {
				id, err := ParseReviewID(testUUIDv7)
				if err != nil {
					return "", err
				}
				err = json.Unmarshal(data, &id)
				return id.String(), err
			},
			want: testUUIDv7,
		},
	}
	for _, test := range cases {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			payloads := [][]byte{
				[]byte("null"),
				[]byte("1"),
				[]byte("true"),
				[]byte("{}"),
				[]byte("[]"),
				[]byte(`"x_` + testUUIDv7 + `"`),
				[]byte(`"unterminated`),
			}
			for _, payload := range payloads {
				if err := test.fresh(payload); err == nil {
					t.Errorf("fresh identifier accepted invalid JSON %s", payload)
				}
				got, err := test.stale(payload)
				if err == nil {
					t.Errorf("populated identifier accepted invalid JSON %s", payload)
					continue
				}
				if got != test.want {
					t.Errorf("failed decode %s mutated identifier to %q, want %q", payload, got, test.want)
				}
			}
		})
	}
}
func TestIdentifierParsingRejectsNoncanonicalValues(t *testing.T) {
	t.Parallel()

	parsers := []struct {
		name   string
		prefix string
		parse  func(string) error
	}{
		{"session", "s_", func(value string) error { _, err := ParseSessionID(value); return err }},
		{"run", "r_", func(value string) error { _, err := ParseRunID(value); return err }},
		{"attempt", "a_", func(value string) error { _, err := ParseAttemptID(value); return err }},
		{"review", "", func(value string) error { _, err := ParseReviewID(value); return err }},
	}
	invalidBodies := []string{
		"",
		" " + testUUIDv7,
		testUUIDv7 + " ",
		testUUIDv7 + "\n",
		testUUIDv7 + "0",
		testUUIDv7[:35],
		"g19f596a-cf80-7c67-b265-f37053d51ccf",
		"019f596a-cf80-6c67-b265-f37053d51ccf",
		"019f596a-cf80-7c67-7265-f37053d51ccf",
		"019F596A-CF80-7C67-B265-F37053D51CCF",
		"019f596acf80-7c67-b265-f37053d51ccf",
		"019f596a--f80-7c67-b265-f37053d51ccf",
		"00000000-0000-7000-8000-000000000000",
	}
	for _, parser := range parsers {
		for _, body := range invalidBodies {
			if err := parser.parse(parser.prefix + body); err == nil {
				t.Errorf("%s parser accepted %q", parser.name, parser.prefix+body)
			}
		}
	}

	typedPrefixes := []string{"s_", "r_", "a_", "x_", "s_s_"}
	for _, parser := range parsers[:3] {
		for _, prefix := range typedPrefixes {
			if prefix == parser.prefix {
				continue
			}
			if err := parser.parse(prefix + testUUIDv7); err == nil {
				t.Errorf("%s parser accepted foreign prefix %q", parser.name, prefix)
			}
		}
		if err := parser.parse(parser.prefix); err == nil {
			t.Errorf("%s parser accepted prefix-only value", parser.name)
		}
	}
	for _, prefix := range typedPrefixes {
		if err := parsers[3].parse(prefix + testUUIDv7); err == nil {
			t.Errorf("review parser accepted prefix %q", prefix)
		}
	}
}

func TestIdentifierParsingSeededCanonicalityProperty(t *testing.T) {
	t.Parallel()

	random := rand.New(rand.NewSource(0x4b41524944))
	parsers := []struct {
		name   string
		prefix string
		parse  func(string) (string, error)
	}{
		{name: "session", prefix: "s_", parse: func(value string) (string, error) {
			id, err := ParseSessionID(value)
			return id.String(), err
		}},
		{name: "run", prefix: "r_", parse: func(value string) (string, error) {
			id, err := ParseRunID(value)
			return id.String(), err
		}},
		{name: "attempt", prefix: "a_", parse: func(value string) (string, error) {
			id, err := ParseAttemptID(value)
			return id.String(), err
		}},
		{name: "review", parse: func(value string) (string, error) {
			id, err := ParseReviewID(value)
			return id.String(), err
		}},
	}
	for iteration := 0; iteration < 512; iteration++ {
		body := seededUUIDv7(random)
		for _, parser := range parsers {
			canonical := parser.prefix + body
			parsed, err := parser.parse(canonical)
			if err != nil || parsed != canonical {
				t.Fatalf("iteration %d %s canonical parse = %q, %v; want %q", iteration, parser.name, parsed, err, canonical)
			}
			corrupted := []byte(body)
			switch iteration % 4 {
			case 0:
				index := random.Intn(len(corrupted))
				for corrupted[index] == '-' {
					index = random.Intn(len(corrupted))
				}
				corrupted[index] = 'g'
			case 1:
				corrupted[14] = '6'
			case 2:
				corrupted[19] = '7'
			case 3:
				corrupted = corrupted[:len(corrupted)-1]
			}
			if _, err := parser.parse(parser.prefix + string(corrupted)); err == nil {
				t.Fatalf("iteration %d %s accepted corrupted identifier %q", iteration, parser.name, parser.prefix+string(corrupted))
			}
		}
	}
}

func seededUUIDv7(random *rand.Rand) string {
	bytes := make([]byte, 16)
	for index := range bytes {
		bytes[index] = byte(random.Intn(256))
	}
	bytes[6] = bytes[6]&0x0f | 0x70
	bytes[8] = bytes[8]&0x3f | 0x80
	encoded := hex.EncodeToString(bytes)
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
}
