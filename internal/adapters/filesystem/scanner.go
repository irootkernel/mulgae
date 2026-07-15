//go:build darwin && arm64

package filesystem

const scannerOverlap = 64

type scanMatch struct {
	detector string
}

type credentialScanner struct {
	tail  [scannerOverlap]byte
	tailN int
}

func (scanner *credentialScanner) Scan(chunk []byte) (scanMatch, bool) {
	var joined [scannerOverlap * 2]byte
	if len(chunk) <= scannerOverlap {
		copy(joined[:scanner.tailN], scanner.tail[:scanner.tailN])
		copy(joined[scanner.tailN:], chunk)
		input := joined[:scanner.tailN+len(chunk)]
		if match, found := scanCredentials(input); found {
			zeroBytes(input)
			scanner.Reset()
			return match, true
		}
		scanner.retain(input)
		zeroBytes(input)
		return scanMatch{}, false
	}

	if match, found := scanner.scanLargeChunk(chunk); found {
		scanner.Reset()
		return match, true
	}
	scanner.retain(chunk)
	return scanMatch{}, false
}

func (scanner *credentialScanner) scanLargeChunk(chunk []byte) (scanMatch, bool) {
	var prefix [scannerOverlap * 2]byte
	copy(prefix[:scanner.tailN], scanner.tail[:scanner.tailN])
	copy(prefix[scanner.tailN:], chunk[:scannerOverlap])
	if match, found := scanCredentials(prefix[:scanner.tailN+scannerOverlap]); found {
		zeroBytes(prefix[:])
		return match, true
	}
	zeroBytes(prefix[:])
	return scanCredentials(chunk)
}

func (scanner *credentialScanner) retain(input []byte) {
	zeroBytes(scanner.tail[:])
	if len(input) > scannerOverlap {
		input = input[len(input)-scannerOverlap:]
	}
	scanner.tailN = copy(scanner.tail[:], input)
}

func (scanner *credentialScanner) Reset() {
	zeroBytes(scanner.tail[:])
	scanner.tailN = 0
}

func scanCredentials(input []byte) (scanMatch, bool) {
	if containsAuthorizationBearer(input) {
		return scanMatch{detector: "authorization_bearer"}, true
	}
	if containsCredentialAssignment(input) {
		return scanMatch{detector: "credential_assignment"}, true
	}
	if containsPrivateKeyPEM(input) {
		return scanMatch{detector: "private_key_pem"}, true
	}
	if containsAWSAccessKeyID(input) {
		return scanMatch{detector: "aws_access_key_id"}, true
	}
	return scanMatch{}, false
}

func containsAuthorizationBearer(input []byte) bool {
	for start := 0; start < len(input); start++ {
		if !hasFoldAt(input, start, "authorization") {
			continue
		}
		position := start + len("authorization")
		position = skipASCIIWhitespace(input, position, 8)
		if position < len(input) && input[position] == ':' {
			position++
		}
		position = skipASCIIWhitespace(input, position, 8)
		if hasFoldAt(input, position, "bearer") {
			return true
		}
	}
	return false
}

func containsCredentialAssignment(input []byte) bool {
	for start := 0; start < len(input); start++ {
		for _, name := range [...]string{"password", "passwd", "secret"} {
			if hasCredentialAssignmentAt(input, start, name) {
				return true
			}
		}
		if hasAPICredentialAssignmentAt(input, start, "api", "key") ||
			hasAPICredentialAssignmentAt(input, start, "access", "token") {
			return true
		}
	}
	return false
}

func hasCredentialAssignmentAt(input []byte, start int, name string) bool {
	if !hasFoldAt(input, start, name) {
		return false
	}
	position := start + len(name)
	return hasAssignmentDelimiter(input, position)
}

func hasAPICredentialAssignmentAt(input []byte, start int, first, second string) bool {
	if !hasFoldAt(input, start, first) {
		return false
	}
	position := start + len(first)
	if position < len(input) && (input[position] == '_' || input[position] == '-') {
		position++
	} else {
		position = skipASCIIWhitespace(input, position, 8)
	}
	if !hasFoldAt(input, position, second) {
		return false
	}
	return hasAssignmentDelimiter(input, position+len(second))
}

func hasAssignmentDelimiter(input []byte, position int) bool {
	position = skipASCIIWhitespace(input, position, 8)
	return position < len(input) && (input[position] == '=' || input[position] == ':')
}

func skipASCIIWhitespace(input []byte, position, maximum int) int {
	for consumed := 0; position < len(input) && consumed < maximum && isASCIIWhitespace(input[position]); consumed++ {
		position++
	}
	return position
}
func containsPrivateKeyPEM(input []byte) bool {
	const prefix = "-----begin "
	const suffix = "private key-----"
	for start := 0; start+len(prefix)+len(suffix) <= len(input); start++ {
		if !hasFoldAt(input, start, prefix) {
			continue
		}
		limit := start + scannerOverlap
		if limit > len(input) {
			limit = len(input)
		}
		for position := start + len(prefix); position+len(suffix) <= limit; position++ {
			if hasFoldAt(input, position, suffix) {
				return true
			}
			if input[position] == '\r' || input[position] == '\n' {
				break
			}
		}
	}
	return false
}

func containsAWSAccessKeyID(input []byte) bool {
	for start := 0; start+20 <= len(input); start++ {
		if (hasAt(input, start, "AKIA") || hasAt(input, start, "ASIA")) && allAWSKeyCharacters(input[start+4:start+20]) {
			if start+20 == len(input) || !isAWSKeyCharacter(input[start+20]) {
				return true
			}
		}
	}
	return false
}

func allAWSKeyCharacters(value []byte) bool {
	for _, character := range value {
		if !isAWSKeyCharacter(character) {
			return false
		}
	}
	return true
}

func isAWSKeyCharacter(character byte) bool {
	return character >= 'A' && character <= 'Z' || character >= '0' && character <= '9'
}

func containsFold(input []byte, needle string) bool {
	for start := 0; start+len(needle) <= len(input); start++ {
		if hasFoldAt(input, start, needle) {
			return true
		}
	}
	return false
}

func hasFoldAt(input []byte, start int, needle string) bool {
	if start < 0 || len(input)-start < len(needle) {
		return false
	}
	for offset := range len(needle) {
		if foldASCII(input[start+offset]) != needle[offset] {
			return false
		}
	}
	return true
}

func hasAt(input []byte, start int, needle string) bool {
	if start < 0 || len(input)-start < len(needle) {
		return false
	}
	for offset := range len(needle) {
		if input[start+offset] != needle[offset] {
			return false
		}
	}
	return true
}

func foldASCII(character byte) byte {
	if character >= 'A' && character <= 'Z' {
		return character + ('a' - 'A')
	}
	return character
}

func isASCIIWhitespace(character byte) bool {
	switch character {
	case ' ', '\t', '\r', '\n':
		return true
	default:
		return false
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
