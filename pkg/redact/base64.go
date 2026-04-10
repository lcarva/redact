package redact

import (
	"encoding/base64"
	"regexp"
)

// base64Re matches candidate base64-encoded strings. False positives
// are filtered by length, valid decode, and secret detection.
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/\-_]{4,}={0,2}`)

// base64Span represents a byte range in the original string that
// contains a base64-encoded secret.
type base64Span struct {
	start int
	end   int
}

// detectBase64Secrets scans the string for base64-encoded content,
// decodes candidates, and runs gitleaks detection on the decoded
// content. Returns byte spans of base64 strings that contain secrets.
func (o *Opt) detectBase64Secrets(s string) []base64Span {
	if o.base64MinLength <= 0 {
		return nil
	}

	matches := base64Re.FindAllStringIndex(s, -1)

	var spans []base64Span
	for _, loc := range matches {
		candidate := s[loc[0]:loc[1]]

		if len(candidate) < o.base64MinLength {
			continue
		}

		// Base64 encoded strings must have length divisible by 4.
		if len(candidate)%4 != 0 {
			continue
		}

		decoded, ok := tryBase64Decode(candidate)
		if !ok {
			continue
		}

		// Run gitleaks detection on the decoded content.
		findings := o.d.DetectString(string(decoded))
		if len(findings) == 0 {
			continue
		}

		spans = append(spans, base64Span{start: loc[0], end: loc[1]})
	}

	return spans
}

// tryBase64Decode attempts to decode a string using standard base64,
// then URL-safe base64 encoding.
func tryBase64Decode(s string) ([]byte, bool) {
	// Try standard encoding.
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, true
	}

	// Try URL-safe encoding.
	if b, err := base64.URLEncoding.DecodeString(s); err == nil {
		return b, true
	}

	// Try raw (no padding) variants.
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return b, true
	}

	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, true
	}

	return nil, false
}
