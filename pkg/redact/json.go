package redact

import (
	"bytes"
	"encoding/json"
)

type jsonStringPos struct {
	start int // byte position of opening quote
	end   int // byte position one past closing quote
}

// isJSON returns true if the content looks like a JSON document
// (object or array). Bare JSON scalars are not treated as JSON.
func isJSON(data []byte) bool {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 {
		return false
	}
	return (trimmed[0] == '{' || trimmed[0] == '[') && json.Valid(data)
}

// jsonStringValues returns the byte positions of all JSON string values
// (not keys) in the given JSON content. Each position includes the
// surrounding quotes.
func jsonStringValues(data []byte) []jsonStringPos {
	var positions []jsonStringPos

	i := 0
	for i < len(data) {
		if data[i] != '"' {
			i++
			continue
		}

		start := i
		i++ // skip opening quote

		// Scan to the closing quote, handling escape sequences.
		for i < len(data) {
			if data[i] == '\\' {
				i += 2 // skip escaped character
				continue
			}
			if data[i] == '"' {
				end := i + 1 // one past closing quote

				// Determine if this string is a key or a value.
				// If the next non-whitespace character is ':', it's a key.
				j := end
				for j < len(data) && (data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r') {
					j++
				}
				if j >= len(data) || data[j] != ':' {
					positions = append(positions, jsonStringPos{start: start, end: end})
				}

				i = end
				break
			}
			i++
		}
	}

	return positions
}

// withinStringValue reports whether a replacement range falls entirely
// within a JSON string value (between the opening and closing quotes).
func withinStringValue(r replacement, positions []jsonStringPos) bool {
	for _, pos := range positions {
		if r.start > pos.start && r.end < pos.end {
			return true
		}
	}
	return false
}

// redactJSON processes JSON content in two phases:
//  1. Full-text detection preserves key context (e.g., "auth": "value"
//     triggers context-dependent rules). Replacements are constrained
//     to fall within JSON string value boundaries.
//  2. Per-value detection unescapes each JSON string value, runs secret
//     detection on the unescaped content (catching secrets like PEM keys
//     with escaped newlines), and re-escapes the result.
func (o *Opt) redactJSON(s string) (string, error) {
	// Phase 1: full-text detection with key context.
	positions := jsonStringValues([]byte(s))
	var constrained []replacement
	for _, r := range o.detectReplacements(s) {
		if withinStringValue(r, positions) {
			constrained = append(constrained, r)
		}
	}
	if len(constrained) > 0 {
		s = applyReplacements(s, constrained)
	}

	// Phase 2: per-value detection for escaped content.
	positions = jsonStringValues([]byte(s))

	// Process in reverse order to preserve byte positions.
	for i := len(positions) - 1; i >= 0; i-- {
		pos := positions[i]
		raw := s[pos.start:pos.end]

		// Unmarshal the JSON string to get the unescaped value.
		var unescaped string
		if err := json.Unmarshal([]byte(raw), &unescaped); err != nil {
			continue // skip malformed strings
		}

		if unescaped == "" {
			continue // nothing to redact in empty strings
		}

		// Run secret detection on the unescaped value.
		redacted, err := o.detectAndReplace(unescaped)
		if err != nil {
			return "", err
		}

		if redacted == unescaped {
			continue // no secrets found, skip re-encoding
		}

		// Re-escape the redacted value back to a JSON string.
		reescaped, err := json.Marshal(redacted)
		if err != nil {
			return "", err
		}

		// Splice the re-escaped string into the original content.
		s = s[:pos.start] + string(reescaped) + s[pos.end:]
	}

	return s, nil
}
