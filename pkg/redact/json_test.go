package redact_test

import (
	"encoding/json"
	"os"
	"testing"

	"go.iscode.ca/redact/pkg/redact"
)

func TestRedactJSON(t *testing.T) {
	b, err := os.ReadFile("../../examples/gitleaks.toml")
	if err != nil {
		t.Fatalf("unable to read rules: %v", err)
	}

	tests := []struct {
		name     string
		in       string
		expected string
	}{
		{
			name:     "password hash in JSON object",
			in:       `{"password": "$6$abc$secrethash123"}`,
			expected: `{"password": "$6$**REDACTED**"}`,
		},
		{
			name:     "PEM private key with escaped newlines",
			in:       `{"private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\nKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\no3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k\nTQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7\n9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy\nv/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs\n/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00\n-----END RSA PRIVATE KEY-----"}`, //gitleaks:allow
			expected: `{"private_key": "**REDACTED**-"}`,
		},
		{
			name:     "preserves JSON formatting",
			in:       "{\n  \"user\": \"root\",\n  \"hash\": \"$6$abc$secrethash123\"\n}",
			expected: "{\n  \"user\": \"root\",\n  \"hash\": \"$6$**REDACTED**\"\n}",
		},
		{
			name:     "nested JSON objects",
			in:       `{"db": {"password": "$6$abc$secrethash123"}, "name": "mydb"}`,
			expected: `{"db": {"password": "$6$**REDACTED**"}, "name": "mydb"}`,
		},
		{
			name:     "JSON array values",
			in:       `{"hashes": ["$6$abc$hash1", "$6$def$hash2"]}`,
			expected: `{"hashes": ["$6$**REDACTED**", "$6$**REDACTED**"]}`,
		},
		{
			name:     "context-dependent secret in JSON value",
			in:       `{"docker.io":{ "auth": "eW9tYW53aGF0c3VwCg=="}}`,
			expected: `{"docker.io":{ "auth": "**REDACTED**"}}`,
		},
		{
			name:     "keys are not scanned",
			in:       `{"$6$abc$secrethash": "value"}`,
			expected: `{"$6$abc$secrethash": "value"}`,
		},
		{
			name:     "non-JSON falls back to text mode",
			in:       "root:$6$abc$secrethash123:18515:0:99999:7:::",
			expected: "root:$6$**REDACTED**:18515:0:99999:7:::",
		},
	}

	r := redact.New(redact.WithRules(string(b)))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := r.Redact(tt.in)
			if err != nil {
				t.Fatalf("Redact() error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("Redact() =\n%s\nwant:\n%s", got, tt.expected)
			}
			if json.Valid([]byte(tt.in)) && !json.Valid([]byte(got)) {
				t.Errorf("output is not valid JSON:\n%s", got)
			}
		})
	}
}
