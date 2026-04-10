package redact_test

import (
	"encoding/base64"
	"os"
	"testing"

	"go.iscode.ca/redact/pkg/redact"
)

func TestRedactBase64(t *testing.T) {
	b, err := os.ReadFile("../../examples/gitleaks.toml")
	if err != nil {
		t.Fatalf("unable to read rules: %v", err)
	}

	// Base64 encode a crypt password hash that gitleaks custom rules will detect.
	secret := "$6$salt$hash123456789"
	encoded := base64.StdEncoding.EncodeToString([]byte(secret))

	// Base64 encode a PEM private key.
	pemKey := "-----BEGIN RSA PRIVATE KEY-----\n" + //gitleaks:allow
		"MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n" +
		"KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\n" +
		"o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k\n" +
		"TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7\n" +
		"9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy\n" +
		"v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs\n" +
		"/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00\n" +
		"-----END RSA PRIVATE KEY-----"
	encodedPEM := base64.StdEncoding.EncodeToString([]byte(pemKey))

	tests := []struct {
		name         string
		in           string
		expected     string
		base64MinLen int
	}{
		{
			name:         "base64-encoded secret detected",
			in:           "payload " + encoded,
			expected:     "payload **REDACTED**",
			base64MinLen: 20,
		},
		{
			name:         "base64-encoded PEM key detected",
			in:           "key: " + encodedPEM,
			expected:     "key: **REDACTED**",
			base64MinLen: 20,
		},
		{
			name:         "below min length ignored",
			in:           "short: " + base64.StdEncoding.EncodeToString([]byte("hi")),
			expected:     "short: " + base64.StdEncoding.EncodeToString([]byte("hi")),
			base64MinLen: 20,
		},
		{
			name:         "non-secret base64 ignored",
			in:           "data: " + base64.StdEncoding.EncodeToString([]byte("hello world, this is normal text")),
			expected:     "data: " + base64.StdEncoding.EncodeToString([]byte("hello world, this is normal text")),
			base64MinLen: 20,
		},
		{
			name:         "base64 detection disabled",
			in:           "payload " + encoded,
			expected:     "payload " + encoded,
			base64MinLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := redact.New(
				redact.WithRules(string(b)),
				redact.WithBase64MinLength(tt.base64MinLen),
			)
			got, err := r.Redact(tt.in)
			if err != nil {
				t.Fatalf("Redact() error: %v", err)
			}
			if got != tt.expected {
				t.Errorf("Redact() =\n%s\nwant:\n%s", got, tt.expected)
			}
		})
	}
}
