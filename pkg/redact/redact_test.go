package redact_test

import (
	"os"
	"testing"

	"github.com/rs/zerolog"
	"go.iscode.ca/redact/pkg/redact"
	"go.iscode.ca/redact/pkg/redact/overwrite"
)

type secrets struct {
	in     string
	redact string
	mask   string
}

var testSecrets = []secrets{
	{`token="abcdef1234567890abcdef"`, `token="**REDACTED**"`, `token="**********************"`},
	{"$9$abc123", "$9$**REDACTED**", "$9$******"},
	{"x$9$abc123\ndef456", "x$9$**REDACTED**\ndef456", "x$9$******\ndef456"},
	{"x$9$abc123\ndef456\n$M$qwqe21034", "x$9$**REDACTED**\ndef456\n$M$**REDACTED**", "x$9$******\ndef456\n$M$*********"},
	{"root:$6$d468dc01f1cd655d$1c0a188389f4db6399265080815ac488ea65c3295a18d2d7da3ce5e8ef082362adeedec9b69.9704d4d188:18515:0:99999:7:::", "root:$6$**REDACTED**:18515:0:99999:7:::", "root:$6$*******************************************************************************************************:18515:0:99999:7:::"},

	// Test keys from https://phpseclib.com/docs/rsa-keys
	{`-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu
KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm
o3qGy0t6z09AIJtH+5OeRV1be+N4cDYJKffGzDa88vQENZiRm0GRq6a+HPGQMd2k
TQIhAKMSvzIBnni7ot/OSie2TmJLY4SwTQAevXysE2RbFDYdAiEBCUEaRQnMnbp7
9mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUCIG2Es59z8ugGrDY+pxLQnwfotadxd+Uy
v/Ow5T0q5gIJAiEAyS4RaI9YG8EWx/2w0T67ZUVAw8eOMB6BIUg0Xcu+3okCIBOs
/5OiPgoTdSy7bcF9IGpSE8ZgGKzgYQVZeN97YE00
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,5C724CE55C702828F3F74B555F594366

odKAmV6AbsoWsyL3thUoYVDEJAsQl8RrH+JuQ9HWUnDLunDdLEM6oNl15XP1xLOH
z3bEq1rvATiQmAByKNOiVujd1gsq7JxfQYDdHRzDhZZrUstnetvGTDBtMHmhzbBX
Oih+1q3eA2RMQ5izXOEkyMKrWWlcKMWVJzMSYjFeFJB8D8wJNmq1ArNCO3uXfwkZ
uMnMhYhx/OYvCs4sMWKe5/etyR2gz0Fvp6VDUa0jNRvoad+8/pHK7KDxB8nW5Kgm
pSjfkl1Ut3zChtwEuAFnSDuypbrODBdphZHD40WmX0f69VKKs44vsKCHr8nzJ8R5
dw+2Ggyq5W5hl3PDTMTqn8Pc+cwmPdVe4bkNqxbCHe2omZXpNIgC31wrMBvkyUYv
pY8rMoBXqgm9hC5JsXzn6Z6X1kpGFhDjkNSdzx4jYzw=
-----END RSA PRIVATE KEY-----
-----BEGIN RSA PUBLIC KEY-----
MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnx
S30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE=
-----END RSA PUBLIC KEY-----
`,
		`**REDACTED**-
**REDACTED**-
-----BEGIN RSA PUBLIC KEY-----
MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnx
S30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE=
-----END RSA PUBLIC KEY-----
`,
		`***********************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-
**********************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-
-----BEGIN RSA PUBLIC KEY-----
MEgCQQCo9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnx
S30WAvQCCo2yU1orfgqr41mM70MBAgMBAAE=
-----END RSA PUBLIC KEY-----
`,
	},
	{`-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAqPfgaTEWEP3S9w0t
gsicURfo+nLW09/0KfOPinhYZ4ouzU+3xC4pSlEp8Ut9FgL0AgqNslNaK34Kq+NZ
jO9DAQIDAQABAkAgkuLEHLaqkWhLgNKagSajeobLS3rPT0Agm0f7k55FXVt743hw
Ngkp98bMNrzy9AQ1mJGbQZGrpr4c8ZAx3aRNAiEAoxK/MgGeeLui385KJ7ZOYktj
hLBNAB69fKwTZFsUNh0CIQEJQRpFCcydunv2bENcN/oBTRw39E8GNv2pIcNxZkcb
NQIgbYSzn3Py6AasNj6nEtCfB+i1p3F35TK/87DlPSrmAgkCIQDJLhFoj1gbwRbH
/bDRPrtlRUDDx44wHoEhSDRdy77eiQIgE6z/k6I+ChN1LLttwX0galITxmAYrOBh
BVl433tgTTQ=
-----END PRIVATE KEY-----
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIpZHwLtkYRb4CAggA
MAwGCCqGSIb3DQIJBQAwHQYJYIZIAWUDBAECBBCCGsoP7F4bd8O5I1poTn8PBIIB
YBtM1tgqsAQgbSZT0475aHufzFuJuPWOYqiHag8OUKMeZuxVHndElipEY2V5lS9m
wddwtWaGuYD/Swcdt0Xht8U8BF0SjSyzQ4YtRsG9CmEHYhWmQ5AqK1W3mDUApO38
Cm5L1HrHV4YJnYmmK9jgq+iWlLFDmB8s4TA6kMPWbCENlpr1kEXz4hLwY3ylH8XW
I65WX2jGSn61jayCwpf1HPFBPDUaS5s3f92aKjk0AE8htsDBBiCVS3Yjq4QSbhfz
uNIZ1TooXT9Xn+EJC0yjVnlTHZMfqrcA3OmVSi4kftugjAax4Z2qDqO+onkgeJAw
P75scMcwH0SQUdrNrejgfIzJFWzcH9xWwKhOT9s9hLx2OfPlMtDDSJVRspqwwQrF
QwinX0cR9Hx84rSMrFndxZi52o9EOLJ7cithncoW1KOAf7lIJIUzP0oIKkskAndQ
o2UiZsxgoMYuq02T07DOknc=
-----END ENCRYPTED PRIVATE KEY-----
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END PUBLIC KEY-----
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAVwAAAAdzc2gtcn
NhAAAAAwEAAQAAAEEAqPfgaTEWEP3S9w0tgsicURfo+nLW09/0KfOPinhYZ4ouzU+3xC4p
SlEp8Ut9FgL0AgqNslNaK34Kq+NZjO9DAQAAATB+9/CSfvfwkgAAAAdzc2gtcnNhAAAAQQ
Co9+BpMRYQ/dL3DS2CyJxRF+j6ctbT3/Qp84+KeFhnii7NT7fELilKUSnxS30WAvQCCo2y
U1orfgqr41mM70MBAAAAAwEAAQAAAEAgkuLEHLaqkWhLgNKagSajeobLS3rPT0Agm0f7k5
5FXVt743hwNgkp98bMNrzy9AQ1mJGbQZGrpr4c8ZAx3aRNAAAAIBOs/5OiPgoTdSy7bcF9
IGpSE8ZgGKzgYQVZeN97YE00AAAAIQCjEr8yAZ54u6Lfzkontk5iS2OEsE0AHr18rBNkWx
Q2HQAAACEBCUEaRQnMnbp79mxDXDf6AU0cN/RPBjb9qSHDcWZHGzUAAAAXcGhwc2VjbGli
LWdlbmVyYXRlZC1rZXkBAgME
-----END OPENSSH PRIVATE KEY-----
`,
		`**REDACTED**-
**REDACTED**-
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END PUBLIC KEY-----
**REDACTED**-
`,
		`****************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-
**********************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
-----END PUBLIC KEY-----
*************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************************-
`},
}

func init() {
	zerolog.SetGlobalLevel(zerolog.DebugLevel)
}

func TestOpt_Redact(t *testing.T) {
	b, err := os.ReadFile("../../examples/gitleaks.toml")
	if err != nil {
		t.Fatalf("unable to read rules: %v", err)
	}

	r := redact.New(redact.WithRules(string(b)))

	for _, v := range testSecrets {
		s, err := r.Redact(v.in)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if s != v.redact {
			t.Fatalf("redact failed: out=%s expected=%s", s, v.mask)
		}
	}
}

func TestOpt_Redact_mask(t *testing.T) {
	b, err := os.ReadFile("../../examples/gitleaks.toml")
	if err != nil {
		t.Fatalf("unable to read rules: %v", err)
	}

	r := redact.New(redact.WithRules(string(b)), redact.WithOverwrite(&overwrite.Mask{Char: byte('*')}))

	for _, v := range testSecrets {
		s, err := r.Redact(v.in)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if s != v.mask {
			//os.WriteFile("/tmp/failed.txt", []byte(s), 0644)
			t.Fatalf("redact failed: out=%s expected=%s", s, v.mask)
		}
	}
}

func TestOpt_Redact_redacttext(t *testing.T) {
	ts := []secrets{
		{"x$9$abc123\ndef456\n$M$qwqe21034", "x$9$XXX\ndef456\n$M$XXX", "x$9$XXXXXX\ndef456\n$M$XXXXXXXXX"},
	}

	b, err := os.ReadFile("../../examples/gitleaks.toml")
	if err != nil {
		t.Fatalf("unable to read rules: %v", err)
	}

	r := redact.New(redact.WithRules(string(b)), redact.WithOverwrite(&overwrite.Redact{Text: "XXX"}))

	for _, v := range ts {
		s, err := r.Redact(v.in)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if s != v.redact {
			t.Fatalf("redact failed: out=%s expected=%s", s, v.redact)
		}
	}

	rmask := redact.New(redact.WithRules(string(b)), redact.WithOverwrite(&overwrite.Mask{Char: byte('X')}))

	for _, v := range ts {
		s, err := rmask.Redact(v.in)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if s != v.mask {
			t.Fatalf("redact failed: out=%s expected=%s", s, v.mask)
		}
	}
}
