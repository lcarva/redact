// Package redact parses a file removing any detected secrets.
package redact

import (
	"cmp"
	_ "embed"
	"go/token"
	"regexp"
	"slices"
	"strings"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"go.iscode.ca/redact/pkg/redact/overwrite"
)

const ReplacementText = "**REDACTED**"

type Opt struct {
	rules          string
	overwrite      overwrite.Replacer
	base64MinLength int
	d              *detect.Detector
	err            error
}

type Option func(*Opt)

// WithOverwrite sets the method for overwriting secrets:
//
//   - redact: substitute the secret with the redaction string
//   - mask: set each character of the secret with the first letter of the
//     redaction string
func WithOverwrite(overwrite overwrite.Replacer) Option {
	return func(o *Opt) {
		o.overwrite = overwrite
	}
}

// WithBase64MinLength sets the minimum length of base64-encoded strings to
// check for secrets. Set to 0 to disable base64 detection.
func WithBase64MinLength(n int) Option {
	return func(o *Opt) {
		o.base64MinLength = n
	}
}

// WithRules adds gitleaks rules to the configuration.
func WithRules(s string) Option {
	return func(o *Opt) {
		if s != "" {
			o.rules = s
		}
	}
}

// New sets the configuration for the redaction process.
func New(opt ...Option) *Opt {
	o := &Opt{
		rules:     config.DefaultConfig,
		overwrite: &overwrite.Redact{Text: ReplacementText},
	}

	for _, fn := range opt {
		fn(o)
	}

	d, err := newDetectorFromTOML(o.rules)
	if err != nil {
		o.err = err
	}
	o.d = d

	return o
}

func (o *Opt) Err() error {
	return o.err
}

// Redact removes secrets detected in the provided string.
func (o *Opt) Redact(s string) (string, error) {
	if o.err != nil {
		return "", o.err
	}

	return o.detectAndReplace(s)
}

// replacement represents a byte range in the original string to be
// replaced with new text.
type replacement struct {
	start int
	end   int
	text  string
}

// detectReplacements returns the replacements for secrets detected in
// the string without applying them.
func (o *Opt) detectReplacements(s string) []replacement {
	var replacements []replacement

	// Gitleaks findings.
	findings := o.d.DetectString(s)

	fset := token.NewFileSet()
	f := fset.AddFile("", -1, len(s))
	f.SetLinesForContent([]byte(s))

	// * token package
	//
	// 	* line: 1-based
	// 	* offset: 0-based (from start of file to beginning of line)
	//
	// * gitleaks detect package
	//
	//	* line: 0-based
	//	* column: 1-based, includes newline at start of line(?)
	//
	// The gitleaks appears to work as follows for the string "abc\n\n\n123\n":
	//
	// abc
	// ^0:1
	// \n
	// ^1:1
	// \n
	// ^2:1
	// \n123
	// ^3:1
	//   ^3:2
	// \n
	// ^4:1
	//
	// For example, for the content:
	//
	// 		12345
	// 		ABCDE
	//
	// 01234 567890 (0-based)
	// 12345 678901 (1-based)
	// 12345\nABCDE\n
	// ^ TOKEN:1,offset=1/0 GITLEAKS:0:1
	//        ^ GITLEAKS:1:2
	//        ^ TOKEN:2,offset=7/6
	for _, finding := range findings {
		nl := 1 // gitleaks column offset is 1-based.
		if finding.StartLine > 0 {
			nl++ // Newline included in column count at start of line.
		}
		pos := f.LineStart(finding.StartLine + 1)
		// Convert 1-based column offset to 0-based string offset accounting for newline.
		off := f.Offset(pos) + (finding.StartColumn - nl)
		off += strings.Index(finding.Match, finding.Secret)
		replacements = append(replacements, replacement{
			start: off,
			end:   off + len(finding.Secret),
			text:  o.overwrite.Replace(finding.Secret),
		})
	}

	// Base64-encoded secrets.
	for _, span := range o.detectBase64Secrets(s) {
		replacements = append(replacements, replacement{
			start: span.start,
			end:   span.end,
			text:  o.overwrite.Replace(s[span.start:span.end]),
		})
	}

	return replacements
}

// applyReplacements deduplicates, sorts, and applies replacements to the string.
func applyReplacements(s string, replacements []replacement) string {
	replacements = deduplicateReplacements(replacements)

	// Sort by start descending: replacing from back to front
	// ensures earlier offsets remain valid.
	slices.SortFunc(replacements, func(a, b replacement) int {
		return cmp.Compare(b.start, a.start)
	})

	for _, r := range replacements {
		s = s[:r.start] + r.text + s[r.end:]
	}

	return s
}

// detectAndReplace runs gitleaks detection on a string and replaces
// any detected secrets using the configured overwrite strategy.
func (o *Opt) detectAndReplace(s string) (string, error) {
	return applyReplacements(s, o.detectReplacements(s)), nil
}

// deduplicateReplacements removes overlapping replacements by merging
// overlapping spans, keeping the replacement text of the larger span.
func deduplicateReplacements(reps []replacement) []replacement {
	if len(reps) <= 1 {
		return reps
	}

	slices.SortFunc(reps, func(a, b replacement) int {
		return cmp.Compare(a.start, b.start)
	})

	var result []replacement
	for _, r := range reps {
		if len(result) > 0 {
			last := &result[len(result)-1]
			if r.start < last.end {
				// Overlap: merge spans, keep the larger one's text.
				rSpan := r.end - r.start
				lastSpan := last.end - last.start
				if r.end > last.end {
					last.end = r.end
				}
				if rSpan > lastSpan {
					last.text = r.text
				}
				continue
			}
		}
		result = append(result, r)
	}

	return result
}

func newDetectorFromTOML(s string) (*detect.Detector, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(s)); err != nil {
		return nil, err
	}

	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return nil, err
	}

	// Handle the extend mechanism manually to avoid the gitleaks
	// global extendDepth counter which silently stops working after
	// 2 calls to Translate() with useDefault=true.
	wantDefault := vc.Extend.UseDefault
	vc.Extend.UseDefault = false
	vc.Extend.Path = ""

	cfg, err := vc.Translate()
	if err != nil {
		return nil, err
	}

	if wantDefault {
		defaultCfg, err := translateTOML(config.DefaultConfig)
		if err != nil {
			return nil, err
		}
		for ruleID, rule := range defaultCfg.Rules {
			if _, ok := cfg.Rules[ruleID]; !ok {
				cfg.Rules[ruleID] = rule
				cfg.Keywords = append(cfg.Keywords, rule.Keywords...)
				cfg.OrderedRules = append(cfg.OrderedRules, ruleID)
			}
		}
	}

	// Overwrite the default private key rule with a regexp with non-greedy matching.
	cfg.Rules["private-key"] = config.Rule{
		Description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
		RuleID:      "private-key",
		Regex:       regexp.MustCompile(`(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY( BLOCK)?-----[\s\S-]*?KEY( BLOCK)?----`),
		Keywords:    []string{"-----BEGIN"},
	}

	return detect.NewDetector(cfg), nil
}

// translateTOML parses a gitleaks TOML config string into a Config
// without using the extend mechanism.
func translateTOML(s string) (config.Config, error) {
	v := viper.New()
	v.SetConfigType("toml")
	if err := v.ReadConfig(strings.NewReader(s)); err != nil {
		return config.Config{}, err
	}

	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, err
	}

	vc.Extend.UseDefault = false
	vc.Extend.Path = ""

	return vc.Translate()
}
