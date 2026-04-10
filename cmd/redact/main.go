// redact secrets from files using gitleaks rules.
//
// By default, the redacted text is written to stdout. Use the -i option
// to modify the source file.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"go.iscode.ca/redact/internal/pkg/fdpair"
	"go.iscode.ca/redact/pkg/redact"
	"go.iscode.ca/redact/pkg/redact/overwrite"
)

const (
	version = "0.4.1"
)

type state struct {
	inplace bool
	skip    []string
}

func usage() {
	fmt.Fprintf(os.Stderr, `%s v%s
Usage: %s [<option>] <file|directory|-> <...>

Redact secrets from files.

Examples:

  # redact files in-place
  redact -i file.txt file.json file.yml

  # from stdin
  cat file | redact -

Options:

`, path.Base(os.Args[0]), version, os.Args[0])
	flag.PrintDefaults()
}

func getenv(s, def string) string {
	if v, ok := os.LookupEnv(s); ok {
		return v
	}
	return def
}

func getenvbool(s string) bool {
	_, ok := os.LookupEnv(s)
	return ok
}

func getenvint(s string, def int) int {
	v, ok := os.LookupEnv(s)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func main() {
	envSkip := getenv("REDACT_SKIP", ".git .gitleaks.toml")
	envRemove := getenv("REDACT_REMOVE", "redact")
	envSubstitute := getenv("REDACT_SUBSTITUTE", redact.ReplacementText)
	envRules := getenv("REDACT_RULES", "")
	envLogLevel := getenv("REDACT_LOG_LEVEL", zerolog.LevelErrorValue)
	envBase64MinLength := getenvint("REDACT_BASE64_MIN_LENGTH", 20)

	envInPlace := getenvbool("REDACT_INPLACE")

	remove := flag.String("remove", envRemove, "Redaction method: redact, mask")
	substitute := flag.String("substitute", envSubstitute, "Text used to overwrite secrets")
	flag.StringVar(substitute, "s", envSubstitute, "Text used to overwrite secrets")
	rules := flag.String("rules", envRules, "Path to file containing gitleaks rules")
	logLevel := flag.String("log-level", envLogLevel, "Set log level")
	skip := flag.String("skip", envSkip, "Skip glob matches in directories")
	flag.StringVar(skip, "S", envSkip, "Skip glob matches in directories")
	base64MinLength := flag.Int("base64-min-length", envBase64MinLength, "Minimum base64 string length to check for secrets (0 to disable)")

	inplace := flag.Bool("inplace", envInPlace, "Redact the file in-place")
	flag.BoolVar(inplace, "i", envInPlace, "Redact the file in-place")

	flag.Usage = func() { usage() }
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	l, err := zerolog.ParseLevel(*logLevel)
	if err != nil {
		flag.Usage()
		os.Exit(2)
	}
	zerolog.SetGlobalLevel(l)

	b, err := readRules(*rules)
	if err != nil {
		log.Fatal().Msg(err.Error())
	}

	st := &state{
		inplace: *inplace,
		skip:    strings.Fields(*skip),
	}

	var replace overwrite.Replacer = &overwrite.Redact{Text: *substitute}

	before, after, ok := strings.Cut(*remove, ":")

	switch before {
	case "redact":
	case "mask":
		unmasked := 0
		if ok {
			n, err := strconv.Atoi(after)
			if err != nil {
				log.Fatal().Msg(err.Error())
			}
			if n < 0 || n > 100 {
				log.Fatal().Str("arg", after).Msg("unmasked value must be a percentage in range 0-100")
			}
			unmasked = n
		}

		var char byte = '*'
		if len(*substitute) > 0 {
			char = (*substitute)[0]
		}
		replace = &overwrite.Mask{Char: char, Unmasked: unmasked}
	default:
		log.Fatal().Str("arg", before).Msg("invalid option for --remove")
	}

	red := redact.New(
		redact.WithOverwrite(replace),
		redact.WithRules(string(b)),
		redact.WithBase64MinLength(*base64MinLength),
	)

	for _, v := range flag.Args() {
		switch v {
		case "-":
			rw := &stdio{
				r:     os.Stdin,
				state: st,
			}

			if err := st.run(rw, red); err != nil {
				log.Fatal().Str("path", v).Msg(err.Error())
			}

		default:
			if err := filepath.WalkDir(v, st.walkFunc(red)); err != nil {
				log.Fatal().Str("path", v).Msg(err.Error())
			}
		}
	}
}

func (st *state) walkFunc(red *redact.Opt) fs.WalkDirFunc {
	return func(path string, de fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		for _, pattern := range st.skip {
			matched, err := filepath.Match(filepath.Join(filepath.Dir(path), pattern), path)
			if err != nil {
				return fmt.Errorf("%s: %w", path, err)
			}

			if !matched {
				log.Debug().Str("path", path).Str("match", pattern).Msg("glob")
				continue
			}

			if de.IsDir() {
				log.Warn().Str("path", path).Str("match", pattern).Msg("skipped")
				return filepath.SkipDir
			}

			return nil
		}

		if de.Type() != 0 {
			return nil
		}

		log.Info().Str("path", path).Msg("matched")

		r, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		defer func() {
			err = errors.Join(err, r.Close())
		}()

		rw := &fsobj{
			r:     r,
			state: st,
		}

		return st.run(rw, red)
	}
}

func (st *state) run(rw fdpair.FD, red *redact.Opt) error {
	in := ""

	if f, ok := rw.In().(*os.File); ok {
		in = f.Name()
	}

	err := rw.Open()
	if err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}

	defer func() {
		err = errors.Join(err, rw.Close())
	}()

	b, err := io.ReadAll(rw.In())
	if err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}

	s, err := red.Redact(string(b))
	if err != nil {
		return fmt.Errorf("%s: %w", in, err)
	}

	out := ""

	if f, ok := rw.Out().(*os.File); ok {
		out = f.Name()
	}

	if _, err := io.WriteString(rw.Out(), s); err != nil {
		return fmt.Errorf("%s: %w", out, err)
	}

	return nil
}

func readRules(s string) ([]byte, error) {
	if s != "" {
		return os.ReadFile(s)
	}
	b, _ := os.ReadFile(".gitleaks.toml")
	return b, nil
}
