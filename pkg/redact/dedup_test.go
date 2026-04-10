package redact

import (
	"testing"
)

func TestDeduplicateReplacements_cascadingOverlap(t *testing.T) {
	// Regression test: three overlapping replacements where pairwise
	// deduplication previously dropped coverage for the earliest region.
	//
	// B(0-10), C(5-15), A(12-100):
	//   Old behavior: B replaced by C (larger), C replaced by A (larger),
	//   region 0-12 lost entirely.
	//   Fixed behavior: spans are merged so the final span covers 0-100.
	input := "0123456789ABCDEfghijklmnopqrstuvwxyz0123456789ABCDEfghijklmnopqrstuvwxyz0123456789ABCDEfghijklmnopqrstuv"

	reps := []replacement{
		{start: 0, end: 10, text: "[B]"},
		{start: 5, end: 15, text: "[C]"},
		{start: 12, end: 100, text: "[A]"},
	}

	result := applyReplacements(input, reps)

	// The merged span should cover 0-100, replacing the entire string.
	if result == input {
		t.Fatal("expected replacements to be applied, got original string")
	}

	// Verify the region 0-12 is NOT present in the output (it was
	// dropped by the old algorithm).
	if len(result) > len(input) {
		t.Fatalf("result is longer than input, something went wrong: %q", result)
	}

	// The old buggy behavior would produce "[A]" (only the largest span),
	// losing characters 0-11. The fix merges all three into one span
	// covering 0-100, so we should get a single replacement.
	expected := applyReplacements(input, []replacement{
		{start: 0, end: 100, text: "[A]"},
	})
	if result != expected {
		t.Errorf("deduplicateReplacements() result = %q, want %q", result, expected)
	}
}

func TestDeduplicateReplacements_noOverlap(t *testing.T) {
	input := "aaa SECRET1 bbb SECRET2 ccc"

	reps := []replacement{
		{start: 4, end: 11, text: "[R1]"},
		{start: 16, end: 23, text: "[R2]"},
	}

	result := applyReplacements(input, reps)
	expected := "aaa [R1] bbb [R2] ccc"
	if result != expected {
		t.Errorf("result = %q, want %q", result, expected)
	}
}

func TestDeduplicateReplacements_simpleOverlap(t *testing.T) {
	input := "0123456789ABCDEF"

	// Two overlapping replacements: the larger one's text should be kept.
	reps := []replacement{
		{start: 2, end: 8, text: "[small]"},
		{start: 4, end: 14, text: "[large]"},
	}

	result := applyReplacements(input, reps)

	// Merged span covers 2-14.
	expected := "01[large]EF"
	if result != expected {
		t.Errorf("result = %q, want %q", result, expected)
	}
}
