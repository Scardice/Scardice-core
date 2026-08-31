package dice

import (
	"strings"
	"testing"
)

func TestGenerateRandomStringUsesReaderUniformly(t *testing.T) {
	got, err := generateRandomString(strings.NewReader("\x00\x01\x02"), 3, "abc")
	if err != nil {
		t.Fatalf("generateRandomString() error = %v", err)
	}
	if got != "abc" {
		t.Fatalf("generateRandomString() = %q, want %q", got, "abc")
	}
}

func TestGenerateRandomStringRejectsInvalidAlphabet(t *testing.T) {
	if _, err := generateRandomString(strings.NewReader(""), 1, ""); err == nil {
		t.Fatal("generateRandomString() accepted an empty alphabet")
	}
}

func TestGenerateFourDigitCodeReturnsFourDigits(t *testing.T) {
	code, err := generateFourDigitCode()
	if err != nil {
		t.Fatalf("generateFourDigitCode() error = %v", err)
	}
	if len(code) != 4 {
		t.Fatalf("generateFourDigitCode() length = %d, want 4", len(code))
	}
	if code[0] == '0' {
		t.Fatalf("generateFourDigitCode() returned a leading zero: %q", code)
	}
}
