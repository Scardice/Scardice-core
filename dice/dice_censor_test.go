package dice

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestFormatCensorHitDetailsEncodesWordsAndContext(t *testing.T) {
	// Given
	words := []string{"敏感词一", "敏感词二"}
	content := "前文 敏感词一 后文"

	// When
	got := formatCensorHitDetails("警告", words, content)

	// Then
	for _, raw := range append(words, content) {
		if strings.Contains(got, raw) {
			t.Fatalf("encoded details leaked raw content %q", raw)
		}
	}
	for _, raw := range append(words, content) {
		encoded := base64.StdEncoding.EncodeToString([]byte(raw))
		if !strings.Contains(got, encoded) {
			t.Fatalf("encoded details missing Base64 value %q", encoded)
		}
	}
}

func TestFormatCensorHitDetailsLimitsContextAroundHit(t *testing.T) {
	// Given
	word := "敏感词"
	content := strings.Repeat("前", maxCensorHitContextRunes) + word + strings.Repeat("后", maxCensorHitContextRunes)

	// When
	got := formatCensorHitDetails("警告", []string{word}, content)
	const contextPrefix = "\n上下文片段(Base64): "
	contextAt := strings.LastIndex(got, contextPrefix)
	if contextAt < 0 {
		t.Fatalf("encoded context missing from details: %q", got)
	}
	decodedContext, err := base64.StdEncoding.DecodeString(got[contextAt+len(contextPrefix):])
	if err != nil {
		t.Fatalf("decode context: %v", err)
	}
	context := string(decodedContext)

	// Then
	if !strings.Contains(context, word) {
		t.Fatalf("limited context does not include hit word: %q", context)
	}
	if !strings.HasPrefix(context, "...") || !strings.HasSuffix(context, "...") {
		t.Fatalf("limited context does not mark omitted text: %q", context)
	}
	if gotRunes, wantMax := len([]rune(context)), maxCensorHitContextRunes+6; gotRunes > wantMax {
		t.Fatalf("limited context has %d runes, want at most %d", gotRunes, wantMax)
	}
}

func TestCensorHitContextReturnsOmissionMarkerWhenLongContentHasNoHit(t *testing.T) {
	// Given
	content := strings.Repeat("内容", maxCensorHitContextRunes)

	// When
	got := censorHitContext(content, []string{"not-present"})

	// Then
	if got != "..." {
		t.Fatalf("context without a direct hit = %q, want omission marker", got)
	}
}
