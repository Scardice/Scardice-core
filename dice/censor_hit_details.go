package dice

import (
	"encoding/base64"
	"fmt"
	"strings"
)

const maxCensorHitContextRunes = 80

func censorHitContext(content string, words []string) string {
	contentRunes := []rune(content)
	if len(contentRunes) <= maxCensorHitContextRunes {
		return content
	}

	contentLower := strings.ToLower(content)
	hitStart := -1
	hitLen := 0
	for _, word := range words {
		if word == "" {
			continue
		}
		byteIndex := strings.Index(contentLower, strings.ToLower(word))
		if byteIndex < 0 {
			continue
		}
		start := len([]rune(contentLower[:byteIndex]))
		if hitStart < 0 || start < hitStart {
			hitStart = start
			hitLen = len([]rune(word))
		}
	}
	if hitStart < 0 {
		return "..."
	}

	start := hitStart
	if hitLen < maxCensorHitContextRunes {
		start -= (maxCensorHitContextRunes - hitLen) / 2
	}
	start = max(0, min(start, len(contentRunes)-maxCensorHitContextRunes))
	end := start + maxCensorHitContextRunes

	context := string(contentRunes[start:end])
	if start > 0 {
		context = "..." + context
	}
	if end < len(contentRunes) {
		context += "..."
	}
	return context
}

func formatCensorHitDetails(levelText string, words []string, content string) string {
	encodedWords := make([]string, 0, len(words))
	for _, word := range words {
		encodedWords = append(encodedWords, base64.StdEncoding.EncodeToString([]byte(word)))
	}
	context := censorHitContext(content, words)

	return fmt.Sprintf(
		"检测到<%s>级敏感词。\n命中词(Base64): %s\n上下文片段(Base64): %s",
		levelText,
		strings.Join(encodedWords, " | "),
		base64.StdEncoding.EncodeToString([]byte(context)),
	)
}
