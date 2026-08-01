package dice

import "strings"

func unescapeXlsxHelpContent(content string) string {
	if !strings.Contains(content, `\`) {
		return content
	}

	var result strings.Builder
	result.Grow(len(content))
	for index := 0; index < len(content); index++ {
		if content[index] != '\\' || index+1 >= len(content) {
			result.WriteByte(content[index])
			continue
		}
		switch content[index+1] {
		case 'n':
			result.WriteByte('\n')
			index++
		case '\\':
			result.WriteByte('\\')
			index++
		default:
			result.WriteByte(content[index])
		}
	}
	return result.String()
}
