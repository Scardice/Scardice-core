package dice

import (
	"path/filepath"
	"testing"

	"github.com/xuri/excelize/v2"
)

func TestUnescapeXlsxHelpContentPreservesEscapeSemantics(t *testing.T) {
	// Given
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "escaped newline", content: `first\nsecond`, want: "first\nsecond"},
		{name: "real newline", content: "first\nsecond", want: "first\nsecond"},
		{name: "escaped backslash protects newline", content: `first\\nsecond`, want: `first\nsecond`},
		{name: "unknown escape", content: `first\xsecond`, want: `first\xsecond`},
		{name: "trailing backslash", content: `first\`, want: `first\`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// When
			got := unescapeXlsxHelpContent(test.content)

			// Then
			if got != test.want {
				t.Fatalf("unescaped XLSX content = %q, want %q", got, test.want)
			}
		})
	}
}

func TestParseHelpDocXLSXUnescapesContent(t *testing.T) {
	// Given
	filePath := filepath.Join(t.TempDir(), "help.xlsx")
	file := excelize.NewFile()
	sheet := file.GetSheetName(0)
	if err := file.SetSheetRow(sheet, "A1", &[]any{"Key", "Synonym", "Content"}); err != nil {
		t.Fatalf("set XLSX header: %v", err)
	}
	if err := file.SetSheetRow(sheet, "A2", &[]any{"entry", "", `first\nsecond`}); err != nil {
		t.Fatalf("set XLSX content: %v", err)
	}
	if err := file.SaveAs(filePath); err != nil {
		t.Fatalf("save XLSX: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close XLSX: %v", err)
	}

	// When
	items, err := parseHelpDocXLSX("test", filePath)

	// Then
	if err != nil {
		t.Fatalf("parse XLSX: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("parsed XLSX items = %d, want 1", len(items))
	}
	if items[0].Content != "first\nsecond" {
		t.Fatalf("parsed XLSX content = %q, want escaped newline converted", items[0].Content)
	}
}

func TestXlsxParserChangeInvalidatesHelpCaches(t *testing.T) {
	// Given / When / Then
	if helpIndexSchemaVersion < 3 {
		t.Fatalf("help index schema version = %d, want at least 3", helpIndexSchemaVersion)
	}
	if helpDocParsedCacheVersion < 3 {
		t.Fatalf("parsed help cache version = %d, want at least 3", helpDocParsedCacheVersion)
	}
}
