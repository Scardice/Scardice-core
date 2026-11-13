package dice

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadGameSystemTemplateFromHJSON(t *testing.T) {
	content := []byte(`{
  # true HJSON: unquoted keys and omitted commas
  name: "hjson-template"
  fullName: "HJSON Template"
  authors: ["tester"]
  version: "1.0.0"
  templateVer: "2"
  attrs: {
    defaults: {
      hp: 10
    }
    defaultsComputed: {}
  }
}`)

	tmpl, err := LoadGameSystemTemplateFromBytes(content, "hjson")
	if err != nil {
		t.Fatalf("LoadGameSystemTemplateFromBytes hjson: %v", err)
	}
	if tmpl.Name != "hjson-template" {
		t.Fatalf("template name = %q, want hjson-template", tmpl.Name)
	}
	if got := tmpl.Attrs.Defaults["hp"]; got != 10 {
		t.Fatalf("template hp default = %d, want 10", got)
	}
}

func TestLoadLegacyGameSystemTemplateFromJSONFallbackToHJSON(t *testing.T) {
	content := []byte(`{
  # true HJSON legacy template in a .json-style load path
  name: "legacy-hjson-template"
  fullName: "Legacy HJSON Template"
  authors: ["tester"]
  version: "1.0.0"
  templateVer: "1"
  defaults: {
    hp: 8
  }
  defaultsComputed: {}
  nameTemplate: {}
  attrConfig: {}
  setConfig: {}
}`)

	tmpl, err := LoadGameSystemTemplateFromBytes(content, "json")
	if err != nil {
		t.Fatalf("LoadGameSystemTemplateFromBytes json fallback hjson: %v", err)
	}
	if tmpl.Name != "legacy-hjson-template" {
		t.Fatalf("legacy template name = %q, want legacy-hjson-template", tmpl.Name)
	}
	if got := tmpl.Attrs.Defaults["hp"]; got != 8 {
		t.Fatalf("legacy template hp default = %d, want 8", got)
	}
}

func TestCollectGameSystemTemplateFilesIncludesHJSON(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"one.hjson", "two.jsonc", "skip.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	files, err := collectGameSystemTemplateFiles(dir)
	if err != nil {
		t.Fatalf("collectGameSystemTemplateFiles: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("collected files = %#v, want two JSON-like template files", files)
	}
}

func TestParseHelpDocJSONFallsBackToHJSON(t *testing.T) {
	root := switchToTempWorkdir(t)
	path := writeRawTestHelpDocFile(t, root, "hjson/help.hjson", `{
  # true HJSON helpdoc
  mod: "hjson-help-pack"
  author: "tester"
  brief: "test"
  comment: "test"
  helpdoc: {
    hjsonEntry: "hello from hjson"
  }
}`)

	items, err := parseHelpDocJSON("hjson", path)
	if err != nil {
		t.Fatalf("parseHelpDocJSON hjson: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("items len = %d, want 1", len(items))
	}
	if items[0].Title != "hjsonEntry" || items[0].Content != "hello from hjson" || items[0].PackageName != "hjson-help-pack" {
		t.Fatalf("unexpected help item: %#v", items[0])
	}

	files, err := collectHelpDocFiles(filepath.Join(root, "data", "helpdoc"))
	if err != nil {
		t.Fatalf("collectHelpDocFiles: %v", err)
	}
	if len(files) != 1 || filepath.Base(files[0].Path) != "help.hjson" {
		t.Fatalf("collectHelpDocFiles = %#v, want help.hjson", files)
	}
}

func TestCustomReplyConfigReadFromHJSON(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "reply.hjson")
	if err := os.WriteFile(path, []byte(`{
  # true HJSON reply config
  enable: true
  name: "hjson-reply"
  author: ["tester"]
  items: [
    {
      enable: true
    }
  ]
}`), 0o644); err != nil {
		t.Fatalf("write reply hjson: %v", err)
	}

	rc, err := CustomReplyConfigReadFromPath(&Dice{}, path, "reply.hjson")
	if err != nil {
		t.Fatalf("CustomReplyConfigReadFromPath hjson: %v", err)
	}
	if !rc.Enable || rc.Name != "hjson-reply" || len(rc.Items) != 1 || !rc.Items[0].Enable {
		t.Fatalf("unexpected reply config: %#v", rc)
	}
}
