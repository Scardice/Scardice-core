package jsengine

import (
	"reflect"
	"testing"
	"time"
)

func TestParseUserScriptMetadata(t *testing.T) {
	metadata, err := ParseUserScript(`// ==UserScript==
// @name demo
// @author author
// @version 1.2.3
// @homepageURL https://example.test
// @license MIT
// @description line\nnext
// @timestamp 1700000000
// @updateUrl https://example.test/demo.js
// @updateUrl https://mirror.test/demo.js
// @etag revision
// @depends dep-author:dependency:>=1.0.0
// @depends another-author:another-dependency
// @runtime quickjs:Scardice,goja:Scardice
// @sealVersion >=1.4.0
// @needCompiled true
// @storeID demo-store
// ==/UserScript==`)
	if err != nil {
		t.Fatal(err)
	}
	want := UserScriptMetadata{
		Name: "demo", Author: "author", Version: "1.2.3",
		HomePage: "https://example.test", License: "MIT",
		Description: "line\nnext", UpdateTime: 1700000000,
		UpdateURLs: []string{"https://example.test/demo.js", "https://mirror.test/demo.js"},
		Etag:       "revision",
		Depends: []UserScriptDependency{
			{Author: "dep-author", Name: "dependency", Constraint: ">=1.0.0", RawKey: "dep-author:dependency:>=1.0.0"},
			{Author: "another-author", Name: "another-dependency", RawKey: "another-author:another-dependency"},
		},
		Runtime: "quickjs:Scardice,goja:Scardice", SealVersion: ">=1.4.0",
		NeedCompiled: true, StoreID: "demo-store",
	}
	if !reflect.DeepEqual(metadata, want) {
		t.Fatalf("metadata = %#v, want %#v", metadata, want)
	}
}

func TestParseUserScriptTimestamp(t *testing.T) {
	for _, tc := range []struct {
		name  string
		value string
		want  int64
	}{
		{name: "date", value: "2024-01-02T03:04:05Z", want: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC).Unix()},
		{name: "invalid", value: "not-a-date", want: 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := ParseUserScript("// ==UserScript==\n// @timestamp " + tc.value + "\n// ==/UserScript==")
			if err != nil || metadata.UpdateTime != tc.want {
				t.Fatalf("timestamp = %d, err = %v; want %d", metadata.UpdateTime, err, tc.want)
			}
		})
	}
}

func TestParseUserScriptDependency(t *testing.T) {
	metadata, err := ParseUserScript("// ==UserScript==\n// @depends  author : plugin : >=1.0.0 || >=2.0.0  \n// ==/UserScript==")
	if err != nil {
		t.Fatal(err)
	}
	want := []UserScriptDependency{{Author: "author", Name: "plugin", Constraint: ">=1.0.0 || >=2.0.0", RawKey: "author : plugin : >=1.0.0 || >=2.0.0"}}
	if !reflect.DeepEqual(metadata.Depends, want) {
		t.Fatalf("dependencies = %#v, want %#v", metadata.Depends, want)
	}
	for _, dependency := range []string{"plugin", ":plugin", "author:", "author: :>=1", "author:plugin:"} {
		t.Run(dependency, func(t *testing.T) {
			metadata, err := ParseUserScript("// ==UserScript==\n// @depends " + dependency + "\n// @depends author:valid\n// @name retained\n// ==/UserScript==")
			if err == nil {
				t.Fatal("invalid dependency accepted")
			}
			if metadata.Name != "retained" || len(metadata.Depends) != 1 || metadata.Depends[0].Name != "valid" {
				t.Fatalf("valid metadata was lost after invalid dependency: %#v", metadata)
			}
		})
	}
}

func TestParseUserScriptHeaderBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		want   UserScriptMetadata
	}{
		{name: "plain script", source: "const value = 1;\n// @runtime invalid"},
		{name: "unclosed header", source: "// ==UserScript==\n// @name incomplete\n// @runtime invalid"},
		{name: "CRLF and tabs", source: "\t//\t==UserScript==\t\r\n\t//\t@name\tdemo\t\r\n\t// ==/UserScript==\r\n", want: UserScriptMetadata{Name: "demo"}},
		{name: "empty value does not consume next field", source: "// ==UserScript==\n// @name \n// @author author\n// ==/UserScript==", want: UserScriptMetadata{Author: "author"}},
		{name: "only comment fields", source: "// ==UserScript==\n@name ignored\n// @author author\n// ==/UserScript==", want: UserScriptMetadata{Author: "author"}},
		{name: "first header only", source: "// ==UserScript==\n// @name first\n// ==/UserScript==\n// @name outside\n// ==UserScript==\n// @name second\n// ==/UserScript==", want: UserScriptMetadata{Name: "first"}},
		{name: "unknown field", source: "// ==UserScript==\n// @unknown value\n// @name demo\n// ==/UserScript==", want: UserScriptMetadata{Name: "demo"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := ParseUserScript(tc.source)
			if err != nil || !reflect.DeepEqual(metadata, tc.want) {
				t.Fatalf("metadata = %#v, err = %v; want %#v", metadata, err, tc.want)
			}
		})
	}
}

func TestParseRuntimeSelectors(t *testing.T) {
	selectors, err := ParseRuntimeSelectors(" QuickJS:某人, goja:Scardice ")
	if err != nil {
		t.Fatal(err)
	}
	want := []RuntimeSelector{
		{ID: "quickjs", Author: "某人"},
		{ID: "goja", Author: "Scardice"},
	}
	if !reflect.DeepEqual(selectors, want) {
		t.Fatalf("selectors = %#v, want %#v", selectors, want)
	}
}

func TestParseUserScriptRejectsInvalidRuntimeSelectors(t *testing.T) {
	for _, selector := range []string{"", "quickjs", ":author", "quickjs:", "quickjs:author,", ",quickjs:author", "quickjs:author,,goja:author"} {
		t.Run(selector, func(t *testing.T) {
			if _, err := ParseRuntimeSelectors(selector); err == nil {
				t.Fatal("invalid selector accepted")
			}
			source := "// ==UserScript==\n// @runtime " + selector + "\n// ==/UserScript=="
			if _, err := ParseUserScript(source); err == nil {
				t.Fatal("invalid runtime metadata accepted")
			}
			if hint, present := UserScriptRuntimeHint(source); !present || hint != selector {
				t.Fatalf("explicit invalid hint lost: %q, %v", hint, present)
			}
		})
	}
}

func TestUserScriptRuntimeHint(t *testing.T) {
	for _, tc := range []struct {
		name        string
		source      string
		want        string
		present     bool
		metadataErr bool
	}{
		{name: "selector", source: "// ==UserScript==\n// @runtime\tquickjs:某人,goja:Scardice\n// ==/UserScript==", want: "quickjs:某人,goja:Scardice", present: true},
		{name: "unrelated malformed field", source: "// ==UserScript==\n// @depends invalid\n// @runtime quickjs:某人\n// ==/UserScript==", want: "quickjs:某人", present: true, metadataErr: true},
		{name: "absent", source: "// ==UserScript==\n// @name demo\n// ==/UserScript=="},
		{name: "outside header", source: "// @runtime quickjs:某人\nconsole.log('demo');"},
		{name: "unclosed header", source: "// ==UserScript==\n// @runtime quickjs:某人"},
		{name: "noncomment", source: "// ==UserScript==\n@runtime quickjs:某人\n// ==/UserScript=="},
		{name: "first selector declaration", source: "// ==UserScript==\n// @runtime quickjs:某人\n// @runtime goja:Scardice\n// ==/UserScript==", want: "quickjs:某人", present: true},
		{name: "CRLF", source: "// ==UserScript==\r\n// @runtime quickjs:某人\r\n// ==/UserScript==\r\n", want: "quickjs:某人", present: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hint, present := UserScriptRuntimeHint(tc.source)
			if present != tc.present || hint != tc.want {
				t.Fatalf("hint = %q, present = %v; want %q, %v", hint, present, tc.want, tc.present)
			}
			metadata, err := ParseUserScript(tc.source)
			if (err != nil) != tc.metadataErr || metadata.Runtime != tc.want {
				t.Fatalf("metadata runtime = %q, err = %v; want %q, error = %v", metadata.Runtime, err, tc.want, tc.metadataErr)
			}
		})
	}
}
