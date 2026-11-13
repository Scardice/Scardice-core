//lint:file-ignore testpackage Tests need access to unexported helpers
package dice //nolint:testpackage // tests rely on unexported helpers

import "testing"

func TestMigrateCoreTextKey(t *testing.T) {
	d := &Dice{
		TextMapRaw: TextTemplateWithWeightDict{
			"核心": {
				"骰子状态附加文本": {
					{"old", 1},
				},
			},
		},
	}

	if !migrateCoreTextKey(d, "骰子状态附加文本", "骰子状态文本") {
		t.Fatalf("expected migrateCoreTextKey to migrate existing old key")
	}

	coreTexts := d.TextMapRaw["核心"]
	if _, ok := coreTexts["骰子状态附加文本"]; ok {
		t.Fatalf("expected old key removed after migration")
	}
	if _, ok := coreTexts["骰子状态文本"]; !ok {
		t.Fatalf("expected new key created after migration")
	}
}

func TestMigrateCoreTextKey_NewKeyExists_OldWins(t *testing.T) {
	d := &Dice{
		TextMapRaw: TextTemplateWithWeightDict{
			"核心": {
				"骰子状态附加文本": {
					{"old", 1},
				},
				"骰子状态文本": {
					{"new", 1},
				},
			},
		},
	}

	if !migrateCoreTextKey(d, "骰子状态附加文本", "骰子状态文本") {
		t.Fatalf("expected migration to delete old key when new key already exists")
	}

	coreTexts := d.TextMapRaw["核心"]
	if _, ok := coreTexts["骰子状态附加文本"]; ok {
		t.Fatalf("expected old key removed when new key exists")
	}
	if got := coreTexts["骰子状态文本"][0][0]; got != "old" {
		t.Fatalf("expected migrated old content preserved, got %v", got)
	}
}

func TestMigrateHelpTextKey_NewKeyExists_OldWins(t *testing.T) {
	d := &Dice{
		TextMapRaw: TextTemplateWithWeightDict{
			"核心": {
				"骰子帮助文本_附加说明": {
					{"legacy-help", 1},
				},
				"骰子帮助文本": {
					{"default-help", 1},
				},
			},
		},
	}

	if !migrateHelpTextKey(d) {
		t.Fatalf("expected migrateHelpTextKey to migrate existing old key")
	}

	coreTexts := d.TextMapRaw["核心"]
	if _, ok := coreTexts["骰子帮助文本_附加说明"]; ok {
		t.Fatalf("expected old help key removed after migration")
	}
	if got := coreTexts["骰子帮助文本"][0][0]; got != "legacy-help" {
		t.Fatalf("expected legacy help content preserved, got %v", got)
	}
}

func TestMigrateSpecialFeatureHelpTextToFeaturedFeature(t *testing.T) {
	d := &Dice{
		TextMapRaw: TextTemplateWithWeightDict{
			"核心": {
				"骰子帮助文本_特殊功能": {{"骰主已填写的教程", 1}},
				"骰子帮助文本_特色功能": {{"新默认文本", 1}},
			},
		},
		TextMapHelpInfo: TextTemplateWithHelpDict{
			"核心": {
				"骰子帮助文本_特殊功能": {SubType: ".help"},
			},
		},
	}

	if !migrateCoreTextKey(d, "骰子帮助文本_特殊功能", "骰子帮助文本_特色功能") {
		t.Fatal("expected special feature help text migration")
	}
	coreTexts := d.TextMapRaw["核心"]
	if _, exists := coreTexts["骰子帮助文本_特殊功能"]; exists {
		t.Fatal("old special feature help key still exists")
	}
	if _, exists := d.TextMapHelpInfo["核心"]["骰子帮助文本_特殊功能"]; exists {
		t.Fatal("old special feature UI help metadata still exists")
	}
	if got := coreTexts["骰子帮助文本_特色功能"][0][0]; got != "骰主已填写的教程" {
		t.Fatalf("migrated featured feature help = %v", got)
	}
}

func TestRestoreMissingBuiltinTextEntriesAfterOldUIReplacement(t *testing.T) {
	d := &Dice{}
	setupBaseTextTemplate(d)

	// Simulate an older WebUI saving the whole core category without fields
	// introduced by a newer backend.
	d.TextMapRaw["核心"] = TextTemplateWithWeight{
		"骰子帮助文本": {{"旧页面保留的帮助", 1}},
	}

	if !RestoreMissingBuiltinTextEntries(d, "核心") {
		t.Fatal("expected missing builtin entries to be restored")
	}
	for _, key := range []string{
		"骰子帮助文本_骰点",
		"骰子帮助文本_房规",
		"骰子帮助文本_特色功能",
	} {
		if _, exists := d.TextMapRaw["核心"][key]; !exists {
			t.Fatalf("missing restored builtin entry %q", key)
		}
		if got := d.TextMapHelpInfo["核心"][key].SubType; got != ".help" {
			t.Fatalf("restored builtin entry %q subtype = %q, want .help", key, got)
		}
	}
	if got := d.TextMapRaw["核心"]["骰子帮助文本"][0][0]; got != "旧页面保留的帮助" {
		t.Fatalf("existing text was overwritten: %v", got)
	}
}
