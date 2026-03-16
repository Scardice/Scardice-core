package dice

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSortJsScripts(t *testing.T) {
	type args struct {
		jsScripts []*JsScriptInfo
	}
	tests := []struct {
		name    string
		args    args
		want    []*JsScriptInfo
		wantErr bool
	}{
		{
			name: "test only builtins",
			args: args{
				jsScripts: []*JsScriptInfo{
					{
						Name:    "A",
						Author:  "sealdice",
						Builtin: true,
					},
					{
						Name:    "B",
						Author:  "sealdice",
						Builtin: true,
						Depends: []JsScriptDepends{
							{
								Author: "sealdice",
								Name:   "C",
							},
						},
					},
					{
						Name:    "C",
						Author:  "sealdice",
						Builtin: true,
						Depends: []JsScriptDepends{
							{
								Author: "sealdice",
								Name:   "A",
							},
						},
					},
					{
						Name:    "D",
						Author:  "sealdice",
						Builtin: true,
						Depends: []JsScriptDepends{
							{
								Author: "sealdice",
								Name:   "B",
							},
							{
								Author: "sealdice",
								Name:   "C",
							},
						},
					},
				},
			},
			want: []*JsScriptInfo{
				{
					Name:    "A",
					Author:  "sealdice",
					Builtin: true,
				},
				{
					Name:    "C",
					Author:  "sealdice",
					Builtin: true,
				},
				{
					Name:    "B",
					Author:  "sealdice",
					Builtin: true,
				},
				{
					Name:    "D",
					Author:  "sealdice",
					Builtin: true,
				},
			},
			wantErr: false,
		},
		{
			name: "test only not builtins",
			args: args{
				jsScripts: []*JsScriptInfo{
					{
						Name:    "A",
						Author:  "JustAnotherID",
						Builtin: false,
					},
					{
						Name:    "B",
						Author:  "JustAnotherID",
						Builtin: false,
						Depends: []JsScriptDepends{
							{
								Author: "JustAnotherID",
								Name:   "C",
							},
						},
					},
					{
						Name:    "C",
						Author:  "JustAnotherID",
						Builtin: false,
						Depends: []JsScriptDepends{
							{
								Author: "JustAnotherID",
								Name:   "A",
							},
						},
					},
				}},
			want: []*JsScriptInfo{
				{
					Name:    "A",
					Author:  "JustAnotherID",
					Builtin: false,
				},
				{
					Name:    "C",
					Author:  "JustAnotherID",
					Builtin: false,
				},
				{
					Name:    "B",
					Author:  "JustAnotherID",
					Builtin: false,
				},
			},
			wantErr: false,
		},
		{
			name: "test both",
			args: args{
				jsScripts: []*JsScriptInfo{
					{
						Name:    "A",
						Author:  "sealdice",
						Builtin: true,
					},
					{
						Name:    "B",
						Author:  "JustAnotherID",
						Builtin: false,
					},
					{
						Name:    "C",
						Author:  "JustAnotherID",
						Builtin: false,
						Depends: []JsScriptDepends{
							{
								Author: "sealdice",
								Name:   "A",
							},
						},
					},
					{
						Name:    "D",
						Author:  "sealdice",
						Builtin: true,
						Depends: []JsScriptDepends{
							{
								Author: "sealdice",
								Name:   "A",
							},
						},
					},
					{
						Name:    "E",
						Author:  "sealdice",
						Builtin: true,
						Depends: []JsScriptDepends{
							{
								Author: "sealdice",
								Name:   "A",
							},
							{
								Author: "sealdice",
								Name:   "D",
							},
						},
					},
				}},
			want: []*JsScriptInfo{
				{
					Name:    "A",
					Author:  "sealdice",
					Builtin: true,
				},
				{
					Name:    "D",
					Author:  "sealdice",
					Builtin: true,
				},
				{
					Name:    "E",
					Author:  "sealdice",
					Builtin: true,
				},
				{
					Name:    "B",
					Author:  "JustAnotherID",
					Builtin: false,
				},
				{
					Name:    "C",
					Author:  "JustAnotherID",
					Builtin: false,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, errMap := sortJsScripts(tt.args.jsScripts)
			if len(errMap) != 0 && !tt.wantErr {
				t.Errorf("sortJsScripts() errMap = %v", errMap)
				return
			}
			if !sameScriptInfos(got, tt.want) {
				t.Errorf("sortJsScripts() got = %v, want %v", showScriptInfos(got), showScriptInfos(tt.want))
			}
		})
	}
}

func showScriptInfos(jsScripts []*JsScriptInfo) string {
	var result []string
	for _, jsScript := range jsScripts {
		result = append(result, fmt.Sprintf("%s::%s", jsScript.Author, jsScript.Name))
	}
	return "[" + strings.Join(result, ", ") + "]"
}

func sameScriptInfos(a []*JsScriptInfo, b []*JsScriptInfo) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !sameScriptInfo(a[i], b[i]) {
			return false
		}
	}
	return true
}

func sameScriptInfo(a *JsScriptInfo, b *JsScriptInfo) bool {
	if a.Name != b.Name {
		return false
	}
	if a.Author != b.Author {
		return false
	}
	if a.Builtin != b.Builtin {
		return false
	}
	return true
}

func TestDetectDangerousAPIUsages(t *testing.T) {
	t.Run("detect seal.inst usage", func(t *testing.T) {
		usages := detectDangerousAPIUsages([]byte(`
const core = seal.inst;
seal.inst.Save(false);
seal.inst.Config;
`))
		if len(usages) != 1 {
			t.Fatalf("expected 1 dangerous api usage, got %d", len(usages))
		}
		if usages[0].ID != "seal.inst" {
			t.Fatalf("expected seal.inst usage, got %s", usages[0].ID)
		}
		if len(usages[0].Occurrences) != 3 {
			t.Fatalf("expected 3 occurrences, got %d", len(usages[0].Occurrences))
		}
		if usages[0].Occurrences[1].Access != "seal.inst.Save()" {
			t.Fatalf("expected second occurrence access to be seal.inst.Save(), got %s", usages[0].Occurrences[1].Access)
		}
		if usages[0].Occurrences[1].MemberDescription == "" {
			t.Fatalf("expected second occurrence to include member description")
		}
		if usages[0].Occurrences[2].Access != "seal.inst.Config" {
			t.Fatalf("expected third occurrence access to be seal.inst.Config, got %s", usages[0].Occurrences[2].Access)
		}
		if len(usages[0].ReferencedMembers) != 2 {
			t.Fatalf("expected 2 referenced members, got %d", len(usages[0].ReferencedMembers))
		}
	})

	t.Run("ignore commented seal.inst", func(t *testing.T) {
		usages := detectDangerousAPIUsages([]byte(`
// seal.inst should not be treated as a real call
/*
seal.inst should not be treated as a real call
*/
const text = "seal.inst";
`))
		if len(usages) != 0 {
			t.Fatalf("expected no dangerous api usage, got %d", len(usages))
		}
	})

	t.Run("direct reference keeps empty arrays instead of nil", func(t *testing.T) {
		usages := detectDangerousAPIUsages([]byte(`
const core = seal.inst;
`))
		if len(usages) != 1 {
			t.Fatalf("expected 1 dangerous api usage, got %d", len(usages))
		}
		if usages[0].ReferencedMembers == nil {
			t.Fatalf("expected referencedMembers to be an empty slice instead of nil")
		}
		if len(usages[0].ReferencedMembers) != 0 {
			t.Fatalf("expected no referenced members, got %d", len(usages[0].ReferencedMembers))
		}
		if usages[0].Occurrences == nil {
			t.Fatalf("expected occurrences to be a non-nil slice")
		}
	})

	t.Run("detect optional and bracket seal inst usage", func(t *testing.T) {
		usages := detectDangerousAPIUsages([]byte(`
seal?.inst?.save();
seal["inst"].config;
seal?.["inst"]?.advancedConfig;
seal.inst["diceMasters"];
`))
		if len(usages) != 1 {
			t.Fatalf("expected 1 dangerous api usage, got %d", len(usages))
		}
		if len(usages[0].Occurrences) != 4 {
			t.Fatalf("expected 4 occurrences, got %d", len(usages[0].Occurrences))
		}
		if usages[0].Occurrences[0].Access != "seal.inst.save()" {
			t.Fatalf("expected first occurrence access to be seal.inst.save(), got %s", usages[0].Occurrences[0].Access)
		}
		if usages[0].Occurrences[1].Access != `seal.inst.config` {
			t.Fatalf("expected second occurrence access to be seal.inst.config, got %s", usages[0].Occurrences[1].Access)
		}
		if usages[0].Occurrences[2].Access != `seal.inst.advancedConfig` {
			t.Fatalf("expected third occurrence access to be seal.inst.advancedConfig, got %s", usages[0].Occurrences[2].Access)
		}
		if usages[0].Occurrences[3].Access != `seal.inst["diceMasters"]` {
			t.Fatalf("expected fourth occurrence access to be seal.inst[\"diceMasters\"], got %s", usages[0].Occurrences[3].Access)
		}
		if len(usages[0].ReferencedMembers) != 4 {
			t.Fatalf("expected 4 referenced members, got %d", len(usages[0].ReferencedMembers))
		}
	})

	t.Run("detect seal inst inside template literal expressions", func(t *testing.T) {
		usages := detectDangerousAPIUsages([]byte(
			"const x = `${seal.inst.Save(false)}`;\n" +
				"const y = `${seal[\"inst\"].config}`;\n",
		))
		if len(usages) != 1 {
			t.Fatalf("expected 1 dangerous api usage, got %d", len(usages))
		}
		if len(usages[0].Occurrences) != 2 {
			t.Fatalf("expected 2 occurrences, got %d", len(usages[0].Occurrences))
		}
		if usages[0].Occurrences[0].Access != "seal.inst.Save()" {
			t.Fatalf("expected first occurrence access to be seal.inst.Save(), got %s", usages[0].Occurrences[0].Access)
		}
		if usages[0].Occurrences[1].Access != `seal.inst.config` {
			t.Fatalf("expected second occurrence access to be seal.inst.config, got %s", usages[0].Occurrences[1].Access)
		}
	})
}

func TestJsParseMetaDangerousAPIUsages(t *testing.T) {
	d := &Dice{}
	info, err := d.JsParseMeta(
		"./data/scripts/test.js",
		time.Unix(1700000000, 0),
		[]byte(`// ==UserScript==
// @name Dangerous Script
// ==/UserScript==
const core = seal.inst;
`),
		false,
	)
	if err != nil {
		t.Fatalf("JsParseMeta returned error: %v", err)
	}
	if !info.HasDangerousAPIUsage {
		t.Fatalf("expected dangerous api usage flag to be true")
	}
	if len(info.DangerousAPIUsages) != 1 {
		t.Fatalf("expected 1 dangerous api usage, got %d", len(info.DangerousAPIUsages))
	}
	if info.DangerousAPIUsages[0].ID != "seal.inst" {
		t.Fatalf("expected seal.inst usage, got %s", info.DangerousAPIUsages[0].ID)
	}
	if len(info.DangerousAPIUsages[0].Occurrences) != 1 {
		t.Fatalf("expected 1 dangerous api occurrence, got %d", len(info.DangerousAPIUsages[0].Occurrences))
	}
	if info.DangerousAPIUsages[0].Occurrences[0].Line != 4 {
		t.Fatalf("expected occurrence line to be 4, got %d", info.DangerousAPIUsages[0].Occurrences[0].Line)
	}
}

func TestNormalizeDangerousAPIUsages(t *testing.T) {
	usages := normalizeDangerousAPIUsages([]JsDangerousAPIUsage{
		{
			ID:                "seal.inst",
			Name:              "seal.inst",
			Description:       "desc",
			Risk:              "risk",
			Occurrences:       nil,
			ReferencedMembers: nil,
		},
	})
	if len(usages) != 1 {
		t.Fatalf("expected 1 usage, got %d", len(usages))
	}
	if usages[0].Occurrences == nil {
		t.Fatalf("expected occurrences to be normalized to an empty slice")
	}
	if usages[0].ReferencedMembers == nil {
		t.Fatalf("expected referencedMembers to be normalized to an empty slice")
	}
}

func TestIsCompatibleJsMetaCacheEntry(t *testing.T) {
	if isCompatibleJsMetaCacheEntry(jsMetaCacheEntry{}) {
		t.Fatalf("expected old cache entry without dangerous api data to be incompatible")
	}
	if !isCompatibleJsMetaCacheEntry(jsMetaCacheEntry{
		Meta: jsMetaInfo{DangerousAPIUsages: []JsDangerousAPIUsage{}},
	}) {
		t.Fatalf("expected cache entry with dangerous api data field to be compatible")
	}
}
