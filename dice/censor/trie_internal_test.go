package censor

import (
	"reflect"
	"testing"
)

func Test_trie_Match(t1 *testing.T) {
	t := newTire()
	t.Insert("nmsl", Danger)
	t.Insert("nn主人", Warning)

	type args struct {
		text string
	}
	tests := []struct {
		name               string
		args               args
		wantSensitiveWords map[string]Level
	}{
		{
			"no keyword",
			args{"--------"},
			map[string]Level{},
		},
		{
			"one keyword",
			args{"--nmsl--"},
			map[string]Level{"nmsl": Danger},
		},
		{
			"keyword is a prefix",
			args{"nmsl----"},
			map[string]Level{"nmsl": Danger},
		},
		{
			"keyword is a suffix",
			args{"----nmsl"},
			map[string]Level{"nmsl": Danger},
		},
		{
			"two keywords",
			args{"nmslnn主人--------"},
			map[string]Level{
				"nmsl": Danger,
				"nn主人": Warning,
			},
		},
		{
			"two separated keywords",
			args{"nmsl--nn主人------"},
			map[string]Level{
				"nmsl": Danger,
				"nn主人": Warning,
			},
		},
	}
	for _, tt := range tests {
		t1.Run(tt.name, func(t1 *testing.T) {
			if gotSensitiveWords := t.Match(tt.args.text); !reflect.DeepEqual(gotSensitiveWords, tt.wantSensitiveWords) {
				t1.Errorf("Match() = %v, want %v", gotSensitiveWords, tt.wantSensitiveWords)
			}
		})
	}
}

func TestTrieMatchPreservesRuneAndPrefixSemantics(t *testing.T) {
	tr := newTire()
	for word, level := range map[string]Level{
		"a": Notice, "ab": Danger, "bc": Warning,
		"你": Caution, "你好": Danger, "\uFFFDx": Danger,
	} {
		tr.Insert(word, level)
	}
	want := map[string]Level{"a": Notice, "bc": Warning, "你": Caution, "\uFFFDx": Danger}
	if got := tr.Match("abcbc你好 \xffx ab"); !reflect.DeepEqual(got, want) {
		t.Fatalf("shortest terminals, overlaps or invalid UTF-8 changed: got %v, want %v", got, want)
	}
	if got := tr.Match(""); got == nil || len(got) != 0 {
		t.Fatalf("empty input must return an empty non-nil map: %v", got)
	}
	if got := (&trie{}).Match("a"); got != nil {
		t.Fatalf("uninitialized trie must return nil: %v", got)
	}
}
