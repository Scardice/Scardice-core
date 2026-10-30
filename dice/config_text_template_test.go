package dice

import (
	"os"
	"path/filepath"
	"testing"

	"go.uber.org/zap"
)

func TestInitializeTextTemplatesUsesBuiltinsWithoutUserConfig(t *testing.T) {
	d := &Dice{Logger: zap.NewNop().Sugar()}
	d.BaseConfig.DataDir = t.TempDir()

	d.initializeTextTemplates()

	got := d.TextMapRaw["核心"]["骰子名字"][0][0]
	if got != "余烬核心" {
		t.Fatalf("builtin dice name = %v, want %q", got, "余烬核心")
	}
}

func TestInitializeTextTemplatesUsesUserConfigWhenPresent(t *testing.T) {
	dataDir := t.TempDir()
	configDir := filepath.Join(dataDir, "configs")
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	config := []byte("核心:\n  骰子名字:\n    - [用户骰名, 1]\n  空文案: []\n")
	if err := os.WriteFile(filepath.Join(configDir, "text-template.yaml"), config, 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	d.BaseConfig.DataDir = dataDir
	d.initializeTextTemplates()

	if got := d.TextMapRaw["核心"]["骰子名字"][0][0]; got != "用户骰名" {
		t.Fatalf("user dice name = %v, want %q", got, "用户骰名")
	}
	if _, exists := d.TextMapRaw["核心"]["骰子状态文本"]; exists {
		t.Fatal("builtin text absent from user config was merged into the user's file")
	}
	if got, exists := d.TextMapRaw["核心"]["空文案"]; !exists || got == nil || len(got) != 0 {
		t.Fatalf("empty user text = %#v, want an explicitly empty list", got)
	}
}

func TestInitializeTextTemplatesFailsOnUnexpectedConfigPathError(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "configs"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Dice{Logger: zap.NewNop().Sugar()}
	d.BaseConfig.DataDir = dataDir
	defer func() {
		recovered := recover()
		if _, ok := recovered.(*os.PathError); !ok {
			t.Fatalf("config path error panic = %#v, want *os.PathError", recovered)
		}
	}()

	d.initializeTextTemplates()
}
