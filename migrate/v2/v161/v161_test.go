package v161

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	upgrade "Scardice-core/utils/upgrader"
	"Scardice-core/utils/upgrader/store"
)

func Test_V161MigrateNoticeTargets_preserves_notice_ids_without_copying_dice_masters(t *testing.T) {
	// Given
	configPath := filepath.Join(t.TempDir(), "serve.yaml")
	original := []byte(`diceMasters:
  - QQ:10001
noticeIds:
  - QQ:20002
  - QQ-Group:30003:disable
  - OpenQQ-Group:100-app-OpenQQ:100-user:only=ban,group,ban
commandPrefix:
  - .
`)
	if err := os.WriteFile(configPath, original, 0o644); err != nil {
		t.Fatalf("write legacy serve config: %v", err)
	}

	// When
	if err := V161MigrateNoticeTargets(configPath); err != nil {
		t.Fatalf("migrate notice targets: %v", err)
	}

	// Then
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read migrated serve config: %v", err)
	}
	var got struct {
		DiceMasters   []string `yaml:"diceMasters"`
		NoticeIDs     []string `yaml:"noticeIds"`
		CommandPrefix []string `yaml:"commandPrefix"`
	}
	if err := yaml.Unmarshal(content, &got); err != nil {
		t.Fatalf("decode migrated serve config: %v", err)
	}
	wantNoticeIDs := []string{
		"QQ:20002",
		"QQ-Group:30003:disable",
		"OpenQQ-Group:100-app-OpenQQ:100-user:only=group,ban",
	}
	if !reflect.DeepEqual(got.NoticeIDs, wantNoticeIDs) {
		t.Fatalf("noticeIds = %#v, want lossless %#v", got.NoticeIDs, wantNoticeIDs)
	}
	if !reflect.DeepEqual(got.DiceMasters, []string{"QQ:10001"}) {
		t.Fatalf("diceMasters = %#v, want permission-only list unchanged", got.DiceMasters)
	}
	if !reflect.DeepEqual(got.CommandPrefix, []string{"."}) {
		t.Fatalf("commandPrefix = %#v, want unrelated config unchanged", got.CommandPrefix)
	}
}

func Test_V161MigrateNoticeTargets_missing_config_is_noop(t *testing.T) {
	// Given
	configPath := filepath.Join(t.TempDir(), "serve.yaml")

	// When
	err := V161MigrateNoticeTargets(configPath)

	// Then
	if err != nil {
		t.Fatalf("missing config migration error = %v, want nil", err)
	}
}

func Test_V161NoticeTargetsMigration_runs_once_with_JSON_records(t *testing.T) {
	// Given
	workDir := t.TempDir()
	configDir := filepath.Join(workDir, "data", "default")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		t.Fatalf("create config directory: %v", err)
	}
	configPath := filepath.Join(configDir, "serve.yaml")
	if err := os.WriteFile(configPath, []byte("diceMasters: [QQ:10001]\nnoticeIds: ['QQ:20002:only=ban,group']\n"), 0o644); err != nil {
		t.Fatalf("write initial config: %v", err)
	}
	t.Chdir(workDir)
	metadataPath := filepath.Join(workDir, "upgrade_metadata.json")
	newManager := func() *upgrade.Manager {
		manager := &upgrade.Manager{Store: store.NewJSONStore(metadataPath)}
		manager.Register(V161NoticeIDsMigration)
		return manager
	}
	if err := newManager().ApplyAll(); err != nil {
		t.Fatalf("apply migration: %v", err)
	}
	if err := os.WriteFile(configPath, []byte("diceMasters: [QQ:10001]\nnoticeIds: ['QQ:changed:only=ban,group']\n"), 0o644); err != nil {
		t.Fatalf("write post-migration user config: %v", err)
	}

	// When
	if err := newManager().ApplyAll(); err != nil {
		t.Fatalf("reapply migration: %v", err)
	}

	// Then
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read post-migration config: %v", err)
	}
	if string(content) != "diceMasters: [QQ:10001]\nnoticeIds: ['QQ:changed:only=ban,group']\n" {
		t.Fatalf("completed migration rewrote user config: %q", content)
	}
	records, err := store.NewJSONStore(metadataPath).LoadRecords()
	if err != nil {
		t.Fatalf("load migration records: %v", err)
	}
	if len(records) != 1 || records[0].ID != V161NoticeIDsMigration.ID || !records[0].Success {
		t.Fatalf("migration records = %#v, want one successful 011 record", records)
	}
}
