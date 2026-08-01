package store_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	upgrade "Scardice-core/utils/upgrader"
	"Scardice-core/utils/upgrader/store"
)

func TestJSONStore_SaveRecord_preserves_existing_schema_and_attempt_order(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	firstAttempt := upgrade.UpgradeRecord{
		ID:        "001",
		Timestamp: time.Date(2026, time.August, 1, 12, 0, 0, 0, time.UTC),
		Success:   false,
		Message:   "interrupted",
		Logs:      []string{"started"},
	}
	secondAttempt := upgrade.UpgradeRecord{
		ID:        "001",
		Timestamp: time.Date(2026, time.August, 1, 12, 1, 0, 0, time.UTC),
		Success:   true,
		Message:   "成功",
		Logs:      []string{"resumed"},
	}

	// When
	jsonStore := store.NewJSONStore(path)
	if err := jsonStore.SaveRecord(firstAttempt); err != nil {
		t.Fatalf("save first attempt: %v", err)
	}
	if err := jsonStore.SaveRecord(secondAttempt); err != nil {
		t.Fatalf("save second attempt: %v", err)
	}

	// Then
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted records: %v", err)
	}
	const wantJSON = "[\n" +
		"  {\n" +
		"    \"id\": \"001\",\n" +
		"    \"timestamp\": \"2026-08-01T12:00:00Z\",\n" +
		"    \"success\": false,\n" +
		"    \"message\": \"interrupted\",\n" +
		"    \"logs\": [\n" +
		"      \"started\"\n" +
		"    ]\n" +
		"  },\n" +
		"  {\n" +
		"    \"id\": \"001\",\n" +
		"    \"timestamp\": \"2026-08-01T12:01:00Z\",\n" +
		"    \"success\": true,\n" +
		"    \"message\": \"成功\",\n" +
		"    \"logs\": [\n" +
		"      \"resumed\"\n" +
		"    ]\n" +
		"  }\n" +
		"]\n"
	if string(contents) != wantJSON {
		t.Fatalf("persisted JSON differs\nwant:\n%s\ngot:\n%s", wantJSON, contents)
	}

	reloadedRecords, err := store.NewJSONStore(path).LoadRecords()
	if err != nil {
		t.Fatalf("reload persisted records: %v", err)
	}
	if !reflect.DeepEqual(reloadedRecords, []upgrade.UpgradeRecord{firstAttempt, secondAttempt}) {
		t.Fatalf("reloaded records differ\nwant: %#v\ngot:  %#v", []upgrade.UpgradeRecord{firstAttempt, secondAttempt}, reloadedRecords)
	}
}

func TestJSONStore_IsApplied_returns_false_when_latest_attempt_failed(t *testing.T) {
	// Given
	jsonStore := store.NewJSONStore(filepath.Join(t.TempDir(), "upgrade_metadata.json"))
	if err := jsonStore.SaveRecord(upgrade.UpgradeRecord{ID: "001", Success: true}); err != nil {
		t.Fatalf("save successful attempt: %v", err)
	}
	if err := jsonStore.SaveRecord(upgrade.UpgradeRecord{ID: "001", Success: false}); err != nil {
		t.Fatalf("save failed attempt: %v", err)
	}

	// When
	applied, err := jsonStore.IsApplied("001")

	// Then
	if err != nil {
		t.Fatalf("check latest attempt: %v", err)
	}
	if applied {
		t.Fatal("failed latest attempt must remain unapplied")
	}
}

func TestJSONStore_IsApplied_returns_true_when_latest_attempt_succeeded(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	jsonStore := store.NewJSONStore(path)
	if err := jsonStore.SaveRecord(upgrade.UpgradeRecord{ID: "001", Success: false}); err != nil {
		t.Fatalf("save failed attempt: %v", err)
	}
	if err := jsonStore.SaveRecord(upgrade.UpgradeRecord{ID: "001", Success: true}); err != nil {
		t.Fatalf("save successful attempt: %v", err)
	}

	// When
	applied, err := store.NewJSONStore(path).IsApplied("001")

	// Then
	if err != nil {
		t.Fatalf("check latest attempt: %v", err)
	}
	if !applied {
		t.Fatal("successful latest attempt must be applied")
	}
}

func TestJSONStore_IsApplied_returns_error_when_record_file_is_corrupt(t *testing.T) {
	// Given
	path := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
		t.Fatalf("write corrupt record file: %v", err)
	}

	// When
	_, err := store.NewJSONStore(path).IsApplied("001")

	// Then
	if err == nil {
		t.Fatal("corrupt record file must return an error")
	}
}
