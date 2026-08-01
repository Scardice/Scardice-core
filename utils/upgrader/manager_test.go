package upgrade_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/utils/dboperator/engine"
	upgrade "Scardice-core/utils/upgrader"
	"Scardice-core/utils/upgrader/store"
)

func TestManager_ApplyAll_Resumes_idempotent_upgrade_after_interruption_without_duplicate_durable_rows(t *testing.T) {
	// Given
	metadataPath := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	durableRowsPath := filepath.Join(filepath.Dir(metadataPath), "durable_rows")
	interrupted := errors.New("interrupted")
	attempts := 0
	up := upgrade.Upgrade{
		ID:         "001",
		Idempotent: true,
		Apply: func(logf func(string), _ engine.DatabaseOperator) error {
			attempts++
			_, err := os.ReadFile(durableRowsPath)
			if os.IsNotExist(err) {
				if err := os.WriteFile(durableRowsPath, []byte("row\n"), 0o644); err != nil {
					return err
				}
				logf("durably wrote row")
				return interrupted
			}
			if err != nil {
				return err
			}
			logf("existing row checkpointed")
			if attempts < 3 {
				return interrupted
			}
			return nil
		},
	}

	// When
	firstManager := &upgrade.Manager{Store: store.NewJSONStore(metadataPath)}
	firstManager.Register(up)
	firstErr := firstManager.ApplyAll()

	// Then
	if !errors.Is(firstErr, interrupted) {
		t.Fatalf("first attempt error = %v, want interruption", firstErr)
	}

	// When
	secondManager := &upgrade.Manager{Store: store.NewJSONStore(metadataPath)}
	secondManager.Register(up)
	secondErr := secondManager.ApplyAll()

	// Then
	if !errors.Is(secondErr, interrupted) {
		t.Fatalf("second attempt error = %v, want interruption", secondErr)
	}

	// When
	thirdManager := &upgrade.Manager{Store: store.NewJSONStore(metadataPath)}
	thirdManager.Register(up)
	thirdErr := thirdManager.ApplyAll()

	// Then
	if thirdErr != nil {
		t.Fatalf("resume idempotent upgrade: %v", thirdErr)
	}
	rows, err := os.ReadFile(durableRowsPath)
	if err != nil {
		t.Fatalf("read durable rows: %v", err)
	}
	if string(rows) != "row\n" {
		t.Fatalf("durable rows = %q, want one row", rows)
	}
	records, err := store.NewJSONStore(metadataPath).LoadRecords()
	if err != nil {
		t.Fatalf("load retry records: %v", err)
	}
	if len(records) != 3 || records[0].Success || records[1].Success || !records[2].Success {
		t.Fatalf("retry records = %#v, want two failed then one successful attempt", records)
	}

	// When
	fourthManager := &upgrade.Manager{Store: store.NewJSONStore(metadataPath)}
	fourthManager.Register(up)
	fourthErr := fourthManager.ApplyAll()

	// Then
	if fourthErr != nil {
		t.Fatalf("skip successful upgrade: %v", fourthErr)
	}
	if attempts != 3 {
		t.Fatalf("upgrade attempts = %d, want 3", attempts)
	}
}

func TestManager_ApplyAll_returns_SaveRecord_error(t *testing.T) {
	// Given
	saveErr := errors.New("save record")
	recordingStore := &recordingStore{saveErr: saveErr}
	manager := &upgrade.Manager{Store: recordingStore}
	manager.Register(upgrade.Upgrade{
		ID: "001",
		Apply: func(logf func(string), _ engine.DatabaseOperator) error {
			logf("applied")
			return nil
		},
	})

	// When
	err := manager.ApplyAll()

	// Then
	if !errors.Is(err, saveErr) {
		t.Fatalf("apply error = %v, want save record error", err)
	}
	if len(recordingStore.records) != 1 {
		t.Fatalf("record count = %d, want 1", len(recordingStore.records))
	}
	if !recordingStore.records[0].Success || len(recordingStore.records[0].Logs) != 1 {
		t.Fatalf("recorded outcome = %#v, want successful logged attempt", recordingStore.records[0])
	}
}

func TestManager_ApplyAll_DoesNotRetry_non_idempotent_upgrade_automatically(t *testing.T) {
	// Given
	metadataPath := filepath.Join(t.TempDir(), "upgrade_metadata.json")
	interrupted := errors.New("interrupted")
	attempts := 0
	up := upgrade.Upgrade{
		ID: "001",
		Apply: func(func(string), engine.DatabaseOperator) error {
			attempts++
			return interrupted
		},
	}
	firstManager := &upgrade.Manager{Store: store.NewJSONStore(metadataPath)}
	firstManager.Register(up)

	// When
	firstErr := firstManager.ApplyAll()

	// Then
	if !errors.Is(firstErr, interrupted) {
		t.Fatalf("first apply error = %v, want interruption", firstErr)
	}
	records, err := store.NewJSONStore(metadataPath).LoadRecords()
	if err != nil {
		t.Fatalf("load failed attempt: %v", err)
	}
	if len(records) != 1 || records[0].Success {
		t.Fatalf("records = %#v, want one failed durable attempt", records)
	}

	// When
	secondManager := &upgrade.Manager{Store: store.NewJSONStore(metadataPath)}
	secondManager.Register(up)
	secondErr := secondManager.ApplyAll()

	// Then
	if secondErr == nil {
		t.Fatal("fresh manager must reject retry of an uncheckpointed upgrade")
	}
	if attempts != 1 {
		t.Fatalf("upgrade attempts = %d, want 1 because no checkpoint makes automatic retry unsafe", attempts)
	}
}

type recordingStore struct {
	records []upgrade.UpgradeRecord
	saveErr error
}

func (s *recordingStore) IsApplied(string) (bool, error) {
	return false, nil
}

func (s *recordingStore) SaveRecord(record upgrade.UpgradeRecord) error {
	s.records = append(s.records, record)
	return s.saveErr
}

func (s *recordingStore) LoadRecords() ([]upgrade.UpgradeRecord, error) {
	return s.records, nil
}
