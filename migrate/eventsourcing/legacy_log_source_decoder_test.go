package eventsourcing

import (
	"errors"
	"testing"
)

func TestDecodeLegacyStoryLogGroupSnapshotPreservesHistoricalScalars(t *testing.T) {
	snapshot, err := decodeLegacyStoryLogGroupSnapshot([]byte(`{
		"groupId":"QQ-Group:42",
		"groupName":"historical group",
		"logCurName":"chapter one",
		"logOn":true,
		"players":{"QQ:1":{"name":"Alice"}},
		"diceIdActiveMap":{"QQ:bot":true}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GroupID != "QQ-Group:42" || snapshot.LogName != "chapter one" || !snapshot.LogOn {
		t.Fatalf("decoded historical story-log state = %#v", snapshot)
	}
}

func TestDecodeLegacyStoryLogGroupSnapshotAllowsAbsentHistoricalLogState(t *testing.T) {
	snapshot, err := decodeLegacyStoryLogGroupSnapshot([]byte(`{"groupName":"no log selected"}`))
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.GroupID != "" || snapshot.LogName != "" || snapshot.LogOn {
		t.Fatalf("absent historical story-log state = %#v", snapshot)
	}
}

func TestDecodeLegacyStoryLogGroupSnapshotRejectsMalformedScalars(t *testing.T) {
	for name, payload := range map[string]string{
		"invalid json":       `{"groupId":`,
		"null object":        `null`,
		"null identity":      `{"groupId":null}`,
		"numeric identity":   `{"groupId":42}`,
		"object log name":    `{"logCurName":{"value":"run"}}`,
		"string log enabled": `{"logOn":"true"}`,
		"trailing value":     `{"logOn":true}{}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeLegacyStoryLogGroupSnapshot([]byte(payload)); !errors.Is(err, ErrValidation) {
				t.Fatalf("decode error = %v, want validation failure", err)
			}
		})
	}
}
