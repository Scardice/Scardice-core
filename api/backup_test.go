package api //nolint:testpackage

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/dice"
)

const backupAPITestToken = "backup-test-token"

func setupBackupAPITest(t *testing.T) *dice.DiceManager {
	t.Helper()
	oldMyDice, oldDM := myDice, dm
	testDice := &dice.Dice{}
	manager := &dice.DiceManager{Dice: []*dice.Dice{testDice}}
	manager.AccessTokens.Store(backupAPITestToken, true)
	testDice.Parent = manager
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		myDice, dm = oldMyDice, oldDM
	})
	return manager
}

func TestBackupGetListHidesTempFiles(t *testing.T) {
	setupBackupAPITest(t)
	t.Chdir(t.TempDir())

	if err := os.MkdirAll(dice.BackupDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", dice.BackupDir, err)
	}
	finalName := "bak_261126_120000_r3f_00000000.zip"
	partName := finalName + dice.BackupTempSuffix
	for _, name := range []string{finalName, partName} {
		if err := os.WriteFile(filepath.Join(dice.BackupDir, name), []byte("test"), 0o644); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", name, err)
		}
	}

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/backup/list", "", backupAPITestToken, backupGetList)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp struct {
		Items []backupFileItem `json:"items"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal response error = %v", err)
	}
	if len(resp.Items) != 1 || resp.Items[0].Name != finalName {
		t.Fatalf("items = %#v, want only %q", resp.Items, finalName)
	}
}

func TestBackupProgressStatusReturnsSnapshot(t *testing.T) {
	manager := setupBackupAPITest(t)

	manager.BeginBackupProgress("正在准备备份数据")
	manager.UpdateBackupProgress("packing", "正在打包备份文件", "data/decks/demo.json", 3, 1024)

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/backup/progress", "", backupAPITestToken, backupProgressStatus)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var resp dice.BackupProgress
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal response error = %v", err)
	}
	if !resp.Running || resp.Stage != "packing" || resp.FileName != "data/decks/demo.json" || resp.Current != 3 || resp.BytesCopied != 1024 {
		t.Fatalf("response = %#v, want packing progress snapshot", resp)
	}

	manager.FinishBackupProgress("备份完成")
	rec = performReplyAPIRequest(t, http.MethodGet, "/sd-api/backup/progress", "", backupAPITestToken, backupProgressStatus)
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Unmarshal response error = %v", err)
	}
	if resp.Running || resp.Percentage != 100 || resp.Error != "" {
		t.Fatalf("response = %#v, want finished progress snapshot", resp)
	}
}

func TestBackupProgressStatusRequiresAuth(t *testing.T) {
	oldMyDice, oldDM := myDice, dm
	testDice := &dice.Dice{}
	manager := &dice.DiceManager{Dice: []*dice.Dice{testDice}}
	testDice.Parent = manager
	myDice, dm = testDice, manager
	t.Cleanup(func() {
		myDice, dm = oldMyDice, oldDM
	})

	rec := performReplyAPIRequest(t, http.MethodGet, "/sd-api/backup/progress", "", "bad-token", backupProgressStatus)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
