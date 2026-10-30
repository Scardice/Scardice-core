package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func postBackup(t *testing.T, server *echo.Echo, selection uint64) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(map[string]uint64{"selection": selection})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/sd-api/backup/do_backup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Token", uiAPIContractToken)
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	return recorder
}

type backupJobResponse struct {
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Job     *dice.BackupJob `json:"job"`
}

func decodeBackupJobResponse(t *testing.T, response *httptest.ResponseRecorder) backupJobResponse {
	t.Helper()
	var result backupJobResponse
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode backup job response (status %d): %v; body=%s", response.Code, err, response.Body.String())
	}
	return result
}

func getBackupStatus(t *testing.T, server *echo.Echo, token string) (*httptest.ResponseRecorder, *dice.BackupJob) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/sd-api/backup/status", nil)
	if token != "" {
		req.Header.Set("Token", token)
	}
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		return recorder, nil
	}
	var result struct {
		Job *dice.BackupJob `json:"job"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode backup status: %v; body=%s", err, recorder.Body.String())
	}
	return recorder, result.Job
}

func waitForBackupTerminal(t *testing.T, server *echo.Echo, jobID string) *dice.BackupJob {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, job := getBackupStatus(t, server, uiAPIContractToken)
		if job != nil && job.ID == jobID && job.Status != dice.BackupJobStatusRunning {
			return job
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup job %q did not reach a terminal state; last status=%#v", jobID, job)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
