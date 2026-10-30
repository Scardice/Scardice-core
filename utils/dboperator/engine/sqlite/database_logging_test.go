package sqlite

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type sqliteDatabaseLogCapture struct {
	messages []string
}

func (c *sqliteDatabaseLogCapture) Infof(format string, args ...any) {
	c.messages = append(c.messages, format)
}

func TestLogSQLiteDatabaseFileStateReportsCreationAndReuse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "data.db")
	capture := &sqliteDatabaseLogCapture{}

	if err := os.WriteFile(path, []byte("created"), 0o600); err != nil {
		t.Fatal(err)
	}
	logSQLiteDatabaseFileState(capture, path, false)
	if len(capture.messages) != 1 || !strings.Contains(capture.messages[0], "自动创建") {
		t.Fatalf("creation log = %#v, want one creation message", capture.messages)
	}

	logSQLiteDatabaseFileState(capture, path, true)
	if len(capture.messages) != 2 || !strings.Contains(capture.messages[1], "复用") {
		t.Fatalf("reuse log = %#v, want one reuse message", capture.messages)
	}
}
