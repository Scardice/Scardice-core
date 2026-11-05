package main

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"
)

func TestMigrationRequiredNoticeNamesTheCommandAndTheBackupStep(t *testing.T) {
	notice := migrationRequiredNotice("/opt/scardice/Scardice-core")
	for _, want := range []string{"/opt/scardice/Scardice-core --import-legacy", "备份", "停止正在运行的其它实例", "继续本次启动"} {
		if !strings.Contains(notice, want) {
			t.Errorf("notice lacks %q", want)
		}
	}
}

func TestMigrationCommandQuotesAPathWithSpaces(t *testing.T) {
	if got := migrationCommand("/opt/my bot/Scardice-core"); got != `"/opt/my bot/Scardice-core" --import-legacy` {
		t.Fatal(got)
	}
}

func TestMigrationRunsOnlyForAnExplicitYesAndContinuesWithoutAnotherPrompt(t *testing.T) {
	for _, input := range []string{"\n", "n\n", "N\n", "maybe\n", "", "y\n", " Y \n", "yes\n"} {
		t.Run(input, func(t *testing.T) {
			var out bytes.Buffer
			called := false
			got := reportMigrationRequired(&out, strings.NewReader(input), true, "Scardice-core", nil, func() bool { called = true; return true })
			want := strings.EqualFold(strings.TrimSpace(input), "y") || strings.EqualFold(strings.TrimSpace(input), "yes")
			if called != want || got != want || strings.Contains(out.String(), "按 Enter 键退出") {
				t.Fatalf("called=%v continued=%v want=%v output=%s", called, got, want, out.String())
			}
		})
	}
}

func TestFailedMigrationDoesNotContinueStartup(t *testing.T) {
	if reportMigrationRequired(io.Discard, strings.NewReader("y\n"), true, "Scardice-core", nil, func() bool { return false }) {
		t.Fatal("failed migration continued")
	}
}

func TestMigrationRequiredDoesNotPromptWithoutATerminal(t *testing.T) {
	reader, writer := io.Pipe()
	defer writer.Close()
	var out bytes.Buffer
	done := make(chan bool, 1)
	go func() {
		done <- reportMigrationRequired(&out, reader, false, "Scardice-core", nil, func() bool { t.Error("migrated without terminal"); return true })
	}()
	select {
	case continued := <-done:
		if continued || !strings.Contains(out.String(), "--import-legacy") || strings.Contains(out.String(), "[y/N]") {
			t.Fatal(out.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waited on nonterminal input")
	}
}

func TestMigrationRequiredReleasesTheDatabaseBeforePrompting(t *testing.T) {
	var out bytes.Buffer
	released := false
	reportMigrationRequired(&out, strings.NewReader("\n"), true, "Scardice-core", func() { released = out.Len() == 0 }, nil)
	if !released {
		t.Fatal("database not released before prompt")
	}
}
