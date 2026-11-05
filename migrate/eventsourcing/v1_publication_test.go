package eventsourcing

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestV1PublicationCrashChild(t *testing.T) {
	active := os.Getenv("SCARDICE_TEST_V1_SWAP_ACTIVE")
	if active == "" {
		return
	}
	phase := os.Getenv("SCARDICE_TEST_V1_SWAP_PHASE")
	proof, err := v1SQLiteMetadata(context.Background(), active)
	if err != nil {
		t.Fatal(err)
	}
	_, err = publishV1Candidate(context.Background(), V1ConvertOptions{Inject: FailureFunc(func(stage string) error {
		if stage == phase {
			os.Exit(79)
		}
		return nil
	})}, os.Getenv("SCARDICE_TEST_V1_SWAP_CANDIDATE"), active, "crash-test", proof)
	if err != nil {
		t.Fatal(err)
	}
	t.Fatal("the requested process-death boundary did not execute")
}

func TestV1PublicationCrashLeavesDurableIntentAndCannotBecomeFresh(t *testing.T) {
	for _, phase := range []string{"swap-intent", "backup-main", "backup-wal", "backup-shm", "activate", "activated"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			active, _ := copyV1WALFixture(t)
			candidate := active + ".candidate"
			target := NewSQLiteTarget(candidate)
			if err := target.Initialize(ctx, "crash-target"); err != nil {
				t.Fatal(err)
			}
			if err := target.closeForPublication(ctx); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestV1PublicationCrashChild$")
			command.Env = append(os.Environ(), "SCARDICE_TEST_V1_SWAP_ACTIVE="+active, "SCARDICE_TEST_V1_SWAP_CANDIDATE="+candidate, "SCARDICE_TEST_V1_SWAP_PHASE="+phase)
			output, err := command.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 79 {
				t.Fatalf("child did not crash at %s: %v\n%s", phase, err, output)
			}
			content, err := os.ReadFile(v1SwapIntentPath(active))
			if err != nil {
				t.Fatalf("missing durable intent: %v", err)
			}
			var intent v1SwapIntent
			if err = json.Unmarshal(content, &intent); err != nil {
				t.Fatal(err)
			}
			if intent.Active != active || intent.Candidate != candidate || intent.Backup != active+".v1.crash-test.bak" {
				t.Fatalf("intent=%+v", intent)
			}
			if _, err = DetectSQLiteFormat(ctx, active); !errors.Is(err, ErrUnfinishedV1Publication) {
				t.Fatalf("restart accepted incomplete swap as a database or fresh state: %v", err)
			}
			if phase == "activate" {
				if _, err = os.Lstat(active); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("expected actual missing-active crash boundary, got %v", err)
				}
			}
		})
	}
}

func TestV1PublicationReturnedErrorRestoresFilesAndClearsIntent(t *testing.T) {
	ctx := context.Background()
	active, _ := copyV1WALFixture(t)
	before, err := v1SQLiteMetadata(ctx, active)
	if err != nil {
		t.Fatal(err)
	}
	candidate := active + ".candidate"
	if err = os.WriteFile(candidate, []byte("candidate owned by this test"), 0o600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("stop before candidate installation")
	_, err = publishV1Candidate(ctx, V1ConvertOptions{Inject: FailureFunc(func(stage string) error {
		if stage == "activate" {
			return injected
		}
		return nil
	})}, candidate, active, "rollback-test", before)
	if !errors.Is(err, injected) {
		t.Fatalf("error=%v", err)
	}
	if err = recheckV1SQLite(ctx, active, before); err != nil {
		t.Fatalf("original files not restored: %v", err)
	}
	if err = CheckUnfinishedV1Publication(active); err != nil {
		t.Fatalf("successful rollback left an intent: %v", err)
	}
	if leftovers, _ := filepath.Glob(active + ".v1.rollback-test.bak*"); len(leftovers) != 0 {
		t.Fatalf("rollback backup leftovers=%v", leftovers)
	}
}
