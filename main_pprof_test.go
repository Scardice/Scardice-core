package main

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"
)

func TestPProfRecorderCreatesNoOutputWhenDisabled(t *testing.T) {
	// Given
	t.Chdir(t.TempDir())
	const bootTime = int64(1722528000)

	// When
	stop, err := startPprofRecordIfEnabled(false, zap.NewNop().Sugar(), bootTime)

	// Then
	if err != nil {
		t.Fatalf("start disabled recorder: %v", err)
	}
	if stop != nil {
		t.Fatal("disabled recorder returned a shutdown callback")
	}
	_, statErr := os.Stat(filepath.Join("data", "pprof", "1722528000"))
	if !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("disabled recorder output stat error = %v, want not exist", statErr)
	}
}

func TestPProfRecorderCreatesProfilesAndStopsWhenEnabled(t *testing.T) {
	// Given
	t.Chdir(t.TempDir())
	const bootTime = int64(1722528001)

	// When
	stop, err := startPprofRecordIfEnabled(true, zap.NewNop().Sugar(), bootTime)
	if err != nil {
		t.Fatalf("start enabled recorder: %v", err)
	}
	if stop == nil {
		t.Fatal("enabled recorder returned no shutdown callback")
	}
	stop()

	// Then
	for _, name := range []string{"cpu.pprof", "heap.pprof", "goroutine.pprof"} {
		info, statErr := os.Stat(filepath.Join("data", "pprof", "1722528001", name))
		if statErr != nil {
			t.Fatalf("stat %s: %v", name, statErr)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
}

func TestPProfStopCallbackExecutesOnceWhenCalledRepeatedlyAndConcurrently(t *testing.T) {
	// Given
	var executions atomic.Int32
	stop := oncePprofStop(func() {
		executions.Add(1)
	})

	// When
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(stop)
	}
	callers.Wait()
	stop()
	stop()

	// Then
	if got := executions.Load(); got != 1 {
		t.Fatalf("stop executions = %d, want 1", got)
	}
}
