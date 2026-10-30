package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/google/pprof/profile"
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
	if stop == nil {
		t.Fatal("disabled recorder must return a no-op shutdown callback")
	}
	stop()
	_, statErr := os.Stat(filepath.Join("data", "pprof", "1722528000"))
	if !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("disabled recorder output stat error = %v, want not exist", statErr)
	}
}

func TestPProfRecorderWritesValidProfilesOnStop(t *testing.T) {
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
	var callers sync.WaitGroup
	for range 32 {
		callers.Go(stop)
	}
	callers.Wait()
	stop()

	// Then
	for _, want := range []struct {
		file, sampleType, unit string
	}{
		{"cpu.pprof", "cpu", "nanoseconds"},
		{"heap.pprof", "inuse_space", "bytes"},
		{"goroutine.pprof", "goroutine", "count"},
	} {
		t.Run(want.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("data", "pprof", "1722528001", want.file))
			if err != nil {
				t.Fatal(err)
			}
			recorded, err := profile.ParseData(data)
			if err != nil {
				t.Fatalf("parse recorded profile: %v", err)
			}
			if !slices.ContainsFunc(recorded.SampleType, func(sample *profile.ValueType) bool {
				return sample.Type == want.sampleType && sample.Unit == want.unit
			}) {
				t.Fatalf("profile sample types = %v, want %s/%s", recorded.SampleType, want.sampleType, want.unit)
			}
		})
	}
}
