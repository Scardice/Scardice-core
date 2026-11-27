//go:build linux

package bootsound

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAvailabilityFollowsMPV(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if ok, player := Availability(); ok || player != "" {
		t.Fatalf("无 mpv 时应不可用，got ok=%v player=%q", ok, player)
	}

	dir := t.TempDir()
	mpv := filepath.Join(dir, "mpv")
	if err := os.WriteFile(mpv, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	if ok, player := Availability(); !ok || player != "mpv" {
		t.Fatalf("有 mpv 时应可用，got ok=%v player=%q", ok, player)
	}
}
