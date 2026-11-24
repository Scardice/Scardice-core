//go:build linux

package api

import "testing"

func TestReadProcSelfCPU(t *testing.T) {
	ticks, ok := readProcSelfCPU()
	t.Logf("ticks=%d ok=%v", ticks, ok)
	if !ok {
		t.Fatal("readProcSelfCPU failed")
	}
}

func TestSampleProcessCPU(t *testing.T) {
	first := sampleProcessCPU()
	second := sampleProcessCPU()
	t.Logf("first=%v second=%v", first, second)
	if first < 0 || second < 0 {
		t.Fatal("cpu percent should not be negative")
	}
}

func TestReadProcMemInfo(t *testing.T) {
	total, available, ok := readProcMemInfo()
	t.Logf("total=%d available=%d ok=%v", total, available, ok)
	if !ok || total == 0 || available > total {
		t.Fatalf("invalid meminfo: total=%d available=%d ok=%v", total, available, ok)
	}
}

func TestReadSystemMemory(t *testing.T) {
	total, available, ok := readSystemMemory()
	t.Logf("total=%d available=%d ok=%v", total, available, ok)
	if !ok || total == 0 || available > total {
		t.Fatalf("invalid system memory: total=%d available=%d ok=%v", total, available, ok)
	}
}

func TestReadSystemLoad(t *testing.T) {
	l1, l5, l15, ok := readSystemLoad()
	t.Logf("load=%v/%v/%v ok=%v", l1, l5, l15, ok)
	if !ok {
		t.Fatal("readSystemLoad failed")
	}
}

func TestReadProcSelfCPUSeconds(t *testing.T) {
	seconds, ok := readProcSelfCPUSeconds()
	t.Logf("cpuSeconds=%v ok=%v", seconds, ok)
	if !ok || seconds < 0 {
		t.Fatalf("invalid process cpu seconds: %v ok=%v", seconds, ok)
	}
}

func TestReadDiskUsage(t *testing.T) {
	total, free, ok := readDiskUsage(t.TempDir())
	t.Logf("total=%d free=%d ok=%v", total, free, ok)
	if !ok || total == 0 || free > total {
		t.Fatalf("invalid disk usage: total=%d free=%d ok=%v", total, free, ok)
	}
}

func TestParseProcMemInfoOldKernel(t *testing.T) {
	data := []byte("MemTotal:       1000000 kB\nMemFree:         100000 kB\nBuffers:          20000 kB\nCached:          300000 kB\nSReclaimable:     50000 kB\n")
	total, available, ok := parseProcMemInfo(data)
	if !ok {
		t.Fatal("parseProcMemInfo failed")
	}
	if total != 1000000*1024 {
		t.Fatalf("total = %d, want %d", total, 1000000*1024)
	}
	if want := uint64(470000 * 1024); available != want {
		t.Fatalf("available = %d, want %d", available, want)
	}
}

func TestParseProcMemInfoMemAvailable(t *testing.T) {
	data := []byte("MemTotal:       1000000 kB\nMemFree:         100000 kB\nMemAvailable:    600000 kB\n")
	total, available, ok := parseProcMemInfo(data)
	if !ok {
		t.Fatal("parseProcMemInfo failed")
	}
	if total != 1000000*1024 || available != 600000*1024 {
		t.Fatalf("total=%d available=%d", total, available)
	}
}

func TestParseProcMemInfoNoTotal(t *testing.T) {
	if _, _, ok := parseProcMemInfo([]byte("MemFree: 1 kB\n")); ok {
		t.Fatal("parseProcMemInfo should fail without MemTotal")
	}
}
