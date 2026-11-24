//go:build linux

package api

import (
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// procClockTicksFallback 仅用于没有 /proc/self/schedstat 的老内核。
// Linux 的 USER_HZ 在 Go 支持的架构上通常为 100；schedstat 可用时不依赖该值。
const procClockTicksFallback = 100.0

func sampleHostAndProcess(dataDir string) overviewHostMetrics {
	host := overviewHostMetrics{}

	idle1, total1, ok1 := readProcCPU()
	cpuOK := false
	if ok1 {
		time.Sleep(150 * time.Millisecond)
		idle2, total2, ok2 := readProcCPU()
		if ok2 && total2 > total1 {
			busy := float64((total2 - total1) - (idle2 - idle1))
			host.CPUPercent = busy / float64(total2-total1) * 100
			cpuOK = true
		}
	}

	load1, load5, load15, loadOK := readSystemLoad()
	if loadOK {
		host.Load1 = load1
		host.Load5 = load5
		host.Load15 = load15
	}

	var memOK, diskOK bool
	host.MemTotal, host.MemAvailable, memOK = readSystemMemory()
	host.DiskTotal, host.DiskFree, diskOK = readDiskUsage(dataDir)

	host.CPUAvailable = cpuOK
	host.MemoryAvailable = memOK
	host.DiskAvailable = diskOK
	host.Available = cpuOK || loadOK || memOK || diskOK
	return host
}

func readProcCPU() (idle, total uint64, ok bool) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "cpu ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return 0, 0, false
		}
		for i, field := range fields[1:] {
			if i >= 8 {
				// guest / guest_nice 已包含在 user / nice 中，重复累加会虚增总量。
				break
			}
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return 0, 0, false
			}
			total += value
			// idle + iowait
			if i == 3 || i == 4 {
				idle += value
			}
		}
		return idle, total, true
	}
	return 0, 0, false
}

// readProcSelfCPUSeconds 返回进程累计 CPU 秒数。
// 优先使用 schedstat（纳秒，精度高且不依赖 USER_HZ）；老内核回退到 /proc/self/stat。
func readProcSelfCPUSeconds() (float64, bool) {
	if ns, ok := readProcSelfSchedstat(); ok && ns > 0 {
		return float64(ns) / 1e9, true
	}
	if ticks, ok := readProcSelfCPU(); ok {
		return float64(ticks) / procClockTicksFallback, true
	}
	return 0, false
}

func readProcSelfSchedstat() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/schedstat")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, false
	}
	ns, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	return ns, true
}

func readProcSelfCPU() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return 0, false
	}
	// comm 字段可能包含空格和括号，取最后一个 ')' 之后的字段。
	idx := strings.LastIndexByte(string(data), ')')
	if idx < 0 || idx+2 >= len(data) {
		return 0, false
	}
	fields := strings.Fields(string(data)[idx+2:])
	// 去掉 comm/state 后：utime 是原第 14 个字段，stime 是第 15 个。
	if len(fields) < 13 {
		return 0, false
	}
	utime, err1 := strconv.ParseUint(fields[11], 10, 64)
	stime, err2 := strconv.ParseUint(fields[12], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	return utime + stime, true
}

func readSystemLoad() (load1, load5, load15 float64, ok bool) {
	if load1, load5, load15, ok := readProcLoadAvg(); ok {
		return load1, load5, load15, true
	}

	// /proc 不可用时用 sysinfo(2) 兜底；Loads 是 1<<16 定点数。
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0, 0, 0, false
	}
	const loadScale = 1 << 16
	return float64(info.Loads[0]) / loadScale,
		float64(info.Loads[1]) / loadScale,
		float64(info.Loads[2]) / loadScale,
		true
}

func readProcLoadAvg() (load1, load5, load15 float64, ok bool) {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0, 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, 0, false
	}
	load1, err1 := strconv.ParseFloat(fields[0], 64)
	load5, err2 := strconv.ParseFloat(fields[1], 64)
	load15, err3 := strconv.ParseFloat(fields[2], 64)
	if err1 != nil || err2 != nil || err3 != nil {
		return 0, 0, 0, false
	}
	return load1, load5, load15, true
}

func readSystemMemory() (total, available uint64, ok bool) {
	if total, available, ok := readProcMemInfo(); ok {
		return total, available, true
	}

	// /proc 不可用时用 sysinfo(2) 兜底；Unit 是每个内存单位对应的字节数。
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0, 0, false
	}
	unit := uint64(info.Unit)
	if unit == 0 {
		unit = 1
	}
	total = uint64(info.Totalram) * unit
	available = (uint64(info.Freeram) + uint64(info.Bufferram)) * unit
	if available > total {
		available = total
	}
	return total, available, total > 0
}

func readProcMemInfo() (total, available uint64, ok bool) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, false
	}
	return parseProcMemInfo(data)
}

func parseProcMemInfo(data []byte) (total, available uint64, ok bool) {
	// MemAvailable 是 Linux 3.14 才有的字段；老内核用 Free+Buffers+Cached 估算。
	var memFree, buffers, cached, sReclaimable uint64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = value * 1024
		case "MemAvailable:":
			available = value * 1024
		case "MemFree:":
			memFree = value * 1024
		case "Buffers:":
			buffers = value * 1024
		case "Cached:":
			cached = value * 1024
		case "SReclaimable:":
			sReclaimable = value * 1024
		}
	}
	if total == 0 {
		return 0, 0, false
	}
	if available == 0 {
		available = memFree + buffers + cached + sReclaimable
	}
	if available > total {
		available = total
	}
	return total, available, true
}

func readProcessRSSBytes() uint64 {
	if statmBytes, ok := readProcSelfStatmRSS(); ok {
		return statmBytes
	}
	// statm 不可用时读 status 的 VmRSS。
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

func readProcSelfStatmRSS() (uint64, bool) {
	data, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, false
	}
	fields := strings.Fields(string(data))
	if len(fields) < 2 {
		return 0, false
	}
	pages, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}

func readDiskUsage(path string) (total, free uint64, ok bool) {
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		return 0, 0, false
	}
	blockSize := uint64(stat.Bsize)
	total = uint64(stat.Blocks) * blockSize
	free = uint64(stat.Bavail) * blockSize
	if free > total {
		free = total
	}
	return total, free, total > 0
}
