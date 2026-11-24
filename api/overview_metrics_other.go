//go:build !linux

package api

// sampleHostAndProcess 在非 Linux 平台只返回空的主机指标；
// 进程指标仍由 runtime.MemStats 提供，页面不会因此报错。
func sampleHostAndProcess(_ string) overviewHostMetrics {
	return overviewHostMetrics{}
}

func readProcessRSSBytes() uint64 {
	return 0
}

func readProcSelfCPU() (uint64, bool) {
	return 0, false
}

func readProcSelfCPUSeconds() (float64, bool) {
	return 0, false
}
