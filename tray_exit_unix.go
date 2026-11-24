//go:build !windows

package main

import (
	"os"
	"time"
)

// exitAfterUIStartupFailure 触发 main 中已注册的信号清理流程后再退出。
// 不能只用 runtime.Goexit 或直接 return：它们只会结束 uiServe goroutine，
// 主 goroutine 仍会卡在 trayInit 的 select{}，表现为进程还在但没有 UI。
func exitAfterUIStartupFailure() {
	processExitCode.Store(1)
	if p, err := os.FindProcess(os.Getpid()); err == nil {
		if err := p.Signal(os.Interrupt); err == nil {
			// 正常情况下信号处理器会在 cleanUp 后 os.Exit，这里只做兜底。
			time.Sleep(10 * time.Second)
		}
	}
	os.Exit(1)
}
