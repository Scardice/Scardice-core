package dice

import (
	"sync"
	"time"
)

// BackupProgress 描述当前备份任务的实时进度，供 WebUI 轮询展示。
// 备份的文件总量在打包前未知，因此打包过程中 Percentage 保持 0，由前端显示为不确定进度条。
type BackupProgress struct {
	Running     bool   `json:"running"`
	Stage       string `json:"stage"`
	Message     string `json:"message"`
	FileName    string `json:"fileName,omitempty"`
	Current     int    `json:"current"`
	Total       int    `json:"total"`
	BytesCopied int64  `json:"bytesCopied"`
	Percentage  int    `json:"percentage"`
	StartedAt   int64  `json:"startedAt,omitempty"`
	UpdatedAt   int64  `json:"updatedAt,omitempty"`
	FinishedAt  int64  `json:"finishedAt,omitempty"`
	Error       string `json:"error,omitempty"`
}

type backupProgressTracker struct {
	mu       sync.RWMutex
	progress BackupProgress
}

// BeginBackupProgress 重置并开始一次新的备份进度。
func (dm *DiceManager) BeginBackupProgress(message string) {
	now := time.Now().UnixMilli()
	tracker := &dm.backupProgress
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.progress = BackupProgress{
		Running:   true,
		Stage:     "starting",
		Message:   message,
		StartedAt: now,
		UpdatedAt: now,
	}
}

// UpdateBackupProgress 更新打包进度。stage 表示当前阶段，fileName 为正在打包的文件。
func (dm *DiceManager) UpdateBackupProgress(stage string, message string, fileName string, current int, bytesCopied int64) {
	now := time.Now().UnixMilli()
	tracker := &dm.backupProgress
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	progress := tracker.progress
	if progress.StartedAt == 0 {
		progress.StartedAt = now
	}
	progress.Running = true
	progress.Stage = stage
	progress.Message = message
	progress.FileName = fileName
	progress.Current = current
	progress.BytesCopied = bytesCopied
	progress.UpdatedAt = now
	progress.FinishedAt = 0
	progress.Error = ""
	tracker.progress = progress
}

// FinishBackupProgress 标记备份完成。
func (dm *DiceManager) FinishBackupProgress(message string) {
	now := time.Now().UnixMilli()
	tracker := &dm.backupProgress
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	progress := tracker.progress
	if progress.StartedAt == 0 {
		progress.StartedAt = now
	}
	progress.Running = false
	progress.Stage = "finished"
	progress.Message = message
	progress.FileName = ""
	progress.Percentage = 100
	progress.UpdatedAt = now
	progress.FinishedAt = now
	progress.Error = ""
	tracker.progress = progress
}

// FailBackupProgress 标记备份失败并记录原因。
func (dm *DiceManager) FailBackupProgress(message string) {
	now := time.Now().UnixMilli()
	tracker := &dm.backupProgress
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	progress := tracker.progress
	if progress.StartedAt == 0 {
		progress.StartedAt = now
	}
	progress.Running = false
	progress.Stage = "failed"
	progress.Message = message
	progress.FileName = ""
	progress.UpdatedAt = now
	progress.FinishedAt = now
	progress.Error = message
	tracker.progress = progress
}

// BackupProgressSnapshot 返回当前备份进度的快照。
func (dm *DiceManager) BackupProgressSnapshot() BackupProgress {
	tracker := &dm.backupProgress
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	return tracker.progress
}
