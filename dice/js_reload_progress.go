package dice

import (
	"math"
	"sync"
	"time"
)

type JsReloadProgress struct {
	Running    bool   `json:"running"`
	Stage      string `json:"stage"`
	Message    string `json:"message"`
	Current    int    `json:"current"`
	Total      int    `json:"total"`
	Percentage int    `json:"percentage"`
	ScriptName string `json:"scriptName,omitempty"`
	StartedAt  int64  `json:"startedAt,omitempty"`
	UpdatedAt  int64  `json:"updatedAt,omitempty"`
	FinishedAt int64  `json:"finishedAt,omitempty"`
	Error      string `json:"error,omitempty"`
}

type JsReloadProgressTracker struct {
	mu       sync.RWMutex
	progress JsReloadProgress
}

func (d *Dice) jsReloadProgressTracker() *JsReloadProgressTracker {
	return &d.JsReloadProgress
}

func (d *Dice) BeginJsReloadProgress(message string) {
	now := time.Now().UnixMilli()
	tracker := d.jsReloadProgressTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.progress = JsReloadProgress{
		Running:    true,
		Stage:      "starting",
		Message:    message,
		Percentage: 0,
		StartedAt:  now,
		UpdatedAt:  now,
	}
}

func (d *Dice) UpdateJsReloadProgress(stage string, message string, current int, total int, percentage int, scriptName string) {
	tracker := d.jsReloadProgressTracker()
	now := time.Now().UnixMilli()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	progress := tracker.progress
	if progress.StartedAt == 0 {
		progress.StartedAt = now
	}
	progress.Running = true
	progress.Stage = stage
	progress.Message = message
	progress.Current = current
	progress.Total = total
	progress.Percentage = clampPercentage(percentage)
	progress.ScriptName = scriptName
	progress.UpdatedAt = now
	progress.FinishedAt = 0
	progress.Error = ""
	tracker.progress = progress
}

func (d *Dice) FinishJsReloadProgress(message string) {
	tracker := d.jsReloadProgressTracker()
	now := time.Now().UnixMilli()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	progress := tracker.progress
	if progress.StartedAt == 0 {
		progress.StartedAt = now
	}
	progress.Running = false
	progress.Stage = "finished"
	progress.Message = message
	progress.Current = progress.Total
	progress.Percentage = 100
	progress.ScriptName = ""
	progress.UpdatedAt = now
	progress.FinishedAt = now
	progress.Error = ""
	tracker.progress = progress
}

func (d *Dice) FailJsReloadProgress(message string) {
	tracker := d.jsReloadProgressTracker()
	now := time.Now().UnixMilli()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	progress := tracker.progress
	if progress.StartedAt == 0 {
		progress.StartedAt = now
	}
	progress.Running = false
	progress.Stage = "failed"
	progress.Message = message
	progress.ScriptName = ""
	progress.UpdatedAt = now
	progress.FinishedAt = now
	progress.Error = message
	tracker.progress = progress
}

func (d *Dice) JsReloadProgressSnapshot() JsReloadProgress {
	tracker := d.jsReloadProgressTracker()
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	return tracker.progress
}

func jsReloadProgressPercent(start int, end int, current int, total int) int {
	if total <= 0 {
		return start
	}
	ratio := float64(current) / float64(total)
	return clampPercentage(start + int(math.Round(float64(end-start)*ratio)))
}

func clampPercentage(percentage int) int {
	if percentage < 0 {
		return 0
	}
	if percentage > 100 {
		return 100
	}
	return percentage
}
