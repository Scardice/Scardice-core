package dice

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"Scardice-core/logger"
)

type BackupJobStatus string

const (
	BackupJobStatusRunning   BackupJobStatus = "running"
	BackupJobStatusSucceeded BackupJobStatus = "succeeded"
	BackupJobStatusFailed    BackupJobStatus = "failed"
)

type BackupJobStage string

const (
	BackupJobStagePreparing  BackupJobStage = "preparing"
	BackupJobStageSnapshot   BackupJobStage = "snapshot"
	BackupJobStageCollecting BackupJobStage = "collecting"
	BackupJobStageArchiving  BackupJobStage = "archiving"
	BackupJobStageFinalizing BackupJobStage = "finalizing"
)

type BackupJob struct {
	ID             string          `json:"id"`
	Status         BackupJobStatus `json:"status"`
	Stage          BackupJobStage  `json:"stage"`
	CompletedFiles int             `json:"completedFiles"`
	TotalFiles     int             `json:"totalFiles"`
	Filename       string          `json:"filename,omitempty"`
	Error          string          `json:"error,omitempty"`
	StartedAt      int64           `json:"startedAt"`
	FinishedAt     int64           `json:"finishedAt,omitempty"`
}

var ErrBackupInProgress = errors.New("backup is already running")

type backupJobProgress struct {
	manager *DiceManager
	jobID   string
}

// BackupJobSnapshot returns a detached copy of the latest in-memory job.
func (dm *DiceManager) BackupJobSnapshot() *BackupJob {
	if dm == nil {
		return nil
	}
	dm.backupJobMu.RLock()
	defer dm.backupJobMu.RUnlock()
	if dm.backupJob == nil {
		return nil
	}
	job := *dm.backupJob
	return &job
}

// StartBackup reserves the manager-wide backup slot and runs the backup in the
// background. The returned job is the accepted running state at admission.
func (dm *DiceManager) StartBackup(sel BackupSelection, fromAuto bool) (BackupJob, error) {
	progress, job, err := dm.beginBackupJob()
	if err != nil {
		return job, err
	}
	go func() {
		_, _ = dm.runBackupJob(progress, sel, fromAuto)
	}()
	return job, nil
}

// Backup preserves the synchronous internal API while sharing the same
// manager-wide single-flight slot and observable lifecycle as asynchronous UI
// backups and cron backups.
func (dm *DiceManager) Backup(sel BackupSelection, fromAuto bool) (string, error) {
	progress, _, err := dm.beginBackupJob()
	if err != nil {
		return "", err
	}
	return dm.runBackupJob(progress, sel, fromAuto)
}

func (dm *DiceManager) beginBackupJob() (*backupJobProgress, BackupJob, error) {
	if dm == nil {
		return nil, BackupJob{}, errors.New("dice: backup manager is unavailable")
	}
	dm.backupJobMu.Lock()
	defer dm.backupJobMu.Unlock()
	if dm.backupJob != nil && dm.backupJob.Status == BackupJobStatusRunning {
		return nil, *dm.backupJob, ErrBackupInProgress
	}
	now := time.Now().UnixMilli()
	job := BackupJob{
		ID: uuid.NewString(), Status: BackupJobStatusRunning, Stage: BackupJobStagePreparing, StartedAt: now,
	}
	dm.backupJob = &job
	return &backupJobProgress{manager: dm, jobID: job.ID}, job, nil
}

func (dm *DiceManager) runBackupJob(progress *backupJobProgress, sel BackupSelection, fromAuto bool) (filename string, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("backup panic: %v", recovered)
			filename = ""
		}
		dm.finishBackupJob(progress.jobID, filename, err)
	}()
	if err = prepareBackupWorkspace(); err != nil {
		return "", err
	}
	filename, err = dm.backup(sel, fromAuto, progress)
	if err == nil && filename == "" {
		err = errors.New("dice: backup completed without an archive filename")
	}
	return filename, err
}

func (dm *DiceManager) finishBackupJob(jobID, filename string, backupErr error) {
	now := time.Now().UnixMilli()
	dm.backupJobMu.Lock()
	if dm.backupJob == nil || dm.backupJob.ID != jobID || dm.backupJob.Status != BackupJobStatusRunning {
		dm.backupJobMu.Unlock()
		return
	}
	if backupErr != nil {
		dm.backupJob.Status = BackupJobStatusFailed
		dm.backupJob.Error = backupErr.Error()
		dm.backupJob.Filename = ""
	} else {
		dm.backupJob.Status = BackupJobStatusSucceeded
		dm.backupJob.Stage = BackupJobStageFinalizing
		dm.backupJob.Filename = filepath.Base(filename)
		dm.backupJob.Error = ""
	}
	dm.backupJob.FinishedAt = now
	job := *dm.backupJob
	dm.backupJobMu.Unlock()

	log := logger.M()
	if len(dm.Dice) > 0 && dm.Dice[0] != nil && dm.Dice[0].Logger != nil {
		log = dm.Dice[0].Logger
	}
	if backupErr != nil {
		log.Errorf("备份任务失败: job=%s stage=%s error=%v", job.ID, job.Stage, backupErr)
		return
	}
	log.Infof("备份任务完成: job=%s filename=%s files=%d", job.ID, job.Filename, job.CompletedFiles)
}

func (p *backupJobProgress) update(stage BackupJobStage, completedFiles, totalFiles int) {
	if p == nil || p.manager == nil {
		return
	}
	if completedFiles < 0 {
		completedFiles = 0
	}
	if totalFiles < 0 {
		totalFiles = 0
	}
	if totalFiles == 0 {
		completedFiles = 0
	} else if completedFiles > totalFiles {
		completedFiles = totalFiles
	}
	p.manager.backupJobMu.Lock()
	defer p.manager.backupJobMu.Unlock()
	job := p.manager.backupJob
	if job == nil || job.ID != p.jobID || job.Status != BackupJobStatusRunning {
		return
	}
	job.Stage = stage
	job.CompletedFiles = completedFiles
	job.TotalFiles = totalFiles
}
