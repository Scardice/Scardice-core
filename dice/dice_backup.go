package dice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"Scardice-core/logger"
	"Scardice-core/utils"
)

const BackupDir = "./backups"

type BackupCleanStrategy int

const (
	BackupCleanStrategyDisabled BackupCleanStrategy = iota
	BackupCleanStrategyByCount
	BackupCleanStrategyByTime
)

type BackupCleanTrigger int

const (
	// BackupCleanTriggerCron 通过独立定时任务触发
	BackupCleanTriggerCron BackupCleanTrigger = 1 << iota
	// BackupCleanTriggerRotate 通过自动备份触发
	BackupCleanTriggerRotate
)

type backupConfigGlobal struct {
	Global  bool                         `json:"global"`
	Decks   bool                         `json:"decks"`
	HelpDoc bool                         `json:"helpDoc"`
	Censor  bool                         `json:"censor"`
	Names   bool                         `json:"names"`
	Images  bool                         `json:"images"`
	Dices   map[string]*backupConfigDice `json:"dices"`
}

type backupConfigDice struct {
	Accounts    bool `json:"accounts"`    // 帐号
	MiscConfig  bool `json:"miscConfig"`  // 综合设置
	PlayerData  bool `json:"playerData"`  // 用户数据
	CustomReply bool `json:"customReply"` // 文案模板
	CustomText  bool `json:"customText"`  // 自定义回复
	JSScripts   bool `json:"jsScripts"`   // JS脚本
}

type BackupSelection uint64

const (
	BackupSelectionJS BackupSelection = 1 << iota
	BackupSelectionDecks
	BackupSelectionHelpDoc
	BackupSelectionCensor
	BackupSelectionNames
	BackupSelectionImages

	BackupSelectionBasic     BackupSelection = 0
	BackupSelectionResources BackupSelection = BackupSelectionImages
	BackupSelectionAll       BackupSelection = BackupSelectionBasic |
		BackupSelectionJS |
		BackupSelectionDecks |
		BackupSelectionHelpDoc |
		BackupSelectionCensor |
		BackupSelectionNames |
		BackupSelectionResources
)

func (dm *DiceManager) backup(sel BackupSelection, fromAuto bool, progress *backupJobProgress) (string, error) {
	if dm == nil || len(dm.Dice) == 0 || dm.Dice[0] == nil {
		return "", errors.New("dice: no runtime Dice is available for backup")
	}
	return dm.backupEventStore(sel, fromAuto, progress)
}

func (dm *DiceManager) BackupAuto() error {
	_, err := dm.Backup(dm.AutoBackupSelection, true)
	return err
}

func (dm *DiceManager) BackupClean(fromAuto bool) (err error) {
	if dm.BackupCleanStrategy == BackupCleanStrategyDisabled {
		return nil
	}

	if fromAuto && (dm.BackupCleanTrigger&BackupCleanTriggerRotate == 0) {
		return nil
	}

	log := logger.M()
	log.Info("开始清理备份文件")

	backupDir, err := os.Open(BackupDir)
	if err != nil {
		return err
	}
	defer func() { _ = backupDir.Close() }()
	if i, _ := backupDir.Stat(); !i.IsDir() {
		return fmt.Errorf("backup directory %q is not a directory", BackupDir)
	}

	files, err := backupDir.ReadDir(-1)
	if err != nil {
		return err
	}

	fileInfos := make([]os.FileInfo, 0, len(files))
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		if fi, err := f.Info(); err == nil {
			fileInfos = append(fileInfos, fi)
		}
	}

	sort.Sort(utils.ByModtime(fileInfos))

	var fileInfoOld []os.FileInfo

	logMsg := strings.Builder{}
	_, _ = fmt.Fprintf(&logMsg, "现有备份文件 %d 个, 清理模式为 ", len(fileInfos)) //nolint:gosec

	switch dm.BackupCleanStrategy {
	case BackupCleanStrategyByCount:
		_, _ = fmt.Fprintf(&logMsg, "保留一定数量(%d)", dm.BackupCleanKeepCount)
		if len(fileInfos) > dm.BackupCleanKeepCount {
			fileInfoOld = fileInfos[:len(fileInfos)-dm.BackupCleanKeepCount]
		}
	case BackupCleanStrategyByTime:
		threshold := time.Now().Add(-dm.BackupCleanKeepDur)
		_, _ = fmt.Fprintf(&logMsg, "保留一定时间(%v, %s)", dm.BackupCleanKeepDur, threshold.Format(time.DateTime))
		idx, _ := sort.Find(len(fileInfos), func(i int) int {
			return threshold.Compare(fileInfos[i].ModTime())
		})
		fileInfoOld = fileInfos[:idx]
	default:
		// no-op
	}

	_, _ = fmt.Fprintf(&logMsg, ", 有以下 %d 个将要被删除", len(fileInfoOld)) //nolint:gosec

	errDel := []string{}
	for i, fi := range fileInfoOld {
		_, _ = fmt.Fprintf(&logMsg, "\n%d. %s", i+1, fi.Name())     //nolint:gosec
		errDelete := os.Remove(filepath.Join(BackupDir, fi.Name())) //nolint:gosec
		if errDelete != nil {
			errDel = append(errDel, errDelete.Error())
		}
	}

	log.Info(logMsg.String())

	if len(errDel) > 0 {
		return errors.New("error(s) occured when deleting files:\n" + strings.Join(errDel, "\n"))
	}
	return nil
}
