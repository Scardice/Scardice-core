package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/alexmullins/zip"

	"Scardice-core/dice/service"
	"Scardice-core/logger"
	"Scardice-core/utils"
	"Scardice-core/utils/constant"
	"Scardice-core/utils/crypto"
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

func (dm *DiceManager) backup(sel BackupSelection, fromAuto bool, progress *backupJobProgress) (result string, resultErr error) {
	if dm == nil || len(dm.Dice) == 0 || dm.Dice[0] == nil {
		return "", errors.New("dice: no runtime Dice is available for backup")
	}
	if dm.EventSourcedMode {
		return dm.backupEventStore(sel, fromAuto, progress)
	}
	if err := os.MkdirAll(BackupDir, 0o755); err != nil {
		return "", fmt.Errorf("create backup directory: %w", err)
	}
	progress.update(BackupJobStageCollecting, 0, 0)
	log := dm.Dice[0].Logger
	if log == nil {
		log = logger.M()
	}

	cfgGlb := backupConfigGlobal{
		Global: true,
		Dices:  map[string]*backupConfigDice{},
	}
	cfgDice := backupConfigDice{
		Accounts:    true,
		MiscConfig:  true,
		PlayerData:  true,
		CustomReply: true,
		CustomText:  true,
	}

	bakFn := "bak_" + time.Now().Format("060102_150405")
	if fromAuto {
		bakFn += "_auto"
	}
	bakFn += "_r" + strconv.FormatUint(uint64(sel), 16)
	fnHashed := crypto.CalculateSHA512Str([]byte(bakFn))[:8]
	bakFn += "_" + fnHashed + ".zip"

	stageDir, err := createBackupStagingDir()
	if err != nil {
		return "", err
	}
	stagePath := filepath.Join(stageDir, "backup.zip")
	archivePath := filepath.Join(BackupDir, bakFn)
	publishedPath := ""
	defer func() {
		if cleanupErr := cleanBackupStagingDir(stageDir, publishedPath); cleanupErr != nil {
			result = ""
			resultErr = errors.Join(resultErr, cleanupErr)
		}
	}()
	fzip, err := os.OpenFile(stagePath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		return "", fmt.Errorf("create staged backup archive: %w", err)
	}
	writer := zip.NewWriter(fzip)
	writerClosed := false
	fileClosed := false
	defer func() {
		if !writerClosed {
			_ = writer.Close()
		}
		if !fileClosed {
			_ = fzip.Close()
		}
	}()

	var backupErr error
	completedFiles := 0
	totalFiles := 0
	recordError := func(err error) {
		if err != nil && backupErr == nil {
			backupErr = err
		}
	}
	fileOK := func(fn string) bool {
		stat, err := os.Stat(fn)
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err != nil {
			recordError(fmt.Errorf("inspect backup file %q: %w", fn, err))
			return false
		}
		if stat.IsDir() {
			recordError(fmt.Errorf("inspect backup file %q: path is a directory", fn))
			return false
		}
		return true
	}
	dirOK := func(fn string) bool {
		stat, err := os.Stat(fn)
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err != nil {
			recordError(fmt.Errorf("inspect backup directory %q: %w", fn, err))
			return false
		}
		if !stat.IsDir() {
			recordError(fmt.Errorf("inspect backup directory %q: path is not a directory", fn))
			return false
		}
		return true
	}
	walkOptionalDir := func(root string, walkFn fs.WalkDirFunc) error {
		info, err := os.Stat(root)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect backup directory %q: %w", root, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("inspect backup directory %q: path is not a directory", root)
		}
		return filepath.WalkDir(root, walkFn)
	}
	backup := func(d *Dice, fn string) {
		if backupErr != nil {
			return
		}
		totalFiles++
		file, err := os.Open(fn)
		if err != nil {
			if !strings.Contains(fn, "session.token") {
				if d != nil {
					d.Logger.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
				} else {
					log.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
				}
			}
			recordError(fmt.Errorf("open backup file %q: %w", fn, err))
			return
		}

		h := &zip.FileHeader{Name: fn, Method: zip.Deflate, Flags: 0x800}
		fileWriter, err := writer.CreateHeader(h)
		if err != nil {
			_ = file.Close()
			recordError(fmt.Errorf("create backup entry %q: %w", fn, err))
			return
		}
		if _, err = io.Copy(fileWriter, file); err != nil {
			_ = file.Close()
			recordError(fmt.Errorf("copy backup file %q: %w", fn, err))
			return
		}
		if err = file.Close(); err != nil {
			recordError(fmt.Errorf("close backup file %q: %w", fn, err))
			return
		}
		completedFiles++
	}

	backupDir := func(path string, info fs.FileInfo, walkErr error) error {
		if walkErr != nil {
			recordError(fmt.Errorf("walk backup path %q: %w", path, walkErr))
			return walkErr
		}
		if !info.IsDir() {
			backup(nil, path)
		}
		return backupErr
	}

	progress.update(BackupJobStageArchiving, 0, 0)
	backup(nil, "data/dice.yaml")

	if sel&BackupSelectionDecks != 0 {
		cfgGlb.Decks = true
		if dirOK("data/decks") {
			if err := filepath.Walk("data/decks", func(path string, info fs.FileInfo, walkErr error) error {
				if walkErr != nil {
					recordError(fmt.Errorf("walk backup path %q: %w", path, walkErr))
					return walkErr
				}
				if !info.IsDir() {
					backup(nil, path)
					return backupErr
				}
				base := filepath.Base(path)
				// 跳过 deck 压缩包解压出的目录
				if strings.HasPrefix(base, "_") && strings.HasSuffix(base, ".deck") {
					if fileOK(filepath.Join(filepath.Dir(path), base[1:])) {
						return filepath.SkipDir
					}
				}
				return nil
			}); err != nil {
				recordError(err)
			}
		}
	}

	if sel&BackupSelectionHelpDoc != 0 {
		if !dirOK("data/helpdoc") {
			log.Warn("备份 helpdoc 失败: 不存在或不是目录")
		} else {
			cfgGlb.HelpDoc = true
			recordError(filepath.Walk("data/helpdoc", backupDir))
		}
	}

	if sel&BackupSelectionCensor != 0 {
		if !dirOK("data/censor") {
			log.Warn("备份 censor 失败: 不存在或不是目录")
		} else {
			cfgGlb.Censor = true
			recordError(filepath.Walk("data/censor", backupDir))
		}
	}

	if sel&BackupSelectionNames != 0 {
		if !dirOK("data/names") {
			log.Warn("备份 names 失败: 不存在或不是目录")
		} else {
			cfgGlb.Names = true
			recordError(filepath.Walk("data/names", backupDir))
		}
	}

	if sel&BackupSelectionImages != 0 {
		if !dirOK("data/images") {
			log.Warn("备份 images 失败: 不存在或不是目录")
		} else {
			cfgGlb.Images = true
			recordError(filepath.Walk("data/images", backupDir))
		}
	}

	withJS := sel&BackupSelectionJS != 0
	cfgDice.JSScripts = withJS

	for _, d := range dm.Dice {
		if d == nil {
			recordError(errors.New("dice: nil runtime Dice in backup"))
			continue
		}
		cfgGlb.Dices[d.BaseConfig.Name] = &cfgDice
		dataDir := d.BaseConfig.DataDir

		backup(d, filepath.Join(dataDir, "serve.yaml"))
		if fn := filepath.Join(dataDir, "advanced.yaml"); fileOK(fn) {
			backup(d, fn)
		}
		if fn := filepath.Join(dataDir, "configs", "plugin-configs.json"); fileOK(fn) {
			backup(d, fn)
		}

		err := service.FlushWAL(d.DBOperator.GetDataDB(constant.WRITE))
		if err != nil {
			d.Logger.Errorf("备份时data数据库flush出错 错误为:%v", err.Error())
			recordError(fmt.Errorf("flush data database before backup: %w", err))
		} else {
			backup(d, filepath.Join(dataDir, "data.db"))
		}
		err = service.FlushWAL(d.DBOperator.GetLogDB(constant.WRITE))
		if err != nil {
			d.Logger.Errorf("备份时logs数据库flush出错 错误为:%v", err.Error())
			recordError(fmt.Errorf("flush logs database before backup: %w", err))
		} else {
			backup(d, filepath.Join(dataDir, "data-logs.db"))
		}
		if d.CensorManager != nil && d.CensorManager.DB != nil {
			err = service.FlushWAL(d.DBOperator.GetCensorDB(constant.WRITE))
			if err != nil {
				d.Logger.Errorf("备份时censor数据库flush出错 %v", err.Error())
				recordError(fmt.Errorf("flush censor database before backup: %w", err))
			} else {
				backup(d, filepath.Join(dataDir, "data-censor.db"))
			}
		}

		backup(d, filepath.Join(dataDir, "configs/text-template.yaml"))

		recordError(walkOptionalDir(filepath.Join(dataDir, "extensions/reply"), func(path string, info fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return fmt.Errorf("walk backup path %q: %w", path, walkErr)
			}
			// NOTE(Xiangze Li): copied from dice.ReplyReload. Should extract as function, but I'm lazy
			if info.IsDir() {
				if strings.EqualFold(info.Name(), "assets") || strings.EqualFold(info.Name(), "images") {
					return fs.SkipDir
				}
				return nil
			}
			if strings.HasPrefix(info.Name(), ".reply") || info.Name() == "info.yaml" {
				return nil
			}

			ext := filepath.Ext(path)
			if ext == ".yaml" || ext == "" {
				backup(d, path)
			}
			return backupErr
		}))

		if withJS {
			recordError(walkOptionalDir(filepath.Join(dataDir, "scripts"), func(path string, info fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return fmt.Errorf("walk backup path %q: %w", path, walkErr)
				}
				if info.IsDir() {
					if info.Name() == "_builtin" {
						return filepath.SkipDir
					}
					return nil
				}
				if filepath.Ext(info.Name()) == ".js" {
					backup(d, path)
				}
				return backupErr
			}))
			extDataDir := filepath.Join(dataDir, "extensions")
			recordError(walkOptionalDir(extDataDir, func(path string, info fs.DirEntry, walkErr error) error {
				if walkErr != nil {
					return fmt.Errorf("walk backup path %q: %w", path, walkErr)
				}
				if info.IsDir() {
					if filepath.Dir(path) == extDataDir {
						if ext := d.ExtFind(info.Name(), false); ext == nil || !ext.IsJsExt {
							return filepath.SkipDir
						}
					}
					return nil
				}
				backup(d, path)
				return backupErr
			}))
		}
	}

	if backupErr != nil {
		return "", backupErr
	}

	// 写入文件信息
	data, err := json.Marshal(map[string]interface{}{
		"config":      cfgGlb,
		"version":     VERSION.String(),
		"versionCode": VERSION_CODE,
	})
	if err != nil {
		return "", fmt.Errorf("encode backup metadata: %w", err)
	}
	totalFiles++
	h := &zip.FileHeader{Name: "backup_info.json", Method: zip.Deflate, Flags: 0x800}
	fileWriter, err := writer.CreateHeader(h)
	if err != nil {
		return "", fmt.Errorf("create backup metadata entry: %w", err)
	}
	if _, err := fileWriter.Write(data); err != nil {
		return "", fmt.Errorf("write backup metadata: %w", err)
	}
	completedFiles++
	progress.update(BackupJobStageFinalizing, completedFiles, totalFiles)
	err = writer.Close()
	writerClosed = true
	if err != nil {
		return "", fmt.Errorf("finish backup archive: %w", err)
	}
	if err := fzip.Sync(); err != nil {
		return "", fmt.Errorf("sync backup archive: %w", err)
	}
	err = fzip.Close()
	fileClosed = true
	if err != nil {
		return "", fmt.Errorf("close backup archive: %w", err)
	}
	if err := os.Link(stagePath, archivePath); err != nil {
		return "", fmt.Errorf("publish backup archive: %w", err)
	}
	publishedPath = archivePath
	return archivePath, nil
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
