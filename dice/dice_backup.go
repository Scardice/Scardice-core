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

// BackupTempSuffix 备份打包期间使用的临时文件后缀。
// 只有在 zip 完整写入并关闭后才会改名为正式文件名，列表与清理逻辑会忽略该后缀。
const BackupTempSuffix = ".part"

// ErrBackupInProgress 表示已有一个备份任务正在执行，同一时间只允许一个备份，避免并发写坏同一目录。
var ErrBackupInProgress = errors.New("已有备份正在进行中，请稍候")

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

// cleanupStaleBackupTempFiles 清理异常退出遗留的临时备份文件，避免长期占用磁盘。
// 只清理超过 24 小时的临时文件，正常执行中的备份不会受影响。
func cleanupStaleBackupTempFiles() {
	entries, err := os.ReadDir(BackupDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), BackupTempSuffix) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		if err := os.Remove(filepath.Join(BackupDir, entry.Name())); err != nil {
			logger.M().Warnf("清理过期备份临时文件失败: %s, 原因: %s", entry.Name(), err.Error())
		}
	}
}

func (dm *DiceManager) Backup(sel BackupSelection, fromAuto bool) (string, error) {
	if !dm.backupLock.TryLock() {
		return "", ErrBackupInProgress
	}
	defer dm.backupLock.Unlock()

	dm.BeginBackupProgress("正在准备备份数据")
	completed := false
	progressErr := ""
	defer func() {
		if completed {
			dm.FinishBackupProgress("备份完成")
			return
		}
		if progressErr == "" {
			progressErr = "备份失败"
		}
		dm.FailBackupProgress(progressErr)
	}()

	_ = os.MkdirAll(BackupDir, 0o755)
	cleanupStaleBackupTempFiles()
	logger := dm.Dice[0].Logger

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

	finalPath := filepath.Join(BackupDir, bakFn)
	partPath := finalPath + BackupTempSuffix

	fzip, err := os.OpenFile(partPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o644)
	if err != nil {
		progressErr = "创建备份文件失败: " + err.Error()
		return "", err
	}
	defer func() {
		if completed {
			return
		}
		_ = fzip.Close()
		_ = os.Remove(partPath)
	}()

	writer := zip.NewWriter(fzip)

	copiedFiles := 0
	var copiedBytes int64

	fileOK := func(fn string) bool {
		stat, err := os.Stat(fn)
		return err == nil && !stat.IsDir()
	}
	dirOK := func(fn string) bool {
		stat, err := os.Stat(fn)
		return err == nil && stat.IsDir()
	}

	stageLabel := "正在备份基础配置"
	backup := func(d *Dice, fn string) {
		file, err := os.Open(fn)
		if err != nil {
			// session.token 不存在是正常情况，静默跳过，不要写入空条目
			if !strings.Contains(fn, "session.token") {
				if d != nil {
					d.Logger.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
				} else {
					logger.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
				}
			}
			return
		}
		defer file.Close()

		dm.UpdateBackupProgress("packing", stageLabel, "", copiedFiles, copiedBytes)

		h := &zip.FileHeader{Name: fn, Method: zip.Deflate, Flags: 0x800}
		fileWriter, err := writer.CreateHeader(h)
		if err != nil {
			if d != nil {
				d.Logger.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
			} else {
				logger.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
			}
			return
		}

		written, err := io.Copy(fileWriter, file)
		copiedFiles++
		copiedBytes += written
		dm.UpdateBackupProgress("packing", stageLabel, "", copiedFiles, copiedBytes)
		if err != nil {
			if d != nil {
				d.Logger.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
			} else {
				logger.Errorf("备份文件失败: %s, 原因: %s", fn, err.Error())
			}
		}
	}

	backupDir := func(path string, info fs.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			backup(nil, path)
		}
		return nil
	}

	backup(nil, "data/dice.yaml")

	if sel&BackupSelectionDecks != 0 {
		cfgGlb.Decks = true
		stageLabel = "正在备份牌堆"
		_ = filepath.Walk("data/decks", func(path string, info fs.FileInfo, err error) error {
			if err != nil || info == nil {
				return nil
			}
			if !info.IsDir() {
				backup(nil, path)
				return nil
			}
			base := filepath.Base(path)
			// 跳过 deck 压缩包解压出的目录
			if strings.HasPrefix(base, "_") && strings.HasSuffix(base, ".deck") {
				if fileOK(filepath.Join(filepath.Dir(path), base[1:])) {
					return filepath.SkipDir
				}
			}
			return nil
		})
	}

	if sel&BackupSelectionHelpDoc != 0 {
		if !dirOK("data/helpdoc") {
			logger.Warn("备份 helpdoc 失败: 不存在或不是目录")
		} else {
			cfgGlb.HelpDoc = true
			stageLabel = "正在备份帮助文档"
			_ = filepath.Walk("data/helpdoc", backupDir)
		}
	}

	if sel&BackupSelectionCensor != 0 {
		if !dirOK("data/censor") {
			logger.Warn("备份 censor 失败: 不存在或不是目录")
		} else {
			cfgGlb.Censor = true
			stageLabel = "正在备份敏感词库"
			_ = filepath.Walk("data/censor", backupDir)
		}
	}

	if sel&BackupSelectionNames != 0 {
		if !dirOK("data/names") {
			logger.Warn("备份 names 失败: 不存在或不是目录")
		} else {
			cfgGlb.Names = true
			stageLabel = "正在备份人名信息"
			_ = filepath.Walk("data/names", backupDir)
		}
	}

	if sel&BackupSelectionImages != 0 {
		if !dirOK("data/images") {
			logger.Warn("备份 images 失败: 不存在或不是目录")
		} else {
			cfgGlb.Images = true
			stageLabel = "正在备份图片"
			_ = filepath.Walk("data/images", backupDir)
		}
	}

	withJS := sel&BackupSelectionJS != 0
	cfgDice.JSScripts = withJS

	for _, d := range dm.Dice {
		cfgGlb.Dices[d.BaseConfig.Name] = &cfgDice
		dataDir := d.BaseConfig.DataDir

		stageLabel = "正在备份骰子配置"
		backup(d, filepath.Join(dataDir, "serve.yaml"))
		if fn := filepath.Join(dataDir, "advanced.yaml"); fileOK(fn) {
			backup(d, fn)
		}
		if fn := filepath.Join(dataDir, "configs", "plugin-configs.json"); fileOK(fn) {
			backup(d, fn)
		}

		stageLabel = "正在备份用户数据"
		err := service.FlushWAL(d.DBOperator.GetDataDB(constant.WRITE))
		if err != nil {
			d.Logger.Errorf("备份时data数据库flush出错 错误为:%v", err.Error())
		} else {
			backup(d, filepath.Join(dataDir, "data.db"))
		}
		err = service.FlushWAL(d.DBOperator.GetLogDB(constant.WRITE))
		if err != nil {
			d.Logger.Errorf("备份时logs数据库flush出错 错误为:%v", err.Error())
		} else {
			backup(d, filepath.Join(dataDir, "data-logs.db"))
		}
		if d.CensorManager != nil && d.CensorManager.DB != nil {
			err = service.FlushWAL(d.DBOperator.GetCensorDB(constant.WRITE))
			if err != nil {
				d.Logger.Errorf("备份时censor数据库flush出错 %v", err.Error())
			} else {
				backup(d, filepath.Join(dataDir, "data-censor.db"))
			}
		}

		stageLabel = "正在备份文案模板"
		backup(d, filepath.Join(dataDir, "configs/text-template.yaml"))

		stageLabel = "正在备份自定义回复"
		_ = filepath.WalkDir(filepath.Join(dataDir, "extensions/reply"), func(path string, info fs.DirEntry, err error) error {
			// NOTE(Xiangze Li): copied from dice.ReplyReload. Should extract as function, but I'm lazy
			if err != nil || info == nil {
				return nil
			}
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
			return nil
		})

		stageLabel = "正在备份账号配置"
		for _, i := range d.ImSession.EndPoints {
			if i.Platform == "QQ" {
				if pa, ok := i.Adapter.(*PlatformAdapterGocq); ok && pa.UseInPackClient {
					workDir := i.RelWorkDir
					if pa.BuiltinMode == "lagrange" {
						backup(d, filepath.Join(dataDir, workDir, "appsettings.json"))
						backup(d, filepath.Join(dataDir, workDir, "device.json"))
						backup(d, filepath.Join(dataDir, workDir, "keystore.json"))
					} else {
						backup(d, filepath.Join(dataDir, workDir, "config.yml"))
						backup(d, filepath.Join(dataDir, workDir, "device.json"))
						backup(d, filepath.Join(dataDir, workDir, "session.token"))
					}
				}
			}
		}

		if withJS {
			stageLabel = "正在备份 JS 插件"
			_ = filepath.WalkDir(filepath.Join(dataDir, "scripts"), func(path string, info fs.DirEntry, err error) error {
				if err != nil || info == nil {
					return nil
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
				return nil
			})
			extDataDir := filepath.Join(dataDir, "extensions")
			_ = filepath.WalkDir(extDataDir, func(path string, info fs.DirEntry, err error) error {
				if err != nil || info == nil {
					return nil
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
				return nil
			})
		}
	}

	// 写入文件信息
	dm.UpdateBackupProgress("finishing", "正在写入备份信息", "", copiedFiles, copiedBytes)
	data, _ := json.Marshal(map[string]interface{}{
		"config":      cfgGlb,
		"version":     VERSION.String(),
		"versionCode": VERSION_CODE,
	})

	h := &zip.FileHeader{Name: "backup_info.json", Method: zip.Deflate, Flags: 0x800}
	fileWriter, err := writer.CreateHeader(h)
	if err != nil {
		progressErr = "写入备份信息失败: " + err.Error()
		return "", err
	}
	if _, err := fileWriter.Write(data); err != nil {
		progressErr = "写入备份信息失败: " + err.Error()
		return "", err
	}

	if err := writer.Close(); err != nil {
		progressErr = "完成备份文件失败: " + err.Error()
		return "", err
	}
	if err := fzip.Close(); err != nil {
		progressErr = "完成备份文件失败: " + err.Error()
		return "", err
	}

	// 正式文件名只精确到秒，进程内已有备份锁；这里仍拒绝覆盖已存在的备份。
	if _, err := os.Stat(finalPath); err == nil {
		progressErr = "备份文件已存在，未覆盖: " + bakFn
		return "", fmt.Errorf("备份文件已存在: %s", bakFn)
	} else if !os.IsNotExist(err) {
		progressErr = "检查备份文件失败: " + err.Error()
		return "", err
	}

	if err := os.Rename(partPath, finalPath); err != nil {
		progressErr = "保存备份文件失败: " + err.Error()
		return "", err
	}

	completed = true
	return finalPath, nil
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
		// 正在打包的临时文件不参与保留数量/时间统计
		if strings.HasSuffix(f.Name(), BackupTempSuffix) {
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
