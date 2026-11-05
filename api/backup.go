package api

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/core/managerstate"
	"Scardice-core/dice"
	"Scardice-core/utils/crypto"
)

type backupFileItem struct {
	Name      string `json:"name"`
	FileSize  int64  `json:"fileSize"`
	Selection int64  `json:"selection"`
}

func ReverseSlice(s interface{}) {
	size := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, size-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

func backupGetList(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	reFn := regexp.MustCompile(`^(bak_\d{6}_\d{6}(?:_auto)?_r([0-9a-f]+))_([0-9a-f]{8})\.zip$`)

	items := make([]*backupFileItem, 0)
	walkErr := filepath.Walk(dice.BackupDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			if os.IsNotExist(err) && strings.HasPrefix(filepath.Base(path), dice.BackupStagingDirPrefix) {
				return nil
			}
			return err
		}
		if info.IsDir() && strings.HasPrefix(info.Name(), dice.BackupStagingDirPrefix) {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			fn := info.Name()
			matches := reFn.FindStringSubmatch(fn)
			selection := int64(0)
			if len(matches) == 4 {
				hashed := crypto.CalculateSHA512Str([]byte(matches[1]))
				if hashed[:8] == matches[3] {
					selection, _ = strconv.ParseInt(matches[2], 16, 64)
				} else {
					selection = -1
				}
			}

			items = append(items, &backupFileItem{
				Name:      fn,
				FileSize:  info.Size(),
				Selection: selection,
			})
		}
		return nil
	})
	if walkErr != nil && !os.IsNotExist(walkErr) {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "读取备份文件列表失败"})
	}

	ReverseSlice(items)
	return c.JSON(http.StatusOK, map[string]interface{}{
		"items": items,
	})
}

func backupDownload(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	name := c.QueryParam("name")
	if name != "" && (!strings.Contains(name, "/")) && (!strings.Contains(name, "\\")) {
		return c.Attachment(dice.BackupDir+"/"+name, name)
	}
	return c.JSON(http.StatusOK, nil)
}

func backupDelete(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	var err error
	name := c.QueryParam("name")
	if name != "" && (!strings.Contains(name, "/")) && (!strings.Contains(name, "\\")) {
		err = os.Remove(dice.BackupDir + "/" + name)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"success": err == nil,
	})
}

func backupBatchDelete(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}

	v := struct {
		Names []string `json:"names"`
	}{}
	err := c.Bind(&v)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}

	fails := make([]string, 0, len(v.Names))
	for _, name := range v.Names {
		if name != "" && (!strings.Contains(name, "/")) && (!strings.Contains(name, "\\")) {
			err = os.Remove(dice.BackupDir + "/" + name)
			if err != nil {
				fails = append(fails, name)
			}
		}
	}

	if len(fails) == 0 {
		return Success(&c, Response{})
	}
	return Error(&c, "失败列表", Response{
		"fails": fails,
	})
}

// 快速备份
func backupExec(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	v := struct {
		Selection uint64 `json:"selection"`
	}{}
	if err := c.Bind(&v); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	}

	job, err := dm.StartBackup(dice.BackupSelection(v.Selection), false)
	if errors.Is(err, dice.ErrBackupInProgress) {
		return c.JSON(http.StatusConflict, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
			"job":     job,
		})
	}
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]interface{}{
			"success": false,
			"error":   err.Error(),
		})
	}
	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"success": true,
		"job":     job,
	})
}

func backupStatus(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"job": dm.BackupJobSnapshot(),
	})
}

type backupConfig struct {
	AutoBackupEnable    bool   `json:"autoBackupEnable"`
	AutoBackupTime      string `json:"autoBackupTime"`
	AutoBackupSelection uint64 `json:"autoBackupSelection"`

	BackupCleanStrategy  int    `json:"backupCleanStrategy"`
	BackupCleanKeepCount int    `json:"backupCleanKeepCount"`
	BackupCleanKeepDur   string `json:"backupCleanKeepDur"`
	BackupCleanTrigger   int    `json:"backupCleanTrigger"`
	BackupCleanCron      string `json:"backupCleanCron"`
}

func backupConfigGet(c echo.Context) error {
	public, _ := dm.ManagerPublicConfigSnapshot()
	bc := backupConfig{
		AutoBackupEnable:     public.AutoBackupEnable,
		AutoBackupTime:       public.AutoBackupTime,
		AutoBackupSelection:  public.AutoBackupSelection,
		BackupCleanStrategy:  public.BackupClean.Strategy,
		BackupCleanKeepCount: public.BackupClean.KeepCount,
		BackupCleanKeepDur:   time.Duration(public.BackupClean.KeepDuration).String(),
		BackupCleanTrigger:   public.BackupClean.Trigger,
		BackupCleanCron:      public.BackupClean.Cron,
	}
	return c.JSON(http.StatusOK, bc)
}

func backupConfigSave(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	v := backupConfig{}
	err := c.Bind(&v)
	if err != nil {
		return c.String(430, "")
	}

	var retention *time.Duration
	if v.BackupCleanStrategy == int(dice.BackupCleanStrategyByTime) && v.BackupCleanKeepDur != "" {
		if duration, parseErr := time.ParseDuration(v.BackupCleanKeepDur); parseErr == nil {
			retention = &duration
		} else {
			myDice.Logger.Errorf("设定的自动清理保留时间有误: %q %v", v.BackupCleanKeepDur, parseErr)
		}
	}
	err = dm.DurableMutateManagerConfig(c.Request().Context(), "backup-settings", v, func(public *managerstate.PublicConfig) error {
		public.AutoBackupEnable = v.AutoBackupEnable
		public.AutoBackupTime = v.AutoBackupTime
		public.AutoBackupSelection = v.AutoBackupSelection
		if int(dice.BackupCleanStrategyDisabled) <= v.BackupCleanStrategy && v.BackupCleanStrategy <= int(dice.BackupCleanStrategyByTime) {
			public.BackupClean.Strategy = v.BackupCleanStrategy
			if v.BackupCleanStrategy == int(dice.BackupCleanStrategyByCount) && v.BackupCleanKeepCount > 0 {
				public.BackupClean.KeepCount = v.BackupCleanKeepCount
			}
			if retention != nil {
				public.BackupClean.KeepDuration = int64(*retention)
			}
			if v.BackupCleanTrigger > 0 {
				public.BackupClean.Trigger = v.BackupCleanTrigger
				if dice.BackupCleanTrigger(v.BackupCleanTrigger)&dice.BackupCleanTriggerCron > 0 {
					public.BackupClean.Cron = v.BackupCleanCron
				}
			}
		}
		return nil
	})
	if err != nil {
		return Error(&c, err.Error(), Response{"code": "config_update_failed"})
	}
	dm.ResetAutoBackup()
	dm.ResetBackupClean()
	return c.String(http.StatusOK, "")
}
