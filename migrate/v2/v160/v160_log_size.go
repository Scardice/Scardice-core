package v160

import (
	"errors"
	"fmt"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	operator "Scardice-core/utils/dboperator/engine"
	upgrade "Scardice-core/utils/upgrader"
)

func V160LogSizeRepairMigrate(dbOperator operator.DatabaseOperator, logf func(string)) error {
	database := dbOperator.GetLogDB(constant.WRITE)
	migrator := database.Migrator()
	if !migrator.HasTable(&model.LogInfo{}) {
		return nil
	}

	columnCreated := false
	if !migrator.HasColumn(&model.LogInfo{}, "size") {
		if err := migrator.AddColumn(&model.LogInfo{}, "Size"); err != nil {
			return fmt.Errorf("为 logs 表补建 size 列失败: %w", err)
		}
		columnCreated = true
	}
	if !migrator.HasTable(&model.LogOneItem{}) {
		return errors.New("logs 表存在但 log_items 表缺失，数据库状态异常，无法重算 size")
	}

	result := database.Exec("UPDATE logs SET size = (SELECT COUNT(1) FROM log_items WHERE log_items.log_id = logs.id AND log_items.removed IS NULL)")
	if result.Error != nil {
		return fmt.Errorf("重算 logs.size 失败: %w", result.Error)
	}
	if columnCreated {
		logf(fmt.Sprintf("数据修复 - Logs表，已补建 size 列并重算了 %d 条记录", result.RowsAffected))
	} else {
		logf(fmt.Sprintf("数据修复 - Logs表，size 列已存在，重算了 %d 条记录", result.RowsAffected))
	}
	return nil
}

var V160LogSizeRepairMigration = upgrade.Upgrade{
	ID: "010_V160LogSizeRepairMigration",
	Description: `
# 升级说明
兜底修复 V150 历史升级失误：若 logs 表缺少 size 列则补建，并对所有日志全量重算 size（该日志下未删除的条目数）。
`,
	Idempotent: true,
	Apply: func(logf func(string), dbOperator operator.DatabaseOperator) error {
		logf("[INFO] V160 logs.size 修复开始")
		if err := V160LogSizeRepairMigrate(dbOperator, logf); err != nil {
			return err
		}
		logf("[INFO] V160 logs.size 修复处置完毕")
		return nil
	},
}
