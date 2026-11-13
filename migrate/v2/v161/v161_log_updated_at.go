package v161

import (
	"errors"
	"fmt"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	operator "Scardice-core/utils/dboperator/engine"
	upgrade "Scardice-core/utils/upgrader"
)

// V161LogUpdatedAtRepairMigrate 按日志最后一条记录时间回填 logs.updated_at；无记录时回退到 created_at。
func V161LogUpdatedAtRepairMigrate(dboperator operator.DatabaseOperator, logf func(string)) error {
	db := dboperator.GetLogDB(constant.WRITE)
	migrator := db.Migrator()

	if !migrator.HasTable(&model.LogInfo{}) {
		return nil
	}
	if !migrator.HasTable(&model.LogOneItem{}) {
		return errors.New("logs 表存在但 log_items 表缺失，数据库状态异常，无法回填 updated_at")
	}

	res := db.Exec(`
UPDATE logs
SET updated_at = COALESCE(
	(SELECT MAX(log_items.time) FROM log_items WHERE log_items.log_id = logs.id),
	created_at
)`)
	if res.Error != nil {
		return res.Error
	}

	logf(fmt.Sprintf("数据修复 - Logs表，按日志最后一条记录时间回填了 %d 条 updated_at", res.RowsAffected))
	return nil
}

var V161LogUpdatedAtRepairMigration = upgrade.Upgrade{
	ID:         "014_V161LogUpdatedAtRepairMigration",
	Idempotent: true,
	Description: `
# 升级说明
按每个 log 的最后一条日志时间回填 logs.updated_at；若没有日志条目，则回退到 created_at。
`,
	Apply: func(logf func(string), dbOperator operator.DatabaseOperator) error {
		logf("[INFO] V161 logs.updated_at 修复开始")
		if err := V161LogUpdatedAtRepairMigrate(dbOperator, logf); err != nil {
			return err
		}
		logf("[INFO] V161 logs.updated_at 修复处置完毕")
		return nil
	},
}
