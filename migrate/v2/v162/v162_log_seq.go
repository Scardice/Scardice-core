package v162

import (
	"fmt"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	operator "Scardice-core/utils/dboperator/engine"
	upgrade "Scardice-core/utils/upgrader"
)

func V162LogSeqMigrate(dboperator operator.DatabaseOperator, logf func(string)) error {
	db := dboperator.GetLogDB(constant.WRITE)
	if !db.Migrator().HasTable(&model.LogOneItem{}) {
		return nil
	}

	target := any(&model.LogOneItem{})
	if dboperator.Type() == constant.MYSQL {
		target = &model.LogOneItemHookMySQL{}
	}

	if db.Migrator().HasColumn(target, "seq") {
		logf("数据升级 - LogItems表，seq列已存在，无需处理")
		return nil
	}
	if err := db.Migrator().AddColumn(target, "Seq"); err != nil {
		return err
	}
	logf("数据升级 - LogItems表，已添加seq列（默认NULL，兼容历史记录）")

	return nil
}

var V162AddLogSeqMigration = upgrade.Upgrade{
	ID:         "012_V162AddLogSeqMigration",
	Idempotent: true,
	Description: `
# 升级说明
为日志条目补齐seq列，用于掉线期间的日志断层检测与补全，历史记录保持NULL
`,
	Apply: func(logf func(string), operator operator.DatabaseOperator) error {
		logf(fmt.Sprintf("[INFO] V162日志seq列升级开始 type=%s", operator.Type()))
		err := V162LogSeqMigrate(operator, logf)
		if err != nil {
			return err
		}
		logf("[INFO] V162日志seq列升级处置完毕")
		return nil
	},
}
