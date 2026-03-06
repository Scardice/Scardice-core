package service

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	engine2 "Scardice-core/utils/dboperator/engine"
)

var ErrEndpointInfoUIDEmpty = errors.New("user id is empty")

func Query(operator engine2.DatabaseOperator, e *model.EndpointInfo) error {
	db := operator.GetDataDB(constant.READ)
	if len(e.UserID) == 0 {
		return ErrEndpointInfoUIDEmpty
	}
	if db == nil {
		return errors.New("db is nil")
	}

	err := db.Model(&model.EndpointInfo{}).
		Where("user_id = ?", e.UserID).
		Select("cmd_num", "cmd_last_time", "online_time", "updated_at").
		Limit(1).
		Find(&e).Error

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return err
	}

	return nil
}

func Save(operator engine2.DatabaseOperator, e *model.EndpointInfo) error {
	db := operator.GetDataDB(constant.WRITE)
	// 检查 user_id 是否为空
	if len(e.UserID) == 0 {
		return ErrEndpointInfoUIDEmpty
	}

	payload := &model.EndpointInfo{
		UserID:      e.UserID,
		CmdNum:      e.CmdNum,
		CmdLastTime: e.CmdLastTime,
		OnlineTime:  e.OnlineTime,
		UpdatedAt:   e.UpdatedAt,
	}

	fn := "GREATEST"
	if strings.EqualFold(operator.Type(), "sqlite") {
		fn = "MAX"
	}

	onConflict := clause.OnConflict{
		Columns: []clause.Column{{Name: "user_id"}},
		DoUpdates: clause.Assignments(map[string]interface{}{
			"cmd_num":       gorm.Expr(fmt.Sprintf("%s(cmd_num, ?)", fn), payload.CmdNum),
			"cmd_last_time": gorm.Expr(fmt.Sprintf("%s(cmd_last_time, ?)", fn), payload.CmdLastTime),
			"online_time":   gorm.Expr(fmt.Sprintf("%s(online_time, ?)", fn), payload.OnlineTime),
			"updated_at":    gorm.Expr(fmt.Sprintf("%s(updated_at, ?)", fn), payload.UpdatedAt),
		}),
	}

	const maxRetries = 20
	for attempt := 0; ; attempt++ {
		err := db.Clauses(onConflict).Create(payload).Error
		if err == nil {
			return nil
		}
		// SQLite 高并发写入时可能出现瞬时锁冲突，短重试可以显著降低假失败概率
		if !strings.EqualFold(operator.Type(), "sqlite") || !isSQLiteLockError(err) || attempt >= maxRetries {
			return err
		}
		time.Sleep(time.Duration(attempt+1) * 5 * time.Millisecond)
	}
}

func isSQLiteLockError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked")
}
