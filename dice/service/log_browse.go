package service

import (
	"errors"
	"strings"

	"gorm.io/gorm"

	"Scardice-core/model"
	"Scardice-core/utils/constant"
	engine2 "Scardice-core/utils/dboperator/engine"
)

const (
	logBrowseDefaultPageSize = 50
	logBrowseMaxPageSize     = 200
)

// QueryLogLineBrowse 群消息 log 浏览器查询参数。
// 只读，按单本日志（groupId + logName）检索。
type QueryLogLineBrowse struct {
	PageNum  int    `query:"pageNum"`
	PageSize int    `query:"pageSize"`
	GroupID  string `query:"groupId"`
	LogName  string `query:"logName"`
	// Keyword 匹配消息正文，支持 % 和 _ 字面量。
	Keyword string `query:"keyword"`
	// Sender 同时匹配昵称、IM 用户 ID 与统一 ID。
	Sender string `query:"sender"`
	// TimeBegin/TimeEnd 为 Unix 秒，闭区间；0 表示不限。
	TimeBegin int64 `query:"timeBegin"`
	TimeEnd   int64 `query:"timeEnd"`
	// Order 为 asc 或 desc，默认 desc（最新消息在前）。
	Order string `query:"order"`
}

func normalizeLogBrowsePage(param *QueryLogLineBrowse) {
	if param.PageNum < 1 {
		param.PageNum = 1
	}
	if param.PageSize <= 0 {
		param.PageSize = logBrowseDefaultPageSize
	}
	if param.PageSize > logBrowseMaxPageSize {
		param.PageSize = logBrowseMaxPageSize
	}
}

// escapeLikePattern 转义 LIKE 的通配符，避免用户输入 % / _ 时命中整表。
// 使用 ! 作为 ESCAPE 字符，避免 MySQL/PostgreSQL 对反斜杠字符串字面量的差异。
func escapeLikePattern(value string) string {
	replacer := strings.NewReplacer(
		`!`, `!!`,
		`%`, `!%`,
		`_`, `!_`,
	)
	return replacer.Replace(value)
}

// LogBrowseLinePage 按条件分页检索一本日志中的群消息，返回总数与当前页。
// 已撤回（removed 非 NULL）的记录不返回，与 LogLinesCountGet 的口径一致。
// 关键词和发送者使用前后通配 LIKE；先按 log_id 缩小范围，超大日志下仍可能较慢。
func LogBrowseLinePage(operator engine2.DatabaseOperator, param *QueryLogLineBrowse) (int, []*model.LogOneItem, error) {
	normalizeLogBrowsePage(param)

	db := operator.GetLogDB(constant.READ)
	logID, err := getIDByGroupIDAndName(db, param.GroupID, param.LogName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return 0, []*model.LogOneItem{}, nil
		}
		return 0, nil, err
	}

	newQuery := func() *gorm.DB {
		query := db.Model(&model.LogOneItem{}).
			Where("log_id = ?", logID).
			Where("removed IS NULL")

		if keyword := strings.TrimSpace(param.Keyword); keyword != "" {
			query = query.Where("message LIKE ? ESCAPE '!'", "%"+escapeLikePattern(keyword)+"%")
		}
		if sender := strings.TrimSpace(param.Sender); sender != "" {
			pattern := "%" + escapeLikePattern(sender) + "%"
			query = query.Where(
				"(nickname LIKE ? ESCAPE '!' OR im_userid LIKE ? ESCAPE '!' OR user_uniform_id LIKE ? ESCAPE '!')",
				pattern, pattern, pattern,
			)
		}
		if param.TimeBegin > 0 {
			query = query.Where("time >= ?", param.TimeBegin)
		}
		if param.TimeEnd > 0 {
			query = query.Where("time <= ?", param.TimeEnd)
		}
		return query
	}

	var total int64
	if err = newQuery().Count(&total).Error; err != nil {
		return 0, nil, err
	}

	order := "time DESC, id DESC"
	if strings.EqualFold(strings.TrimSpace(param.Order), "asc") {
		order = "time ASC, id ASC"
	}

	var items = make([]*model.LogOneItem, 0)
	err = newQuery().
		Select("id, nickname, im_userid, time, message, is_dice, command_id, command_info, raw_msg_id, user_uniform_id").
		Order(order).
		Limit(param.PageSize).
		Offset((param.PageNum - 1) * param.PageSize).
		Scan(&items).Error
	if err != nil {
		return 0, nil, err
	}
	return int(total), items, nil
}
