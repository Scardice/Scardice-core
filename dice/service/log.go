package service

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pilagod/gorm-cursor-paginator/v2/paginator"
	"go.uber.org/zap"
	"gorm.io/gorm"

	"Scardice-core/logger"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
	engine2 "Scardice-core/utils/dboperator/engine"
	"Scardice-core/utils/dboperator/schema"
)

type LogOne struct {
	// Version int           `json:"version,omitempty"`
	Items []model.LogOneItem `json:"items"`
	Info  model.LogInfo      `json:"info"`
}

var ErrLogNotFound = errors.New("日志不存在")

// logAppendDedupeMu 串行化“按 raw_msg_id 查重 + 插入”，防止实时消息与补录
// 在同一进程内交错写入同一条平台消息。跨进程/多实例仍需要数据库唯一约束；
// 这里不建唯一索引，避免历史库里已有重复行导致迁移失败。
var logAppendDedupeMu sync.Mutex

// LogGetInfo 查询日志简略信息（近似估算）
// 返回值保持原结构：logs 最大 ID、log_items 最大 ID、logs 近似行数、log_items 近似行数。
func LogGetInfo(operator engine2.DatabaseOperator) ([]int, error) {
	db := operator.GetLogDB(constant.READ)
	dbType := operator.Type()
	logMaxID, logRows, err := logTableApproxInfo(db, dbType, "logs", &model.LogInfo{})
	if err != nil {
		return nil, err
	}
	itemMaxID, itemRows, err := logTableApproxInfo(db, dbType, "log_items", &model.LogOneItem{})
	if err != nil {
		return nil, err
	}
	return []int{int(logMaxID), int(itemMaxID), int(logRows), int(itemRows)}, nil
}

func logTableApproxInfo(db *gorm.DB, dbType string, tableName string, modelValue interface{}) (maxID int64, rows int64, err error) {
	maxID, err = queryMaxID(db, modelValue)
	if err != nil {
		return 0, 0, err
	}
	rows = maxID
	switch dbType {
	case constant.SQLITE:
		if seq, ok := querySQLiteSequence(db, tableName); ok {
			rows = seq
		}
	case constant.MYSQL:
		if tableRows, ok := queryMySQLTableRows(db, tableName); ok {
			rows = tableRows
		}
	case constant.POSTGRESQL, "pgsql":
		if tableRows, ok := queryPostgreSQLTableRows(db, tableName); ok {
			rows = tableRows
		}
	}
	return maxID, rows, nil
}

func querySQLiteSequence(db *gorm.DB, tableName string) (int64, bool) {
	var seq sql.NullInt64
	if err := db.Raw("SELECT seq FROM sqlite_sequence WHERE name = ?", tableName).Scan(&seq).Error; err != nil {
		return 0, false
	}
	return seq.Int64, seq.Valid
}

func queryMySQLTableRows(db *gorm.DB, tableName string) (int64, bool) {
	var rows sql.NullInt64
	err := db.Raw(
		"SELECT TABLE_ROWS FROM information_schema.tables WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
		tableName,
	).Scan(&rows).Error
	if err != nil || !rows.Valid || rows.Int64 < 0 {
		return 0, false
	}
	return rows.Int64, true
}

func queryPostgreSQLTableRows(db *gorm.DB, tableName string) (int64, bool) {
	var rows sql.NullInt64
	err := db.Raw("SELECT reltuples::BIGINT FROM pg_class WHERE oid = ?::regclass", tableName).Scan(&rows).Error
	if err != nil || !rows.Valid || rows.Int64 < 0 {
		return 0, false
	}
	return rows.Int64, true
}

func queryMaxID(db *gorm.DB, modelValue interface{}) (int64, error) {
	var maxID sql.NullInt64
	if err := db.Model(modelValue).Select("MAX(id)").Scan(&maxID).Error; err != nil {
		return 0, err
	}
	return maxID.Int64, nil
}

// Deprecated: replaced by page
func LogGetLogs(operator engine2.DatabaseOperator) ([]*model.LogInfo, error) {
	db := operator.GetLogDB(constant.READ)
	var lst []*model.LogInfo

	// 使用 GORM 查询 logs 表
	if err := db.Model(&model.LogInfo{}).
		Select("id, name, group_id, created_at, updated_at").
		Find(&lst).Error; err != nil {
		return nil, err
	}

	return lst, nil
}

type QueryLogPage struct {
	PageNum          int    `db:"page_num"           query:"pageNum"`
	PageSize         int    `db:"page_siz"           query:"pageSize"`
	Name             string `db:"name"               query:"name"`
	GroupID          string `db:"group_id"           query:"groupId"`
	CreatedTimeBegin string `db:"created_time_begin" query:"createdTimeBegin"`
	CreatedTimeEnd   string `db:"created_time_end"   query:"createdTimeEnd"`
}

// LogGetLogPage 获取分页
func LogGetLogPage(operator engine2.DatabaseOperator, param *QueryLogPage) (int, []*model.LogInfo, error) {
	db := operator.GetLogDB(constant.READ)
	var lst []*model.LogInfo

	// 构建基础查询
	query := db.Model(&model.LogInfo{}).Select("logs.id, logs.name, logs.group_id, logs.created_at, logs.updated_at,COALESCE(logs.size, 0) as size").Order("logs.updated_at desc")
	// 添加条件
	if param.Name != "" {
		query = query.Where("logs.name LIKE ?", "%"+param.Name+"%")
	}
	if param.GroupID != "" {
		query = query.Where("logs.group_id LIKE ?", "%"+param.GroupID+"%")
	}
	if param.CreatedTimeBegin != "" {
		query = query.Where("logs.created_at >= ?", param.CreatedTimeBegin)
	}
	if param.CreatedTimeEnd != "" {
		query = query.Where("logs.created_at <= ?", param.CreatedTimeEnd)
	}

	// 获取总数
	var count int64
	if err := db.Model(&model.LogInfo{}).Count(&count).Error; err != nil {
		return 0, nil, err
	}

	// 分页查询
	query = query.Group("logs.id").Limit(param.PageSize).Offset((param.PageNum - 1) * param.PageSize)

	// 执行查询
	if err := query.Scan(&lst).Error; err != nil {
		return 0, nil, err
	}

	return int(count), lst, nil
}

// LogGetList 获取列表
func LogGetList(operator engine2.DatabaseOperator, groupID string) ([]string, error) {
	db := operator.GetLogDB(constant.READ)
	var lst []string

	// 执行查询
	if err := db.Model(&model.LogInfo{}).
		Select("name").
		Where("group_id = ?", groupID).
		Order("updated_at DESC").
		Pluck("name", &lst).Error; err != nil {
		return nil, err
	}

	return lst, nil
}

// getIDByGroupIDAndName 获取ID 私有函数，可以直接使用db
func getIDByGroupIDAndName(db *gorm.DB, groupID string, logName string) (logID uint64, err error) {
	var logInfo model.LogInfo
	err = db.Model(&model.LogInfo{}).
		Select("id").
		Where("group_id = ? AND name = ?", groupID, logName).
		Take(&logInfo).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrLogNotFound
		}
		return 0, err
	}
	if logInfo.ID == 0 {
		return 0, ErrLogNotFound
	}
	return logInfo.ID, nil
}

// LogGetIDByName 按群号和日志名查询已有日志的内部 ID。
// 只读，不创建日志；日志不存在时返回 ErrLogNotFound。
// 用于修复“日志关闭但持久化 LogCurID 丢失”的老数据（1119.fix1）。
func LogGetIDByName(operator engine2.DatabaseOperator, groupID, logName string) (uint64, error) {
	if operator == nil || groupID == "" || logName == "" {
		return 0, ErrLogNotFound
	}
	return getIDByGroupIDAndName(operator.GetLogDB(constant.READ), groupID, logName)
}

func getLogInfoByID(db *gorm.DB, logID uint64) (*model.LogInfo, error) {
	var logInfo model.LogInfo
	err := db.Model(&model.LogInfo{}).
		Where("id = ?", logID).
		Take(&logInfo).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrLogNotFound
		}
		return nil, err
	}
	if logInfo.ID == 0 {
		return nil, ErrLogNotFound
	}
	return &logInfo, nil
}

func getLogInfoByRawMsgID(db *gorm.DB, groupID string, rawID interface{}) (*model.LogInfo, error) {
	rid := fmt.Sprintf("%v", rawID)
	if rid == "" {
		return nil, ErrLogNotFound
	}

	// NOTE:
	// - 这里依赖 log_items 上的复合索引 (group_id, raw_msg_id, id)，以支撑 WHERE + ORDER BY 的查询模式。
	// - 正常情况下，同一群内不应存在多条相同 raw_msg_id 的日志项；若出现，默认以最新一条为准。
	var candidates []struct {
		ID    uint64 `gorm:"column:id"`
		LogID uint64 `gorm:"column:log_id"`
	}
	err := db.Model(&model.LogOneItem{}).
		Select("id, log_id").
		Where("group_id = ? AND raw_msg_id = ?", groupID, rid).
		Order("id DESC").
		Limit(2).
		Find(&candidates).Error
	if err != nil {
		return nil, err
	}

	if len(candidates) == 0 || candidates[0].LogID == 0 {
		return nil, ErrLogNotFound
	}

	if len(candidates) > 1 {
		zap.S().Named(logger.LogKeyDatabase).Warnf("日志RawMsgID出现重复，按最新记录处理: group=%s raw_msg_id=%s latest_item_id=%d", groupID, rid, candidates[0].ID)
	}

	return getLogInfoByID(db, candidates[0].LogID)
}

func createLog(tx *gorm.DB, groupID string, logName string, nowTimestamp int64) (uint64, error) {
	newLog := model.LogInfo{Name: logName, GroupID: groupID, CreatedAt: nowTimestamp, UpdatedAt: nowTimestamp}
	if err := tx.Create(&newLog).Error; err != nil {
		existedLogID, findErr := getIDByGroupIDAndName(tx, groupID, logName)
		if findErr != nil {
			return 0, err
		}
		return existedLogID, nil
	}
	return newLog.ID, nil
}

// LogGetOrCreate 返回指定群和日志名对应的内部 log_id，不存在时自动创建。
func LogGetOrCreate(operator engine2.DatabaseOperator, groupID string, logName string) (uint64, error) {
	db := operator.GetLogDB(constant.WRITE)
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err == nil {
		return logID, nil
	}
	if !errors.Is(err, ErrLogNotFound) {
		return 0, err
	}

	nowTimestamp := time.Now().Unix()
	err = db.Transaction(func(tx *gorm.DB) error {
		var createErr error
		logID, createErr = createLog(tx, groupID, logName, nowTimestamp)
		return createErr
	})
	if err != nil {
		return 0, err
	}
	return logID, nil
}

// LogGetUploadInfo 获取上传信息
func LogGetUploadInfo(operator engine2.DatabaseOperator, groupID string, logName string) (url string, uploadTime, updateTime int64, err error) {
	db := operator.GetLogDB(constant.READ)
	var logInfo struct {
		UpdatedAt  int64  `gorm:"column:updated_at"`
		UploadURL  string `gorm:"column:upload_url"`
		UploadTime int64  `gorm:"column:upload_time"`
	}

	err = db.Model(&model.LogInfo{}).
		Select("updated_at, upload_url, upload_time").
		Where("group_id = ? AND name = ?", groupID, logName).
		Take(&logInfo).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", 0, 0, ErrLogNotFound
		}
		return "", 0, 0, err
	}

	// 提取结果
	updateTime = logInfo.UpdatedAt
	url = logInfo.UploadURL
	uploadTime = logInfo.UploadTime
	return url, uploadTime, updateTime, err
}

// LogSetUploadInfo 设置上传信息
func LogSetUploadInfo(operator engine2.DatabaseOperator, groupID string, logName string, url string) error {
	db := operator.GetLogDB(constant.WRITE)
	if len(url) == 0 {
		return nil
	}

	now := time.Now().Unix()

	// 元数据写回不能刷新 logs.updated_at；该字段只表示日志内容最后变更时间。
	result := db.Model(&model.LogInfo{}).
		Where("group_id = ? AND name = ?", groupID, logName).
		UpdateColumns(map[string]interface{}{
			"upload_url":  url,
			"upload_time": now,
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return ErrLogNotFound
	}
	return nil
}

// LogGetAllLines 获取log的所有行数据
func CreateLoggerPaginator(
	cursor paginator.Cursor,
	order *paginator.Order,
) *paginator.Paginator {
	opts := []paginator.Option{
		&paginator.Config{
			Keys:  []string{"ID", "Time"}, // 这里设置的是结构体的字段名称，而不是gorm里的名称……
			Limit: 4000,
			Order: paginator.ASC,
		},
	}
	if order != nil {
		opts = append(opts, paginator.WithOrder(*order))
	}
	if cursor.After != nil {
		opts = append(opts, paginator.WithAfter(*cursor.After))
	}
	if cursor.Before != nil {
		opts = append(opts, paginator.WithBefore(*cursor.Before))
	}
	return paginator.New(opts...)
}

func LogGetAllLines(operator engine2.DatabaseOperator, groupID string, logName string) ([]*model.LogOneItem, error) {
	db := operator.GetLogDB(constant.READ)
	// 获取log的ID
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return []*model.LogOneItem{}, nil
		}
		return nil, err
	}

	var items []*model.LogOneItem

	// 查询行数据
	err = db.Model(&model.LogOneItem{}).
		Select("id, nickname, im_userid, time, message, is_dice, command_id, command_info, raw_msg_id, user_uniform_id").
		Where("log_id = ?", logID).
		Order("time ASC").
		Find(&items).Error

	if err != nil {
		return nil, err
	}
	return items, nil
}

func LogGetCommandInfoStrList(operator engine2.DatabaseOperator, groupID string, logName string) ([]string, error) {
	db := operator.GetLogDB(constant.READ)
	// 获取log的ID
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return []string{}, nil
		}
		return nil, err
	}

	var items []string

	// 查询行数据
	err = db.Model(&model.LogOneItem{}).
		Where("log_id = ?", logID).
		Order("time ASC").
		Pluck("command_info", &items).Error

	if err != nil {
		return nil, err
	}
	return items, nil
}

func LogGetCursorLines(operator engine2.DatabaseOperator, groupID string, logName string, cursor paginator.Cursor) ([]model.LogOneItem, paginator.Cursor, error) {
	db := operator.GetLogDB(constant.READ)
	// 获取log的ID
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return []model.LogOneItem{}, paginator.Cursor{}, nil
		}
		return nil, paginator.Cursor{}, err
	}
	var items []model.LogOneItem
	stmt := db.Model(&model.LogOneItem{}).
		Select("id, nickname, im_userid, time, message, is_dice, command_id, command_info, raw_msg_id, user_uniform_id").
		Where("log_id = ?", logID)
	// 获取游标分页器
	p := CreateLoggerPaginator(cursor, nil)
	// 进行游标分页
	result, cursor, err := p.Paginate(stmt, &items)
	if err != nil {
		return nil, paginator.Cursor{}, err
	}
	// this is gorm error
	if result.Error != nil {
		return nil, paginator.Cursor{}, result.Error
	}
	return items, cursor, nil
}

func LogGetExportCursorLines(operator engine2.DatabaseOperator, groupID string, logName string, cursor paginator.Cursor) ([]model.LogOneItemParquet, paginator.Cursor, error) {
	db := operator.GetLogDB(constant.READ)
	// 获取log的ID
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return []model.LogOneItemParquet{}, paginator.Cursor{}, nil
		}
		return nil, paginator.Cursor{}, err
	}
	var items []model.LogOneItemParquet
	stmt := db.Model(&model.LogOneItemParquet{}).
		Select("id, nickname, im_userid, time, message, is_dice, command_id, command_info, raw_msg_id, user_uniform_id").
		Where("log_id = ?", logID)
	// 获取游标分页器
	p := CreateLoggerPaginator(cursor, nil)
	// 进行游标分页
	result, cursor, err := p.Paginate(stmt, &items)
	if err != nil {
		return nil, paginator.Cursor{}, err
	}
	// this is gorm error
	if result.Error != nil {
		return nil, paginator.Cursor{}, result.Error
	}
	return items, cursor, nil
}

type QueryLogLinePage struct {
	PageNum  int    `query:"pageNum"`
	PageSize int    `query:"pageSize"`
	GroupID  string `query:"groupId"`
	LogName  string `query:"logName"`
	// PlayerID 按玩家过滤（同时匹配 im_userid 与 user_uniform_id）
	PlayerID string `query:"playerId"`
}

// LogGetLinePage 获取log的行分页
func LogGetLinePage(operator engine2.DatabaseOperator, param *QueryLogLinePage) ([]*model.LogOneItem, error) {
	db := operator.GetLogDB(constant.READ)
	// 获取log的ID
	logID, err := getIDByGroupIDAndName(db, param.GroupID, param.LogName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return []*model.LogOneItem{}, nil
		}
		return nil, err
	}

	var items []*model.LogOneItem

	// 查询行数据
	stmt := db.Model(&model.LogOneItem{}).
		Select("id, nickname, im_userid, time, message, is_dice, command_id, command_info, raw_msg_id, user_uniform_id").
		Where("log_id = ?", logID)
	if param.PlayerID != "" {
		stmt = stmt.Where("(im_userid = ? OR user_uniform_id = ?)", param.PlayerID, param.PlayerID)
	}
	err = stmt.Order("time ASC").
		Limit(param.PageSize).
		Offset((param.PageNum - 1) * param.PageSize).
		Scan(&items).Error

	if err != nil {
		return nil, err
	}

	return items, nil
}

// LogLinesCountGet 获取日志行数
func LogLinesCountGet(operator engine2.DatabaseOperator, groupID string, logName string) (int64, bool) {
	db := operator.GetLogDB(constant.READ)
	// 获取日志 ID
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		return 0, false
	}

	// 获取日志行数
	var count int64
	err = db.Model(&model.LogOneItem{}).
		Where("log_id = ? and removed IS NULL", logID).
		Count(&count).Error

	if err != nil {
		return 0, false
	}

	return count, true
}

// LogGetLastSeq 查询指定log中已记录的最大消息序号，用于跨进程重启恢复断层检测基线。
// MAX 天然忽略 NULL，故返回 0 表示该log中没有任何带seq的记录（全新log、旧版本数据或不支持seq的平台）。
func LogGetLastSeq(operator engine2.DatabaseOperator, logID uint64) (int64, error) {
	if logID == 0 {
		return 0, nil
	}
	db := operator.GetLogDB(constant.READ)

	var maxSeq sql.NullInt64
	err := db.Model(&model.LogOneItem{}).
		Where("log_id = ?", logID).
		Select("MAX(seq)").
		Scan(&maxSeq).Error
	if err != nil {
		return 0, err
	}

	return maxSeq.Int64, nil
}

// LogGetNameByID 查询指定 log_id 的日志名称。
// 用于校验持久化的当前日志 ID 是否仍指向同一本日志：日志被 Web UI 删除时返回
// ErrLogNotFound，ID 被复用（数据库恢复）时返回另一个名字，调用方据此自愈。
func LogGetNameByID(operator engine2.DatabaseOperator, logID uint64) (string, error) {
	_, name, err := LogGetOwnerByID(operator, logID)
	return name, err
}

// LogGetOwnerByID 查询指定 log_id 的归属群与日志名称。
// 只查名字发现不了“ID 被复用成另一个群的同名日志”：那种情况下运行期会被
// LogAppendByID 的归属校验拒绝，启动时应按名字重建本群自己的日志。
func LogGetOwnerByID(operator engine2.DatabaseOperator, logID uint64) (groupID string, name string, err error) {
	if logID == 0 {
		return "", "", ErrLogNotFound
	}
	logInfo, err := getLogInfoByID(operator.GetLogDB(constant.READ), logID)
	if err != nil {
		return "", "", err
	}
	return logInfo.GroupID, logInfo.Name, nil
}

// LoggedSeqKeys 是补录去重所需的已记录键集合。
type LoggedSeqKeys struct {
	RawMsgIDs map[string]struct{}
	Seqs      map[int64]struct{}
}

// LoggedKeysInSeqRange 返回指定 log 在 (fromSeq, toSeq) 区间内已记录的
// raw_msg_id 与 seq 集合。1118: seq 也参与去重，解决平台不返回 raw_msg_id
// 时重试/分段汇总产生重复行的问题。
func LoggedKeysInSeqRange(operator engine2.DatabaseOperator, logID uint64, fromSeq, toSeq int64) (LoggedSeqKeys, error) {
	result := LoggedSeqKeys{
		RawMsgIDs: make(map[string]struct{}),
		Seqs:      make(map[int64]struct{}),
	}
	if logID == 0 || toSeq <= fromSeq+1 {
		return result, nil
	}
	db := operator.GetLogDB(constant.READ)

	var rows []struct {
		RawMsgID sql.NullString `gorm:"column:raw_msg_id"`
		Seq      sql.NullInt64  `gorm:"column:seq"`
	}
	err := db.Model(&model.LogOneItem{}).
		Select("raw_msg_id, seq").
		Where("log_id = ? AND seq IS NOT NULL AND is_dice IS NOT TRUE AND seq > ? AND seq < ?", logID, fromSeq, toSeq).
		Scan(&rows).Error
	if err != nil {
		return result, err
	}
	for _, row := range rows {
		if row.Seq.Valid {
			result.Seqs[row.Seq.Int64] = struct{}{}
		}
		// "0" 表示平台没有返回真实消息 ID（见 logItemRawMsgID），不能当成
		// 已记录过的消息，否则会跳过之后所有缺 ID 的补录。
		if row.RawMsgID.Valid && row.RawMsgID.String != "" && row.RawMsgID.String != "0" {
			result.RawMsgIDs[row.RawMsgID.String] = struct{}{}
		}
	}
	return result, nil
}

// LogRawMsgIDsInSeqRange 返回指定 log 在 (fromSeq, toSeq) 区间内已记录的 raw_msg_id 集合。
// 用于日志补全前去重：平台补发/重连时同一消息可能既走过正常事件路径，又被历史拉取到。
func LogRawMsgIDsInSeqRange(operator engine2.DatabaseOperator, logID uint64, fromSeq, toSeq int64) (map[string]struct{}, error) {
	keys, err := LoggedKeysInSeqRange(operator, logID, fromSeq, toSeq)
	if err != nil {
		return nil, err
	}
	return keys.RawMsgIDs, nil
}

// LogDelete 删除log
func LogDelete(operator engine2.DatabaseOperator, groupID string, logName string) error {
	db := operator.GetLogDB(constant.WRITE)
	// 获取 log ID
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		return err
	}
	err = db.Transaction(func(tx *gorm.DB) error {
		// 删除 log_id 相关的 log_items 记录
		if err = tx.Where("log_id = ?", logID).Delete(&model.LogOneItem{}).Error; err != nil {
			return err
		}

		// 删除 log_id 相关的 logs 记录
		if err = tx.Where("id = ?", logID).Delete(&model.LogInfo{}).Error; err != nil {
			return err
		}
		return nil
	})

	return err
}

var (
	logSchemaHealed atomic.Bool
	logSchemaHealMu sync.Mutex
)

func isMissingColumnErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such column") ||
		strings.Contains(msg, "has no column") ||
		strings.Contains(msg, "unknown column")
}

func maybeHealLogSchema(operator engine2.DatabaseOperator, err error) bool {
	if !isMissingColumnErr(err) || logSchemaHealed.Load() {
		return false
	}
	logSchemaHealMu.Lock()
	defer logSchemaHealMu.Unlock()
	if logSchemaHealed.Load() {
		return false
	}
	dbLog := zap.S().Named(logger.LogKeyDatabase)
	healErr := schema.EnsureLogSchema(operator.GetLogDB(constant.WRITE), operator.Type())
	if healErr != nil {
		dbLog.Errorf("log schema self-heal failed: %v (cause: %v)", healErr, err)
		return false
	}
	logSchemaHealed.Store(true)
	dbLog.Warnf("log schema self-heal completed after write error: %v", err)
	return true
}

func logAppendDBErr(op string, groupID, logName string, logID uint64, err error) {
	zap.S().Named(logger.LogKeyDatabase).Errorf(
		"%s failed group=%s name=%s logID=%d err=%v",
		op, groupID, logName, logID, err,
	)
}

// LogAppend 向指定的log中添加一条信息
func LogAppend(operator engine2.DatabaseOperator, groupID string, logName string, logItem *model.LogOneItem) bool {
	logAppendDedupeMu.Lock()
	defer logAppendDedupeMu.Unlock()
	err := logAppendOnce(operator, groupID, logName, logItem)
	if err != nil && maybeHealLogSchema(operator, err) {
		err = logAppendOnce(operator, groupID, logName, logItem)
	}
	if err != nil {
		logAppendDBErr("LogAppend", groupID, logName, 0, err)
		return false
	}
	return true
}

// logItemRawMsgID 返回与 model.LogOneItem.BeforeSave 一致的 raw_msg_id 字符串。
// "0" 与空值都视为“平台没有提供可用的消息 ID”：部分 OneBot 实现在缺失
// message_id 时会序列化成 0，若拿 "0" 去重，会把之后所有同类消息都误判成重复。
func logItemRawMsgID(item *model.LogOneItem) string {
	if item == nil {
		return ""
	}
	rawID := item.RawMsgIDStr
	if item.RawMsgID != nil {
		rawID = fmt.Sprintf("%v", item.RawMsgID)
	}
	if rawID == "0" {
		return ""
	}
	return rawID
}

// logAppendDuplicate 在事务内检查同一日志是否已经写入过该平台消息。
// 调用方需持有 logAppendDedupeMu，保证“查重+插入”在进程内串行。
//
// 只比较 is_dice=false 的条目：去重的目标是“玩家/其他机器人的群消息”
// 在实时路径与历史补录路径之间去重。骰子自身发言（is_dice=true）不参与：
//   - 它不会进入补录路径（logItem/replay 写入的都是非骰子消息）；
//   - 私聊暗骰回显、群内骰子回复、不同私聊会话的回显来自不同的消息 ID
//     命名空间（Telegram 等平台按会话独立编号），同号时会互相顶掉。
//
// 代价是同一骰子回调被重复触发时会多落一行；这里优先保证不丢日志。
//
// group_id 参与条件是给 MySQL 用的：MySQL 的 log_items 由
// LogOneItemHookMySQL 建表，raw_msg_id 是 TEXT 列，不能直接建
// (log_id, raw_msg_id) 普通索引；带上 group_id 可以复用已有的
// idx_log_delete_by_id(group_id(20), raw_msg_id(20), id) 前缀索引。
// SQLite/PostgreSQL 仍会走 idx_log_raw(log_id, raw_msg_id)。
func logAppendDuplicate(tx *gorm.DB, logID uint64, groupID, rawID string, seq *int64, isGapFill bool) (bool, error) {
	// 1118: 补录条目按 (log_id, seq) 再去重一次。平台不返回 raw_msg_id
	// （"0"/空）时，分段补录 + 失败重试/最终汇总会重复写同一 seq；
	// seq 在同一本日志内唯一，比 raw id 更可靠。
	//
	// 1119: 只在 raw id 不可用时才按 seq 去重。平台 seq 重置后，新消息可能
	// 撞上旧日志行；raw id 不同说明是另一条消息，不能因此静默丢掉。
	if isGapFill && seq != nil && *seq > 0 && rawID == "" {
		var seqCount int64
		if err := tx.Model(&model.LogOneItem{}).
			Where("log_id = ? AND seq = ?", logID, *seq).
			Count(&seqCount).Error; err != nil {
			return false, err
		}
		if seqCount > 0 {
			return true, nil
		}
	}
	if rawID == "" {
		return false, nil
	}
	var count int64
	if err := tx.Model(&model.LogOneItem{}).
		Where("log_id = ? AND group_id = ? AND raw_msg_id = ? AND is_dice IS NOT TRUE", logID, groupID, rawID).
		Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func logAppendOnce(operator engine2.DatabaseOperator, groupID string, logName string, logItem *model.LogOneItem) error {
	db := operator.GetLogDB(constant.WRITE)
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			logID = 0
		} else {
			return err
		}
	}

	now := time.Now()
	nowTimestamp := now.Unix()

	timestamp := nowTimestamp
	if logItem.Time != 0 {
		timestamp = logItem.Time
	}

	newLogItem := model.LogOneItem{
		LogID:       logID,
		GroupID:     groupID,
		Nickname:    logItem.Nickname,
		IMUserID:    logItem.IMUserID,
		Time:        timestamp,
		Message:     logItem.Message,
		IsDice:      logItem.IsDice,
		CommandID:   logItem.CommandID,
		CommandInfo: logItem.CommandInfo,
		RawMsgID:    logItem.RawMsgID,
		UniformID:   logItem.UniformID,
		Seq:         logItem.Seq,
		IsGapFill:   logItem.IsGapFill,
	}
	return db.Transaction(func(tx *gorm.DB) error {
		if logID == 0 {
			newLog := model.LogInfo{Name: logName, GroupID: groupID, CreatedAt: nowTimestamp, UpdatedAt: nowTimestamp}
			if createErr := tx.Create(&newLog).Error; createErr != nil {
				existedLogID, findErr := getIDByGroupIDAndName(tx, groupID, logName)
				if findErr != nil {
					return createErr
				}
				logID = existedLogID
			} else {
				logID = newLog.ID
			}
		}
		newLogItem.LogID = logID
		// 同一平台消息只落一行：实时路径与补录路径可能几乎同时写入同一条
		// raw_msg_id，log_items 没有唯一约束，必须在事务内查重。
		// 只对 is_dice=false 的玩家/机器人消息去重；骰子自身发言（含私聊
		// 暗骰回显）不参与，避免跨会话 ID 命名空间互相顶掉。
		if !logItem.IsDice {
			if dup, dupErr := logAppendDuplicate(tx, logID, groupID, logItemRawMsgID(&newLogItem), newLogItem.Seq, newLogItem.IsGapFill); dupErr != nil {
				return dupErr
			} else if dup {
				return nil
			}
		}
		if createErr := tx.Create(&newLogItem).Error; createErr != nil {
			return createErr
		}
		if updateErr := tx.Model(&model.LogInfo{}).
			Where("id = ?", logID).
			Updates(map[string]interface{}{
				"updated_at": nowTimestamp,
				"size":       gorm.Expr("COALESCE(size, 0) + ?", 1),
			}).Error; updateErr != nil {
			return updateErr
		}
		return nil
	})
}

// LogAppendByID 向指定 log_id 的日志中追加一条消息。
func LogAppendByID(operator engine2.DatabaseOperator, logID uint64, groupID string, logItem *model.LogOneItem) bool {
	if logID == 0 {
		return false
	}
	logAppendDedupeMu.Lock()
	defer logAppendDedupeMu.Unlock()
	err := logAppendByIDOnce(operator, logID, groupID, logItem)
	if err != nil && maybeHealLogSchema(operator, err) {
		err = logAppendByIDOnce(operator, logID, groupID, logItem)
	}
	if err != nil {
		logAppendDBErr("LogAppendByID", groupID, "", logID, err)
		return false
	}
	return true
}

func logAppendByIDOnce(operator engine2.DatabaseOperator, logID uint64, groupID string, logItem *model.LogOneItem) error {
	db := operator.GetLogDB(constant.WRITE)

	now := time.Now()
	nowTimestamp := now.Unix()

	timestamp := nowTimestamp
	if logItem.Time != 0 {
		timestamp = logItem.Time
	}

	newLogItem := model.LogOneItem{
		LogID:       logID,
		GroupID:     groupID,
		Nickname:    logItem.Nickname,
		IMUserID:    logItem.IMUserID,
		Time:        timestamp,
		Message:     logItem.Message,
		IsDice:      logItem.IsDice,
		CommandID:   logItem.CommandID,
		CommandInfo: logItem.CommandInfo,
		RawMsgID:    logItem.RawMsgID,
		UniformID:   logItem.UniformID,
		Seq:         logItem.Seq,
		IsGapFill:   logItem.IsGapFill,
	}

	return db.Transaction(func(tx *gorm.DB) error {
		logInfo, getErr := getLogInfoByID(tx, logID)
		if getErr != nil {
			return getErr
		}
		if logInfo.GroupID != groupID {
			return fmt.Errorf("log append by id: log %d 不属于群 %s", logID, groupID)
		}
		if !logItem.IsDice {
			if dup, dupErr := logAppendDuplicate(tx, logID, groupID, logItemRawMsgID(&newLogItem), newLogItem.Seq, newLogItem.IsGapFill); dupErr != nil {
				return dupErr
			} else if dup {
				return nil
			}
		}
		if err := tx.Create(&newLogItem).Error; err != nil {
			return err
		}
		if err := tx.Model(&model.LogInfo{}).
			Where("id = ?", logID).
			Updates(map[string]interface{}{
				"updated_at": nowTimestamp,
				"size":       gorm.Expr("COALESCE(size, 0) + ?", 1),
			}).Error; err != nil {
			return err
		}
		return nil
	})
}

// LogMarkDeleteByMsgID 撤回删除
func LogMarkDeleteByMsgID(operator engine2.DatabaseOperator, groupID string, logName string, rawID interface{}) error {
	db := operator.GetLogDB(constant.WRITE)
	// 获取 log id
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return nil
		}
		return err
	}
	rid := fmt.Sprintf("%v", rawID)
	err = db.Transaction(func(tx *gorm.DB) error {
		if err = tx.Where("log_id = ? AND raw_msg_id = ?", logID, rid).Delete(&model.LogOneItem{}).Error; err != nil {
			zap.S().Named(logger.LogKeyDatabase).Errorf("log delete error %s", err.Error())
			return err
		}
		// 更新 logs 表中的 updated_at 字段 和 size 字段
		// 真的有默认为NULL还能触发删除的情况吗？！
		if err = tx.Model(&model.LogInfo{}).Where("id = ?", logID).Updates(map[string]interface{}{
			"updated_at": time.Now().Unix(),
			"size":       gorm.Expr("COALESCE(size, 0) - ?", 1),
		}).Error; err != nil {
			return err
		}
		return nil
	})
	return err
}

// LogDeleteByLogIDSeq 删除指定日志中 seq 对应的一行（历史补录纠正用）。
// 只按 log_id + seq 精确删除，不做跨日志的 raw_msg_id 反查，避免误删同名消息。
func LogDeleteByLogIDSeq(operator engine2.DatabaseOperator, logID uint64, seq int64) error {
	if logID == 0 || seq <= 0 {
		return nil
	}
	// 与实时/补录写入串行，避免删除后并发补写又把同一行插回来。
	logAppendDedupeMu.Lock()
	defer logAppendDedupeMu.Unlock()
	db := operator.GetLogDB(constant.WRITE)
	return db.Transaction(func(tx *gorm.DB) error {
		res := tx.Where("log_id = ? AND seq = ?", logID, seq).Delete(&model.LogOneItem{})
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return nil
		}
		return tx.Model(&model.LogInfo{}).Where("id = ?", logID).Updates(map[string]interface{}{
			"updated_at": time.Now().Unix(),
			"size":       gorm.Expr("COALESCE(size, 0) - ?", res.RowsAffected),
		}).Error
	})
}

// LogMarkDeleteByRawMsgID 根据消息 ID 反查所属日志并删除，避免依赖当前日志名。
func LogMarkDeleteByRawMsgID(operator engine2.DatabaseOperator, groupID string, rawID interface{}) error {
	db := operator.GetLogDB(constant.WRITE)
	logInfo, err := getLogInfoByRawMsgID(db, groupID, rawID)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return nil
		}
		return err
	}
	return LogMarkDeleteByMsgID(operator, logInfo.GroupID, logInfo.Name, rawID)
}

// LogEditByMsgID 编辑日志
func LogEditByMsgID(operator engine2.DatabaseOperator, groupID, logName, newContent string, rawID interface{}) error {
	db := operator.GetLogDB(constant.WRITE)
	logID, err := getIDByGroupIDAndName(db, groupID, logName)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return nil
		}
		return err
	}

	rid := ""
	if rawID != nil {
		rid = fmt.Sprintf("%v", rawID)
	}

	// 更新 log_items 表中的内容
	if err := db.Model(&model.LogOneItem{}).
		Where("log_id = ? AND raw_msg_id = ?", logID, rid).
		Update("message", newContent).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return fmt.Errorf("log edit: %w", err)
	}

	return nil
}

// LogEditByRawMsgID 根据消息 ID 反查所属日志并编辑，避免依赖当前日志名。
func LogEditByRawMsgID(operator engine2.DatabaseOperator, groupID, newContent string, rawID interface{}) error {
	db := operator.GetLogDB(constant.WRITE)
	logInfo, err := getLogInfoByRawMsgID(db, groupID, rawID)
	if err != nil {
		if errors.Is(err, ErrLogNotFound) {
			return nil
		}
		return err
	}
	return LogEditByMsgID(operator, logInfo.GroupID, logInfo.Name, newContent, rawID)
}
