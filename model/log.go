package model

import (
	"encoding/json"
	"fmt"

	"gorm.io/gorm"
)

type LogOneItemParquet struct {
	ID             uint64 `gorm:"column:id"              json:"id"        parquet:"id, type=UINT_64"`
	Nickname       string `gorm:"column:nickname"        json:"nickname"  parquet:"nickname, type=UTF8"`
	IMUserID       string `gorm:"column:im_userid"       json:"IMUserId"  parquet:"IMUserId, type=UTF8"`
	Time           int64  `gorm:"column:time"            json:"time"      parquet:"time, type=INT_64"`
	Message        string `gorm:"column:message"         json:"message"   parquet:"message, type=UTF8"`
	IsDice         bool   `gorm:"column:is_dice"         json:"isDice"    parquet:"isDice, type=BOOLEAN"`
	CommandID      int64  `gorm:"column:command_id"      json:"commandId" parquet:"commandId, type=INT_64"`
	CommandInfoStr string `gorm:"column:command_info"    json:"-"         parquet:"commandInfo, type=UTF8"`
	UniformID      string `gorm:"column:user_uniform_id" json:"uniformId" parquet:"uniformId, type=UTF8"`
}

// 兼容旧版本的数据库设计
func (*LogOneItemParquet) TableName() string {
	return "log_items"
}

type LogOneItem struct {
	ID             uint64      `gorm:"primaryKey;autoIncrement;column:id;index:idx_log_delete_by_id,priority:3" json:"id"`
	LogID          uint64      `gorm:"column:log_id;index:idx_log_items_log_id;index:idx_log_raw,priority:1;index:idx_log_items_log_seq,priority:1" json:"-"`
	GroupID        string      `gorm:"index:idx_log_items_group_id;column:group_id;index:idx_log_delete_by_id,priority:1"`
	Nickname       string      `gorm:"column:nickname"                                                         json:"nickname"`
	IMUserID       string      `gorm:"column:im_userid"                                                        json:"IMUserId"`
	Time           int64       `gorm:"column:time"                                                             json:"time"`
	Message        string      `gorm:"column:message"                                                          json:"message"`
	IsDice         bool        `gorm:"column:is_dice"                                                          json:"isDice"`
	CommandID      int64       `gorm:"column:command_id"                                                       json:"commandId"`
	CommandInfo    interface{} `gorm:"-"                                                                       json:"commandInfo" parquet:"-"`
	CommandInfoStr string      `gorm:"column:command_info"                                                     json:"-"`
	// 这里的RawMsgID 真的什么都有可能
	RawMsgID    interface{} `gorm:"-"                                                                 json:"rawMsgId"  parquet:"-"`
	RawMsgIDStr string      `gorm:"column:raw_msg_id;index:idx_raw_msg_id;index:idx_log_delete_by_id,priority:2;index:idx_log_raw,priority:2" json:"-"`
	UniformID   string      `gorm:"column:user_uniform_id"                                            json:"uniformId"`
	// 数据库里没有的
	Channel string `gorm:"-" json:"channel"`
	// 数据库里有，JSON里没有的
	// 允许default=NULL
	Removed  *int `gorm:"column:removed"   json:"-"`
	ParentID *int `gorm:"column:parent_id" json:"-"`
	// Seq 平台消息序号，用于掉线期间的日志断层检测与补全
	// 允许default=NULL，历史记录与不支持seq的平台均为NULL
	Seq *int64 `gorm:"column:seq;index:idx_log_items_log_seq,priority:2" json:"seq,omitempty"`
	// IsGapFill 是日志断层自动补全写入的内部标记。
	// 1115.fix4 起不再对外暴露（JSON/导出/API 筛选均已移除），仅保留数据库列与
	// 内部写入，保证旧库结构和 V150 重建兼容；新代码不要再把它用于用户侧功能。
	IsGapFill bool `gorm:"column:is_gap_fill;not null;default:false;index:idx_log_items_gap_fill" json:"-"`
}

// 兼容旧版本的数据库设计
func (*LogOneItem) TableName() string {
	return "log_items"
}

// BeforeSave 钩子函数: 查询前,interface{}转换为json
func (item *LogOneItem) BeforeSave(_ *gorm.DB) (err error) {
	// 将 CommandInfo 转换为 JSON 字符串保存到 CommandInfoStr
	if item.CommandInfo != nil {
		if data, err := json.Marshal(item.CommandInfo); err == nil {
			item.CommandInfoStr = string(data)
		} else {
			return err
		}
	}

	// 将 RawMsgID 转换为 string 字符串，保存到 RawMsgIDStr
	if item.RawMsgID != nil {
		item.RawMsgIDStr = fmt.Sprintf("%v", item.RawMsgID)
	}

	return nil
}

// AfterFind 钩子函数: 查询后,interface{}转换为json
func (item *LogOneItem) AfterFind(_ *gorm.DB) (err error) {
	// 将 CommandInfoStr 从 JSON 字符串反序列化为 CommandInfo
	if item.CommandInfoStr != "" {
		if err := json.Unmarshal([]byte(item.CommandInfoStr), &item.CommandInfo); err != nil {
			return err
		}
	}

	// 将 RawMsgIDStr string 直接赋值给 RawMsgID
	if item.RawMsgIDStr != "" {
		item.RawMsgID = item.RawMsgIDStr
	}

	return nil
}

type LogInfo struct {
	ID        uint64 `gorm:"primaryKey;autoIncrement;column:id"                      json:"id"`
	Name      string `gorm:"index:idx_log_group_id_name,unique"                      json:"name"`
	GroupID   string `gorm:"index:idx_logs_group;index:idx_log_group_id_name,unique" json:"groupId"`
	CreatedAt int64  `gorm:"column:created_at"                                       json:"createdAt"`
	UpdatedAt int64  `gorm:"column:updated_at;index:idx_logs_update_at"              json:"updatedAt"`
	// 允许数据库NULL值
	// 原版代码中，此处标记了db:size，但实际上，该列并不存在。
	// 考虑到该处数据将会为未来log查询提供优化手段，保留该结构体定义，但不使用。
	// 使用GORM:<-:false 无写入权限，这样它就不会建库，但请注意，下面LogGetLogPage处，如果你查询出的名称不是size
	// 不能在这里绑定column，因为column会给你建立那一列。
	// TODO: 将这个字段使用上会不会比后台查询就JOIN更合适？
	Size *int `gorm:"column:size" json:"size"`
	// 数据库里有，json不展示的
	// 允许数据库NULL值（该字段当前不使用）
	Extra *string `gorm:"column:extra" json:"-"`
	// 原本标记为：测试版特供，由于原代码每次都会执行，故直接启用此处column记录。
	UploadURL  string `gorm:"column:upload_url"  json:"-"` // 测试版特供
	UploadTime int    `gorm:"column:upload_time" json:"-"` // 测试版特供
}

func (*LogInfo) TableName() string {
	return "logs"
}

// ADD FROM MYSQL

type LogInfoHookMySQL struct {
	ID         uint64  `gorm:"primaryKey;autoIncrement;column:id" json:"id"`
	Name       string  `gorm:"column:name"                        json:"name"`
	GroupID    string  `gorm:"column:group_id"                    json:"groupId"`
	CreatedAt  int64   `gorm:"column:created_at"                  json:"createdAt"`
	UpdatedAt  int64   `gorm:"column:updated_at"                  json:"updatedAt"`
	Size       *int    `gorm:"<-:false"                           json:"size"`
	Extra      *string `gorm:"column:extra"                       json:"-"`
	UploadURL  string  `gorm:"column:upload_url"                  json:"-"`
	UploadTime int     `gorm:"column:upload_time"                 json:"-"`
}

func (*LogInfoHookMySQL) TableName() string {
	return "logs"
}

// LogOneItemHookMySQL 只用于 MySQL 的 AutoMigrate。
// 注意：不要给 RawMsgIDStr 加 idx_log_raw。MySQL 上 raw_msg_id 是 TEXT，
// 直接建 (log_id, raw_msg_id) 普通索引会失败；去重查询带 group_id，
// 复用已有的 idx_log_delete_by_id(group_id(20), raw_msg_id(20), id) 前缀索引。
// 下面两个 length:20 是显式声明前缀长度，保证新库/迁移建出的索引与查询匹配。
type LogOneItemHookMySQL struct {
	ID             uint64      `gorm:"primaryKey;autoIncrement;column:id;index:idx_log_delete_by_id,priority:3" json:"id"`
	LogID          uint64      `gorm:"column:log_id;index:idx_log_items_log_seq,priority:1" json:"-"`
	GroupID        string      `gorm:"column:group_id;index:idx_log_delete_by_id,priority:1,length:20"`
	Nickname       string      `gorm:"column:nickname"                    json:"nickname"`
	IMUserID       string      `gorm:"column:im_userid"                   json:"IMUserId"`
	Time           int64       `gorm:"column:time"                        json:"time"`
	Message        string      `gorm:"column:message"                     json:"message"`
	IsDice         bool        `gorm:"column:is_dice"                     json:"isDice"`
	CommandID      int64       `gorm:"column:command_id"                  json:"commandId"`
	CommandInfo    interface{} `gorm:"-"                                  json:"commandInfo"`
	CommandInfoStr string      `gorm:"column:command_info"                json:"-"`
	RawMsgID       interface{} `gorm:"-"                                  json:"rawMsgId"`
	RawMsgIDStr    string      `gorm:"column:raw_msg_id;index:idx_log_delete_by_id,priority:2,length:20" json:"-"`
	UniformID      string      `gorm:"column:user_uniform_id"             json:"uniformId"`
	Channel        string      `gorm:"-"                                  json:"channel"`
	Removed        *int        `gorm:"column:removed"                     json:"-"`
	ParentID       *int        `gorm:"column:parent_id"                   json:"-"`
	Seq            *int64      `gorm:"column:seq;index:idx_log_items_log_seq,priority:2" json:"seq,omitempty"`
	// IsGapFill 仅保留数据库列以兼容旧库；不再对外输出。
	IsGapFill bool `gorm:"column:is_gap_fill;not null;default:false" json:"-"`
}

func (*LogOneItemHookMySQL) TableName() string {
	return "log_items"
}
