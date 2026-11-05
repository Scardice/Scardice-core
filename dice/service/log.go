package service

import "errors"

var ErrLogNotFound = errors.New("日志不存在")

type QueryLogPage struct {
	PageNum          int    `db:"page_num"           query:"pageNum"`
	PageSize         int    `db:"page_siz"           query:"pageSize"`
	Name             string `db:"name"               query:"name"`
	GroupID          string `db:"group_id"           query:"groupId"`
	CreatedTimeBegin string `db:"created_time_begin" query:"createdTimeBegin"`
	CreatedTimeEnd   string `db:"created_time_end"   query:"createdTimeEnd"`
}

type QueryLogLinePage struct {
	PageNum  int    `query:"pageNum"`
	PageSize int    `query:"pageSize"`
	GroupID  string `query:"groupId"`
	LogName  string `query:"logName"`
}
