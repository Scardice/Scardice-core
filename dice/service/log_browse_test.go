package service_test

import (
	"testing"

	"Scardice-core/dice/service"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

func logBrowseTestIntPtr(v int) *int {
	return &v
}

func TestLogBrowseLinePageFiltersAndPagination(t *testing.T) {
	db := newLogInfoTestDB(t)
	seedLogInfoTestDB(t, db)

	// seedLogInfoTestDB 会删掉第 2 条 log 与第 2 条 log_item，所以 log-1
	// 实际剩 3 条消息。这里给 log-3 加带昵称、用户 ID、时间、撤回标记的数据，
	// 用来验证浏览器筛选。
	extra := []*model.LogOneItem{
		{
			LogID:     3,
			GroupID:   "group",
			Nickname:  "雪桃",
			IMUserID:  "u-100",
			UniformID: "uniform-100",
			Time:      100,
			Message:   "今天的团很顺利",
		},
		{
			LogID:     3,
			GroupID:   "group",
			Nickname:  "白祈",
			IMUserID:  "u-200",
			UniformID: "uniform-200",
			Time:      200,
			Message:   "进度 100% 完成",
		},
		{
			LogID:    2,
			GroupID:  "group",
			Nickname: "旧消息",
			Time:     300,
			Message:  "这条已撤回",
			Removed:  logBrowseTestIntPtr(1),
		},
		{
			LogID:     3,
			GroupID:   "group",
			Nickname:  "雪桃",
			IMUserID:  "u-100",
			UniformID: "uniform-100",
			Time:      400,
			Message:   "第二条雪桃消息",
		},
	}
	for _, item := range extra {
		if err := db.Create(item).Error; err != nil {
			t.Fatalf("create extra log item: %v", err)
		}
	}

	operator := &logInfoTestOperator{db: db, dbType: constant.SQLITE}

	t.Run("default desc pagination", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID:  "group",
			LogName:  "log-1",
			PageNum:  1,
			PageSize: 2,
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 3 {
			t.Fatalf("total = %d, want 3", total)
		}
		if len(items) != 2 || items[0].Message != "message-4" || items[1].Message != "message-3" {
			t.Fatalf("items = %+v, want message-4, message-3", items)
		}
	})

	t.Run("second page", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID:  "group",
			LogName:  "log-1",
			PageNum:  2,
			PageSize: 2,
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 3 {
			t.Fatalf("total = %d, want 3", total)
		}
		if len(items) != 1 || items[0].Message != "message-1" {
			t.Fatalf("items = %+v, want message-1", items)
		}
	})

	t.Run("asc order", func(t *testing.T) {
		_, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID:  "group",
			LogName:  "log-1",
			PageNum:  1,
			PageSize: 2,
			Order:    "asc",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if len(items) != 2 || items[0].Message != "message-1" || items[1].Message != "message-3" {
			t.Fatalf("items = %+v, want message-1, message-3", items)
		}
	})

	t.Run("keyword", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID: "group",
			LogName: "log-1",
			Keyword: "message-3",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 1 || len(items) != 1 || items[0].Message != "message-3" {
			t.Fatalf("total = %d, items = %+v, want only message-3", total, items)
		}
	})

	t.Run("keyword without match returns empty slice", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID: "group",
			LogName: "log-1",
			Keyword: "definitely-not-present",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 0 || len(items) != 0 {
			t.Fatalf("total = %d, items = %+v, want empty", total, items)
		}
		if items == nil {
			t.Fatal("items should be an empty slice, not nil")
		}
	})

	t.Run("keyword treats percent as literal", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID: "group",
			LogName: "log-3",
			Keyword: "%",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 1 || len(items) != 1 || items[0].Message != "进度 100% 完成" {
			t.Fatalf("total = %d, items = %+v, want only the literal percent message", total, items)
		}
	})

	t.Run("sender matches nickname", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID: "group",
			LogName: "log-1",
			Sender:  "nick-3",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 1 || len(items) != 1 || items[0].Nickname != "nick-3" {
			t.Fatalf("total = %d, items = %+v, want only nick-3", total, items)
		}
	})

	t.Run("sender matches user id", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID: "group",
			LogName: "log-3",
			Sender:  "u-100",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 2 || len(items) != 2 {
			t.Fatalf("total = %d, items = %+v, want 2 items for u-100", total, items)
		}
		if items[0].Message != "第二条雪桃消息" || items[1].Message != "今天的团很顺利" {
			t.Fatalf("items = %+v, want desc order of u-100 messages", items)
		}
	})

	t.Run("time range", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID:   "group",
			LogName:   "log-3",
			TimeBegin: 150,
			TimeEnd:   250,
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 1 || len(items) != 1 || items[0].Message != "进度 100% 完成" {
			t.Fatalf("total = %d, items = %+v, want only the 150..250 message", total, items)
		}
	})

	t.Run("removed messages are hidden", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID: "group",
			LogName: "log-3",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 3 || len(items) != 3 {
			t.Fatalf("total = %d, items = %+v, want 3 visible messages", total, items)
		}
		for _, item := range items {
			if item.Message == "这条已撤回" {
				t.Fatalf("removed message should not be returned: %+v", item)
			}
		}
	})

	t.Run("missing log returns empty", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID: "group",
			LogName: "missing",
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 0 || len(items) != 0 {
			t.Fatalf("total = %d, items = %+v, want empty", total, items)
		}
		if items == nil {
			t.Fatal("items should be an empty slice, not nil")
		}
	})

	t.Run("page size is clamped", func(t *testing.T) {
		total, items, err := service.LogBrowseLinePage(operator, &service.QueryLogLineBrowse{
			GroupID:  "group",
			LogName:  "log-1",
			PageSize: 9999,
		})
		if err != nil {
			t.Fatalf("LogBrowseLinePage() error = %v", err)
		}
		if total != 3 || len(items) != 3 {
			t.Fatalf("total = %d, len(items) = %d, want 3", total, len(items))
		}
	})
}

func TestLogGetLogPageCountRespectsFilters(t *testing.T) {
	db := newLogInfoTestDB(t)
	seedLogInfoTestDB(t, db)
	operator := &logInfoTestOperator{db: db, dbType: constant.SQLITE}

	total, logs, err := service.LogGetLogPage(operator, &service.QueryLogPage{
		PageNum:  1,
		PageSize: 10,
		Name:     "log-1",
	})
	if err != nil {
		t.Fatalf("LogGetLogPage() error = %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].Name != "log-1" {
		t.Fatalf("total = %d, logs = %+v, want only log-1", total, logs)
	}
}
