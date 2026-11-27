package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	"Scardice-core/dice"
	"Scardice-core/model"
	"Scardice-core/utils/constant"
)

type storyBrowseTestOperator struct {
	db *gorm.DB
}

func (o *storyBrowseTestOperator) Init(_ context.Context) error           { return nil }
func (o *storyBrowseTestOperator) Type() string                           { return constant.SQLITE }
func (o *storyBrowseTestOperator) DBCheck()                               {}
func (o *storyBrowseTestOperator) GetDataDB(_ constant.DBMode) *gorm.DB   { return o.db }
func (o *storyBrowseTestOperator) GetLogDB(_ constant.DBMode) *gorm.DB    { return o.db }
func (o *storyBrowseTestOperator) GetCensorDB(_ constant.DBMode) *gorm.DB { return o.db }
func (o *storyBrowseTestOperator) Close()                                 {}

func newStoryBrowseTestDice(t *testing.T) string {
	t.Helper()

	dbPath := filepath.ToSlash(filepath.Join(t.TempDir(), "story-browse.db"))
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		t.Fatalf("open sqlite db: %v", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err = db.AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatalf("migrate log tables: %v", err)
	}

	logInfo := &model.LogInfo{Name: "团", GroupID: "g1", CreatedAt: 1, UpdatedAt: 1}
	if err = db.Create(logInfo).Error; err != nil {
		t.Fatalf("create log info: %v", err)
	}
	items := []*model.LogOneItem{
		{LogID: logInfo.ID, GroupID: "g1", Nickname: "雪桃", IMUserID: "u-1", Time: 10, Message: "hello"},
		{LogID: logInfo.ID, GroupID: "g1", Nickname: "白祈", IMUserID: "u-2", Time: 20, Message: "world"},
	}
	for _, item := range items {
		if err = db.Create(item).Error; err != nil {
			t.Fatalf("create log item: %v", err)
		}
	}

	manager := &dice.DiceManager{}
	token := "story-browse-token"
	manager.AccessTokens.Store(token, true)
	testDice := &dice.Dice{
		Parent:     manager,
		DBOperator: &storyBrowseTestOperator{db: db},
		Logger:     zap.NewNop().Sugar(),
	}
	manager.Dice = []*dice.Dice{testDice}

	previousDice := myDice
	t.Cleanup(func() { myDice = previousDice })
	myDice = testDice
	return token
}

type storyBrowseResponse struct {
	Result   bool               `json:"result"`
	Err      string             `json:"err"`
	Total    int                `json:"total"`
	PageNum  int                `json:"pageNum"`
	PageSize int                `json:"pageSize"`
	Data     []model.LogOneItem `json:"data"`
}

func callStoryBrowse(t *testing.T, query, token string) (int, storyBrowseResponse) {
	t.Helper()

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/sd-api/story/items/browse?"+query, nil)
	if token != "" {
		req.Header.Set("Token", token)
	}
	rec := httptest.NewRecorder()
	if err := storyBrowseItemPage(e.NewContext(req, rec)); err != nil {
		t.Fatalf("storyBrowseItemPage() error = %v", err)
	}

	var resp storyBrowseResponse
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode response: %v, body = %s", err, rec.Body.String())
		}
	}
	return rec.Code, resp
}

func TestStoryBrowseItemPageRequiresAuth(t *testing.T) {
	newStoryBrowseTestDice(t)

	status, _ := callStoryBrowse(t, "groupId=g1&logName=%E5%9B%A2", "")
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
}

func TestStoryBrowseItemPagePaginationAndFilters(t *testing.T) {
	token := newStoryBrowseTestDice(t)

	status, resp := callStoryBrowse(t, "groupId=g1&logName=%E5%9B%A2&pageNum=1&pageSize=1", token)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !resp.Result || resp.Total != 2 || len(resp.Data) != 1 {
		t.Fatalf("resp = %+v, want result with total 2 and 1 item", resp)
	}
	if resp.Data[0].Message != "world" {
		t.Fatalf("first page message = %q, want world", resp.Data[0].Message)
	}

	status, resp = callStoryBrowse(t, "groupId=g1&logName=%E5%9B%A2&pageNum=2&pageSize=1", token)
	if status != http.StatusOK || !resp.Result || resp.Total != 2 || len(resp.Data) != 1 {
		t.Fatalf("second page resp = %+v", resp)
	}
	if resp.Data[0].Message != "hello" {
		t.Fatalf("second page message = %q, want hello", resp.Data[0].Message)
	}

	status, resp = callStoryBrowse(t, "groupId=g1&logName=%E5%9B%A2&keyword=world", token)
	if status != http.StatusOK || !resp.Result || resp.Total != 1 || len(resp.Data) != 1 {
		t.Fatalf("keyword resp = %+v", resp)
	}
	if resp.Data[0].Message != "world" {
		t.Fatalf("keyword message = %q, want world", resp.Data[0].Message)
	}

	status, resp = callStoryBrowse(t, "groupId=g1&logName=%E5%9B%A2&keyword=no-such-message", token)
	if status != http.StatusOK || !resp.Result || resp.Total != 0 || len(resp.Data) != 0 {
		t.Fatalf("no-match resp = %+v", resp)
	}
	if resp.Data == nil {
		t.Fatal("data should be an empty array, not null")
	}
}

func TestStoryBrowseItemPageRejectsMissingLogParams(t *testing.T) {
	token := newStoryBrowseTestDice(t)

	status, resp := callStoryBrowse(t, "groupId=g1", token)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if resp.Result || !strings.Contains(resp.Err, "logName") {
		t.Fatalf("resp = %+v, want result=false with logName error", resp)
	}
}
