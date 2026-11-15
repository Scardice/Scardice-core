package dice

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"

	"Scardice-core/dice/service"
	"Scardice-core/model"
)

func TestResetLogSeqPersistsAcrossReload(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	g.resetLogSeq(150, "msg-150")

	if g.LogSeqBaseline != 150 || g.LogSeqBaselineMsgID != "msg-150" {
		t.Fatalf("persisted baseline = (%d,%q), want (150,msg-150)", g.LogSeqBaseline, g.LogSeqBaselineMsgID)
	}

	data, err := json.Marshal(g)
	if err != nil {
		t.Fatal(err)
	}
	var reloaded GroupInfo
	if err := json.Unmarshal(data, &reloaded); err != nil {
		t.Fatal(err)
	}
	reloaded.initLogSeqFromPersisted()

	lastSeq, lastMsgID, _ := reloaded.updateLogSeq(151, "msg-151")
	if lastSeq != 150 {
		t.Fatalf("reloaded baseline = %d, want 150", lastSeq)
	}
	if lastMsgID != "msg-150" {
		t.Fatalf("reloaded baseline msg id = %v, want msg-150", lastMsgID)
	}
}

type fakeHistoryFetcher struct {
	calls     int
	pageLimit int
}

func (f *fakeHistoryFetcher) FetchGroupMsgHistory(_ context.Context, _ string, fromSeq int64, count int) ([]*Message, error) {
	f.calls++
	if f.pageLimit > 0 && count > f.pageLimit {
		count = f.pageLimit
	}
	msgs := make([]*Message, 0, count)
	for i := 0; i < count; i++ {
		seq := fromSeq + 1 + int64(i)
		msgs = append(msgs, &Message{
			Seq:      seq,
			RawID:    "m-" + strconv.FormatInt(seq, 10),
			Platform: "QQ",
			Sender:   SenderBase{UserID: "QQ:100", Nickname: "玩家"},
		})
	}
	return msgs, nil
}

func TestLogGapFetchHistoryPaginates(t *testing.T) {
	d := &Dice{Logger: zap.NewNop().Sugar()}
	g := &GroupInfo{GroupID: "QQ-Group:1"}
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:999"}}
	task := logGapFillTask{dice: d, endpoint: endpoint, group: g, fromSeq: 10, toSeq: 250}
	fetcher := &fakeHistoryFetcher{pageLimit: 37}

	msgs, err := task.fetchHistoryOnce(context.Background(), fetcher)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 239 {
		t.Fatalf("fetched %d messages, want 239", len(msgs))
	}
	if msgs[0].Seq != 11 || msgs[len(msgs)-1].Seq != 249 {
		t.Fatalf("range = [%d,%d], want [11,249]", msgs[0].Seq, msgs[len(msgs)-1].Seq)
	}
	if fetcher.calls < 2 {
		t.Fatalf("expected pagination, calls = %d", fetcher.calls)
	}

	// 自身消息必须剔除；其他 bot 保留供日志记录（只是不执行）。
	msgs = append(msgs, &Message{Seq: 12, Sender: SenderBase{UserID: endpoint.UserID}})
	msgs = append(msgs, &Message{Seq: 13, Sender: SenderBase{UserID: "QQ:888", IsRobot: true}})
	filtered := task.filterMissing(msgs)
	for _, m := range filtered {
		if m.Sender.UserID == endpoint.UserID {
			t.Fatal("self message was not filtered")
		}
	}
	foundBot := false
	for _, m := range filtered {
		if m.Sender.UserID == "QQ:888" {
			foundBot = true
		}
	}
	if !foundBot {
		t.Fatal("other bot message should stay in log backfill")
	}
}

func TestLogGapDeniedReplayCommand(t *testing.T) {
	task := logGapFillTask{dice: &Dice{CommandPrefix: []string{".", "。"}}}
	tests := map[string]bool{
		".log off":    true,
		"。log on":     true,
		".bot off":    true,
		".master":     true,
		".r 1d100":    false,
		"log off":     false,
		".story test": false,
	}
	for text, want := range tests {
		if got := task.isDeniedReplayCommand(&Message{Platform: "QQ", Message: text}); got != want {
			t.Errorf("isDeniedReplayCommand(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestLogGapBackfillUsesPlayerAnnotation(t *testing.T) {
	g := &GroupInfo{GroupID: "QQ-Group:1", Players: new(SyncMap[string, *GroupPlayerInfo])}
	g.Players.Store("QQ:100", &GroupPlayerInfo{Name: "调查员A"})
	task := logGapFillTask{
		dice:     &Dice{Logger: zap.NewNop().Sugar()},
		endpoint: &EndPointInfo{EndPointInfoBase: EndPointInfoBase{UserID: "QQ:999"}},
		group:    g,
	}
	item := task.logItem(&Message{
		Seq:    20,
		RawID:  "m-20",
		Sender: SenderBase{UserID: "QQ:100", Nickname: "平台昵称"},
	})
	if item.Nickname != "调查员A" {
		t.Fatalf("nickname = %q, want player annotation 调查员A", item.Nickname)
	}
	if item.UniformID != "QQ:100" {
		t.Fatalf("uniform id = %q, want QQ:100", item.UniformID)
	}
	if !item.IsGapFill {
		t.Fatal("backfilled entry must be marked IsGapFill")
	}
}

func TestLogGapFilterAlreadyLogged(t *testing.T) {
	db, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "log-gap.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.db.AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatal(err)
	}

	const groupID = "QQ-Group:1"
	logID, err := service.LogGetOrCreate(db, groupID, "log")
	if err != nil {
		t.Fatal(err)
	}
	d := &Dice{DBOperator: db, Logger: zap.NewNop().Sugar()}
	mctx := &MsgContext{Dice: d}
	if !LogAppend(mctx, groupID, logID, "log", &model.LogOneItem{
		Nickname:  "调查员A",
		IMUserID:  "100",
		UniformID: "QQ:100",
		Message:   "已记录",
		RawMsgID:  "m-20",
		Seq:       ptrInt64(20),
	}) {
		t.Fatal("LogAppend failed")
	}

	task := logGapFillTask{
		dice:    d,
		group:   &GroupInfo{GroupID: groupID},
		logID:   logID,
		fromSeq: 10,
		toSeq:   30,
	}
	filtered, ok := task.filterAlreadyLogged([]*Message{
		{Seq: 20, RawID: "m-20", Sender: SenderBase{UserID: "QQ:100"}},
		{Seq: 21, RawID: "m-21", Sender: SenderBase{UserID: "QQ:100"}},
	})
	if !ok {
		t.Fatal("filterAlreadyLogged reported a query failure for an available database")
	}
	if len(filtered) != 1 || filtered[0].RawID != "m-21" {
		t.Fatalf("filtered = %#v, want only m-21", filtered)
	}
}

func TestGocqMessageCarriesSequence(t *testing.T) {
	msg := (&MessageQQ{
		MessageQQBase: MessageQQBase{
			MessageID:   1,
			MessageSeq:  42,
			MessageType: "group",
		},
		Message: "hello",
	}).toStdMessage()
	if msg.Seq != 42 {
		t.Fatalf("Seq = %d, want 42", msg.Seq)
	}
}

func TestLogLinePageFiltersGapFill(t *testing.T) {
	db, err := newMockDatabaseOperator(filepath.Join(t.TempDir(), "log-filter.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.db.AutoMigrate(&model.LogInfo{}, &model.LogOneItem{}); err != nil {
		t.Fatal(err)
	}

	const (
		groupID = "QQ-Group:1"
		logName = "log"
	)
	logID, err := service.LogGetOrCreate(db, groupID, logName)
	if err != nil {
		t.Fatal(err)
	}
	d := &Dice{DBOperator: db, Logger: zap.NewNop().Sugar()}
	mctx := &MsgContext{Dice: d}
	items := []*model.LogOneItem{
		{Nickname: "正常", IMUserID: "100", UniformID: "QQ:100", Message: "实时", RawMsgID: "m-1", Seq: ptrInt64(1)},
		{Nickname: "补录", IMUserID: "100", UniformID: "QQ:100", Message: "补录", RawMsgID: "m-2", Seq: ptrInt64(2), IsGapFill: true},
	}
	for _, item := range items {
		if !LogAppend(mctx, groupID, logID, logName, item) {
			t.Fatal("LogAppend failed")
		}
	}

	yes := true
	lines, err := service.LogGetLinePage(db, &service.QueryLogLinePage{
		PageNum: 1, PageSize: 10, GroupID: groupID, LogName: logName, GapFill: &yes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || !lines[0].IsGapFill || lines[0].Message != "补录" {
		t.Fatalf("gapFill filter returned %#v", lines)
	}

	no := false
	lines, err = service.LogGetLinePage(db, &service.QueryLogLinePage{
		PageNum: 1, PageSize: 10, GroupID: groupID, LogName: logName, GapFill: &no,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 1 || lines[0].IsGapFill {
		t.Fatalf("non-gapFill filter returned %#v", lines)
	}
}

func TestQueryLogLinePageBindsGapFill(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/story/items/page?gapFill=true&playerId=QQ%3A100", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	var q service.QueryLogLinePage
	if err := c.Bind(&q); err != nil {
		t.Fatal(err)
	}
	if q.GapFill == nil || !*q.GapFill {
		t.Fatalf("gapFill not bound: %#v", q.GapFill)
	}
	if q.PlayerID != "QQ:100" {
		t.Fatalf("playerId = %q, want QQ:100", q.PlayerID)
	}
}
