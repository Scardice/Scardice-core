package dice

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bytedance/sonic"
	"go.uber.org/zap"

	emitter "Scardice-core/dice/imsdk/onebot"
	"Scardice-core/dice/imsdk/onebot/schema"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
	"Scardice-core/message"
)

var errOnebotRecallTestUnsupported = errors.New("unsupported in onebot recall test emitter")

type onebotRecallTestEmitter struct {
	mu             sync.Mutex
	sendGroupCalls int
	delCalls       []int64
	sequence       []string
	delCh          chan int64
}

func (m *onebotRecallTestEmitter) SendPvtMsg(_ context.Context, _ int64, _ schema.MessageChain) (*emitterTypes.SendMsgRes, error) {
	return &emitterTypes.SendMsgRes{MessageId: 0}, nil
}

func (m *onebotRecallTestEmitter) SendGrMsg(_ context.Context, _ int64, msg schema.MessageChain) (*emitterTypes.SendMsgRes, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sendGroupCalls++
	m.sequence = append(m.sequence, fmt.Sprintf("send_group:%d", len(msg)))
	return &emitterTypes.SendMsgRes{MessageId: 1001}, nil
}

func (m *onebotRecallTestEmitter) GetMsg(_ context.Context, _ int64) (*emitterTypes.GetMsgRes, error) {
	return nil, errOnebotRecallTestUnsupported
}

func (m *onebotRecallTestEmitter) DelMsg(_ context.Context, msgId int64) error {
	m.mu.Lock()
	m.delCalls = append(m.delCalls, msgId)
	m.sequence = append(m.sequence, fmt.Sprintf("del:%d", msgId))
	delCh := m.delCh
	m.mu.Unlock()
	if delCh != nil {
		delCh <- msgId
	}
	return nil
}

func (m *onebotRecallTestEmitter) GetLoginInfo(_ context.Context) (*emitterTypes.LoginInfo, error) {
	return nil, errOnebotRecallTestUnsupported
}

func (m *onebotRecallTestEmitter) GetStrangerInfo(_ context.Context, _ int64, _ bool) (*emitterTypes.StrangerInfo, error) {
	return nil, errOnebotRecallTestUnsupported
}

func (m *onebotRecallTestEmitter) GetStatus(_ context.Context) (*emitterTypes.Status, error) {
	return nil, errOnebotRecallTestUnsupported
}

func (m *onebotRecallTestEmitter) GetVersionInfo(_ context.Context) (*emitterTypes.VersionInfo, error) {
	return nil, errOnebotRecallTestUnsupported
}

func (m *onebotRecallTestEmitter) GetSelfId(_ context.Context) (int64, error) {
	return 0, nil
}

func (m *onebotRecallTestEmitter) SetSelfId(_ context.Context, _ int64) error {
	return nil
}

func (m *onebotRecallTestEmitter) SetFriendAddRequest(_ context.Context, _ string, _ bool, _ string) error {
	return nil
}

func (m *onebotRecallTestEmitter) SetGroupAddRequest(_ context.Context, _ string, _ bool, _ string) error {
	return nil
}

func (m *onebotRecallTestEmitter) SetGroupSpecialTitle(_ context.Context, _ int64, _ int64, _ string, _ int) error {
	return nil
}

func (m *onebotRecallTestEmitter) QuitGroup(_ context.Context, _ int64) error {
	return nil
}

func (m *onebotRecallTestEmitter) SetGroupCard(_ context.Context, _ int64, _ int64, _ string) error {
	return nil
}

func (m *onebotRecallTestEmitter) GetGroupInfo(_ context.Context, _ int64, _ bool) (*emitterTypes.GroupInfo, error) {
	return nil, errOnebotRecallTestUnsupported
}

func (m *onebotRecallTestEmitter) GetGroupMemberInfo(_ context.Context, _ int64, _ int64, _ bool) (*emitterTypes.GroupMemberInfo, error) {
	return nil, errOnebotRecallTestUnsupported
}

func (m *onebotRecallTestEmitter) Raw(_ context.Context, _ emitter.Action, _ any) ([]byte, error) {
	return nil, nil
}

func (m *onebotRecallTestEmitter) HandleEcho(_ emitter.Response[sonic.NoCopyRawMessage]) {}

func (m *onebotRecallTestEmitter) GetDroppedEchoCount() uint64 {
	return 0
}

var _ emitter.Emitter = (*onebotRecallTestEmitter)(nil)

func TestPlatformAdapterOnebotSendSegmentToGroup_RecallOnly(t *testing.T) {
	mockEmitter := &onebotRecallTestEmitter{}
	pa := &PlatformAdapterOnebot{
		sendEmitter: mockEmitter,
		ctx:         context.Background(),
		logger:      zap.NewNop().Sugar(),
	}

	msg := message.ConvertStringMessage("[CQ:recall,id=123456]")
	pa.SendSegmentToGroup(&MsgContext{}, FormatOnebotDiceIDQQGroup("10001"), msg, "")

	mockEmitter.mu.Lock()
	defer mockEmitter.mu.Unlock()
	if mockEmitter.sendGroupCalls != 0 {
		t.Fatalf("expected no group send calls, got %d", mockEmitter.sendGroupCalls)
	}
	if len(mockEmitter.delCalls) != 1 || mockEmitter.delCalls[0] != 123456 {
		t.Fatalf("unexpected delete calls: %#v", mockEmitter.delCalls)
	}
}

func TestPlatformAdapterOnebotSendSegmentToGroup_SendThenRecall(t *testing.T) {
	mockEmitter := &onebotRecallTestEmitter{}
	pa := &PlatformAdapterOnebot{
		sendEmitter: mockEmitter,
		ctx:         context.Background(),
		logger:      zap.NewNop().Sugar(),
	}

	msg := message.ConvertStringMessage("hello[CQ:recall,id=654321]")
	pa.SendSegmentToGroup(&MsgContext{}, FormatOnebotDiceIDQQGroup("10001"), msg, "")

	mockEmitter.mu.Lock()
	defer mockEmitter.mu.Unlock()
	if mockEmitter.sendGroupCalls != 1 {
		t.Fatalf("expected 1 group send call, got %d", mockEmitter.sendGroupCalls)
	}
	if len(mockEmitter.delCalls) != 1 || mockEmitter.delCalls[0] != 654321 {
		t.Fatalf("unexpected delete calls: %#v", mockEmitter.delCalls)
	}
	if len(mockEmitter.sequence) != 2 {
		t.Fatalf("unexpected action sequence: %#v", mockEmitter.sequence)
	}
	if mockEmitter.sequence[0] != "send_group:1" || mockEmitter.sequence[1] != "del:654321" {
		t.Fatalf("unexpected action sequence: %#v", mockEmitter.sequence)
	}
}

func TestPlatformAdapterOnebotSendSegmentToGroup_RecallWithoutIDUsesSentMessageID(t *testing.T) {
	mockEmitter := &onebotRecallTestEmitter{}
	pa := &PlatformAdapterOnebot{
		sendEmitter: mockEmitter,
		ctx:         context.Background(),
		logger:      zap.NewNop().Sugar(),
	}

	msg := message.ConvertStringMessage("[CQ:recall]你好")
	pa.SendSegmentToGroup(&MsgContext{}, FormatOnebotDiceIDQQGroup("10001"), msg, "")

	mockEmitter.mu.Lock()
	defer mockEmitter.mu.Unlock()
	if mockEmitter.sendGroupCalls != 1 {
		t.Fatalf("expected 1 group send call, got %d", mockEmitter.sendGroupCalls)
	}
	if len(mockEmitter.delCalls) != 1 || mockEmitter.delCalls[0] != 1001 {
		t.Fatalf("unexpected delete calls: %#v", mockEmitter.delCalls)
	}
}

func TestPlatformAdapterOnebotSendSegmentToGroup_DelayedRecallDoesNotBlock(t *testing.T) {
	mockEmitter := &onebotRecallTestEmitter{delCh: make(chan int64, 1)}
	pa := &PlatformAdapterOnebot{
		sendEmitter: mockEmitter,
		ctx:         context.Background(),
		logger:      zap.NewNop().Sugar(),
	}

	start := time.Now()
	msg := message.ConvertStringMessage("hello[CQ:recall,id=654321,delay=50]")
	pa.SendSegmentToGroup(&MsgContext{}, FormatOnebotDiceIDQQGroup("10001"), msg, "")
	elapsed := time.Since(start)

	if elapsed >= 50*time.Millisecond {
		t.Fatalf("send path blocked for delayed recall: %v", elapsed)
	}

	select {
	case got := <-mockEmitter.delCh:
		if got != 654321 {
			t.Fatalf("unexpected delayed delete id: %d", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for delayed recall")
	}
}
