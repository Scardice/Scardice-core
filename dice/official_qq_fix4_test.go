package dice

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sealdice/botgo/dto"
)

func TestOfficialQQEventQueueSerializes(t *testing.T) {
	q := newOfficialQQEventQueue()
	defer q.Close()

	var active, overlap int32
	var wg sync.WaitGroup
	const n = 64
	wg.Add(n)
	for range n {
		go func() {
			if !q.Enqueue(func() {
				if atomic.AddInt32(&active, 1) > 1 {
					atomic.StoreInt32(&overlap, 1)
				}
				time.Sleep(time.Millisecond)
				atomic.AddInt32(&active, -1)
				wg.Done()
			}) {
				wg.Done()
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("event queue did not drain")
	}
	if atomic.LoadInt32(&overlap) != 0 {
		t.Fatal("official QQ event queue executed events concurrently")
	}
}

func TestOfficialQQEventQueueRecoversPanic(t *testing.T) {
	q := newOfficialQQEventQueue()
	defer q.Close()

	var ran int32
	q.Enqueue(func() { panic("boom") })
	q.Enqueue(func() { atomic.StoreInt32(&ran, 1) })
	deadline := time.Now().Add(2 * time.Second)
	for atomic.LoadInt32(&ran) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if atomic.LoadInt32(&ran) != 1 {
		t.Fatal("event after a panic was not executed")
	}
}

func TestOfficialQQEventQueueRejectsAfterClose(t *testing.T) {
	q := newOfficialQQEventQueue()
	q.Close()
	if q.Enqueue(func() {}) {
		t.Fatal("Enqueue() succeeded after Close()")
	}
}

func TestParseBotSelfOpenIDsPrefersMemberOpenID(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{UIN: "uin"}
	payload := &dto.WSPayload{
		RawMessage: []byte(`{"d":{"mentions":[{"id":"global-id","member_openid":"member-id","user_openid":"user-id","is_you":true}]}}`),
	}
	ids := pa.parseBotSelfOpenIDs(payload)
	if len(ids) != 3 || ids[0] != "member-id" || ids[1] != "user-id" || ids[2] != "global-id" {
		t.Fatalf("parseBotSelfOpenIDs() = %#v, want member/user/global order", ids)
	}
}

func TestChannelMsgSetsGuildSelfMentionTmpUID(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{UIN: "uin"}
	payload := &dto.WSPayload{
		RawMessage: []byte(`{"d":{"mentions":[{"id":"guild-bot-id","is_you":true}]}}`),
	}
	msgQQ := &dto.WSATMessageData{
		ID:        "msg-1",
		ChannelID: "channel-1",
		GuildID:   "guild-1",
		Content:   `<@!guild-bot-id> .r`,
	}
	msg := pa.channelMsgToStdMsg(payload, msgQQ)
	if msg.TmpUID != "OpenQQCH:guild-bot-id" {
		t.Fatalf("TmpUID = %q, want OpenQQCH:guild-bot-id", msg.TmpUID)
	}
}
