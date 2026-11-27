package dice

import (
	"context"
	"net/http"
	"testing"
)

// TestOfficialQQClaimServeRejectsDisabled_1121fix1 锁定：启动代次有效但端点
// 已被禁用时，claimServe 必须失败，不能把禁用吞掉再写回 Connecting。
func TestOfficialQQClaimServeRejectsDisabled_1121fix1(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: false, State: StateDisconnected}}
	pa := &PlatformAdapterOfficialQQ{EndPoint: ep}
	pa.serveEpoch = 1

	if pa.claimServe(1) {
		t.Fatal("claimServe must reject a disabled endpoint")
	}
	ep.Enable = true
	if !pa.claimServe(1) {
		t.Fatal("claimServe must accept an enabled endpoint with the current epoch")
	}
	if !pa.DiceServing || ep.State != StateConnecting || !ep.Enable {
		t.Fatalf("claim state = serving=%v enable=%v state=%d", pa.DiceServing, ep.Enable, ep.State)
	}
	if pa.claimServe(2) {
		t.Fatal("stale epoch must not claim")
	}
}

// TestOfficialQQReadyTimeoutFailsAfterLimit_1121fix1 锁定：READY 连续超时
// 达到上限后必须置失败终态，而不是每 60 秒无限重连、UI 永远 Connecting。
func TestOfficialQQReadyTimeoutFailsAfterLimit_1121fix1(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	pa := &PlatformAdapterOfficialQQ{EndPoint: ep}

	for i := range maxOfficialQQReadyTimeouts {
		ctx, cancel := context.WithCancel(context.Background())
		if !pa.beginSession(ctx, cancel) {
			t.Fatalf("beginSession failed at %d", i)
		}
		ep.Enable = true
		ep.State = StateConnecting
		handled, retry := pa.failReadyTimeoutIfCurrent(ctx)
		if !handled {
			t.Fatalf("timeout %d not handled", i)
		}
		wantRetry := i < maxOfficialQQReadyTimeouts-1
		if retry != wantRetry {
			t.Fatalf("timeout %d retry=%v, want %v", i, retry, wantRetry)
		}
		cancel()
	}
	if ep.Enable || ep.State != StateConnectionFailed {
		t.Fatalf("endpoint = (enable=%v, state=%d), want disabled/failed", ep.Enable, ep.State)
	}
}

// TestOfficialQQReadyTimeoutDoesNotKillReadySession_1121fix1 锁定：READY 已经
// 到达时，超时清理不能杀健康会话。
func TestOfficialQQReadyTimeoutDoesNotKillReadySession_1121fix1(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	pa := &PlatformAdapterOfficialQQ{EndPoint: ep}
	ctx, cancel := context.WithCancel(context.Background())
	if !pa.beginSession(ctx, cancel) {
		t.Fatal("beginSession failed")
	}
	defer cancel()
	pa.markReadyIfCurrent(ctx)

	handled, _ := pa.failReadyTimeoutIfCurrent(ctx)
	if handled {
		t.Fatal("READY session must not be failed by the timeout path")
	}
	if pa.Ctx != ctx {
		t.Fatal("session was stopped despite READY")
	}
}

// TestOfficialQQWebhookServerOwnership_1121fix1 锁定：旧会话的停止流程
// 不能关闭新会话安装的 webhook server。
func TestOfficialQQWebhookServerOwnership_1121fix1(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{EndPoint: &EndPointInfo{}}
	oldCtx, oldCancel := context.WithCancel(context.Background())
	defer oldCancel()
	newCtx, newCancel := context.WithCancel(context.Background())
	defer newCancel()

	oldServer := &http.Server{}
	newServer := &http.Server{}
	pa.setWebhookServer(oldServer, oldCtx)
	pa.setWebhookServer(newServer, newCtx)

	pa.shutdownWebhookServerFor(oldCtx)
	if !pa.webhookServerIsCurrent(newServer, newCtx) {
		t.Fatal("old ctx shutdown must not close the new webhook server")
	}

	pa.shutdownWebhookServerFor(newCtx)
	if pa.webhookServer != nil || pa.webhookCtx != nil {
		t.Fatal("owning ctx shutdown must clear the webhook server")
	}
}
