//nolint:testpackage
package dice

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func newOfficialQQStabilityTestAdapter(t *testing.T) (*Dice, *PlatformAdapterOfficialQQ, *EndPointInfo, context.Context, context.CancelFunc) {
	t.Helper()
	d, _, _, cleanup := newExecuteNewTestDice(t)
	t.Cleanup(cleanup)

	conn := &PlatformAdapterOfficialQQ{}
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID:       "qq-1114",
		Platform: "QQ",
		Enable:   true,
		State:    StateConnecting,
		Session:  d.ImSession,
	}}
	ep.Adapter = conn
	conn.EndPoint = ep

	ctx, cancel := context.WithCancel(t.Context())
	conn.sessionMu.Lock()
	conn.Ctx = ctx
	conn.CancelFunc = cancel
	conn.readyCh = make(chan struct{})
	conn.sessionMu.Unlock()
	t.Cleanup(cancel)
	return d, conn, ep, ctx, cancel
}

// TestOfficialQQReadyWatchdogRestarts_1114 锁定“WS 已提交但 READY 永不到达”：
// 超时后按瞬时失败停止本次会话（Enable 仍为 true、StateConnecting），并重启重试循环。
func TestOfficialQQReadyWatchdogRestarts_1114(t *testing.T) {
	_, conn, ep, ctx, _ := newOfficialQQStabilityTestAdapter(t)

	var restarts int32
	oldTimeout, oldStart := officialQQReadyTimeout, officialQQStart
	officialQQReadyTimeout = 10 * time.Millisecond
	officialQQStart = func(*Dice, *EndPointInfo) { atomic.AddInt32(&restarts, 1) }
	t.Cleanup(func() {
		officialQQReadyTimeout = oldTimeout
		officialQQStart = oldStart
	})

	conn.watchOfficialQQReady(ctx, conn.readyCh)

	if got := atomic.LoadInt32(&restarts); got != 1 {
		t.Fatalf("restarts = %d, want 1", got)
	}
	if conn.isSessionRunning() {
		t.Fatal("session must be stopped after READY timeout")
	}
	if !ep.Enable || ep.State != StateConnecting {
		t.Fatalf("endpoint state after READY timeout = enable:%t state:%d, want enabled/connecting", ep.Enable, ep.State)
	}
}

// TestOfficialQQReadyWatchdogNoRestartWhenReady_1114 锁定 READY 正常到达时不重启。
func TestOfficialQQReadyWatchdogNoRestartWhenReady_1114(t *testing.T) {
	_, conn, _, ctx, _ := newOfficialQQStabilityTestAdapter(t)

	var restarts int32
	oldStart := officialQQStart
	officialQQStart = func(*Dice, *EndPointInfo) { atomic.AddInt32(&restarts, 1) }
	t.Cleanup(func() { officialQQStart = oldStart })

	conn.sessionMu.Lock()
	close(conn.readyCh)
	conn.sessionMu.Unlock()
	conn.watchOfficialQQReady(ctx, conn.readyCh)

	if got := atomic.LoadInt32(&restarts); got != 0 {
		t.Fatalf("restarts = %d, want 0 when READY arrived", got)
	}
	if !conn.isSessionRunning() {
		t.Fatal("session must keep running when READY arrived")
	}
}

// TestOfficialQQSetEnableKeepsEnabledDuringAsyncStart_1114 锁定启用窗口：
// SetEnable(true) 不能在异步 Serve 启动前把 Enable 置 false，否则用户立即点禁用
// 时 EndPointInfo.SetEnable 会因值相等而不转发，挂起的 Serve 仍会连上。
func TestOfficialQQSetEnableKeepsEnabledDuringAsyncStart_1114(t *testing.T) {
	d, conn, ep, _, _ := newOfficialQQStabilityTestAdapter(t)
	// 这条用例模拟“没有会话、第一次启用”的异步启动窗口。
	conn.sessionMu.Lock()
	conn.Ctx, conn.CancelFunc, conn.readyCh = nil, nil, nil
	conn.sessionMu.Unlock()
	ep.Enable = false
	ep.State = StateDisconnected

	var starts int32
	oldStart := officialQQStart
	officialQQStart = func(*Dice, *EndPointInfo) { atomic.AddInt32(&starts, 1) }
	t.Cleanup(func() { officialQQStart = oldStart })

	conn.SetEnable(true)
	if !ep.Enable || ep.State != StateConnecting {
		t.Fatalf("after SetEnable(true): enable=%t state=%d, want true/connecting", ep.Enable, ep.State)
	}
	if got := atomic.LoadInt32(&starts); got != 1 {
		t.Fatalf("serve starts = %d, want 1", got)
	}

	// 用户在这个窗口内点禁用：必须真正转发到适配器。
	ep.SetEnable(d, false)
	if ep.Enable {
		t.Fatal("disable during async start was not forwarded")
	}
	if ep.State != StateDisconnected {
		t.Fatalf("state after disable = %d, want StateDisconnected", ep.State)
	}
}

// TestOfficialQQMarkReadyClosesReadyChannel_1114 锁定 READY 信号只关一次且只对当前会话生效。
func TestOfficialQQMarkReadyClosesReadyChannel_1114(t *testing.T) {
	_, conn, _, ctx, _ := newOfficialQQStabilityTestAdapter(t)

	conn.markReadyIfCurrent(ctx)
	select {
	case <-conn.readyCh:
	default:
		t.Fatal("markReadyIfCurrent must close the ready channel")
	}
	// 重复调用不能 panic（channel 已关闭）。
	conn.markReadyIfCurrent(ctx)

	otherCtx, otherCancel := context.WithCancel(context.Background())
	defer otherCancel()
	conn.sessionMu.Lock()
	conn.readyCh = make(chan struct{})
	conn.sessionMu.Unlock()
	conn.markReadyIfCurrent(otherCtx)
	select {
	case <-conn.readyCh:
		t.Fatal("stale context must not close the current session's ready channel")
	default:
	}
}

// TestQrLoginExpired_1114 锁定扫码总时长上限。
func TestQrLoginExpired_1114(t *testing.T) {
	now := time.Now()
	if !qrLoginExpired(now.Add(-6*time.Minute), now, 5*time.Minute) {
		t.Fatal("6-minute-old QR session must be expired")
	}
	if qrLoginExpired(now.Add(-4*time.Minute), now, 5*time.Minute) {
		t.Fatal("4-minute-old QR session must not be expired")
	}
	if qrLoginExpired(time.Time{}, now, 5*time.Minute) {
		t.Fatal("zero CreatedAt must not be treated as expired")
	}
}

// TestServerOfficialQQSkipsDisabledEndpoint_1114 锁定异步启动窗口：
// 用户点禁用后，迟到的 ServerOfficialQQ 不能把端点重新打开。
func TestServerOfficialQQSkipsDisabledEndpoint_1114(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	conn := &PlatformAdapterOfficialQQ{}
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID:       "qq-1114-disabled",
		Platform: "QQ",
		Enable:   false,
		State:    StateDisconnected,
		Session:  d.ImSession,
	}}
	ep.Adapter = conn
	conn.EndPoint = ep

	var attempts int32
	oldServe := officialQQServe
	officialQQServe = func(*PlatformAdapterOfficialQQ) int {
		atomic.AddInt32(&attempts, 1)
		return 0
	}
	t.Cleanup(func() { officialQQServe = oldServe })

	serverOfficialQQ(d, ep, conn)

	if got := atomic.LoadInt32(&attempts); got != 0 {
		t.Fatalf("Serve called %d times for a disabled endpoint, want 0", got)
	}
	if ep.Enable || ep.State != StateDisconnected {
		t.Fatalf("disabled endpoint state changed: enable=%t state=%d", ep.Enable, ep.State)
	}
}

// TestOfficialQQDoReloginSetsConnectingBeforeStart_1114 锁定重登与“已禁用不启动”
// 守卫的配合：DoRelogin 内部会先把端点置 Disconnected，启动前必须恢复
// Enable=true/Connecting，否则新的 serverOfficialQQ 守卫会直接返回。
func TestOfficialQQDoReloginSetsConnectingBeforeStart_1114(t *testing.T) {
	d, conn, ep, _, _ := newOfficialQQStabilityTestAdapter(t)
	conn.sessionMu.Lock()
	conn.Ctx, conn.CancelFunc, conn.readyCh = nil, nil, nil
	conn.sessionMu.Unlock()
	ep.Enable = true
	ep.State = StateConnected

	var starts int32
	oldStart := officialQQStart
	officialQQStart = func(*Dice, *EndPointInfo) { atomic.AddInt32(&starts, 1) }
	t.Cleanup(func() { officialQQStart = oldStart })

	if !conn.DoRelogin() {
		t.Fatal("DoRelogin should accept an enabled endpoint")
	}
	if got := atomic.LoadInt32(&starts); got != 1 {
		t.Fatalf("serve starts = %d, want 1", got)
	}
	if !ep.Enable || ep.State != StateConnecting {
		t.Fatalf("after DoRelogin: enable=%t state=%d, want true/connecting", ep.Enable, ep.State)
	}
	_ = d
}
