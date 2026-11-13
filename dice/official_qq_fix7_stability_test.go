//nolint:testpackage
package dice

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sealdice/botgo/errs"
)

// TestOfficialQQAuthErrorFormats_1113fix7 锁定 botgo 的真实错误格式：
// `code:401, text:...`、`100007.appid invalid`、`http status 401` 都必须识别为
// 永久鉴权失败，否则错填 AppID/Secret 时端点会永远“连接中”。
func TestOfficialQQAuthErrorFormats_1113fix7(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"botgo code 401", errors.New("code:401, text:unauthorized, traceID:abc"), true},
		{"botgo code 403", errors.New("code:403, text:forbidden, traceID:abc"), true},
		{"ws 4004", errors.New("code:4004, text:auth failed, traceID:abc"), true},
		{"ws 4915", errors.New("code:4915, text:bot banned, traceID:abc"), true},
		{"token 100007", errors.New("100007.appid invalid, traceID: abc"), true},
		{"token 100016", errors.New("100016.invalid appid or secret, traceID: abc"), true},
		{"http status 401", errors.New("retrieve token http status 401, traceID abc"), true},
		{"http status 403", errors.New("retrieve token http status 403, traceID abc"), true},
		{"invalid app secret", errors.New("invalid app secret"), true},
		{"network timeout", errors.New("dial tcp 1.2.3.4:443: i/o timeout"), false},
		{"server 500", errors.New("code:500, text:internal error, traceID:abc"), false},
		{"nil", nil, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isOfficialQQConnectAuthError(c.err); got != c.want {
				t.Fatalf("isOfficialQQConnectAuthError(%v) = %v, want %v", c.err, got, c.want)
			}
		})
	}

	// botgo 的结构化错误码必须走 errors.As，而不是只靠字符串。
	if !isOfficialQQConnectAuthError(errs.New(401, "unauthorized")) {
		t.Fatal("errs.New(401) must be classified as auth failure")
	}
	if !isOfficialQQConnectAuthError(errs.New(4004, "auth failed")) {
		t.Fatal("errs.New(4004) must be classified as auth failure")
	}
	if isOfficialQQConnectAuthError(errs.New(500, "internal error")) {
		t.Fatal("errs.New(500) must not be classified as auth failure")
	}
}

// TestOfficialQQDoReloginReturnsFalseWhenDisabled_1113fix7 锁定 DoRelogin 的诚实语义：
// 端点已禁用或不存在时不能返回 true，否则调用方会误以为“已开始重连”。
func TestOfficialQQDoReloginReturnsFalseWhenDisabled_1113fix7(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{}
	if pa.DoRelogin() {
		t.Fatal("DoRelogin with nil endpoint must return false")
	}
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: false}}
	pa.EndPoint = ep
	if pa.DoRelogin() {
		t.Fatal("DoRelogin on a disabled endpoint must return false")
	}
}

// TestOfficialQQRetryExhaustsAndFails_1113fix7 锁定连续失败达到上限后的终态：
// 必须置 Enable=false / StateConnectionFailed 并停止，不能无限退避。
func TestOfficialQQRetryExhaustsAndFails_1113fix7(t *testing.T) {
	d, _, _, cleanup := newExecuteNewTestDice(t)
	defer cleanup()

	conn := &PlatformAdapterOfficialQQ{}
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID:       "qq-fix7",
		Enable:   true,
		State:    StateConnecting,
		Session:  d.ImSession,
		Platform: "QQ",
	}}
	ep.Adapter = conn
	conn.EndPoint = ep

	var attempts int32
	oldServe := officialQQServe
	oldMax := officialQQMaxConnectAttempts
	oldBackoff := officialQQInitialBackoff
	officialQQServe = func(*PlatformAdapterOfficialQQ) int {
		atomic.AddInt32(&attempts, 1)
		return 1
	}
	officialQQMaxConnectAttempts = 2
	officialQQInitialBackoff = time.Millisecond
	t.Cleanup(func() {
		officialQQServe = oldServe
		officialQQMaxConnectAttempts = oldMax
		officialQQInitialBackoff = oldBackoff
	})

	serverOfficialQQ(d, ep, conn)

	if got := atomic.LoadInt32(&attempts); got != 2 {
		t.Fatalf("serve attempts = %d, want 2", got)
	}
	if ep.Enable {
		t.Fatal("endpoint must be disabled after retry budget is exhausted")
	}
	if ep.State != StateConnectionFailed {
		t.Fatalf("endpoint state = %d, want StateConnectionFailed", ep.State)
	}
	if conn.DiceServing {
		t.Fatal("DiceServing must be false after retry loop exits")
	}
}

// TestQrCompleteStateRejectsStaleGeneration_1113fix7 锁定扫码 Complete 分支的
// 状态写回：禁用/换轮次后迟到的 Connecting 不能挂回 UI。
func TestQrCompleteStateRejectsStaleGeneration_1113fix7(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{}
	gen := pa.nextQrGeneration()
	pa.clearQrLoginState() // 代次推进，模拟用户禁用

	if pa.setQrStateIfCurrent(gen, OfficialQQLoginStateConnecting, true) {
		t.Fatal("stale generation must not write Connecting")
	}
	if pa.QrLoginState == OfficialQQLoginStateConnecting {
		t.Fatal("stale write resurrected Connecting state")
	}

	newGen := pa.nextQrGeneration()
	pa.qrMu.Lock()
	pa.QrURL = "https://example.invalid/qr"
	pa.QrCodeData = []byte("png")
	pa.qrSession = &QQOfficialQrLoginSession{ID: "s"}
	pa.qrMu.Unlock()
	if !pa.setQrStateIfCurrent(newGen, OfficialQQLoginStateConnecting, true) {
		t.Fatal("current generation should accept the state write")
	}
	pa.qrMu.Lock()
	defer pa.qrMu.Unlock()
	if pa.QrLoginState != OfficialQQLoginStateConnecting {
		t.Fatalf("state = %v, want Connecting", pa.QrLoginState)
	}
	if pa.QrURL != "" || pa.QrCodeData != nil || pa.qrSession != nil {
		t.Fatal("Connecting state must clear the QR fields")
	}
}
