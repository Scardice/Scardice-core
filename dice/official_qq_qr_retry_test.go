//nolint:testpackage
package dice

import "testing"

// TestOfficialQQShouldRetryAfterQrConnect 扫码成功后首次 connect 失败时，
// 只有“瞬时失败”（Enable 仍为 true、State=Connecting、代次未变）才允许转入
// 后台重试；永久失败/用户禁用/代次过期都必须落到失败态。
func TestOfficialQQShouldRetryAfterQrConnect(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	pa := &PlatformAdapterOfficialQQ{EndPoint: ep}
	generation := pa.nextQrGeneration()

	// failConnectTransient 的终态：凭据有效，网络瞬时失败。
	pa.setEndpointState(true, StateConnecting)
	if !pa.shouldRetryAfterQrConnect(generation) {
		t.Fatal("transient failure after QR login should be retried in background")
	}

	// failConnect 的终态：凭据/配置错误。
	pa.setEndpointState(false, StateConnectionFailed)
	if pa.shouldRetryAfterQrConnect(generation) {
		t.Fatal("permanent failure must not be retried")
	}

	// 用户禁用。
	pa.setEndpointState(false, StateDisconnected)
	if pa.shouldRetryAfterQrConnect(generation) {
		t.Fatal("user-disabled endpoint must not be restarted")
	}

	// 代次已过期（期间被禁用/重登/重新扫码）。
	pa.setEndpointState(true, StateConnecting)
	pa.clearQrLoginState()
	if pa.shouldRetryAfterQrConnect(generation) {
		t.Fatal("stale QR generation must not restart the connection")
	}
}

// TestOfficialQQEndpointStateSnapshot 确认状态快照读取到的是同一把锁保护的值。
func TestOfficialQQEndpointStateSnapshot(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{EndPoint: &EndPointInfo{}}
	if enabled, state := pa.endpointStateSnapshot(); enabled || state != StateDisconnected {
		t.Fatalf("empty endpoint snapshot = (%v,%d), want (false,%d)", enabled, state, StateDisconnected)
	}
	pa.setEndpointState(true, StateConnected)
	if enabled, state := pa.endpointStateSnapshot(); !enabled || state != StateConnected {
		t.Fatalf("snapshot = (%v,%d), want (true,%d)", enabled, state, StateConnected)
	}
}
