//nolint:testpackage
package dice

import "testing"

// TestQrStateWriteRejectsStaleGeneration 锁定二维码写回的原子性。
// 修复前是 isCurrentQrGeneration(gen) 之后再单独 qrMu.Lock() 写入：禁用端点
// 恰好在两步之间推进代次时，迟到的二维码仍会挂回 UI，而轮询协程已经退出，
// 用户会看到一个永远不可用的码。这里直接验证“代次已过期则拒绝写入”。
func TestQrStateWriteRejectsStaleGeneration(t *testing.T) {
	pa := &PlatformAdapterOfficialQQ{}

	generation := pa.nextQrGeneration()
	session := &QQOfficialQrLoginSession{ID: "s1", QrURL: "https://example.invalid/qr"}
	if !pa.setQrLoginSessionIfCurrent(generation, session, []byte("png")) {
		t.Fatal("current generation should accept the write")
	}
	if pa.QrLoginState != OfficialQQLoginStateQRWaitingForScan || pa.QrURL == "" {
		t.Fatalf("state after write = %v url=%q", pa.QrLoginState, pa.QrURL)
	}

	// 用户禁用端点：代次推进并清空二维码
	pa.clearQrLoginState()

	if pa.setQrLoginSessionIfCurrent(generation, session, []byte("png")) {
		t.Fatal("stale generation must not write the first QR back")
	}
	if pa.QrURL != "" || pa.QrCodeData != nil {
		t.Fatalf("stale write resurrected QR: url=%q", pa.QrURL)
	}

	if pa.setQrCodeIfCurrent(generation, "https://example.invalid/new", []byte("png2")) {
		t.Fatal("stale generation must not write the refreshed QR back")
	}
	if pa.QrURL != "" {
		t.Fatalf("stale refresh resurrected QR: %q", pa.QrURL)
	}

	// 新代次仍可正常写入。
	newGen := pa.nextQrGeneration()
	if !pa.setQrCodeIfCurrent(newGen, "https://example.invalid/ok", []byte("png3")) {
		t.Fatal("current generation should accept the refreshed QR")
	}
}
