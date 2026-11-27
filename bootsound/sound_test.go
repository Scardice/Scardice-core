package bootsound

import (
	"math"
	"testing"
)

func TestScaleWAVKeepsLengthAndBoostsPeak(t *testing.T) {
	base, basePeak, ok := scaleWAV(1.0)
	if !ok {
		t.Fatal("内嵌 WAV 解析失败")
	}
	if len(base) != len(startupWAV) {
		t.Fatalf("缩放后长度变化: %d != %d", len(base), len(startupWAV))
	}
	if basePeak <= 0 || basePeak > 1 {
		t.Fatalf("原始峰值异常: %v", basePeak)
	}

	_, loudPeak, ok := scaleWAV(2.0)
	if !ok {
		t.Fatal("2x 缩放失败")
	}
	if loudPeak <= basePeak {
		t.Fatalf("2x 缩放后峰值未提高: %v <= %v", loudPeak, basePeak)
	}
}

func TestStatusSnapshot(t *testing.T) {
	setStatus(Status{Player: "mpv", Played: true, Message: "ok"})
	got := StatusSnapshot()
	if got.Player != "mpv" || !got.Played || got.Message != "ok" || got.UpdatedAt == 0 {
		t.Fatalf("StatusSnapshot() = %+v", got)
	}
}

func TestComputeGain(t *testing.T) {
	basePeak := math.Pow(10, -8.0/20) // 最终内嵌音效的线性峰值
	cases := []struct {
		amplitude float64
		want      float64
	}{
		{0.512, 0.98}, // PipeWire 80%
		{1.0, 0.50},   // 100%
		{0.1, 2.24},   // 触发不削波上限
		{0.02, 2.24},
		{0, 0.98}, // 未知音量按 80% 等效幅度处理
	}
	for _, tc := range cases {
		got := computeGain(basePeak, tc.amplitude)
		if math.Abs(got-tc.want) > 0.02 {
			t.Errorf("computeGain(amplitude=%v)=%v, want %v", tc.amplitude, got, tc.want)
		}
		if scaled := basePeak * got; scaled > math.Pow(10, maxScaledPeakDB/20)+1e-9 {
			t.Errorf("缩放后峰值 %v 超过不削波上限", scaled)
		}
	}
}
