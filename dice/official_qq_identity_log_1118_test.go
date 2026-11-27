package dice

import "testing"

// 1118: 身份迁移合并日志状态时必须成对复制 LogCurID/LogCurName，
// 并重置 seq 基线，避免拼出“目标名 + 来源 ID”的错误日志。
func TestMergeOfficialQQGroupMemoryPairsLogState_1118(t *testing.T) {
	target := &GroupInfo{
		GroupID:          "OpenQQ-Group:target",
		LogCurName:       "half-state",
		LogCurID:         0,
		LogSeqBaseline:   1234,
		logSeqCalibrated: true,
	}
	source := &GroupInfo{
		GroupID:    "OpenQQ-Group:source",
		LogCurName: "source-log",
		LogCurID:   42,
		LogOn:      true,
	}

	if !mergeOfficialQQGroupMemory(target, source, nil) {
		t.Fatal("merge should report changes")
	}
	if target.LogCurName != "source-log" || target.LogCurID != 42 || !target.LogOn {
		t.Fatalf("log state = name=%q id=%d on=%t, want source pair 42/source-log/on",
			target.LogCurName, target.LogCurID, target.LogOn)
	}
	if target.LogSeqBaseline != 0 {
		t.Fatalf("LogSeqBaseline = %d, want 0 after adopting another log", target.LogSeqBaseline)
	}
	if target.logSeqCalibrated {
		t.Fatal("logSeqCalibrated should be false after adopting another log")
	}
}
