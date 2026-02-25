package jsengine

import "testing"

func TestLifecycleStateTransitions(t *testing.T) {
	lc := NewLifecycle()
	if lc.State() != StateNew {
		t.Fatalf("初始状态错误: got=%v want=%v", lc.State(), StateNew)
	}

	if !lc.CompareAndSwap(StateNew, StateIniting) {
		t.Fatal("期望从 StateNew 切换到 StateIniting 成功")
	}
	if lc.State() != StateIniting {
		t.Fatalf("状态错误: got=%v want=%v", lc.State(), StateIniting)
	}

	if lc.CompareAndSwap(StateNew, StateReady) {
		t.Fatal("不应允许从错误旧状态切换")
	}

	lc.Store(StateReady)
	if lc.State() != StateReady {
		t.Fatalf("Store 后状态错误: got=%v want=%v", lc.State(), StateReady)
	}
}
