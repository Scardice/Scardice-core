package jsengine

import "sync/atomic"

// State 表示引擎生命周期状态。
type State int32

const (
	StateNew State = iota
	StateIniting
	StateReady
	StateDisposing
	StateClosed
)

// Lifecycle 提供线程安全的引擎状态管理。
// 用于统一 Init/Dispose 并发时的状态切换约束。
type Lifecycle struct {
	state atomic.Int32
}

// NewLifecycle 创建生命周期管理器，初始状态为 StateNew。
func NewLifecycle() *Lifecycle {
	l := &Lifecycle{}
	l.state.Store(int32(StateNew))
	return l
}

// State 返回当前状态。
func (l *Lifecycle) State() State {
	return State(l.state.Load())
}

// CompareAndSwap 尝试原子切换状态。
func (l *Lifecycle) CompareAndSwap(oldState, newState State) bool {
	return l.state.CompareAndSwap(int32(oldState), int32(newState))
}

// Store 强制设置状态。
func (l *Lifecycle) Store(s State) {
	l.state.Store(int32(s))
}
