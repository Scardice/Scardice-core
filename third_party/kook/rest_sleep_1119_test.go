package kook

import (
	"testing"
	"time"
)

// TestSleepUnlessClosedReturnsOnClose 锁定 1119 修复：429/网络重试的等待
// 必须在 Session 关闭时立即返回，不能把事件分发协程睡满 60 秒。
func TestSleepUnlessClosedReturnsOnClose(t *testing.T) {
	s := &Session{closedCh: make(chan struct{})}
	go func() {
		time.Sleep(20 * time.Millisecond)
		s.Lock()
		if !s.closed {
			s.closed = true
			close(s.closedCh)
		}
		s.Unlock()
	}()

	start := time.Now()
	if s.sleepUnlessClosed(5 * time.Second) {
		t.Fatal("sleepUnlessClosed should return false after Close")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("sleepUnlessClosed took %s, want prompt return", elapsed)
	}
}

func TestSleepUnlessClosedWaits(t *testing.T) {
	s := &Session{closedCh: make(chan struct{})}
	if !s.sleepUnlessClosed(10 * time.Millisecond) {
		t.Fatal("expected true when session stays open")
	}
}
