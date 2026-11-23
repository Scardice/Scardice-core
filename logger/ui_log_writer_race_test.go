package logger

import (
	"sync"
	"testing"
)

// TestUIWriterUnsubscribeDuringAppend 锁定订阅者生命周期：
// append 的非阻塞发送与 Unsubscribe 的 close 必须串行化，
// 否则 SSE 客户端断开时可能 send on closed channel panic。
func TestUIWriterUnsubscribeDuringAppend(t *testing.T) {
	const (
		iterations = 200
		subsPerRun = 64
	)

	w := NewUIWriter()
	for i := 0; i < iterations; i++ {
		ids := make([]int64, 0, subsPerRun)
		for j := 0; j < subsPerRun; j++ {
			id, _, _ := w.Subscribe(1)
			ids = append(ids, id)
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			w.append(&LogItem{Level: "info", Module: "test", Msg: "race"})
		}()
		for _, id := range ids {
			w.Unsubscribe(id)
		}
		wg.Wait()
	}
}
