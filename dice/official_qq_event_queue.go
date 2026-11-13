package dice

import (
	"runtime/debug"
	"sync"
	"time"

	botevent "github.com/sealdice/botgo/event"
	"go.uber.org/zap"

	"Scardice-core/logger"
)

// maxOfficialQQQueuedEvents 限制 webhook 并发突发时的排队上限，
// 避免异常流量把内存撑爆。WS 模式下列队通常不会超过 1。
const maxOfficialQQQueuedEvents = 1024

type queuedOfficialQQEvent struct {
	run func()
	// done 非空时表示调用方在等待该事件执行完成（WS 模式）。
	// 成功为 nil；执行 panic 时是 botgo 的 PanicError，队列关闭/丢弃时是
	// errOfficialQQEventQueueClosed。buffered=1，避免 Abandon 与 worker 同时发送时阻塞。
	done chan error
}

// officialQQEventQueue 用单独的 worker 串行执行事件。
// Webhook 模式只负责入队，HTTP 层可以立即 ACK；WS 模式用 EnqueueWait
// 等到事件真正执行后再返回，让 botgo 的 SeqAfterHandle 仍然有意义。
type officialQQEventQueue struct {
	mu        sync.Mutex
	cond      *sync.Cond
	events    []queuedOfficialQQEvent
	closed    bool
	executing bool
}

func newOfficialQQEventQueue() *officialQQEventQueue {
	q := new(officialQQEventQueue)
	q.cond = sync.NewCond(&q.mu)
	go q.work()
	return q
}

// Enqueue 只入队，返回是否被接收；事件由 worker 异步执行。
func (q *officialQQEventQueue) Enqueue(event func()) bool {
	return q.enqueue(event, nil)
}

// EnqueueWait 入队并等待事件执行完成。
// 成功返回 nil；队列在事件执行前被关闭/丢弃时返回 errOfficialQQEventQueueClosed；
// 事件执行 panic 时返回 botgo 的 PanicError（webhook/WS 会按 panic 语义 ACK 并丢弃，
// 不会把确定性 panic 当成普通可重试错误反复重试）。
func (q *officialQQEventQueue) EnqueueWait(event func()) error {
	done := make(chan error, 1)
	if !q.enqueue(event, done) {
		return errOfficialQQEventQueueClosed
	}
	return <-done
}

func (q *officialQQEventQueue) enqueue(event func(), done chan error) bool {
	if event == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed || len(q.events) >= maxOfficialQQQueuedEvents {
		if q.closed {
			return false
		}
		zap.S().Named(logger.LogKeyAdapter).Warnf("official qq event queue is full (%d), rejecting event", maxOfficialQQQueuedEvents)
		return false
	}
	q.events = append(q.events, queuedOfficialQQEvent{run: event, done: done})
	q.cond.Signal()
	return true
}

func (q *officialQQEventQueue) work() {
	for {
		q.mu.Lock()
		for len(q.events) == 0 && !q.closed {
			q.cond.Wait()
		}
		if len(q.events) == 0 {
			q.mu.Unlock()
			return
		}
		event := q.events[0]
		q.events[0] = queuedOfficialQQEvent{}
		q.events = q.events[1:]
		q.executing = true
		q.mu.Unlock()

		err := runOfficialQQEvent(event.run)

		q.mu.Lock()
		q.executing = false
		if event.done != nil {
			event.done <- err
		}
		q.mu.Unlock()
	}
}

// runOfficialQQEvent 隔离单个事件的 panic，避免一个坏插件/坏消息把 worker 带崩。
// 返回 nil 表示事件正常执行完成；panic 时返回 botgo 的 PanicError，让上层
// （webhook/WS）能识别“确定性 panic”并 ACK/丢弃，而不是当普通错误反复重试。
func runOfficialQQEvent(event func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			zap.S().Named(logger.LogKeyAdapter).Errorf("official qq event panic: %v\n%s", r, debug.Stack())
			err = botevent.NewPanicError("official qq event", r)
		}
	}()
	event()
	return nil
}

// Close 停止接收新事件；worker 会继续执行已经入队的事件，然后退出。
func (q *officialQQEventQueue) Close() {
	q.mu.Lock()
	if !q.closed {
		q.closed = true
		q.cond.Broadcast()
	}
	q.mu.Unlock()
}

// Abandon 立即丢弃尚未执行的事件，并让等待者得到失败结果。
// 正在执行的事件无法取消，只能等它自己返回。
func (q *officialQQEventQueue) Abandon() int {
	q.mu.Lock()
	q.closed = true
	pending := q.events
	q.events = nil
	q.cond.Broadcast()
	q.mu.Unlock()
	for _, event := range pending {
		if event.done != nil {
			event.done <- errOfficialQQEventQueueClosed
		}
	}
	return len(pending)
}

// WaitForIdle 在有限时间内等待所有已入队事件执行完成。
func (q *officialQQEventQueue) WaitForIdle(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		q.mu.Lock()
		idle := len(q.events) == 0 && !q.executing
		q.mu.Unlock()
		if idle {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// officialQQEventDeduper 给 webhook 路径提供按 event id/msg id 的短 TTL 去重。
// botgo 的 HandlerOptions 支持 Deduper，但不会提供默认实现；不配置时平台重复推送会重复执行。
type officialQQEventDeduper struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
	max  int
}

func newOfficialQQEventDeduper(ttl time.Duration, maxEntries int) *officialQQEventDeduper {
	return &officialQQEventDeduper{
		seen: make(map[string]time.Time),
		ttl:  ttl,
		max:  maxEntries,
	}
}

func (d *officialQQEventDeduper) pruneLocked(now time.Time) {
	for key, at := range d.seen {
		if now.Sub(at) > d.ttl {
			delete(d.seen, key)
		}
	}
}

func (d *officialQQEventDeduper) Seen(key string) bool {
	if d == nil || key == "" {
		return false
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	at, ok := d.seen[key]
	if !ok {
		return false
	}
	if now.Sub(at) > d.ttl {
		delete(d.seen, key)
		return false
	}
	return true
}

func (d *officialQQEventDeduper) Mark(key string) {
	if d == nil || key == "" {
		return
	}
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.max > 0 && len(d.seen) >= d.max {
		d.pruneLocked(now)
		if len(d.seen) >= d.max {
			d.seen = make(map[string]time.Time)
		}
	}
	d.seen[key] = now
}

func (d *officialQQEventDeduper) Unmark(key string) {
	if d == nil || key == "" {
		return
	}
	d.mu.Lock()
	delete(d.seen, key)
	d.mu.Unlock()
}
