package kook

import (
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// queuedEvent 是读循环交给事件分发协程的最小上下文。
// data 在入队前完成解析，避免 dispatcher 因坏包卡住心跳读取。
type queuedEvent struct {
	conn  *websocket.Conn
	epoch uint64
	event *Event
	data  EventData
	// skip 表示该 sn 的事件体无法解析；分发协程应记录并跳过它，
	// 不能让一个坏包把后续 sn 永久堵在 pending 里。
	skip bool
}

const maxQueuedEvents = 4096

// eventDispatcher 是每连接一个的无界（有上限）事件队列。
// 读循环只负责收包和解析头部，handler 在独立协程执行，保证 PONG 不会被慢 handler 堵住。
type eventDispatcher struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  []*queuedEvent
	closed bool
	// done is closed by dispatchEvents when its goroutine exits.  It lets a
	// reconnect give the old handler a bounded chance to finish before starting
	// a new dispatcher.
	done chan struct{}
}

func newEventDispatcher() *eventDispatcher {
	d := &eventDispatcher{done: make(chan struct{})}
	d.cond = sync.NewCond(&d.mu)
	return d
}

func (d *eventDispatcher) waitForExit(timeout time.Duration) bool {
	if d == nil || d.done == nil {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-d.done:
		return true
	case <-timer.C:
		return false
	}
}

func (d *eventDispatcher) push(q *queuedEvent) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed || len(d.queue) >= maxQueuedEvents {
		return false
	}
	d.queue = append(d.queue, q)
	d.cond.Signal()
	return true
}

func (d *eventDispatcher) pop() (*queuedEvent, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for len(d.queue) == 0 && !d.closed {
		d.cond.Wait()
	}
	if d.closed {
		return nil, false
	}
	q := d.queue[0]
	d.queue[0] = nil
	d.queue = d.queue[1:]
	return q, true
}

func (d *eventDispatcher) close() {
	d.mu.Lock()
	d.closed = true
	d.cond.Broadcast()
	d.mu.Unlock()
}
