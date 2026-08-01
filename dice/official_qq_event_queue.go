package dice

import "sync"

type officialQQEventQueue struct {
	mu      sync.Mutex
	idle    *sync.Cond
	events  []func()
	running bool
	closed  bool
}

func newOfficialQQEventQueue() *officialQQEventQueue {
	queue := new(officialQQEventQueue)
	queue.idle = sync.NewCond(&queue.mu)
	return queue
}

func (q *officialQQEventQueue) Enqueue(event func()) bool {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return false
	}
	q.events = append(q.events, event)
	if q.running {
		q.mu.Unlock()
		return true
	}
	q.running = true
	q.mu.Unlock()

	defer func() {
		if recovered := recover(); recovered != nil {
			q.mu.Lock()
			q.events = nil
			q.running = false
			q.closed = true
			q.idle.Broadcast()
			q.mu.Unlock()
			panic(recovered)
		}
	}()
	q.drain()
	return true
}

func (q *officialQQEventQueue) drain() {
	for {
		q.mu.Lock()
		if len(q.events) == 0 {
			q.running = false
			q.idle.Broadcast()
			q.mu.Unlock()
			return
		}
		event := q.events[0]
		q.events[0] = nil
		q.events = q.events[1:]
		q.mu.Unlock()

		event()
	}
}

func (q *officialQQEventQueue) Close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
}

func (q *officialQQEventQueue) closeAndWait() {
	q.Close()
	q.mu.Lock()
	for q.running {
		q.idle.Wait()
	}
	q.events = nil
	q.mu.Unlock()
}
