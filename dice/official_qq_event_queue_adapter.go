package dice

import (
	"errors"
	"time"

	"go.uber.org/zap"

	"Scardice-core/logger"
)

var (
	errOfficialQQEventQueueClosed = errors.New("official qq event queue is closed")
)

// quiesceOfficialQQEventQueue 停止接收新事件并等待已入队事件执行完成。
func (pa *PlatformAdapterOfficialQQ) quiesceOfficialQQEventQueue(timeout time.Duration) bool {
	pa.eventQueueMu.Lock()
	queue := pa.eventQueue
	pa.eventQueueMu.Unlock()
	return pa.quiesceOfficialQQEventQueueInstance(queue, timeout)
}

// quiesceOfficialQQEventQueueInstance 只处理指定的队列，避免并发启用时
// 把新会话刚安装的队列也关掉。超时后丢弃尚未执行的事件。
func (pa *PlatformAdapterOfficialQQ) quiesceOfficialQQEventQueueInstance(queue *officialQQEventQueue, timeout time.Duration) bool {
	if queue == nil {
		return true
	}
	pa.eventQueueMu.Lock()
	if pa.eventQueue == queue {
		pa.eventQueueAccepting = false
	}
	pa.eventQueueMu.Unlock()
	queue.Close()
	if queue.WaitForIdle(timeout) {
		return true
	}
	dropped := queue.Abandon()
	zap.S().Named(logger.LogKeyAdapter).Warnf(
		"official qq old event handler did not stop within %s; dropped %d pending events before starting new session",
		timeout, dropped,
	)
	return false
}

// startOfficialQQEventQueue 为一次连接创建新的串行队列。
// 旧队列先停止接收事件，并排空已经入队的事件。
func (pa *PlatformAdapterOfficialQQ) startOfficialQQEventQueue() *officialQQEventQueue {
	pa.quiesceOfficialQQEventQueue(2 * time.Second)
	queue := newOfficialQQEventQueue()
	pa.eventQueueMu.Lock()
	pa.eventQueue = queue
	pa.eventQueueAccepting = true
	pa.eventQueueMu.Unlock()
	return queue
}

func (pa *PlatformAdapterOfficialQQ) currentEventQueue() *officialQQEventQueue {
	pa.eventQueueMu.Lock()
	defer pa.eventQueueMu.Unlock()
	return pa.eventQueue
}

// closeOfficialQQEventQueueInstance 只关闭指定的旧队列，不能误关新会话的队列。
// 先排空已入队事件，避免旧会话事件在新会话启动后继续执行。
func (pa *PlatformAdapterOfficialQQ) closeOfficialQQEventQueueInstance(queue *officialQQEventQueue) {
	pa.quiesceOfficialQQEventQueueInstance(queue, 2*time.Second)
}

// dispatchOfficialQQEvent 是各 handler 的统一入口：
//   - 队列从未启动（测试/极早期）：就地同步执行，保持兼容；
//   - Webhook/WS 都入队并等待**分发闭包**执行完成；适配器的
//     Execute(..., false) 会在闭包内启动命令 goroutine，因此队列和
//     eventExecMu 只保证分发顺序，不保证命令执行顺序，也不是“命令完成后再 ACK”；
//   - 入队失败返回 errOfficialQQEventQueueClosed，让平台重试；
//   - handler panic 返回 botgo 的 PanicError，让 webhook/WS 走 panic 分支
//     （记录堆栈后 ACK/丢弃），避免确定性 panic 被平台反复重试。
func (pa *PlatformAdapterOfficialQQ) dispatchOfficialQQEvent(event func()) error {
	pa.eventQueueMu.Lock()
	queue := pa.eventQueue
	accepting := pa.eventQueueAccepting
	pa.eventQueueMu.Unlock()

	// 旧队列/新队列的 worker 可能同时存在，必须在这一层串行执行 handler，
	// 否则重连时旧长命令会和新会话命令并发修改同一批骰子数据。
	run := func() {
		pa.eventExecMu.Lock()
		defer pa.eventExecMu.Unlock()
		event()
	}

	if !accepting {
		if queue == nil {
			return runOfficialQQEvent(run)
		}
		return errOfficialQQEventQueueClosed
	}
	if queue == nil {
		return runOfficialQQEvent(run)
	}
	return queue.EnqueueWait(run)
}
