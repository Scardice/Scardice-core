package dice

func (pa *PlatformAdapterOfficialQQ) startOfficialQQEventQueue() {
	queue := newOfficialQQEventQueue()
	pa.eventQueueMu.Lock()
	previous := pa.eventQueue
	pa.eventQueue = queue
	pa.eventQueueAccepting = true
	pa.eventQueueMu.Unlock()
	if previous != nil {
		previous.closeAndWait()
	}
}

func (pa *PlatformAdapterOfficialQQ) enqueueOfficialQQEvent(event func()) bool {
	pa.eventQueueMu.Lock()
	queue := pa.eventQueue
	accepting := pa.eventQueueAccepting
	pa.eventQueueMu.Unlock()
	if !accepting || queue == nil {
		return false
	}
	return queue.Enqueue(event)
}

func (pa *PlatformAdapterOfficialQQ) closeOfficialQQEventQueue() {
	pa.eventQueueMu.Lock()
	pa.eventQueueAccepting = false
	queue := pa.eventQueue
	pa.eventQueueMu.Unlock()
	if queue != nil {
		queue.closeAndWait()
	}
}
