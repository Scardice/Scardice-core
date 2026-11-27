package dice

import (
	"sort"
	"time"
)

// LogGapFillGroupStatus 是单个群当前的补全状态快照。
type LogGapFillGroupStatus struct {
	GroupID      string `json:"groupId"`
	GroupName    string `json:"groupName,omitempty"`
	LogName      string `json:"logName,omitempty"`
	LogOn        bool   `json:"logOn"`
	State        string `json:"state"` // running / pending / waiting / retry
	FromSeq      int64  `json:"fromSeq"`
	ToSeq        int64  `json:"toSeq"`
	OffDiscovery bool   `json:"offDiscovery"`
	RetryAfter   int64  `json:"retryAfter"`
	LastSeenSeq  int64  `json:"lastSeenSeq"`
}

// LogGapFillStatus 是自动补全页面的只读状态快照。
type LogGapFillStatus struct {
	Enabled       bool                    `json:"enabled"`
	LastReconcile int64                   `json:"lastReconcile"`
	PendingGroups int                     `json:"pendingGroups"`
	RunningGroups int                     `json:"runningGroups"`
	RetryGroups   int                     `json:"retryGroups"`
	Groups        []LogGapFillGroupStatus `json:"groups"`
}

// LogGapFillStatusSnapshot 汇总当前排队、运行和等待重试的补全任务。
// 只读取内存状态与已持久化的 pending 区间，不触发历史拉取和数据库写入。
func (d *Dice) LogGapFillStatusSnapshot() LogGapFillStatus {
	status := LogGapFillStatus{Groups: make([]LogGapFillGroupStatus, 0)}
	if d == nil {
		return status
	}
	status.Enabled = d.LogGapFillEnabled()
	if d.ImSession == nil || d.ImSession.ServiceAtNew == nil {
		return status
	}
	status.LastReconcile = d.ImSession.LogGapLastReconcileAt.Load()

	now := time.Now().Unix()
	d.ImSession.ServiceAtNew.Range(func(_ string, group *GroupInfo) bool {
		item, ok := group.logGapFillGroupStatusSnapshot(now)
		if !ok {
			return true
		}
		switch item.State {
		case "running":
			status.RunningGroups++
		case "retry":
			status.RetryGroups++
		default:
			status.PendingGroups++
		}
		status.Groups = append(status.Groups, item)
		return true
	})

	sort.SliceStable(status.Groups, func(i, j int) bool {
		ri := logGapFillStatusStateRank(status.Groups[i].State)
		rj := logGapFillStatusStateRank(status.Groups[j].State)
		if ri != rj {
			return ri < rj
		}
		return status.Groups[i].GroupID < status.Groups[j].GroupID
	})
	return status
}

// logGapFillStatusStateRank 让补录中的群排在前面，等待重试的群排在最后。
func logGapFillStatusStateRank(state string) int {
	switch state {
	case "running":
		return 0
	case "pending":
		return 1
	case "waiting":
		return 2
	default:
		return 3
	}
}

// logGapFillGroupStatusSnapshot 读取单个群的补全状态；没有待处理任务时返回 false。
func (g *GroupInfo) logGapFillGroupStatusSnapshot(now int64) (LogGapFillGroupStatus, bool) {
	if g == nil {
		return LogGapFillGroupStatus{}, false
	}

	g.logGapQueueMu.Lock()
	hasPending := g.logGapPending != nil
	hasRunning := g.logGapRunningTask != nil
	var pendingFrom, pendingTo int64
	var pendingOff bool
	if hasPending {
		pendingFrom = g.logGapPending.fromSeq
		pendingTo = g.logGapPending.toSeq
		pendingOff = g.logGapPending.discoverFromOff
	}
	var runningFrom, runningTo int64
	var runningOff bool
	if hasRunning {
		runningFrom = g.logGapRunningTask.fromSeq
		runningTo = g.logGapRunningTask.toSeq
		runningOff = g.logGapRunningTask.discoverFromOff
	}
	g.logGapQueueMu.Unlock()

	persistentFrom, persistentTo, persistentOff := g.pendingLogGapRangeSnapshot()
	filling := g.logGapFilling.Load()
	fillFrom := g.logGapFillFrom.Load()
	fillTo := g.logGapFillTo.Load()
	retryAfter := g.logGapRetryAt.Load()
	retrying := retryAfter > now
	hasPersistent := persistentFrom > 0 && persistentTo > persistentFrom

	if !hasPending && !hasRunning && !filling && !hasPersistent && !retrying {
		return LogGapFillGroupStatus{}, false
	}

	state := "waiting"
	switch {
	case hasRunning || filling:
		state = "running"
	case hasPending:
		state = "pending"
	case retrying:
		state = "retry"
	}

	// 优先展示持久化的完整区间；没有时退回队列/运行中的任务窗口。
	fromSeq, toSeq, offDiscovery := persistentFrom, persistentTo, persistentOff
	if !hasPersistent {
		switch {
		case hasPending:
			fromSeq, toSeq, offDiscovery = pendingFrom, pendingTo, pendingOff
		case hasRunning:
			fromSeq, toSeq, offDiscovery = runningFrom, runningTo, runningOff
		case filling:
			fromSeq, toSeq, offDiscovery = fillFrom, fillTo, false
		}
	}

	logState := g.GetLogState()
	status := LogGapFillGroupStatus{
		GroupID:      g.GroupID,
		GroupName:    g.GroupName,
		LogName:      logState.Name,
		LogOn:        logState.On,
		State:        state,
		FromSeq:      fromSeq,
		ToSeq:        toSeq,
		OffDiscovery: offDiscovery,
		LastSeenSeq:  g.logSeenSeqSnapshot(),
	}
	// 只有处于重试等待时才展示重试时间；运行/排队中的旧退避时间会误导页面。
	if state == "retry" && retrying {
		status.RetryAfter = retryAfter
	}
	return status, true
}
