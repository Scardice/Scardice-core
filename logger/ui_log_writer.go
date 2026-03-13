package logger

import (
	"encoding/json"
	"io"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"
)

const (
	logLimitDefault   = 100
	timeFormatISO8601 = "2006-01-02T15:04:05.000Z0700"
)

type LogItem struct {
	Level  string  `json:"level"`
	Module string  `json:"module"`
	TS     float64 `json:"ts"`
	Caller string  `json:"caller"`
	Msg    string  `json:"msg"`
}

type UIWriter struct {
	mu         sync.RWMutex
	logLimit   int
	items      []*LogItem
	nextSubID  int64
	subscribed map[int64]chan *LogItem
}

var _ io.Writer = (*UIWriter)(nil)

func NewUIWriter() *UIWriter {
	return &UIWriter{
		logLimit:   logLimitDefault,
		items:      make([]*LogItem, 0),
		subscribed: make(map[int64]chan *LogItem),
	}
}

func (l *UIWriter) Write(p []byte) (int, error) {
	var a struct {
		Level  zapcore.Level `json:"level"`
		Module string        `json:"module"`
		Time   string        `json:"time"`
		Msg    string        `json:"msg"`
	}
	err := json.Unmarshal(p, &a)
	if err == nil {
		ts, _ := time.Parse(timeFormatISO8601, a.Time)
		item := &LogItem{
			Level:  a.Level.String(),
			Module: a.Module,
			TS:     float64(ts.Unix()),
			Caller: "",
			Msg:    a.Msg,
		}

		l.mu.Lock()
		l.items = append(l.items, item)
		if l.logLimit == 0 {
			l.logLimit = logLimitDefault
		}
		if len(l.items) > l.logLimit {
			l.items = l.items[len(l.items)-l.logLimit:]
		}
		subs := make([]chan *LogItem, 0, len(l.subscribed))
		for _, ch := range l.subscribed {
			subs = append(subs, ch)
		}
		l.mu.Unlock()

		for _, ch := range subs {
			select {
			case ch <- item:
			default:
			}
		}
	}
	return len(p), nil
}

func (l *UIWriter) SetLogLimit(limit int) {
	if limit <= 0 {
		limit = logLimitDefault
	}

	l.mu.Lock()
	l.logLimit = limit
	if len(l.items) > l.logLimit {
		l.items = l.items[len(l.items)-l.logLimit:]
	}
	l.mu.Unlock()
}

func (l *UIWriter) Snapshot() []*LogItem {
	l.mu.RLock()
	defer l.mu.RUnlock()

	result := make([]*LogItem, 0, len(l.items))
	for _, item := range l.items {
		if item == nil {
			continue
		}
		cp := *item
		result = append(result, &cp)
	}
	return result
}

func (l *UIWriter) Subscribe(buffer int) (int64, <-chan *LogItem, []*LogItem) {
	if buffer <= 0 {
		buffer = 32
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	id := l.nextSubID
	l.nextSubID++

	ch := make(chan *LogItem, buffer)
	l.subscribed[id] = ch

	snapshot := make([]*LogItem, 0, len(l.items))
	for _, item := range l.items {
		if item == nil {
			continue
		}
		cp := *item
		snapshot = append(snapshot, &cp)
	}
	return id, ch, snapshot
}

func (l *UIWriter) Unsubscribe(id int64) {
	l.mu.Lock()
	ch, ok := l.subscribed[id]
	if ok {
		delete(l.subscribed, id)
	}
	l.mu.Unlock()

	if ok {
		close(ch)
	}
}
