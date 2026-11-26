package logger

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logLimitDefault   = 300
	timeFormatISO8601 = "2006-01-02T15:04:05.000Z0700"

	uiHistoryFileMaxSizeMB  = 20
	uiHistoryFileMaxBackups = 2
	uiHistoryFileMaxAgeDays = 7
	uiHistoryReadLimit      = 100
	uiHistoryReadMaxLimit   = 500
)

type LogItem struct {
	Level  string  `json:"level"`
	Module string  `json:"module"`
	TS     float64 `json:"ts"`
	Caller string  `json:"caller"`
	Msg    string  `json:"msg"`
	Seq    int64   `json:"seq"`
}

// HistoryQuery 描述一次历史日志翻页请求。
// BeforeSeq 为 0 时表示不返回任何记录；Limit 会被限制在 1~500 之间。
type HistoryQuery struct {
	BeforeSeq int64
	Limit     int
	Levels    map[string]struct{}
	StartTS   float64
	EndTS     float64
	Keyword   string
}

type UIWriter struct {
	mu         sync.RWMutex
	logLimit   int
	items      []*LogItem
	nextSubID  int64
	subscribed map[int64]chan *LogItem

	seq         int64
	historyPath string
	historyDir  string
	history     io.WriteCloser
}

var _ io.Writer = (*UIWriter)(nil)

func NewUIWriter() *UIWriter {
	return &UIWriter{
		logLimit:   logLimitDefault,
		items:      make([]*LogItem, 0),
		subscribed: make(map[int64]chan *LogItem),
	}
}

// EnableHistory 开启 UI 日志持久化。历史记录会写入 path，
// 并按大小轮转，供主页“加载更早”和历史日志面板读取。
func (l *UIWriter) EnableHistory(path string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.history != nil {
		_ = l.history.Close()
	}

	l.historyPath = path
	l.historyDir = filepath.Dir(path)
	l.seq = l.loadLastSeqLocked()
	l.history = &lumberjack.Logger{
		Filename:   path,
		MaxSize:    uiHistoryFileMaxSizeMB,
		MaxBackups: uiHistoryFileMaxBackups,
		MaxAge:     uiHistoryFileMaxAgeDays,
	}
}

// CloseHistory 关闭历史日志文件，主要用于测试和优雅退出。
func (l *UIWriter) CloseHistory() {
	l.mu.Lock()
	history := l.history
	l.history = nil
	l.mu.Unlock()

	if history != nil {
		_ = history.Close()
	}
}

func (l *UIWriter) Write(p []byte) (int, error) {
	var a struct {
		Level  zapcore.Level `json:"level"`
		Module string        `json:"module"`
		Time   string        `json:"time"`
		Caller string        `json:"caller"`
		Msg    string        `json:"msg"`
	}
	err := json.Unmarshal(p, &a)
	if err == nil {
		ts, _ := time.Parse(timeFormatISO8601, a.Time)
		l.append(&LogItem{
			Level:  a.Level.String(),
			Module: a.Module,
			TS:     float64(ts.Unix()),
			Caller: a.Caller,
			Msg:    a.Msg,
		})
	}
	return len(p), nil
}

func (l *UIWriter) append(item *LogItem) {
	l.mu.Lock()
	l.seq++
	item.Seq = l.seq

	l.items = append(l.items, item)
	if l.logLimit == 0 {
		l.logLimit = logLimitDefault
	}
	if len(l.items) > l.logLimit {
		l.items = l.items[len(l.items)-l.logLimit:]
	}

	// 在锁内写入，保证文件顺序与 seq 顺序一致，倒序读取时才能准确翻页。
	if l.history != nil {
		if buf, err := json.Marshal(item); err == nil {
			_, _ = l.history.Write(append(buf, '\n'))
		}
	}

	// 订阅者发送必须在锁内完成：Unsubscribe 也是在锁内 close(ch)，
	// 若先解锁再发送，SSE 客户端断开时可能撞上已关闭的 channel，
	// 触发 send on closed channel panic。发送是非阻塞的，不会拖慢日志写入。
	for _, ch := range l.subscribed {
		select {
		case ch <- item:
		default:
		}
	}
	l.mu.Unlock()
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

// ReadHistory 从最新的历史文件开始倒序读取，返回 beforeSeq 之前的一页日志。
// 返回结果按时间从早到晚排列；hasMore 表示是否还有更早的记录。
func (l *UIWriter) ReadHistory(q HistoryQuery) ([]*LogItem, bool, error) {
	limit := q.Limit
	if limit <= 0 {
		limit = uiHistoryReadLimit
	}
	if limit > uiHistoryReadMaxLimit {
		limit = uiHistoryReadMaxLimit
	}
	if q.BeforeSeq <= 0 {
		return nil, false, nil
	}

	l.mu.RLock()
	files := l.historyFilesLocked()
	l.mu.RUnlock()
	if len(files) == 0 {
		return nil, false, nil
	}

	keyword := strings.ToLower(strings.TrimSpace(q.Keyword))
	collected := make([]*LogItem, 0, limit+1)

	for i := len(files) - 1; i >= 0; i-- {
		data, err := os.ReadFile(files[i])
		if err != nil {
			continue
		}

		end := len(data)
		for end > 0 {
			if data[end-1] == '\n' {
				end--
				continue
			}
			start := bytes.LastIndexByte(data[:end], '\n') + 1
			line := data[start:end]
			end = start
			if len(line) == 0 {
				continue
			}

			var item LogItem
			if err := json.Unmarshal(line, &item); err != nil {
				continue
			}
			if item.Seq <= 0 || item.Seq >= q.BeforeSeq {
				continue
			}
			if len(q.Levels) > 0 {
				if _, ok := q.Levels[item.Level]; !ok {
					continue
				}
			}
			if q.StartTS > 0 && item.TS < q.StartTS {
				continue
			}
			if q.EndTS > 0 && item.TS > q.EndTS {
				continue
			}
			if keyword != "" && !strings.Contains(strings.ToLower(item.Msg), keyword) {
				continue
			}

			collected = append(collected, &item)
			if len(collected) > limit {
				break
			}
		}
		if len(collected) > limit {
			break
		}
	}

	hasMore := len(collected) > limit
	if hasMore {
		collected = collected[:limit]
	}
	for i, j := 0, len(collected)-1; i < j; i, j = i+1, j-1 {
		collected[i], collected[j] = collected[j], collected[i]
	}
	return collected, hasMore, nil
}

// historyFilesLocked 返回按时间从旧到新排列的历史文件，当前文件在最后。
// 调用方需持有 l.mu。
func (l *UIWriter) historyFilesLocked() []string {
	if l.historyPath == "" {
		return nil
	}
	backups, _ := filepath.Glob(filepath.Join(l.historyDir, "ui-*.log"))
	sort.Strings(backups)

	files := make([]string, 0, len(backups)+1)
	files = append(files, backups...)
	files = append(files, l.historyPath)
	return files
}

// loadLastSeqLocked 从最新的历史文件读回最后一个 seq，避免重启后 seq 归零。
// 调用方需持有 l.mu。
func (l *UIWriter) loadLastSeqLocked() int64 {
	files := l.historyFilesLocked()
	for i := len(files) - 1; i >= 0; i-- {
		data, err := os.ReadFile(files[i])
		if err != nil {
			continue
		}

		end := len(data)
		for end > 0 {
			if data[end-1] == '\n' {
				end--
				continue
			}
			start := bytes.LastIndexByte(data[:end], '\n') + 1
			line := data[start:end]
			end = start
			if len(line) == 0 {
				continue
			}

			var item LogItem
			if err := json.Unmarshal(line, &item); err != nil {
				continue
			}
			if item.Seq > 0 {
				return item.Seq
			}
		}
	}
	return 0
}
