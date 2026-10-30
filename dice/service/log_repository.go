package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pilagod/gorm-cursor-paginator/v2/paginator"

	"Scardice-core/eventstore"
	"Scardice-core/model"
	engine "Scardice-core/utils/dboperator/engine"
)

// LogRepository is the runtime-facing log contract. A repository is bound to
// one Dice; every group operation therefore carries an explicit group scope.
type LogRepository interface {
	DiceID() string
	GetOrCreate(groupID, name string) (uint64, error)
	List(groupID string) ([]string, error)
	Count(groupID, name string) (int64, bool)
	Delete(groupID, name string) error
	Append(groupID, name string, item *model.LogOneItem) error
	AppendByID(groupID string, logID uint64, item *model.LogOneItem) error
	Entries(groupID, name string) ([]*model.LogOneItem, error)
	CommandInfo(groupID, name string) ([]string, error)
	LastSeq(logID uint64) (int64, error)
	DeleteByRawID(groupID string, rawID interface{}) error
	EditByRawID(groupID string, rawID interface{}, message string) error
	CursorEntries(groupID, name string, cursor paginator.Cursor) ([]model.LogOneItem, paginator.Cursor, error)
	ExportCursorEntries(groupID, name string, cursor paginator.Cursor) ([]model.LogOneItemParquet, paginator.Cursor, error)
	StorageInfo() ([]int, error)
	AllLogs() ([]*model.LogInfo, error)
	LogsPage(*QueryLogPage) (int, []*model.LogInfo, error)
	ItemsPage(groupID, name string, page, pageSize int) ([]*model.LogOneItem, error)
	UploadInfo(groupID, name string) (url string, uploadTime, updateTime int64, err error)
	SetUploadInfo(groupID, name, url string) error
	StoryLogStats(groupID, name string) (int64, error)
}

var ErrLogRepositoryUnavailable = errors.New("日志存储未初始化，当前存储模式不可用")

// LogState is a group's current log selection. BaselineSeq is the provider
// sequence number of the message that last switched the log on (zero when
// unknown); a gap in the log is never measured from before it.
type LogState struct {
	ID          uint64
	Name        string
	On          bool
	BaselineSeq int64
}

type LogStateRepository interface {
	GetState(groupID string) (LogState, error)
	SetState(groupID string, state LogState) error
}

type legacyLogRepository struct {
	diceID   string
	operator engine.DatabaseOperator
}

func NewLegacyLogRepository(operator engine.DatabaseOperator, diceID string) LogRepository {
	if operator == nil {
		return nil
	}
	return &legacyLogRepository{diceID: diceID, operator: operator}
}

func (r *legacyLogRepository) DiceID() string { return r.diceID }
func (r *legacyLogRepository) GetOrCreate(groupID, name string) (uint64, error) {
	return LogGetOrCreate(r.operator, groupID, name)
}
func (r *legacyLogRepository) List(groupID string) ([]string, error) {
	return LogGetList(r.operator, groupID)
}
func (r *legacyLogRepository) Count(groupID, name string) (int64, bool) {
	return LogLinesCountGet(r.operator, groupID, name)
}
func (r *legacyLogRepository) StoryLogStats(groupID, name string) (int64, error) {
	if count, ok := LogLinesCountGet(r.operator, groupID, name); ok {
		return count, nil
	}
	return 0, ErrLogNotFound
}
func (r *legacyLogRepository) Delete(groupID, name string) error {
	return LogDelete(r.operator, groupID, name)
}
func (r *legacyLogRepository) Append(groupID, name string, item *model.LogOneItem) error {
	if !LogAppend(r.operator, groupID, name, item) {
		return errors.New("story log append failed")
	}
	return nil
}
func (r *legacyLogRepository) AppendByID(groupID string, logID uint64, item *model.LogOneItem) error {
	if !LogAppendByID(r.operator, logID, groupID, item) {
		return errors.New("story log append failed")
	}
	return nil
}
func (r *legacyLogRepository) Entries(groupID, name string) ([]*model.LogOneItem, error) {
	return LogGetAllLines(r.operator, groupID, name)
}
func (r *legacyLogRepository) CommandInfo(groupID, name string) ([]string, error) {
	return LogGetCommandInfoStrList(r.operator, groupID, name)
}
func (r *legacyLogRepository) LastSeq(logID uint64) (int64, error) {
	return LogGetLastSeq(r.operator, logID)
}
func (r *legacyLogRepository) DeleteByRawID(groupID string, rawID interface{}) error {
	return LogMarkDeleteByRawMsgID(r.operator, groupID, rawID)
}
func (r *legacyLogRepository) EditByRawID(groupID string, rawID interface{}, message string) error {
	return LogEditByRawMsgID(r.operator, groupID, message, rawID)
}
func (r *legacyLogRepository) CursorEntries(groupID, name string, cursor paginator.Cursor) ([]model.LogOneItem, paginator.Cursor, error) {
	return LogGetCursorLines(r.operator, groupID, name, cursor)
}
func (r *legacyLogRepository) ExportCursorEntries(groupID, name string, cursor paginator.Cursor) ([]model.LogOneItemParquet, paginator.Cursor, error) {
	return LogGetExportCursorLines(r.operator, groupID, name, cursor)
}

func (r *legacyLogRepository) StorageInfo() ([]int, error) {
	return LogGetInfo(r.operator)
}
func (r *legacyLogRepository) AllLogs() ([]*model.LogInfo, error) {
	return LogGetLogs(r.operator)
}
func (r *legacyLogRepository) LogsPage(query *QueryLogPage) (int, []*model.LogInfo, error) {
	return LogGetLogPage(r.operator, query)
}
func (r *legacyLogRepository) ItemsPage(groupID, name string, page, pageSize int) ([]*model.LogOneItem, error) {
	return LogGetLinePage(r.operator, &QueryLogLinePage{GroupID: groupID, LogName: name, PageNum: page, PageSize: pageSize})
}
func (r *legacyLogRepository) UploadInfo(groupID, name string) (string, int64, int64, error) {
	return LogGetUploadInfo(r.operator, groupID, name)
}
func (r *legacyLogRepository) SetUploadInfo(groupID, name, url string) error {
	return LogSetUploadInfo(r.operator, groupID, name, url)
}

type eventStoreLogRepository struct {
	diceID string
	repo   eventstore.LogRepository
}

func NewEventStoreLogRepository(repo eventstore.LogRepository, diceID string) LogRepository {
	if repo == nil || strings.TrimSpace(diceID) == "" {
		return nil
	}
	return &eventStoreLogRepository{diceID: diceID, repo: repo}
}

func (r *eventStoreLogRepository) DiceID() string { return r.diceID }
func (r *eventStoreLogRepository) GetOrCreate(groupID, name string) (uint64, error) {
	session, err := r.repo.CreateStoryLog(context.Background(), r.diceID, groupID, name)
	return session.ID, err
}
func (r *eventStoreLogRepository) List(groupID string) ([]string, error) {
	sessions, err := r.repo.ListStoryLogs(context.Background(), r.diceID, groupID)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(sessions))
	for i, session := range sessions {
		out[i] = session.Name
	}
	return out, nil
}
func (r *eventStoreLogRepository) Count(groupID, name string) (int64, bool) {
	if name == "" {
		return 0, false
	}
	sessions, err := r.repo.ListStoryLogs(context.Background(), r.diceID, groupID)
	if err != nil {
		return 0, false
	}
	found := false
	for _, session := range sessions {
		if session.Name == name {
			found = true
			break
		}
	}
	if !found {
		return 0, false
	}
	count, err := r.repo.StoryLogStats(context.Background(), r.diceID, groupID, name)
	return count, err == nil
}
func mapEventStoreLogError(err error) error {
	if errors.Is(err, eventstore.ErrNotFound) {
		return ErrLogNotFound
	}
	return err
}

func (r *eventStoreLogRepository) StoryLogStats(groupID, name string) (int64, error) {
	count, err := r.repo.StoryLogStats(context.Background(), r.diceID, groupID, name)
	return count, mapEventStoreLogError(err)
}
func (r *eventStoreLogRepository) GetState(groupID string) (LogState, error) {
	state, err := r.repo.GetStoryLogState(context.Background(), r.diceID, groupID)
	return LogState{ID: state.SessionID, Name: state.Name, On: state.On, BaselineSeq: state.BaselineSeq}, err
}
func (r *eventStoreLogRepository) SetState(groupID string, state LogState) error {
	return r.repo.SetStoryLogState(context.Background(), eventstore.StoryLogState{
		DiceID: r.diceID, GroupID: groupID, SessionID: state.ID, Name: state.Name, On: state.On, BaselineSeq: state.BaselineSeq,
	})
}
func (r *eventStoreLogRepository) Delete(groupID, name string) error {
	return mapEventStoreLogError(r.repo.DeleteStoryLog(context.Background(), r.diceID, groupID, name))
}
func (r *eventStoreLogRepository) Append(groupID, name string, item *model.LogOneItem) error {
	return mapEventStoreLogError(r.repo.AppendStoryLogEntry(context.Background(), eventStoreEntry(r.diceID, groupID, name, item)))
}
func (r *eventStoreLogRepository) AppendByID(groupID string, logID uint64, item *model.LogOneItem) error {
	sessions, err := r.repo.ListStoryLogs(context.Background(), r.diceID, groupID)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if session.ID == logID {
			return r.Append(groupID, session.Name, item)
		}
	}
	return ErrLogNotFound
}
func (r *eventStoreLogRepository) Entries(groupID, name string) ([]*model.LogOneItem, error) {
	entries, err := r.repo.GetStoryLogEntries(context.Background(), r.diceID, groupID, name)
	if err != nil {
		return nil, err
	}
	out := make([]*model.LogOneItem, 0, len(entries))
	for _, entry := range entries {
		out = append(out, eventStoreModelEntry(entry))
	}
	return out, nil
}
func (r *eventStoreLogRepository) CommandInfo(groupID, name string) ([]string, error) {
	entries, err := r.repo.GetStoryLogEntries(context.Background(), r.diceID, groupID, name)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if len(entry.CommandInfo) > 0 {
			out = append(out, string(entry.CommandInfo))
		}
	}
	return out, nil
}
func (r *eventStoreLogRepository) LastSeq(logID uint64) (int64, error) {
	sessions, err := r.allSessions()
	if err != nil {
		return 0, err
	}
	for _, session := range sessions {
		if session.ID != logID {
			continue
		}
		entries, err := r.repo.GetStoryLogEntries(context.Background(), r.diceID, session.GroupID, session.Name)
		if err != nil {
			return 0, mapEventStoreLogError(err)
		}
		var last int64
		for _, entry := range entries {
			if entry.Seq != nil && *entry.Seq > last {
				last = *entry.Seq
			}
		}
		return last, nil
	}
	return 0, ErrLogNotFound
}
func (r *eventStoreLogRepository) DeleteByRawID(groupID string, rawID interface{}) error {
	return r.repo.DeleteStoryLogEntryByRawID(context.Background(), r.diceID, groupID, fmt.Sprint(rawID))
}
func (r *eventStoreLogRepository) EditByRawID(groupID string, rawID interface{}, message string) error {
	return r.repo.EditStoryLogEntryByRawID(context.Background(), r.diceID, groupID, fmt.Sprint(rawID), message)
}
func (r *eventStoreLogRepository) CursorEntries(groupID, name string, cursor paginator.Cursor) ([]model.LogOneItem, paginator.Cursor, error) {
	entries, err := r.repo.GetStoryLogEntries(context.Background(), r.diceID, groupID, name)
	if err != nil {
		return nil, paginator.Cursor{}, err
	}
	items := make([]model.LogOneItem, 0, len(entries))
	for _, entry := range entries {
		items = append(items, *eventStoreModelEntry(entry))
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].ID != items[j].ID {
			return items[i].ID < items[j].ID
		}
		return items[i].Time < items[j].Time
	})
	start := 0
	if cursor.After != nil {
		id, tm, ok := decodeStoryLogCursor(*cursor.After)
		if !ok {
			return nil, paginator.Cursor{}, ErrInvalidStoryLogCursor
		}
		start = sort.Search(len(items), func(i int) bool { return items[i].ID > id || (items[i].ID == id && items[i].Time > tm) })
	} else if cursor.Before != nil {
		id, tm, ok := decodeStoryLogCursor(*cursor.Before)
		if !ok {
			return nil, paginator.Cursor{}, ErrInvalidStoryLogCursor
		}
		start = sort.Search(len(items), func(i int) bool { return items[i].ID >= id || (items[i].ID == id && items[i].Time >= tm) })
	}
	if start >= len(items) {
		return []model.LogOneItem{}, paginator.Cursor{}, nil
	}
	end := start + 4000
	if end > len(items) {
		end = len(items)
	}
	page := items[start:end]
	var next paginator.Cursor
	if end < len(items) && len(page) > 0 {
		last := page[len(page)-1]
		token := fmt.Sprintf("%d:%d", last.ID, last.Time)
		next.After = &token
	}
	return page, next, nil
}
func (r *eventStoreLogRepository) ExportCursorEntries(groupID, name string, cursor paginator.Cursor) ([]model.LogOneItemParquet, paginator.Cursor, error) {
	items, next, err := r.CursorEntries(groupID, name, cursor)
	if err != nil {
		return nil, paginator.Cursor{}, err
	}
	out := make([]model.LogOneItemParquet, 0, len(items))
	for _, item := range items {
		out = append(out, model.LogOneItemParquet{ID: item.ID, Nickname: item.Nickname, IMUserID: item.IMUserID, Time: item.Time, Message: item.Message, IsDice: item.IsDice, CommandID: item.CommandID, CommandInfoStr: item.CommandInfoStr, UniformID: item.UniformID})
	}
	return out, next, nil
}

var ErrInvalidStoryLogCursor = errors.New("invalid story log cursor")

func eventStoreEntry(diceID, groupID, name string, item *model.LogOneItem) eventstore.StoryLogEntry {
	entry := eventstore.StoryLogEntry{DiceID: diceID, GroupID: groupID, LogName: name}
	if item == nil {
		return entry
	}
	entry.Nickname, entry.IMUserID, entry.Time, entry.Message = item.Nickname, item.IMUserID, item.Time, item.Message
	entry.IsDice, entry.CommandID, entry.UniformID, entry.Seq = item.IsDice, item.CommandID, item.UniformID, item.Seq
	entry.RawMsgID = item.RawMsgIDStr
	if item.RawMsgID != nil && entry.RawMsgID == "" {
		entry.RawMsgID = fmt.Sprint(item.RawMsgID)
	}
	if item.CommandInfo != nil {
		if raw, err := json.Marshal(item.CommandInfo); err == nil {
			entry.CommandInfo = raw
		}
	} else if item.CommandInfoStr != "" {
		entry.CommandInfo = json.RawMessage(item.CommandInfoStr)
	}
	return entry
}
func eventStoreModelEntry(entry eventstore.StoryLogEntry) *model.LogOneItem {
	item := &model.LogOneItem{
		ID: entry.ID, LogID: entry.LogID, GroupID: entry.GroupID, Nickname: entry.Nickname, IMUserID: entry.IMUserID,
		Time: entry.Time, Message: entry.Message, IsDice: entry.IsDice, CommandID: entry.CommandID,
		RawMsgIDStr: entry.RawMsgID, UniformID: entry.UniformID, Seq: entry.Seq, Removed: entry.Removed, ParentID: entry.ParentID,
	}
	if entry.RawMsgID != "" {
		item.RawMsgID = entry.RawMsgID
	}
	if len(entry.CommandInfo) > 0 {
		item.CommandInfoStr = string(entry.CommandInfo)
		var value any
		if json.Unmarshal(entry.CommandInfo, &value) == nil {
			item.CommandInfo = value
		}
	}
	return item
}
func decodeStoryLogCursor(value string) (uint64, int64, bool) {
	idPart, timePart, ok := strings.Cut(value, ":")
	if !ok {
		return 0, 0, false
	}
	id, err := strconv.ParseUint(idPart, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	tm, err := strconv.ParseInt(timePart, 10, 64)
	return id, tm, err == nil
}
func (r *eventStoreLogRepository) allSessions() ([]eventstore.StoryLogSession, error) {
	return r.repo.ListStoryLogsForDice(context.Background(), r.diceID)
}

func (r *eventStoreLogRepository) StorageInfo() ([]int, error) {
	sessions, err := r.allSessions()
	if err != nil {
		return nil, err
	}
	maxSessionID, maxEntryID, entryCount := uint64(0), uint64(0), 0
	for _, session := range sessions {
		if session.ID > maxSessionID {
			maxSessionID = session.ID
		}
		entries, err := r.repo.GetStoryLogEntries(context.Background(), r.diceID, session.GroupID, session.Name)
		if err != nil {
			return nil, mapEventStoreLogError(err)
		}
		entryCount += len(entries)
		for _, entry := range entries {
			if entry.ID > maxEntryID {
				maxEntryID = entry.ID
			}
		}
	}
	return []int{int(maxSessionID), int(maxEntryID), len(sessions), entryCount}, nil
}

func (r *eventStoreLogRepository) AllLogs() ([]*model.LogInfo, error) {
	sessions, err := r.allSessions()
	if err != nil {
		return nil, err
	}
	out := make([]*model.LogInfo, 0, len(sessions))
	for _, session := range sessions {
		info, err := r.sessionInfo(session)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

func (r *eventStoreLogRepository) LogsPage(query *QueryLogPage) (int, []*model.LogInfo, error) {
	sessions, err := r.allSessions()
	if err != nil {
		return 0, nil, err
	}
	total := len(sessions)
	filtered := make([]eventstore.StoryLogSession, 0, len(sessions))
	var begin, end *int64
	if query != nil && query.CreatedTimeBegin != "" {
		value, err := strconv.ParseInt(query.CreatedTimeBegin, 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid story log begin time: %w", err)
		}
		begin = &value
	}
	if query != nil && query.CreatedTimeEnd != "" {
		value, err := strconv.ParseInt(query.CreatedTimeEnd, 10, 64)
		if err != nil {
			return 0, nil, fmt.Errorf("invalid story log end time: %w", err)
		}
		end = &value
	}
	for _, session := range sessions {
		if query != nil {
			if query.Name != "" && !strings.Contains(session.Name, query.Name) {
				continue
			}
			if query.GroupID != "" && !strings.Contains(session.GroupID, query.GroupID) {
				continue
			}
			if begin != nil && session.CreatedAt < *begin {
				continue
			}
			if end != nil && session.CreatedAt > *end {
				continue
			}
		}
		filtered = append(filtered, session)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].UpdatedAt != filtered[j].UpdatedAt {
			return filtered[i].UpdatedAt > filtered[j].UpdatedAt
		}
		return filtered[i].ID > filtered[j].ID
	})
	page, pageSize := 1, 20
	if query != nil {
		if query.PageNum > 0 {
			page = query.PageNum
		}
		if query.PageSize > 0 {
			pageSize = query.PageSize
		}
	}
	start := (page - 1) * pageSize
	if start >= len(filtered) {
		return total, []*model.LogInfo{}, nil
	}
	stop := start + pageSize
	if stop > len(filtered) {
		stop = len(filtered)
	}
	out := make([]*model.LogInfo, 0, stop-start)
	for _, session := range filtered[start:stop] {
		info, err := r.sessionInfo(session)
		if err != nil {
			return 0, nil, err
		}
		out = append(out, info)
	}
	return total, out, nil
}

func (r *eventStoreLogRepository) sessionInfo(session eventstore.StoryLogSession) (*model.LogInfo, error) {
	size, err := r.repo.StoryLogStats(context.Background(), r.diceID, session.GroupID, session.Name)
	if err != nil {
		return nil, mapEventStoreLogError(err)
	}
	count := int(size)
	extra := session.Extra
	return &model.LogInfo{
		ID: session.ID, Name: session.Name, GroupID: session.GroupID, CreatedAt: session.CreatedAt,
		UpdatedAt: session.UpdatedAt, Size: &count, Extra: extra, UploadURL: session.UploadURL,
		UploadTime: int(session.UploadTime),
	}, nil
}

func (r *eventStoreLogRepository) ItemsPage(groupID, name string, page, pageSize int) ([]*model.LogOneItem, error) {
	items, err := r.Entries(groupID, name)
	if err != nil {
		return nil, err
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Time != items[j].Time {
			return items[i].Time < items[j].Time
		}
		return items[i].ID < items[j].ID
	})
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	start := (page - 1) * pageSize
	if start >= len(items) {
		return []*model.LogOneItem{}, nil
	}
	stop := start + pageSize
	if stop > len(items) {
		stop = len(items)
	}
	return items[start:stop], nil
}

func (r *eventStoreLogRepository) UploadInfo(groupID, name string) (string, int64, int64, error) {
	sessions, err := r.repo.ListStoryLogs(context.Background(), r.diceID, groupID)
	if err != nil {
		return "", 0, 0, err
	}
	for _, session := range sessions {
		if session.Name == name {
			return session.UploadURL, session.UploadTime, session.UpdatedAt, nil
		}
	}
	return "", 0, 0, ErrLogNotFound
}

func (r *eventStoreLogRepository) SetUploadInfo(groupID, name, url string) error {
	if url == "" {
		return nil
	}
	return mapEventStoreLogError(r.repo.SetStoryLogUploadInfo(context.Background(), r.diceID, groupID, name, url, time.Now().Unix()))
}
