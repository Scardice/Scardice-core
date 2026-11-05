package eventstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	sealdicelogger "Scardice-core/logger"

	"gorm.io/gorm"
)

const (
	queueSchedulingVersion          uint8 = 1
	queueSchedulingBatchSize              = 256
	queueSchedulingProgressInterval       = 5 * time.Second

	queueReadyActionClaim   = "claim"
	queueReadyActionRecover = "recover"
)

const inboxClaimableSQL = `
SELECT active_id AS inbox_id, active_sequence AS ordering_sequence
FROM lane_heads
WHERE kind = ?
  AND ready_action = ?
  AND ready_at IS NOT NULL
  AND ready_at <= ?
ORDER BY ready_at ASC, active_since ASC, id ASC
LIMIT 1`

func inboxClaimable(query *gorm.DB, now time.Time) *gorm.DB {
	return query.Raw(inboxClaimableSQL, inboxLaneKind, queueReadyActionClaim, now)
}

func scanInboxClaimable(query *gorm.DB, now time.Time, candidate any) *gorm.DB {
	return inboxClaimable(query, now).Scan(candidate)
}

const outboxClaimableSQL = `
SELECT active_id AS effect_id, active_sequence AS ordering_sequence
FROM lane_heads
WHERE kind = ?
  AND ready_action = ?
  AND ready_at IS NOT NULL
  AND ready_at <= ?
ORDER BY ready_at ASC, active_since ASC, id ASC
LIMIT 1`

func outboxClaimable(query *gorm.DB, now time.Time) *gorm.DB {
	return query.Raw(outboxClaimableSQL, outboxLaneKind, queueReadyActionClaim, now)
}

func scanOutboxClaimable(query *gorm.DB, now time.Time, candidate any) *gorm.DB {
	return outboxClaimable(query, now).Scan(candidate)
}

type queueLaneRef struct {
	kind string
	lane string
}

func queueReadyTime(activeSince time.Time, due *time.Time) time.Time {
	if due != nil && due.After(activeSince) {
		return *due
	}
	return activeSince
}

func earliestInboxLaneRow(tx *gorm.DB, lane string) (inboxMessageRow, bool, error) {
	laneID, err := findLaneID(tx, inboxLaneKind, lane)
	if errors.Is(err, ErrNotFound) {
		return inboxMessageRow{}, false, nil
	}
	if err != nil {
		return inboxMessageRow{}, false, err
	}
	statuses := [...]string{InboxStatusLeased, InboxStatusCallbackStarted}
	var selected inboxMessageRow
	found := false
	for _, status := range statuses {
		var row inboxMessageRow
		q := locked(tx).Where("lane_id = ? AND status = ?", laneID, status).Order("ordering_sequence ASC").Limit(1).Take(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if q.Error != nil {
			return inboxMessageRow{}, false, q.Error
		}
		if !found || row.OrderingSequence < selected.OrderingSequence {
			selected, found = row, true
		}
	}
	if found {
		return selected, true, nil
	}
	q := locked(tx).Where("lane_id = ? AND status = ?", laneID, InboxStatusPending).Order("ordering_sequence ASC").Limit(1).Take(&selected)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return inboxMessageRow{}, false, nil
	}
	if q.Error != nil {
		return inboxMessageRow{}, false, q.Error
	}
	return selected, true, nil
}

func earliestOutboxLaneRow(tx *gorm.DB, lane string) (outboxEffectRow, bool, error) {
	laneID, err := findLaneID(tx, outboxLaneKind, lane)
	if errors.Is(err, ErrNotFound) {
		return outboxEffectRow{}, false, nil
	}
	if err != nil {
		return outboxEffectRow{}, false, err
	}
	statuses := [...]string{OutboxStatusLeased, OutboxStatusDispatched}
	var selected outboxEffectRow
	found := false
	for _, status := range statuses {
		var row outboxEffectRow
		q := locked(tx).Where("lane_id = ? AND status = ?", laneID, status).Order("ordering_sequence ASC").Limit(1).Take(&row)
		if errors.Is(q.Error, gorm.ErrRecordNotFound) {
			continue
		}
		if q.Error != nil {
			return outboxEffectRow{}, false, q.Error
		}
		if !found || row.OrderingSequence < selected.OrderingSequence {
			selected, found = row, true
		}
	}
	if found {
		return selected, true, nil
	}
	q := locked(tx).Where("lane_id = ? AND status = ?", laneID, OutboxStatusPending).Order("ordering_sequence ASC").Limit(1).Take(&selected)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return outboxEffectRow{}, false, nil
	}
	if q.Error != nil {
		return outboxEffectRow{}, false, q.Error
	}
	return selected, true, nil
}

func refreshQueueLane(tx *gorm.DB, kind string, lane string, now time.Time) error {
	var head laneHeadRow
	if err := laneQuery(locked(tx), kind, lane).First(&head).Error; err != nil {
		return errors.New("eventstore: load queue lane scheduling failed")
	}
	updates := map[string]any{
		"active_id": "", "active_sequence": uint64(0), "active_since": nil,
		"ready_at": nil, "ready_action": "", "scheduling_version": queueSchedulingVersion, "updated_at": now,
	}
	switch kind {
	case inboxLaneKind:
		row, found, err := earliestInboxLaneRow(tx, lane)
		if err != nil {
			return errors.New("eventstore: find inbox lane head failed")
		}
		if found {
			activeSince := now
			if head.ActiveID == row.InboxID && head.ActiveSince != nil {
				activeSince = *head.ActiveSince
			}
			action := queueReadyActionClaim
			var due *time.Time
			switch row.Status {
			case InboxStatusCallbackStarted:
				action = queueReadyActionRecover
				due = row.LeaseExpiry
			case InboxStatusLeased:
				due = row.LeaseExpiry
			}
			var readyAt *time.Time
			if action != queueReadyActionRecover || due != nil {
				value := queueReadyTime(activeSince, due)
				readyAt = &value
			}
			updates["active_id"], updates["active_sequence"], updates["active_since"] = row.InboxID, row.OrderingSequence, activeSince
			updates["ready_at"], updates["ready_action"] = readyAt, action
		}
	case outboxLaneKind:
		row, found, err := earliestOutboxLaneRow(tx, lane)
		if err != nil {
			return errors.New("eventstore: find outbox lane head failed")
		}
		if found {
			activeSince := now
			if head.ActiveID == row.EffectID && head.ActiveSince != nil {
				activeSince = *head.ActiveSince
			}
			var due *time.Time
			switch row.Status {
			case OutboxStatusPending:
				due = row.NextAttemptAt
			case OutboxStatusLeased:
				due = row.LeaseExpiry
			case OutboxStatusDispatched:
				if row.LeaseExpiry == nil {
					updates["active_id"], updates["active_sequence"], updates["active_since"] = row.EffectID, row.OrderingSequence, activeSince
					break
				}
				due = row.LeaseExpiry
			}
			if row.Status != OutboxStatusDispatched || row.LeaseExpiry != nil {
				value := queueReadyTime(activeSince, due)
				updates["active_id"], updates["active_sequence"], updates["active_since"] = row.EffectID, row.OrderingSequence, activeSince
				updates["ready_at"], updates["ready_action"] = &value, queueReadyActionClaim
			}
		}
	default:
		return errors.New("eventstore: invalid queue lane kind")
	}
	q := tx.Model(&laneHeadRow{}).Where("id = ?", head.ID).Updates(updates)
	if q.Error != nil {
		return errors.New("eventstore: refresh queue lane scheduling failed")
	}
	return nil
}

func refreshQueueLaneRefs(tx *gorm.DB, refs []queueLaneRef, now time.Time) error {
	if len(refs) == 0 {
		return nil
	}
	unique := make(map[string]queueLaneRef, len(refs))
	for _, ref := range refs {
		if ref.lane != "" {
			unique[ref.kind+"\x00"+ref.lane] = ref
		}
	}
	keys := make([]string, 0, len(unique))
	for key := range unique {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		ref := unique[key]
		if err := refreshQueueLane(tx, ref.kind, ref.lane, now); err != nil {
			return err
		}
	}
	return nil
}

func (s *GORMStore) refreshQueueScheduling(ctx context.Context, tx *gorm.DB, work UnitOfWork) error {
	if s == nil || tx == nil {
		return errors.New("eventstore: queue scheduling unavailable")
	}
	tx = tx.WithContext(ctx)
	refs := make([]queueLaneRef, 0, len(work.InboxUpdates)+len(work.Effects))
	for _, update := range work.InboxUpdates {
		lane := update.Lane
		if lane == "" {
			var row inboxMessageRow
			if err := tx.Select("lane").Where("inbox_id = ?", update.InboxID).First(&row).Error; err != nil {
				return errors.New("eventstore: load inbox lane for scheduling failed")
			}
			lane = row.Lane
		}
		refs = append(refs, queueLaneRef{kind: inboxLaneKind, lane: lane})
	}
	for _, effect := range work.Effects {
		lane := effect.Lane
		if lane == "" {
			var row outboxEffectRow
			if err := tx.Select("lane").Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
				return errors.New("eventstore: load outbox lane for scheduling failed")
			}
			lane = row.Lane
		}
		refs = append(refs, queueLaneRef{kind: outboxLaneKind, lane: lane})
	}
	return refreshQueueLaneRefs(tx, refs, s.task5Now())
}
func ensureQueueLanesForMigration(tx *gorm.DB, kind string, lanes map[string]string, keys []string, now time.Time) error {
	for _, key := range keys {
		lane := lanes[key]
		head, err := task5Lane(tx, kind, lane, now)
		if err != nil {
			return err
		}
		if err := tx.Model(&laneHeadRow{}).Where("id = ?", head.ID).UpdateColumn("scheduling_version", uint8(0)).Error; err != nil {
			return err
		}
	}
	return nil
}

type queueSchedulingMigrationProgress struct {
	phase         string
	startedAt     time.Time
	lastLoggedAt  time.Time
	committedRows int64
}

func (progress *queueSchedulingMigrationProgress) start() {
	if !progress.startedAt.IsZero() {
		return
	}
	progress.startedAt = time.Now()
	progress.lastLoggedAt = progress.startedAt
	sealdicelogger.M().Infof("事件数据库队列升级开始：phase=%s", progress.phase)
}

func (progress *queueSchedulingMigrationProgress) committed(rows int) {
	progress.committedRows += int64(rows)
	now := time.Now()
	if now.Sub(progress.lastLoggedAt) < queueSchedulingProgressInterval {
		return
	}
	sealdicelogger.M().Infof(
		"事件数据库队列升级进度：phase=%s migrated_rows=%d elapsed=%s",
		progress.phase,
		progress.committedRows,
		now.Sub(progress.startedAt).Round(time.Millisecond),
	)
	progress.lastLoggedAt = now
}

func (progress *queueSchedulingMigrationProgress) complete() {
	if progress.startedAt.IsZero() {
		return
	}
	sealdicelogger.M().Infof(
		"事件数据库队列升级完成：phase=%s migrated_rows=%d elapsed=%s",
		progress.phase,
		progress.committedRows,
		time.Since(progress.startedAt).Round(time.Millisecond),
	)
}

// Keep the scheduling version first in both the predicate and ordering. The
// migration indexes can then skip committed rows instead of repeatedly
// scanning or sorting the already-migrated primary-key prefix.
func inboxSchedulingMigrationBatch(db *gorm.DB, rows *[]inboxMessageRow) *gorm.DB {
	return db.Select("inbox_id", "lane").
		Where("scheduling_version < ?", queueSchedulingVersion).
		Order("scheduling_version ASC, inbox_id ASC").
		Limit(queueSchedulingBatchSize).
		Find(rows)
}

func outboxSchedulingMigrationBatch(db *gorm.DB, rows *[]outboxEffectRow) *gorm.DB {
	return db.Select("effect_id", "lane").
		Where("scheduling_version < ?", queueSchedulingVersion).
		Order("scheduling_version ASC, effect_id ASC").
		Limit(queueSchedulingBatchSize).
		Find(rows)
}

func laneSchedulingMigrationBatch(db *gorm.DB, rows *[]laneHeadRow) *gorm.DB {
	return db.Where("scheduling_version < ?", queueSchedulingVersion).
		Order("scheduling_version ASC, id ASC").
		Limit(queueSchedulingBatchSize).
		Find(rows)
}

func migrateInboxSchedulingRows(db *gorm.DB) error {
	progress := queueSchedulingMigrationProgress{phase: "inbox"}
	for {
		var rows []inboxMessageRow
		if err := inboxSchedulingMigrationBatch(db, &rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			progress.complete()
			return nil
		}
		progress.start()
		tx := db.Begin()
		if tx.Error != nil {
			return tx.Error
		}
		rollback := func(err error) error {
			_ = tx.Rollback().Error
			return err
		}
		ids := make([]string, len(rows))
		lanes := make(map[string]string, len(rows))
		for i := range rows {
			ids[i] = rows[i].InboxID
			lanes[rows[i].Lane] = rows[i].Lane
		}
		laneKeys := make([]string, 0, len(lanes))
		for key := range lanes {
			laneKeys = append(laneKeys, key)
		}
		sort.Strings(laneKeys)
		if err := ensureQueueLanesForMigration(tx, inboxLaneKind, lanes, laneKeys, time.Unix(0, 0).UTC()); err != nil {
			return rollback(err)
		}
		q := tx.Model(&inboxMessageRow{}).
			Where("inbox_id IN ? AND scheduling_version < ?", ids, queueSchedulingVersion).
			Update("scheduling_version", queueSchedulingVersion)
		if q.Error != nil {
			return rollback(q.Error)
		}
		if q.RowsAffected != int64(len(rows)) {
			return rollback(errors.New("eventstore: inbox scheduling migration conflict"))
		}
		if err := tx.Commit().Error; err != nil {
			return err
		}
		progress.committed(len(rows))
	}
}

func migrateOutboxSchedulingRows(db *gorm.DB) error {
	progress := queueSchedulingMigrationProgress{phase: "outbox"}
	for {
		var rows []outboxEffectRow
		if err := outboxSchedulingMigrationBatch(db, &rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			progress.complete()
			return nil
		}
		progress.start()
		tx := db.Begin()
		if tx.Error != nil {
			return tx.Error
		}
		rollback := func(err error) error {
			_ = tx.Rollback().Error
			return err
		}
		ids := make([]string, len(rows))
		lanes := make(map[string]string, len(rows))
		for i := range rows {
			ids[i] = rows[i].EffectID
			lanes[rows[i].Lane] = rows[i].Lane
		}
		laneKeys := make([]string, 0, len(lanes))
		for key := range lanes {
			laneKeys = append(laneKeys, key)
		}
		sort.Strings(laneKeys)
		if err := ensureQueueLanesForMigration(tx, outboxLaneKind, lanes, laneKeys, time.Unix(0, 0).UTC()); err != nil {
			return rollback(err)
		}
		q := tx.Model(&outboxEffectRow{}).
			Where("effect_id IN ? AND scheduling_version < ?", ids, queueSchedulingVersion).
			Update("scheduling_version", queueSchedulingVersion)
		if q.Error != nil {
			return rollback(q.Error)
		}
		if q.RowsAffected != int64(len(rows)) {
			return rollback(errors.New("eventstore: outbox scheduling migration conflict"))
		}
		if err := tx.Commit().Error; err != nil {
			return err
		}
		progress.committed(len(rows))
	}
}

func migrateLaneScheduling(db *gorm.DB) error {
	progress := queueSchedulingMigrationProgress{phase: "lane-heads"}
	for {
		var heads []laneHeadRow
		if err := laneSchedulingMigrationBatch(db, &heads).Error; err != nil {
			return err
		}
		if len(heads) == 0 {
			progress.complete()
			return nil
		}
		progress.start()
		tx := db.Begin()
		if tx.Error != nil {
			return tx.Error
		}
		for i := range heads {
			now := heads[i].UpdatedAt
			if now.IsZero() {
				now = time.Now().UTC()
			}
			if err := refreshQueueLane(tx, heads[i].Kind, heads[i].Lane, now); err != nil {
				_ = tx.Rollback().Error
				return err
			}
		}
		if err := tx.Commit().Error; err != nil {
			return err
		}
		progress.committed(len(heads))
	}
}

func migrateQueueScheduling(db *gorm.DB) error {
	if db == nil {
		return errors.New("eventstore: queue scheduling migration unavailable")
	}
	if err := migrateInboxSchedulingRows(db); err != nil {
		return databaseStage("queue scheduling inbox rows", err)
	}
	if err := migrateOutboxSchedulingRows(db); err != nil {
		return databaseStage("queue scheduling outbox rows", err)
	}
	if err := migrateLaneScheduling(db); err != nil {
		return databaseStage("queue scheduling lane heads", err)
	}
	for _, obsolete := range []struct {
		model any
		name  string
	}{
		{model: &inboxMessageRow{}, name: "ix_inbox_status_ordering"},
		{model: &outboxEffectRow{}, name: "ix_outbox_status_ordering"},
	} {
		if db.Migrator().HasIndex(obsolete.model, obsolete.name) {
			if err := db.Migrator().DropIndex(obsolete.model, obsolete.name); err != nil {
				return fmt.Errorf("drop obsolete queue index %s: %w", obsolete.name, err)
			}
		}
	}
	return nil
}

// HasInboxWork is an advisory wake-up probe, not a lease or readiness check.
// ClaimInbox still authorizes every mutation under its publication lock.
func (s *GORMStore) HasInboxWork(ctx context.Context) (bool, error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return false, err
	}
	now := s.task5Now()
	var available bool
	ready := base.Model(&laneHeadRow{}).Select("1").Where("kind = ? AND ready_action IN (?, ?) AND ready_at IS NOT NULL AND ready_at <= ?", inboxLaneKind, queueReadyActionClaim, queueReadyActionRecover, now).Limit(1)
	if err = base.Raw("SELECT EXISTS(?)", ready).Scan(&available).Error; err != nil {
		return false, err
	}
	return available, nil
}

// MaxInboxStatusQuery bounds how many inbox rows one InboxStatuses call asks about.
const MaxInboxStatusQuery = 1000

// InboxStatuses reports the status of the given inbox rows, keyed by inbox ID.
// It reads status only, never a body, and changes nothing. A row that does not
// exist (purged, or never accepted) has no entry.
func (s *GORMStore) InboxStatuses(ctx context.Context, inboxIDs []string) (map[string]string, error) {
	if len(inboxIDs) > MaxInboxStatusQuery {
		return nil, ErrInvalidMetadata
	}
	statuses := make(map[string]string, len(inboxIDs))
	if len(inboxIDs) == 0 {
		return statuses, nil
	}
	base, err := s.task5Base(ctx)
	if err != nil {
		return nil, err
	}
	var rows []struct {
		InboxID string `gorm:"column:inbox_id"`
		Status  string `gorm:"column:status"`
	}
	if err := base.Model(&inboxMessageRow{}).Select("inbox_id, status").Where("inbox_id IN ?", inboxIDs).Scan(&rows).Error; err != nil {
		return nil, ErrParticipantFailure
	}
	for _, row := range rows {
		statuses[row.InboxID] = row.Status
	}
	return statuses, nil
}

// HasOutboxWork is an advisory wake-up probe, not a lease or readiness check.
// ClaimOutbox remains authoritative when work is claimed.
func (s *GORMStore) HasOutboxWork(ctx context.Context) (bool, error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return false, err
	}
	now := s.task5Now()
	var available bool
	ready := base.Model(&laneHeadRow{}).Select("1").Where("kind = ? AND ready_action = ? AND ready_at IS NOT NULL AND ready_at <= ?", outboxLaneKind, queueReadyActionClaim, now).Limit(1)
	if err = base.Raw("SELECT EXISTS(?)", ready).Scan(&available).Error; err != nil {
		return false, err
	}
	return available, nil
}
