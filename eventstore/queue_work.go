package eventstore

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	sealdicelogger "Scardice-core/logger"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
ORDER BY ready_at ASC, active_since ASC, lane_hmac ASC
LIMIT 1`

func inboxClaimable(query *gorm.DB, now time.Time) *gorm.DB {
	return query.Raw(inboxClaimableSQL, inboxLaneKind, queueReadyActionClaim, now)
}

func scanInboxClaimable(query *gorm.DB, now time.Time, candidate any) *gorm.DB {
	return inboxClaimable(query, now).Scan(candidate)
}

type task5ExpiredPayloadCandidate struct {
	ID string `gorm:"column:row_id"`
}

const inboxExpiredPayloadCandidatesSQL = `
SELECT i.inbox_id AS row_id, i.payload_expires_at
FROM inbox_messages AS i
WHERE i.status = ?
  AND i.payload_expires_at IS NOT NULL
  AND i.payload_expires_at <= ?
UNION ALL
SELECT i.inbox_id AS row_id, i.payload_expires_at
FROM inbox_messages AS i
WHERE i.status = ?
  AND i.payload_expires_at IS NOT NULL
  AND i.payload_expires_at <= ?
UNION ALL
SELECT i.inbox_id AS row_id, i.payload_expires_at
FROM inbox_messages AS i
WHERE i.status = ?
  AND i.payload_expires_at IS NOT NULL
  AND i.payload_expires_at <= ?
UNION ALL
SELECT i.inbox_id AS row_id, i.payload_expires_at
FROM inbox_messages AS i
WHERE i.status = ?
  AND i.payload_present = ?
  AND i.payload_expires_at IS NOT NULL
  AND i.payload_expires_at <= ?
ORDER BY payload_expires_at ASC, row_id ASC
LIMIT ?`

func inboxExpiredPayloadCandidates(query *gorm.DB, now time.Time, limit int) *gorm.DB {
	return query.Raw(
		inboxExpiredPayloadCandidatesSQL,
		InboxStatusPending, now,
		InboxStatusLeased, now,
		InboxStatusCallbackStarted, now,
		InboxStatusAmbiguous, true, now,
		limit,
	)
}

const outboxExpiredPayloadCandidatesSQL = `
SELECT o.effect_id AS row_id, o.payload_expires_at
FROM outbox_effects AS o
WHERE o.status = ?
  AND o.payload_expires_at IS NOT NULL
  AND o.payload_expires_at <= ?
UNION ALL
SELECT o.effect_id AS row_id, o.payload_expires_at
FROM outbox_effects AS o
WHERE o.status = ?
  AND o.payload_expires_at IS NOT NULL
  AND o.payload_expires_at <= ?
UNION ALL
SELECT o.effect_id AS row_id, o.payload_expires_at
FROM outbox_effects AS o
WHERE o.status = ?
  AND o.payload_expires_at IS NOT NULL
  AND o.payload_expires_at <= ?
UNION ALL
SELECT o.effect_id AS row_id, o.payload_expires_at
FROM outbox_effects AS o
WHERE o.status = ?
  AND o.payload_present = ?
  AND o.payload_expires_at IS NOT NULL
  AND o.payload_expires_at <= ?
ORDER BY payload_expires_at ASC, row_id ASC
LIMIT ?`

func outboxExpiredPayloadCandidates(query *gorm.DB, now time.Time, limit int) *gorm.DB {
	return query.Raw(
		outboxExpiredPayloadCandidatesSQL,
		OutboxStatusPending, now,
		OutboxStatusLeased, now,
		OutboxStatusDispatched, now,
		OutboxStatusAmbiguous, true, now,
		limit,
	)
}

func loadLockedInboxPayloadCandidates(tx *gorm.DB, candidates []task5ExpiredPayloadCandidate) ([]inboxMessageRow, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	ids := make([]string, len(candidates))
	for i := range candidates {
		ids[i] = candidates[i].ID
	}
	var rows []inboxMessageRow
	if err := locked(tx).Where("inbox_id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	byID := make(map[string]inboxMessageRow, len(rows))
	for i := range rows {
		byID[rows[i].InboxID] = rows[i]
	}
	ordered := make([]inboxMessageRow, 0, len(candidates))
	for _, candidate := range candidates {
		row, ok := byID[candidate.ID]
		if !ok {
			return nil, gorm.ErrRecordNotFound
		}
		ordered = append(ordered, row)
	}
	return ordered, nil
}

func loadLockedOutboxPayloadCandidates(tx *gorm.DB, candidates []task5ExpiredPayloadCandidate) ([]outboxEffectRow, error) {
	if len(candidates) == 0 {
		return nil, nil
	}
	ids := make([]string, len(candidates))
	for i := range candidates {
		ids[i] = candidates[i].ID
	}
	var rows []outboxEffectRow
	if err := locked(tx).Where("effect_id IN ?", ids).Find(&rows).Error; err != nil {
		return nil, err
	}
	byID := make(map[string]outboxEffectRow, len(rows))
	for i := range rows {
		byID[rows[i].EffectID] = rows[i]
	}
	ordered := make([]outboxEffectRow, 0, len(candidates))
	for _, candidate := range candidates {
		row, ok := byID[candidate.ID]
		if !ok {
			return nil, gorm.ErrRecordNotFound
		}
		ordered = append(ordered, row)
	}
	return ordered, nil
}

const outboxClaimableSQL = `
SELECT active_id AS effect_id, active_sequence AS ordering_sequence
FROM lane_heads
WHERE kind = ?
  AND ready_action = ?
  AND ready_at IS NOT NULL
  AND ready_at <= ?
ORDER BY ready_at ASC, active_since ASC, lane_hmac ASC
LIMIT 1`

func outboxClaimable(query *gorm.DB, now time.Time) *gorm.DB {
	return query.Raw(outboxClaimableSQL, outboxLaneKind, queueReadyActionClaim, now)
}

func scanOutboxClaimable(query *gorm.DB, now time.Time, candidate any) *gorm.DB {
	return outboxClaimable(query, now).Scan(candidate)
}

type queueLaneRef struct {
	kind string
	lane []byte
}

func queueReadyTime(activeSince time.Time, due *time.Time) time.Time {
	if due != nil && due.After(activeSince) {
		return *due
	}
	return activeSince
}

func earliestInboxLaneRow(tx *gorm.DB, lane []byte) (inboxMessageRow, bool, error) {
	statuses := [...]string{InboxStatusLeased, InboxStatusCallbackStarted}
	var selected inboxMessageRow
	found := false
	for _, status := range statuses {
		var row inboxMessageRow
		q := locked(tx).Where("lane_hmac = ? AND status = ?", lane, status).Order("ordering_sequence ASC").Limit(1).First(&row)
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
	q := locked(tx).Where("lane_hmac = ? AND status = ?", lane, InboxStatusPending).Order("ordering_sequence ASC").Limit(1).First(&selected)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return inboxMessageRow{}, false, nil
	}
	if q.Error != nil {
		return inboxMessageRow{}, false, q.Error
	}
	return selected, true, nil
}

func earliestOutboxLaneRow(tx *gorm.DB, lane []byte) (outboxEffectRow, bool, error) {
	statuses := [...]string{OutboxStatusLeased, OutboxStatusDispatched}
	var selected outboxEffectRow
	found := false
	for _, status := range statuses {
		var row outboxEffectRow
		q := locked(tx).Where("lane_hmac = ? AND status = ?", lane, status).Order("ordering_sequence ASC").Limit(1).First(&row)
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
	q := locked(tx).Where("lane_hmac = ? AND status = ?", lane, OutboxStatusPending).Order("ordering_sequence ASC").Limit(1).First(&selected)
	if errors.Is(q.Error, gorm.ErrRecordNotFound) {
		return outboxEffectRow{}, false, nil
	}
	if q.Error != nil {
		return outboxEffectRow{}, false, q.Error
	}
	return selected, true, nil
}

func refreshQueueLane(tx *gorm.DB, kind string, lane []byte, now time.Time) error {
	var head laneHeadRow
	if err := locked(tx).Where("kind = ? AND lane_hmac = ?", kind, lane).First(&head).Error; err != nil {
		return errors.New("eventstore: load queue lane scheduling failed")
	}
	updates := map[string]any{
		"active_id":          "",
		"active_sequence":    uint64(0),
		"active_since":       nil,
		"ready_at":           nil,
		"ready_action":       "",
		"scheduling_version": queueSchedulingVersion,
		"updated_at":         now,
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
			updates["active_id"] = row.InboxID
			updates["active_sequence"] = row.OrderingSequence
			updates["active_since"] = activeSince
			updates["ready_at"] = readyAt
			updates["ready_action"] = action
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
					updates["active_id"] = row.EffectID
					updates["active_sequence"] = row.OrderingSequence
					updates["active_since"] = activeSince
					break
				}
				due = row.LeaseExpiry
			}
			if row.Status != OutboxStatusDispatched || row.LeaseExpiry != nil {
				value := queueReadyTime(activeSince, due)
				updates["active_id"] = row.EffectID
				updates["active_sequence"] = row.OrderingSequence
				updates["active_since"] = activeSince
				updates["ready_at"] = &value
				updates["ready_action"] = queueReadyActionClaim
			}
		}
	default:
		return errors.New("eventstore: invalid queue lane kind")
	}
	q := tx.Model(&laneHeadRow{}).Where("kind = ? AND lane_hmac = ?", kind, lane).Updates(updates)
	if q.Error != nil {
		return errors.New("eventstore: refresh queue lane scheduling failed")
	}
	return nil
}

func refreshQueueLaneRefs(tx *gorm.DB, refs []queueLaneRef, now time.Time) error {
	if len(refs) == 0 {
		return nil
	}
	if len(refs) == 1 {
		if len(refs[0].lane) == 0 {
			return nil
		}
		return refreshQueueLane(tx, refs[0].kind, refs[0].lane, now)
	}
	unique := make(map[string]queueLaneRef, len(refs))
	for _, ref := range refs {
		if len(ref.lane) == 0 {
			continue
		}
		key := ref.kind + "\x00" + string(ref.lane)
		if _, ok := unique[key]; !ok {
			ref.lane = append([]byte(nil), ref.lane...)
			unique[key] = ref
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
		lane := update.LaneHMAC
		if len(lane) == 0 {
			var row inboxMessageRow
			if err := tx.Select("lane_hmac").Where("inbox_id = ?", update.InboxID).First(&row).Error; err != nil {
				return errors.New("eventstore: load inbox lane for scheduling failed")
			}
			lane = row.LaneHMAC
		}
		refs = append(refs, queueLaneRef{kind: inboxLaneKind, lane: lane})
	}
	for _, effect := range work.Effects {
		lane := effect.LaneHMAC
		if len(lane) == 0 {
			var row outboxEffectRow
			if err := tx.Select("lane_hmac").Where("effect_id = ?", effect.EffectID).First(&row).Error; err != nil {
				return errors.New("eventstore: load outbox lane for scheduling failed")
			}
			lane = row.LaneHMAC
		}
		refs = append(refs, queueLaneRef{kind: outboxLaneKind, lane: lane})
	}
	return refreshQueueLaneRefs(tx, refs, s.task5Now())
}

func createQueueLaneForMigration(tx *gorm.DB, kind string, lane []byte, now time.Time) error {
	var maximum uint64
	var query *gorm.DB
	switch kind {
	case inboxLaneKind:
		query = tx.Model(&inboxMessageRow{}).Select("COALESCE(MAX(ordering_sequence), 0)").Where("lane_hmac = ?", lane).Scan(&maximum)
	case outboxLaneKind:
		query = tx.Model(&outboxEffectRow{}).Select("COALESCE(MAX(ordering_sequence), 0)").Where("lane_hmac = ?", lane).Scan(&maximum)
	default:
		return errors.New("eventstore: invalid queue lane kind")
	}
	if query.Error != nil {
		return query.Error
	}
	next, err := nextVersion(maximum)
	if err != nil {
		return err
	}
	head := laneHeadRow{
		Kind: kind, LaneHMAC: append([]byte(nil), lane...), NextSequence: next,
		SchedulingVersion: 0, UpdatedAt: now,
	}
	return tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&head).Error
}

func ensureQueueLanesForMigration(tx *gorm.DB, kind string, lanes map[string][]byte, keys []string, now time.Time) error {
	if len(keys) == 0 {
		return nil
	}
	values := make([][]byte, len(keys))
	for i, key := range keys {
		values[i] = lanes[key]
	}
	var existing []laneHeadRow
	if err := tx.Select("lane_hmac").Where("kind = ? AND lane_hmac IN ?", kind, values).Find(&existing).Error; err != nil {
		return err
	}
	present := make(map[string]struct{}, len(existing))
	for i := range existing {
		present[string(existing[i].LaneHMAC)] = struct{}{}
	}
	for _, key := range keys {
		if _, ok := present[key]; ok {
			continue
		}
		if err := createQueueLaneForMigration(tx, kind, lanes[key], now); err != nil {
			return err
		}
	}
	return tx.Model(&laneHeadRow{}).
		Where("kind = ? AND lane_hmac IN ?", kind, values).
		UpdateColumn("scheduling_version", uint8(0)).Error
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
	return db.Select("inbox_id", "lane_hmac").
		Where("scheduling_version < ?", queueSchedulingVersion).
		Order("scheduling_version ASC, inbox_id ASC").
		Limit(queueSchedulingBatchSize).
		Find(rows)
}

func outboxSchedulingMigrationBatch(db *gorm.DB, rows *[]outboxEffectRow) *gorm.DB {
	return db.Select("effect_id", "lane_hmac").
		Where("scheduling_version < ?", queueSchedulingVersion).
		Order("scheduling_version ASC, effect_id ASC").
		Limit(queueSchedulingBatchSize).
		Find(rows)
}

func laneSchedulingMigrationBatch(db *gorm.DB, rows *[]laneHeadRow) *gorm.DB {
	return db.Where("scheduling_version < ?", queueSchedulingVersion).
		Order("scheduling_version ASC, kind ASC, lane_hmac ASC").
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
		lanes := make(map[string][]byte, len(rows))
		for i := range rows {
			ids[i] = rows[i].InboxID
			key := string(rows[i].LaneHMAC)
			if _, ok := lanes[key]; !ok {
				lanes[key] = rows[i].LaneHMAC
			}
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
			Updates(map[string]any{
				"payload_present":    gorm.Expr("CASE WHEN (payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0) OR (payload_nonce IS NOT NULL AND length(payload_nonce) > 0) THEN ? ELSE ? END", true, false),
				"scheduling_version": queueSchedulingVersion,
			})
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
		lanes := make(map[string][]byte, len(rows))
		for i := range rows {
			ids[i] = rows[i].EffectID
			key := string(rows[i].LaneHMAC)
			if _, ok := lanes[key]; !ok {
				lanes[key] = rows[i].LaneHMAC
			}
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
			Updates(map[string]any{
				"payload_present":    gorm.Expr("CASE WHEN (payload_ciphertext IS NOT NULL AND length(payload_ciphertext) > 0) OR (payload_nonce IS NOT NULL AND length(payload_nonce) > 0) THEN ? ELSE ? END", true, false),
				"scheduling_version": queueSchedulingVersion,
			})
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
			if err := refreshQueueLane(tx, heads[i].Kind, heads[i].LaneHMAC, now); err != nil {
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
	ready := base.Model(&laneHeadRow{}).Select("1").Where(
		"kind = ? AND ready_action IN (?, ?) AND ready_at IS NOT NULL AND ready_at <= ?",
		inboxLaneKind, queueReadyActionClaim, queueReadyActionRecover, now,
	).Limit(1)
	if err = base.Raw("SELECT EXISTS(?)", ready).Scan(&available).Error; err != nil || available {
		return available, err
	}
	var candidate task5ExpiredPayloadCandidate
	q := inboxExpiredPayloadCandidates(base, now, 1).Scan(&candidate)
	return q.RowsAffected != 0, q.Error
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

// HasOutboxWork includes retry, lease and TTL maintenance but never sends data.
// Results may become stale immediately; ClaimOutbox remains authoritative.
func (s *GORMStore) HasOutboxWork(ctx context.Context) (bool, error) {
	base, err := s.task5Base(ctx)
	if err != nil {
		return false, err
	}
	now := s.task5Now()
	var available bool
	ready := base.Model(&laneHeadRow{}).Select("1").Where(
		"kind = ? AND ready_action = ? AND ready_at IS NOT NULL AND ready_at <= ?",
		outboxLaneKind, queueReadyActionClaim, now,
	).Limit(1)
	if err = base.Raw("SELECT EXISTS(?)", ready).Scan(&available).Error; err != nil || available {
		return available, err
	}
	var candidate task5ExpiredPayloadCandidate
	q := outboxExpiredPayloadCandidates(base, now, 1).Scan(&candidate)
	return q.RowsAffected != 0, q.Error
}
