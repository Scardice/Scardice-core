package eventstore

import (
	"context"
	"time"

	"gorm.io/gorm"
)

const terminalInboxRetention = 30 * 24 * time.Hour

// DeleteExpiredTerminalInbox removes whole terminal rows only after their
// completed-at retention period. Ambiguous rows remain available for manual
// resolution throughout that period; no terminal transition scrubs its body.
func (s *GORMStore) DeleteExpiredTerminalInbox(ctx context.Context) (int64, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return 0, err
	}
	now := s.task5Now()
	cutoff := now.Add(-terminalInboxRetention)
	terminal := []string{InboxStatusConfirmedConsumed, InboxStatusFailed, InboxStatusSkipped, InboxStatusAmbiguous}
	var deleted int64
	err := s.db.GORM().WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := s.lockMutationPublication(ctx, tx); err != nil {
			return err
		}
		var lanes []queueLaneRef
		for {
			var rows []struct {
				InboxID string
				Lane    string
			}
			if err := tx.Model(&inboxMessageRow{}).Select("inbox_id", "lane").Where("status IN ? AND completed_at < ?", terminal, cutoff).Order("completed_at ASC, inbox_id ASC").Limit(queueSchedulingBatchSize).Find(&rows).Error; err != nil {
				return ErrParticipantFailure
			}
			if len(rows) == 0 {
				break
			}
			ids := make([]string, len(rows))
			for i, row := range rows {
				ids[i] = row.InboxID
				lanes = append(lanes, queueLaneRef{kind: inboxLaneKind, lane: row.Lane})
			}
			result := tx.Where("inbox_id IN ? AND status IN ? AND completed_at < ?", ids, terminal, cutoff).Delete(&inboxMessageRow{})
			if result.Error != nil {
				return ErrParticipantFailure
			}
			if result.RowsAffected != int64(len(rows)) {
				return ErrParticipantConflict
			}
			deleted += result.RowsAffected
		}
		return refreshQueueLaneRefs(tx, lanes, now)
	})
	if err != nil {
		return 0, err
	}
	if deleted != 0 {
		s.signalInboxWork()
	}
	return deleted, nil
}
