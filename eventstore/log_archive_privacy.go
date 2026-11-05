package eventstore

import (
	"context"
	"hash"

	"gorm.io/gorm"
)

// Archive rows use explicit dice/group ownership; the session id remains the
// public log identity and import identities remain source strings.
func visitPrivacyStoryRows[T any](tx *gorm.DB, req PrivacyDryRunRequest, key string, keyOf func(T) any, h hash.Hash, table string) (int64, error) {
	var cursor any
	var count int64
	for {
		query := storyOwnerQuery(tx, req.GroupID, req.DiceIDs).Order(key + " ASC").Limit(privacyReadPageSize)
		if cursor != nil {
			query = query.Where(key+" > ?", cursor)
		}
		var rows []T
		if err := query.Find(&rows).Error; err != nil {
			return 0, ErrParticipantFailure
		}
		for _, row := range rows {
			if err := writePrivacyRecord(h, table, row); err != nil {
				return 0, err
			}
			count++
		}
		if len(rows) < privacyReadPageSize {
			return count, nil
		}
		cursor = keyOf(rows[len(rows)-1])
	}
}
func (s *GORMStore) privacyStoryLogSelection(ctx context.Context, tx *gorm.DB, req PrivacyDryRunRequest, h hash.Hash, selection *privacySelection) error {
	tx = tx.WithContext(ctx)
	var err error
	counts := &selection.result.Counts
	counts.LogSessions, err = visitPrivacyStoryRows(tx, req, "id", func(row storyLogSessionRow) any { return row.ID }, h, tableStoryLogSessions)
	if err != nil {
		return err
	}
	counts.LogStates, err = visitPrivacyStoryRows(tx, req, "id", func(row storyLogStateRow) any { return row.ID }, h, tableStoryLogStates)
	if err != nil {
		return err
	}
	counts.LogEntries, err = visitPrivacyStoryRows(tx, req, "id", func(row logArchiveEntryRow) any { return row.ID }, h, tableStoryLogEntries)
	if err != nil {
		return err
	}
	counts.LogIntents, err = visitPrivacyStoryRows(tx, req, "effect_id", func(row logArchiveIntentRow) any { return row.EffectID }, h, tableStoryLogIntents)
	if err != nil {
		return err
	}
	counts.LogImports, err = visitPrivacyStoryRows(tx, req, "id", func(row storyLogImportRow) any { return row.ID }, h, tableStoryLogImports)
	if err != nil {
		return err
	}
	for _, diceID := range req.DiceIDs {
		scope, err := storyLogScope(diceID, req.GroupID)
		if err != nil {
			return err
		}
		selection.catalogs[catalogResource(storyLogRevisionCatalog, scope)] = struct{}{}
	}
	return nil
}
func privacyDeleteStoryLogs(tx *gorm.DB, req PrivacyDryRunRequest, counts *PrivacyCounts) error {
	for _, entry := range []struct {
		model any
		count *int64
	}{
		{&logArchiveEntryRow{}, &counts.LogEntries},
		{&logArchiveIntentRow{}, &counts.LogIntents},
		{&storyLogStateRow{}, &counts.LogStates},
		{&storyLogImportRow{}, &counts.LogImports},
		{&storyLogSessionRow{}, &counts.LogSessions},
	} {
		q := storyOwnerQuery(tx, req.GroupID, req.DiceIDs).Delete(entry.model)
		if q.Error != nil {
			return ErrParticipantFailure
		}
		*entry.count = q.RowsAffected
	}
	return nil
}
