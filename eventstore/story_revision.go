package eventstore

import (
	"context"
	"errors"

	"gorm.io/gorm"
)

const storyLogRevisionCatalog = "story-log-scope/v1"

type storyLogRevisionGuardContextKey struct{}

type storyLogRevisionGuard struct {
	prepared map[string]struct{}
	advanced map[string]struct{}
}

func withStoryLogRevisionPlan(ctx context.Context, work UnitOfWork) context.Context {
	guard, _ := ctx.Value(storyLogRevisionGuardContextKey{}).(*storyLogRevisionGuard)
	if guard == nil {
		guard = &storyLogRevisionGuard{prepared: make(map[string]struct{}), advanced: make(map[string]struct{})}
		ctx = context.WithValue(ctx, storyLogRevisionGuardContextKey{}, guard)
	}
	for _, update := range work.CatalogUpdates {
		if update.Catalog == storyLogRevisionCatalog && update.Owner != "" {
			guard.prepared[update.Owner] = struct{}{}
		}
	}
	return ctx
}

func storyLogRevisionGuarded(ctx context.Context, scope string) bool {
	guard, _ := ctx.Value(storyLogRevisionGuardContextKey{}).(*storyLogRevisionGuard)
	if guard == nil {
		return false
	}
	if _, ok := guard.prepared[scope]; ok {
		return true
	}
	_, ok := guard.advanced[scope]
	return ok
}

func withStoryLogRevisionAdvanced(ctx context.Context, scope string) context.Context {
	guard, _ := ctx.Value(storyLogRevisionGuardContextKey{}).(*storyLogRevisionGuard)
	if guard == nil {
		guard = &storyLogRevisionGuard{
			prepared: make(map[string]struct{}),
			advanced: make(map[string]struct{}),
		}
		ctx = context.WithValue(ctx, storyLogRevisionGuardContextKey{}, guard)
	}
	guard.advanced[scope] = struct{}{}
	return ctx
}

func (s *GORMStore) storyLogScopeForUpdate(ctx context.Context, db *gorm.DB, update LogUpdate) (string, bool, error) {
	if update.Kind == logUpdateFinishIntent {
		var intent logArchiveIntentRow
		query := db.WithContext(ctx).Select("scope").Where("effect_id = ?", update.EffectID).Take(&intent)
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return "", false, nil
		}
		if query.Error != nil || intent.Scope == "" {
			return "", false, ErrParticipantFailure
		}
		return intent.Scope, true, nil
	}
	diceID, groupID := update.DiceID, update.GroupID
	if update.Kind == logUpdatePutIntent {
		diceID, groupID = update.Intent.Entry.DiceID, update.Intent.Entry.GroupID
	}
	scope, err := storyLogScope(diceID, groupID)
	return scope, err == nil, err
}

func (s *GORMStore) advanceStoryLogScopeRevisionTx(tx *gorm.DB, scope string) error {
	if tx == nil || scope == "" {
		return ErrParticipantFailure
	}
	resource := catalogResource(storyLogRevisionCatalog, scope)
	var head revisionHeadRow
	err := revisionQuery(locked(tx), resource.kind, resource.scope, resource.member).Take(&head).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		head = revisionRow(resource, 0, true, s.task5Now())
		if err := tx.Create(&head).Error; err != nil {
			return ErrParticipantFailure
		}
	} else if err != nil {
		return ErrParticipantFailure
	}
	next, err := nextVersion(head.Revision)
	if err != nil {
		return err
	}
	result := tx.Model(&revisionHeadRow{}).Where("id = ? AND revision = ?", head.ID, head.Revision).
		Updates(map[string]any{"revision": next, "present": true, "updated_at": s.task5Now()})
	if result.Error != nil {
		return ErrParticipantFailure
	}
	if result.RowsAffected != 1 {
		return ErrParticipantConflict
	}
	return nil
}

// GetStoryLogStateSnapshot returns the state and the exact scope revision read
// in the same database snapshot. Callers must add the expectation to the same
// execution owner that stages any resulting Story update.
func (s *GORMStore) GetStoryLogStateSnapshot(ctx context.Context, diceID, groupID string) (StoryLogState, CatalogReadExpectation, error) {
	return s.getStoryLogStateSnapshot(ctx, diceID, groupID)
}

func (s *GORMStore) getStoryLogStateSnapshot(ctx context.Context, diceID, groupID string) (StoryLogState, CatalogReadExpectation, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.requireReady(ctx); err != nil {
		return StoryLogState{}, CatalogReadExpectation{}, err
	}
	scopeKey, err := storyLogScope(diceID, groupID)
	if err != nil {
		return StoryLogState{}, CatalogReadExpectation{}, err
	}
	if err = s.ensureCatalogRevisionHead(ctx, storyLogRevisionCatalog, scopeKey); err != nil {
		return StoryLogState{}, CatalogReadExpectation{}, err
	}
	resource := catalogResource(storyLogRevisionCatalog, scopeKey)
	var row storyLogStateRow
	found := false
	expectation := CatalogReadExpectation{Catalog: storyLogRevisionCatalog, Owner: scopeKey}
	err = s.db.ReadSnapshot(ctx, func(tx *gorm.DB) error {
		if _, readErr := readDependencyControl(tx); readErr != nil {
			return readErr
		}
		var head revisionHeadRow
		if readErr := revisionQuery(tx, resource.kind, resource.scope, resource.member).First(&head).Error; readErr != nil {
			return ErrParticipantFailure
		}
		expectation.ExpectedRevision = head.Revision
		query := storyScopeQuery(tx, scopeKey).Take(&row)
		if errors.Is(query.Error, gorm.ErrRecordNotFound) {
			return nil
		}
		if query.Error != nil {
			return ErrParticipantFailure
		}
		found = true
		return nil
	})
	if err != nil {
		return StoryLogState{}, CatalogReadExpectation{}, err
	}
	if !found {
		return StoryLogState{DiceID: diceID, GroupID: groupID}, expectation, nil
	}
	if row.DiceID != diceID || row.GroupID != groupID {
		return StoryLogState{}, CatalogReadExpectation{}, ErrInvalidMetadata
	}
	return StoryLogState{DiceID: row.DiceID, GroupID: row.GroupID, SessionID: row.SessionID, Name: row.Name, On: row.On, BaselineSeq: row.BaselineSeq}, expectation, nil
}
