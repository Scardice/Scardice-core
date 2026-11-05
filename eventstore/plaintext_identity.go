package eventstore

import (
	"context"
	"errors"
	"reflect"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/schema"
)

// SQL text cannot represent every opaque plugin key (notably PostgreSQL NUL).
// These fields therefore bind their unchanged string bytes to native binary
// columns. This is not a payload transform: no prefix, escaping or framing is added.
type rawStringSerializer struct{}

//nolint:gochecknoinits // GORM's package-global serializer registry must be populated before schema parsing.
func init() { schema.RegisterSerializer("raw_string", rawStringSerializer{}) }
func (rawStringSerializer) Scan(ctx context.Context, field *schema.Field, dst reflect.Value, value any) error {
	switch v := value.(type) {
	case nil:
		return field.Set(ctx, dst, "")
	case []byte:
		return field.Set(ctx, dst, string(v))
	case string:
		return field.Set(ctx, dst, v)
	default:
		return ErrInvalidMetadata
	}
}
func (rawStringSerializer) Value(_ context.Context, _ *schema.Field, _ reflect.Value, value any) (any, error) {
	v, ok := value.(string)
	if !ok {
		return nil, ErrInvalidMetadata
	}
	return []byte(v), nil
}
func rawStringQuery(db *gorm.DB, column, value string) *gorm.DB {
	return db.Where(clause.Eq{Column: clause.Column{Name: column}, Value: []byte(value)})
}
func textStringQuery(db *gorm.DB, column, value string) *gorm.DB {
	if db.Name() == "mysql" {
		return db.Where(clause.Expr{SQL: "BINARY ? = ?", Vars: []any{clause.Column{Name: column}, []byte(value)}})
	}
	if db.Name() == "postgres" {
		return db.Where(clause.Expr{SQL: "convert_to(?, 'UTF8') = ?", Vars: []any{clause.Column{Name: column}, []byte(value)}})
	}
	return db.Where(clause.Eq{Column: clause.Column{Name: column}, Value: value})
}

type revisionLookup struct{ digest, kind, scope, member []byte }

func revisionLookupFor(key revisionResourceKey) revisionLookup {
	return revisionLookup{digest: Digest("revision-lookup/v1", key.kind, key.scope, key.member), kind: []byte(key.kind), scope: []byte(key.scope), member: []byte(key.member)}
}
func (lookup revisionLookup) query(db *gorm.DB) *gorm.DB {
	return db.Where("lookup_digest = ?", lookup.digest).
		Where(clause.Eq{Column: clause.Column{Name: "kind"}, Value: lookup.kind}).
		Where(clause.Eq{Column: clause.Column{Name: "scope"}, Value: lookup.scope}).
		Where(clause.Eq{Column: clause.Column{Name: "member"}, Value: lookup.member})
}
func revisionQuery(db *gorm.DB, kind, scope, member string) *gorm.DB {
	return revisionLookupFor(revisionResourceKey{kind: kind, scope: scope, member: member}).query(db)
}
func (row *revisionHeadRow) BeforeCreate(_ *gorm.DB) error {
	if len(row.LookupDigest) == 0 {
		row.LookupDigest = Digest("revision-lookup/v1", row.Kind, row.Scope, row.Member)
	}
	return nil
}
func pluginQuery(db *gorm.DB, extension, key string) *gorm.DB {
	return rawStringQuery(rawStringQuery(db, "extension_id", extension), "key", key)
}
func secretOwnerQuery(db *gorm.DB, ref, endpoint, adapter string) *gorm.DB {
	return rawStringQuery(rawStringQuery(rawStringQuery(db, "secret_ref", ref), "endpoint_id", endpoint), "adapter_id", adapter)
}
func inboxProviderQuery(db *gorm.DB, endpoint, provider string) *gorm.DB {
	return rawStringQuery(rawStringQuery(db.Where("dedupe_lookup = ?", Digest("inbox-provider-lookup/v1", endpoint, provider)), "endpoint_id", endpoint), "provider_event_id", provider)
}
func executionQuery(db *gorm.DB, identity string) *gorm.DB {
	return rawStringQuery(db, "identity", identity)
}

// A lookup digest only narrows candidates. The raw identity is always compared
// exactly, and the nonunique index permits different identities to collide.
func laneQuery(db *gorm.DB, kind, lane string) *gorm.DB {
	return textStringQuery(db.Where("kind = ? AND lookup_digest = ?", kind, Digest("lane-lookup/v1", lane)), "lane", lane)
}
func (row *laneHeadRow) BeforeCreate(_ *gorm.DB) error {
	row.LookupDigest = Digest("lane-lookup/v1", row.Lane)
	return nil
}
func (row *inboxMessageRow) BeforeCreate(tx *gorm.DB) error {
	row.DedupeLookup = Digest("inbox-provider-lookup/v1", row.EndpointID, row.ProviderEventKey)
	if row.Lane == "" {
		return ErrInvalidMetadata
	}
	if row.LaneID == 0 {
		head, err := seedQueueLane(tx, inboxLaneKind, row.Lane, row.OrderingSequence, valueTime(row.CompletedAt))
		if err != nil {
			return err
		}
		row.LaneID = head.ID
	}
	return nil
}
func (row *outboxEffectRow) BeforeCreate(tx *gorm.DB) error {
	if row.Lane == "" {
		return ErrInvalidMetadata
	}
	if row.LaneID == 0 {
		head, err := seedQueueLane(tx, outboxLaneKind, row.Lane, row.OrderingSequence, row.CreatedAt)
		if err != nil {
			return err
		}
		row.LaneID = head.ID
	}
	return nil
}
func seedQueueLane(tx *gorm.DB, kind, lane string, sequence uint64, now time.Time) (laneHeadRow, error) {
	head, err := task5Lane(tx, kind, lane, now)
	if err != nil {
		return laneHeadRow{}, err
	}
	if sequence >= head.NextSequence {
		next, err := nextVersion(sequence)
		if err != nil {
			return laneHeadRow{}, err
		}
		if err := tx.Model(&laneHeadRow{}).Where("id = ?", head.ID).Update("next_sequence", next).Error; err != nil {
			return laneHeadRow{}, err
		}
		head.NextSequence = next
	}
	return head, nil
}
func rawStrings(values []string) [][]byte {
	out := make([][]byte, len(values))
	for i, value := range values {
		out[i] = []byte(value)
	}
	return out
}
func storyImportsByIdentities(db *gorm.DB, values []string) *gorm.DB {
	digests := make([][]byte, len(values))
	for i, value := range values {
		digests[i] = Digest("story-import-lookup/v1", value)
	}
	return db.Where("identity_lookup IN ?", digests).Where("identity IN ?", rawStrings(values))
}
func storyOwnerQuery(db *gorm.DB, groupID string, diceIDs []string) *gorm.DB {
	scopes := make([]string, len(diceIDs))
	digests := make([][]byte, len(diceIDs))
	for i, dice := range diceIDs {
		scopes[i] = privacyCanonical(dice, groupID)
		digests[i] = Digest("story-scope-lookup/v1", scopes[i])
	}
	return db.Where("scope_lookup IN ?", digests).Where("scope IN ?", rawStrings(scopes))
}
func storyDiceQuery(db *gorm.DB, diceID string) *gorm.DB {
	return rawStringQuery(db.Where("dice_lookup = ?", Digest("story-dice-lookup/v1", diceID)), "dice_id", diceID)
}
func orderPluginKeys(db *gorm.DB) *gorm.DB {
	return db.Order(clause.OrderByColumn{Column: clause.Column{Name: "key"}})
}
func storyScopeQuery(db *gorm.DB, scope string) *gorm.DB {
	return rawStringQuery(db.Where("scope_lookup = ?", Digest("story-scope-lookup/v1", scope)), "scope", scope)
}
func storySessionQuery(db *gorm.DB, scope, name string) *gorm.DB {
	return rawStringQuery(rawStringQuery(db.Where("lookup_digest = ?", Digest("story-session-lookup/v1", scope, name)), "scope", scope), "name", name)
}
func (row *storyLogSessionRow) BeforeCreate(_ *gorm.DB) error {
	row.DiceLookup = Digest("story-dice-lookup/v1", row.DiceID)
	row.ScopeLookup = Digest("story-scope-lookup/v1", row.Scope)
	row.LookupDigest = Digest("story-session-lookup/v1", row.Scope, row.Name)
	return nil
}
func (row *storyLogStateRow) BeforeCreate(_ *gorm.DB) error {
	row.ScopeLookup = Digest("story-scope-lookup/v1", row.Scope)
	return nil
}
func (row *logArchiveEntryRow) BeforeCreate(_ *gorm.DB) error {
	row.ScopeLookup = Digest("story-scope-lookup/v1", row.Scope)
	row.RawMsgLookup = Digest("story-raw-lookup/v1", row.RawMsgID)
	return nil
}
func (row *logArchiveIntentRow) BeforeCreate(_ *gorm.DB) error {
	row.ScopeLookup = Digest("story-scope-lookup/v1", row.Scope)
	return nil
}
func (row *storyLogImportRow) BeforeCreate(_ *gorm.DB) error {
	row.DiceLookup = Digest("story-dice-lookup/v1", row.DiceID)
	row.ScopeLookup = Digest("story-scope-lookup/v1", row.Scope)
	row.IdentityLookup = Digest("story-import-lookup/v1", row.Identity)
	return nil
}

func findLaneID(tx *gorm.DB, kind, lane string) (uint64, error) {
	var head laneHeadRow
	if err := laneQuery(tx, kind, lane).Select("id").Take(&head).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	return head.ID, nil
}
