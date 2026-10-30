package dice

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
)

type groupCardSQLiteKeySource struct{}

func (groupCardSQLiteKeySource) IndexRootID(context.Context) (string, error) {
	return "card-index-v1", nil
}
func (groupCardSQLiteKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}
func (groupCardSQLiteKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: "card-root-v1", Material: []byte("abcdefghijklmnopqrstuvwxyz123456")}, nil
}
func (groupCardSQLiteKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if id != "card-root-v1" {
		return nil, eventstore.ErrKeyUnavailable
	}
	return []byte("abcdefghijklmnopqrstuvwxyz123456"), nil
}

type groupCardSQLiteResolver struct{ snapshot messageflow.EndpointSnapshot }

func (r groupCardSQLiteResolver) Resolve(context.Context, adapterapi.EndpointID) (messageflow.EndpointSnapshot, error) {
	return r.snapshot, nil
}

type groupCardSQLiteIndexSigner struct{}

func (groupCardSQLiteIndexSigner) KeyedDigest(_ context.Context, domain string, parts ...string) ([]byte, string, error) {
	mac := hmac.New(sha256.New, []byte("01234567890123456789012345678901"))
	_, _ = mac.Write([]byte(domain))
	for _, part := range parts {
		_, _ = mac.Write([]byte(part))
	}
	return mac.Sum(nil), "card-index-v1", nil
}

func newGroupCardSQLiteContext(t *testing.T) (*eventstore.Database, *eventstore.GORMStore, *MsgContext) {
	t.Helper()
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/group-card.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	keys := groupCardSQLiteKeySource{}
	store := eventstore.NewStore(db, eventstore.WithKeySource(keys))
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "group-card-test-db",
		IndexRootID: "card-index-v1", EncryptionRootIDs: []string{"card-root-v1"},
		SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32),
		CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	endpointID := adapterapi.EndpointID("endpoint-card-test")
	resolver := groupCardSQLiteResolver{snapshot: messageflow.EndpointSnapshot{
		EndpointID: endpointID, AdapterKey: OnebotAdapterKey,
		DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected,
		Capabilities: adapterapi.CapabilityOutbound | adapterapi.CapabilityActions,
		Actions:      adapterapi.ActionSet(0).With(adapterapi.ActionKindSetGroupCard),
		IndexRootID:  "card-index-v1", IndexSigner: groupCardSQLiteIndexSigner{},
	}}
	service, err := messageflow.NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}

	dice := &Dice{Logger: logger.M(), DurableStore: store, Config: Config{}}
	session := &IMSession{Parent: dice}
	dice.ImSession = session
	endpoint := compatibilityCallbackEndpoint(session, messageflow.CallbackRequest{
		EndpointID: string(endpointID),
		Message:    adapterapi.InboundMessage{Platform: "QQ", Target: "QQ:9001"},
	})
	if endpoint.Adapter != nil {
		t.Fatal("compatibility callback endpoint unexpectedly has an adapter")
	}
	dice.OutboundBridge = NewDurableOutboundBridge(service, resolver, eventstore.UUIDGenerator{})
	return db, store, &MsgContext{
		Dice: dice, Session: session, EndPoint: endpoint,
		Group:          &GroupInfo{GroupID: "QQ-Group:2002"},
		Player:         &GroupPlayerInfo{UserID: "QQ:1001", Name: "Alice"},
		SystemTemplate: &GameSystemTemplate{},
	}
}

func groupCardSQLiteRowCounts(t *testing.T, db *eventstore.Database) (int64, int64, int64) {
	t.Helper()
	var events, operations, effects int64
	for _, item := range []struct {
		table string
		count *int64
	}{{"domain_events", &events}, {"operations", &operations}, {"outbox_effects", &effects}} {
		if err := db.GORM().Table(item.table).Count(item.count).Error; err != nil {
			t.Fatal(err)
		}
	}
	return events, operations, effects
}

func assertPersistedGroupCard(t *testing.T, db *eventstore.Database, store *eventstore.GORMStore, wantCard string) {
	t.Helper()
	var row struct {
		EffectID          string `gorm:"column:effect_id"`
		EndpointID        string `gorm:"column:endpoint_id"`
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
		EncryptionKeyID   string `gorm:"column:encryption_key_id"`
	}
	if err := db.GORM().Table("outbox_effects").Take(&row).Error; err != nil {
		t.Fatal(err)
	}
	plain, err := store.DecryptBound(context.Background(), "outbox/v1", row.EffectID, row.EndpointID, 1, row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Effect adapterapi.OutboundEffect `json:"effect"`
	}
	if err := json.Unmarshal(plain, &wire); err != nil {
		t.Fatal(err)
	}
	payload := wire.Effect.Payload
	if wire.Effect.Kind != adapterapi.EffectKindAction || payload.Kind != adapterapi.EffectPayloadSetGroupCard || payload.Target.Kind != adapterapi.TargetGroup || payload.Target.Conversation != "QQ-Group:2002" || payload.Target.Member != "QQ:1001" || payload.Card != wantCard {
		t.Fatalf("persisted card effect = %#v", wire.Effect)
	}
}

func TestSetPlayerGroupCardByTemplatePersistsDurableActionWithoutAdapter(t *testing.T) {
	for _, test := range []struct {
		name, template, card string
	}{
		{name: "evaluated card", template: "Card {1+1}", card: "Card 2"},
		{name: "clear card", template: "", card: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, store, ctx := newGroupCardSQLiteContext(t)
			if ctx.EndPoint.Adapter != nil {
				t.Fatal("fixture must model the adapter-free event-sourced endpoint")
			}
			text, err := SetPlayerGroupCardByTemplate(ctx, test.template)
			if err != nil || text != test.card {
				t.Fatalf("SetPlayerGroupCardByTemplate() = %q, %v", text, err)
			}
			if events, operations, effects := groupCardSQLiteRowCounts(t, db); events != 1 || operations != 1 || effects != 1 {
				t.Fatalf("durable participants = events:%d operations:%d effects:%d", events, operations, effects)
			}
			assertPersistedGroupCard(t, db, store, test.card)
		})
	}
}

func TestSetPlayerGroupCardByTemplateStagesCallbackActionUntilCommit(t *testing.T) {
	db, store, ctx := newGroupCardSQLiteContext(t)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	ctx.callbackTransaction = &DurableCallbackTransaction{collector: collector}
	text, err := SetPlayerGroupCardByTemplate(ctx, "Card {1+1}")
	if err != nil || text != "Card 2" {
		t.Fatalf("SetPlayerGroupCardByTemplate() = %q, %v", text, err)
	}
	if events, operations, effects := groupCardSQLiteRowCounts(t, db); events != 0 || operations != 0 || effects != 0 {
		t.Fatalf("callback persisted before its UnitOfWork commit: events:%d operations:%d effects:%d", events, operations, effects)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Operations) != 1 || len(work.Effects) != 1 {
		t.Fatalf("prepared callback action participants = %#v", work)
	}
	if _, err := store.Commit(context.Background(), work); err != nil {
		t.Fatal(err)
	}
	if events, operations, effects := groupCardSQLiteRowCounts(t, db); events != 1 || operations != 1 || effects != 1 {
		t.Fatalf("committed callback participants = events:%d operations:%d effects:%d", events, operations, effects)
	}
	assertPersistedGroupCard(t, db, store, "Card 2")
}

func TestSetPlayerGroupCardByTemplateUsesCardInCallbackIdentity(t *testing.T) {
	db, store, ctx := newGroupCardSQLiteContext(t)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	ctx.callbackTransaction = &DurableCallbackTransaction{collector: collector}
	for _, card := range []string{"First card", "Second card"} {
		if text, err := SetPlayerGroupCardByTemplate(ctx, card); err != nil || text != card {
			t.Fatalf("SetPlayerGroupCardByTemplate(%q) = %q, %v", card, text, err)
		}
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatalf("build callback UnitOfWork: %v", err)
	}
	if len(work.Operations) != 2 || len(work.Effects) != 2 {
		t.Fatalf("prepared callback actions = operations:%d effects:%d, want 2 each", len(work.Operations), len(work.Effects))
	}
	if _, err := store.Commit(context.Background(), work); err != nil {
		t.Fatalf("commit callback actions: %v", err)
	}
	if _, operations, effects := groupCardSQLiteRowCounts(t, db); operations != 2 || effects != 2 {
		t.Fatalf("committed callback actions = operations:%d effects:%d, want 2 each", operations, effects)
	}
}

func TestSetPlayerGroupCardByTemplateCallbackCommitFailureLeavesNoIntent(t *testing.T) {
	db, store, ctx := newGroupCardSQLiteContext(t)
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	ctx.callbackTransaction = &DurableCallbackTransaction{collector: collector}
	if _, err := SetPlayerGroupCardByTemplate(ctx, "Card {1+1}"); err != nil {
		t.Fatal(err)
	}
	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Streams) != 1 || len(work.Effects) != 1 {
		t.Fatalf("prepared callback work = %#v", work)
	}
	// Force the callback's atomic UnitOfWork to conflict before the effect can commit.
	work.Streams[0].ExpectedVersion = 1
	if _, err := store.Commit(context.Background(), work); err == nil {
		t.Fatal("callback UnitOfWork unexpectedly committed")
	}
	if events, operations, effects := groupCardSQLiteRowCounts(t, db); events != 0 || operations != 0 || effects != 0 {
		t.Fatalf("failed callback left durable participants: events:%d operations:%d effects:%d", events, operations, effects)
	}
}

func TestSetPlayerGroupCardByTemplateRejectsInvalidAndOverlongBeforeSubmitting(t *testing.T) {
	for _, test := range []struct {
		name string
		tmpl string
	}{
		{name: "invalid template", tmpl: "{1 + }"},
		{name: "QQ card over limit", tmpl: strings.Repeat("x", 60)},
	} {
		t.Run(test.name, func(t *testing.T) {
			db, _, ctx := newGroupCardSQLiteContext(t)
			if _, err := SetPlayerGroupCardByTemplate(ctx, test.tmpl); err == nil {
				t.Fatal("invalid or overlong template unexpectedly succeeded")
			}
			if events, operations, effects := groupCardSQLiteRowCounts(t, db); events != 0 || operations != 0 || effects != 0 {
				t.Fatalf("rejected template created durable participants: events:%d operations:%d effects:%d", events, operations, effects)
			}
		})
	}
}
