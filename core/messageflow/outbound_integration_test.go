package messageflow

import (
	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

type integrationKeySource struct {
	indexID string
	index   []byte
	rootID  string
	root    []byte
}

func (s integrationKeySource) IndexRootID(context.Context) (string, error) { return s.indexID, nil }
func (s integrationKeySource) IndexRootMaterial(context.Context) ([]byte, error) {
	return append([]byte(nil), s.index...), nil
}
func (s integrationKeySource) CurrentEncryptionRoot(context.Context) (eventstore.EncryptionRoot, error) {
	return eventstore.EncryptionRoot{ID: s.rootID, Material: append([]byte(nil), s.root...)}, nil
}
func (s integrationKeySource) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	if id != s.rootID {
		return nil, eventstore.ErrKeyUnavailable
	}
	return append([]byte(nil), s.root...), nil
}

func TestOutboundSubmitRealSQLiteA6AtomicParticipants(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/outbound.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	source := integrationKeySource{indexID: "index-v1", index: []byte("01234567890123456789012345678901"), rootID: "root-v1", root: []byte("abcdefghijklmnopqrstuvwxyz123456")}
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: source.indexID, EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	root := source.index
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Minute).UTC()
	effect.Lane, _ = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1)
	resolver := testResolver{snap: EndpointSnapshot{EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: source.indexID, IndexSigner: store}}
	resolver.snap.Capabilities = adapterapi.CapabilityOutbound | adapterapi.CapabilityRichMessages | adapterapi.CapabilityArtifacts
	svc, err := NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	result, err := svc.Submit(ctx, SubmitRequest{Effect: effect, CommandID: "sqlite-command", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	if result.EffectID == "" || result.OperationID == "" {
		t.Fatalf("result=%#v", result)
	}
	events, err := store.Load(ctx, eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: result.EffectID}, 0)
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), err)
	}
	if strings.Contains(string(events[0].Payload), "hello") || strings.Contains(string(events[0].Payload), "person-1") {
		t.Fatal("immutable event leaked payload")
	}
	segments := effect
	segments.ID = "effect-segments"
	segments.OperationID = "operation-segments"
	segments.CorrelationID = "corr-segments"
	segments.CausationID = "cause-segments"
	segments.Payload = adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSegments, Target: effect.Payload.Target, Segments: []adapterapi.MessageSegment{{Kind: "text", Text: "segment-secret"}, {Kind: "file", Artifact: &adapterapi.ArtifactInput{ID: "artifact-1", ContentType: "text/plain", Filename: "file.txt"}}}}
	segments.RequiredCapabilities = adapterapi.CapabilityOutbound | adapterapi.CapabilityRichMessages | adapterapi.CapabilityArtifacts
	segments.Lane, _ = adapterapi.NewLaneMetadata(segments.EndpointID, segments.Payload.Target, root, 2)
	segmentResult, err := svc.Submit(ctx, SubmitRequest{Effect: segments, CommandID: "segments-command", PrincipalID: "principal-a"})
	if err != nil {
		t.Fatal(err)
	}
	var row struct {
		PayloadCiphertext []byte `gorm:"column:payload_ciphertext"`
		PayloadNonce      []byte `gorm:"column:payload_nonce"`
		EncryptionKeyID   string `gorm:"column:encryption_key_id"`
	}
	if err := db.GORM().Table("outbox_effects").Where("effect_id = ?", segmentResult.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	plain, err := store.DecryptBound(ctx, "outbox/v1", segmentResult.EffectID, string(segments.EndpointID), 1, row.PayloadCiphertext, row.PayloadNonce, row.EncryptionKeyID)
	if err != nil {
		t.Fatal(err)
	}
	var wire effectWire
	if err := json.Unmarshal(plain, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Effect.Payload.Segments) != 2 || wire.Effect.Payload.Segments[0].Text != "segment-secret" {
		t.Fatalf("segments payload=%#v", wire.Effect.Payload)
	}
	second := wire.Effect.Payload.Segments[1]
	if second.Artifact == nil || second.Artifact.ID != "artifact-1" || second.Artifact.ContentType != "text/plain" || second.Artifact.Filename != "file.txt" {
		t.Fatalf("artifact segment=%#v", second)
	}
	segmentEvent, err := store.Load(ctx, eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: segmentResult.EffectID}, 0)
	if err != nil || len(segmentEvent) != 1 {
		t.Fatalf("segment events=%d err=%v", len(segmentEvent), err)
	}
	if strings.Contains(string(segmentEvent[0].Payload), "segment-secret") || strings.Contains(string(segmentEvent[0].Payload), "file.txt") {
		t.Fatal("segment event leaked payload")
	}
	concurrent := effect
	concurrent.ID = "effect-concurrent"
	concurrent.OperationID = "operation-concurrent"
	concurrent.CorrelationID = "corr-concurrent"
	concurrent.CausationID = "cause-concurrent"
	concurrent.Lane, _ = adapterapi.NewLaneMetadata(concurrent.EndpointID, concurrent.Payload.Target, root, 3)
	svcA, err := NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	svcB, err := NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	var concurrentBeforeEvents, concurrentBeforeOps, concurrentBeforeOutbox, concurrentBeforeLanes int64
	for _, item := range []struct {
		name  string
		value *int64
	}{{"domain_events", &concurrentBeforeEvents}, {"operations", &concurrentBeforeOps}, {"outbox_effects", &concurrentBeforeOutbox}, {"lane_heads", &concurrentBeforeLanes}} {
		if err := db.GORM().Table(item.name).Count(item.value).Error; err != nil {
			t.Fatal(err)
		}
	}
	type concurrentResult struct {
		value SubmitResult
		err   error
	}
	var wg sync.WaitGroup
	results := make(chan concurrentResult, 2)
	for _, candidate := range []*OutboundService{svcA, svcB} {
		wg.Add(1)
		go func(service *OutboundService) {
			defer wg.Done()
			value, callErr := service.Submit(ctx, SubmitRequest{Effect: concurrent, CommandID: "concurrent-command", PrincipalID: "principal-a"})
			results <- concurrentResult{value, callErr}
		}(candidate)
	}
	wg.Wait()
	close(results)
	var concurrentValues []SubmitResult
	for item := range results {
		if item.err != nil {
			t.Fatalf("concurrent submit err=%v", item.err)
		}
		concurrentValues = append(concurrentValues, item.value)
	}
	if len(concurrentValues) != 2 || concurrentValues[0].OperationID != concurrentValues[1].OperationID || concurrentValues[0].EffectID != concurrentValues[1].EffectID || string(concurrentValues[0].Digest) != string(concurrentValues[1].Digest) {
		t.Fatalf("concurrent results=%#v", concurrentValues)
	}
	var concurrentAfterEvents, concurrentAfterOps, concurrentAfterOutbox, concurrentAfterLanes int64
	for _, item := range []struct {
		name  string
		value *int64
	}{{"domain_events", &concurrentAfterEvents}, {"operations", &concurrentAfterOps}, {"outbox_effects", &concurrentAfterOutbox}, {"lane_heads", &concurrentAfterLanes}} {
		if err := db.GORM().Table(item.name).Count(item.value).Error; err != nil {
			t.Fatal(err)
		}
	}
	if concurrentAfterEvents-concurrentBeforeEvents != 1 || concurrentAfterOps-concurrentBeforeOps != 1 || concurrentAfterOutbox-concurrentBeforeOutbox != 1 {
		t.Fatalf("concurrent durable increments events=%d ops=%d outbox=%d", concurrentAfterEvents-concurrentBeforeEvents, concurrentAfterOps-concurrentBeforeOps, concurrentAfterOutbox-concurrentBeforeOutbox)
	}
	// All same-target requests reuse one persisted lane head.
	if concurrentAfterLanes-concurrentBeforeLanes != 0 {
		t.Fatalf("same-target lane head count changed by %d", concurrentAfterLanes-concurrentBeforeLanes)
	}
	replayEffect := effect
	replayEffect.ID = "effect-replay"
	replayEffect.OperationID = "operation-replay"
	replayEffect.Deadline = effect.Deadline.Add(time.Hour)
	replayEffect.CorrelationID = "corr-replay"
	replayEffect.CausationID = "cause-replay"
	replayEffect.Lane, err = adapterapi.NewLaneMetadata(replayEffect.EndpointID, replayEffect.Payload.Target, root, 2)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewOutboundService(store, resolver, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := replay.Submit(ctx, SubmitRequest{Effect: replayEffect, CommandID: "sqlite-command", PrincipalID: "principal-a"})
	if err != nil || !repeated.Deduplicated || repeated.EffectID != result.EffectID {
		t.Fatalf("durable replay=%#v err=%v", repeated, err)
	}
	effect.Payload.Text = "changed"
	if _, err := replay.Submit(ctx, SubmitRequest{Effect: effect, CommandID: "sqlite-command", PrincipalID: "principal-a"}); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed digest err=%v", err)
	}
	after, err := store.Load(ctx, eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: result.EffectID}, 0)
	if err != nil || len(after) != 1 {
		t.Fatalf("rollback/event count=%d err=%v", len(after), err)
	}
	var beforeEvents, beforeOps, beforeOutbox, beforeLanes int64
	for _, item := range []struct {
		name  string
		value *int64
	}{{"domain_events", &beforeEvents}, {"operations", &beforeOps}, {"outbox_effects", &beforeOutbox}, {"lane_heads", &beforeLanes}} {
		if err := db.GORM().Table(item.name).Count(item.value).Error; err != nil {
			t.Fatal(err)
		}
	}
	conflict := effect
	if _, err := replay.Submit(ctx, SubmitRequest{Effect: conflict, CommandID: "participant-conflict", PrincipalID: "principal-a"}); err == nil {
		t.Fatal("participant conflict committed")
	}
	var afterEvents, afterOps, afterOutbox, afterLanes int64
	for _, item := range []struct {
		name  string
		value *int64
	}{{"domain_events", &afterEvents}, {"operations", &afterOps}, {"outbox_effects", &afterOutbox}, {"lane_heads", &afterLanes}} {
		if err := db.GORM().Table(item.name).Count(item.value).Error; err != nil {
			t.Fatal(err)
		}
	}
	if beforeEvents != afterEvents || beforeOps != afterOps || beforeOutbox != afterOutbox || beforeLanes != afterLanes {
		t.Fatalf("rollback changed counts events=%d/%d ops=%d/%d outbox=%d/%d lanes=%d/%d", beforeEvents, afterEvents, beforeOps, afterOps, beforeOutbox, afterOutbox, beforeLanes, afterLanes)
	}
}
