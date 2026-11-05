package messageflow

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

func TestOutboundSubmitRealSQLiteAtomicParticipants(t *testing.T) {
	ctx := context.Background()
	db, submitErr := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/outbound.db"})
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	defer db.Close()
	store := eventstore.NewStore(db)
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 2, DatabaseIdentity: "db-1", CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	effect := testEffect()
	effect.Deadline = time.Now().Add(time.Minute).UTC()
	effect.Lane, _ = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, 1)
	resolver := testResolver{snap: EndpointSnapshot{EndpointID: effect.EndpointID, DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage)}}
	resolver.snap.Capabilities = adapterapi.CapabilityOutbound | adapterapi.CapabilityRichMessages | adapterapi.CapabilityArtifacts
	svc, submitErr := NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	result, submitErr := svc.Submit(ctx, SubmitRequest{Effect: effect, CommandID: "sqlite-command", PrincipalID: "principal-a"})
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	if result.EffectID == "" || result.OperationID == "" {
		t.Fatalf("result=%#v", result)
	}
	events, submitErr := store.Load(ctx, eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: result.EffectID}, 0)
	if submitErr != nil || len(events) != 1 {
		t.Fatalf("events=%d err=%v", len(events), submitErr)
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
	segments.Lane, _ = adapterapi.NewLaneMetadata(segments.EndpointID, segments.Payload.Target, 2)
	segmentResult, submitErr := svc.Submit(ctx, SubmitRequest{Effect: segments, CommandID: "segments-command", PrincipalID: "principal-a"})
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	var row struct {
		Payload []byte
		Lane    string
		Subject string
	}
	if err := db.GORM().Table("outbox_effects").Where("effect_id = ?", segmentResult.EffectID).First(&row).Error; err != nil {
		t.Fatal(err)
	}
	if row.Lane != `["endpoint-1","person","person-1"]` || row.Subject != "person-1" {
		t.Fatalf("stored effect lane=%q subject=%q", row.Lane, row.Subject)
	}
	var wire effectWire
	if err := json.Unmarshal(row.Payload, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Effect.Payload.Segments) != 2 || wire.Effect.Payload.Segments[0].Text != "segment-secret" {
		t.Fatalf("segments payload=%#v", wire.Effect.Payload)
	}
	second := wire.Effect.Payload.Segments[1]
	if second.Artifact == nil || second.Artifact.ID != "artifact-1" || second.Artifact.ContentType != "text/plain" || second.Artifact.Filename != "file.txt" {
		t.Fatalf("artifact segment=%#v", second)
	}
	segmentEvent, submitErr := store.Load(ctx, eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: segmentResult.EffectID}, 0)
	if submitErr != nil || len(segmentEvent) != 1 {
		t.Fatalf("segment events=%d err=%v", len(segmentEvent), submitErr)
	}
	if strings.Contains(string(segmentEvent[0].Payload), "segment-secret") || strings.Contains(string(segmentEvent[0].Payload), "file.txt") {
		t.Fatal("segment event leaked payload")
	}
	concurrent := effect
	concurrent.ID = "effect-concurrent"
	concurrent.OperationID = "operation-concurrent"
	concurrent.CorrelationID = "corr-concurrent"
	concurrent.CausationID = "cause-concurrent"
	concurrent.Lane, _ = adapterapi.NewLaneMetadata(concurrent.EndpointID, concurrent.Payload.Target, 3)
	svcA, submitErr := NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	svcB, submitErr := NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if submitErr != nil {
		t.Fatal(submitErr)
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
	results := make(chan concurrentResult, 3)
	for _, candidate := range []*OutboundService{svcA, svcA, svcB} {
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
	deduplicated := 0
	for item := range results {
		if item.err != nil {
			t.Fatalf("concurrent submit err=%v", item.err)
		}
		if item.value.Deduplicated {
			deduplicated++
		}
		concurrentValues = append(concurrentValues, item.value)
	}
	if len(concurrentValues) != 3 {
		t.Fatalf("concurrent results=%#v", concurrentValues)
	}
	for _, value := range concurrentValues[1:] {
		if value.OperationID != concurrentValues[0].OperationID || value.EffectID != concurrentValues[0].EffectID || string(value.Digest) != string(concurrentValues[0].Digest) {
			t.Fatalf("concurrent results=%#v", concurrentValues)
		}
	}
	if deduplicated != 2 {
		t.Fatalf("deduplicated submissions=%d results=%#v", deduplicated, concurrentValues)
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
	replayEffect.Lane, submitErr = adapterapi.NewLaneMetadata(replayEffect.EndpointID, replayEffect.Payload.Target, 2)
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	replay, submitErr := NewOutboundService(store, resolver, eventstore.UUIDGenerator{})
	if submitErr != nil {
		t.Fatal(submitErr)
	}
	repeated, submitErr := replay.Submit(ctx, SubmitRequest{Effect: replayEffect, CommandID: "sqlite-command", PrincipalID: "principal-a"})
	if submitErr != nil || !repeated.Deduplicated || repeated.EffectID != result.EffectID {
		t.Fatalf("durable replay=%#v err=%v", repeated, submitErr)
	}
	effect.Payload.Text = "changed"
	if _, err := replay.Submit(ctx, SubmitRequest{Effect: effect, CommandID: "sqlite-command", PrincipalID: "principal-a"}); !errors.Is(err, ErrCommandConflict) {
		t.Fatalf("changed digest err=%v", err)
	}
	after, submitErr := store.Load(ctx, eventstore.StreamID{AggregateType: "outbound-effect", AggregateID: result.EffectID}, 0)
	if submitErr != nil || len(after) != 1 {
		t.Fatalf("rollback/event count=%d err=%v", len(after), submitErr)
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
