package dice

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

type jsMutationCryptoFake struct{ calls []string }
func (f *jsMutationCryptoFake) KeyedDigest(_ context.Context, domain string, parts ...string) ([]byte, string, error) {
	f.calls = append(f.calls, domain)
	return []byte(strings.Repeat("i", 32)), "key-id", nil
}
func (f *jsMutationCryptoFake) EncryptBound(_ context.Context, domain, identity, owner string, version uint64, plain []byte) ([]byte, []byte, string, error) {
	f.calls = append(f.calls, domain+":"+identity+":"+owner)
	return append([]byte("cipher:"), plain...), []byte("012345678901"), "key-id", nil
}

type jsMutationBackendFake struct {
	items map[string]eventstore.PluginKVItem
	work  []eventstore.UnitOfWork
	fail  error
}
func (f *jsMutationBackendFake) Commit(_ context.Context, w eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if f.fail != nil {
		return eventstore.CommitResult{}, f.fail
	}
	f.work = append(f.work, w)
	return eventstore.CommitResult{}, nil
}
func (f *jsMutationBackendFake) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) { return nil, nil }
func (f *jsMutationBackendFake) Close() error { return nil }
func (f *jsMutationBackendFake) GetPluginKV(_ context.Context, ext, key string) (eventstore.PluginKVItem, error) {
	item, ok := f.items[ext+"\x00"+key]; if !ok { return eventstore.PluginKVItem{}, eventstore.ErrPluginKVNotFound }; return item, nil
}
func (f *jsMutationBackendFake) ListPluginKV(_ context.Context, req eventstore.PluginKVListRequest) ([]eventstore.PluginKVItem, error) {
	out := make([]eventstore.PluginKVItem, 0)
	for _, item := range f.items { if item.ExtensionID == req.ExtensionID && strings.HasPrefix(item.Key, req.Prefix) { out = append(out, item) } }
	return out, nil
}

func TestJSMutationCollectorCapturesTypedOwnersAndTransientState(t *testing.T) {
	core := messageflow.NewMutationCollector(eventstore.EventFactory{})
	collector := NewJSMutationCollector(core, JSMutationScope{DiceID: "dice", GroupID: "group", UserID: "user"}, eventstore.Metadata{CommandID: "command", CorrelationID: "correlation", OccurredAt: time.Unix(1, 0).UTC()})
	if err := collector.CaptureGroup(groupstate.NewGroupNameChangedV1("new name")); err != nil { t.Fatal(err) }
	if err := collector.CapturePlayer(playerstate.NewPlayerNameChangedV1("new player")); err != nil { t.Fatal(err) }
	if err := collector.CaptureGroupUserAttrs([]playerstate.GroupUserAttrsEvent{playerstate.NewGroupUserAttrsIncrementedV1("score", 1)}, map[string]any{"$t": "local"}); err != nil { t.Fatal(err) }
	if err := collector.CaptureModeration(playerstate.NewModerationRankChangedV1(2)); err != nil { t.Fatal(err) }
	work, err := collector.UnitOfWork(); if err != nil { t.Fatal(err) }
	if len(work.Streams) != 4 { t.Fatalf("streams=%d", len(work.Streams)) }
	for _, stream := range work.Streams { for _, event := range stream.Events { if strings.Contains(string(event.Payload), "$t") { t.Fatalf("transient leaked in %#v", event) } } }
}

func TestJSPluginKVOverlayEncryptsAndReadsWrites(t *testing.T) {
	crypto := &jsMutationCryptoFake{}
	backend := &jsMutationBackendFake{items: map[string]eventstore.PluginKVItem{}}
	overlay, err := NewJSPluginKVOverlay("extension", crypto, backend)
	if err != nil { t.Fatal(err) }
	if err := overlay.Put(context.Background(), "key", []byte("value"), 0); err != nil { t.Fatal(err) }
	item, err := overlay.Get(context.Background(), "key"); if err != nil || string(item.Value) != "value" { t.Fatalf("item=%#v err=%v", item, err) }
	if err := overlay.Put(context.Background(), "key", []byte("value-2"), 0); err != nil { t.Fatal(err) }
	item, err = overlay.Get(context.Background(), "key"); if err != nil || string(item.Value) != "value-2" || item.Version != 1 { t.Fatalf("second write item=%#v err=%v", item, err) }
	if len(backend.work) != 0 { t.Fatal("backend committed before explicit commit") }
	if err := overlay.Commit(context.Background()); err != nil { t.Fatal(err) }
	if len(backend.work) != 1 || len(backend.work[0].PluginKVUpdates) != 1 { t.Fatalf("work=%#v", backend.work) }
	update := backend.work[0].PluginKVUpdates[0]
	if len(update.KeyHMAC) != 32 || len(update.KeyCiphertext) == 0 || len(update.KeyNonce) == 0 || len(update.ValueCiphertext) == 0 || len(update.ValueNonce) == 0 { t.Fatalf("update=%#v", update) }
	if len(crypto.calls) < 3 || crypto.calls[0] != "plugin-key-index/v1" || !strings.HasPrefix(crypto.calls[1], "plugin-kv-key/v1") || !strings.HasPrefix(crypto.calls[2], "plugin-kv-value/v1") { t.Fatalf("calls=%v", crypto.calls) }
}

func TestJSPluginKVOverlayRejectsBounds(t *testing.T) {
	overlay, err := NewJSPluginKVOverlay("extension", &jsMutationCryptoFake{}, &jsMutationBackendFake{items: map[string]eventstore.PluginKVItem{}}); if err != nil { t.Fatal(err) }
	if err := overlay.Put(context.Background(), strings.Repeat("k", eventstore.MaxPluginKeyBytes+1), []byte("v"), 0); !errors.Is(err, eventstore.ErrOversizeInput) { t.Fatalf("key err=%v", err) }
	if _, err := overlay.List(context.Background(), "", eventstore.MaxPluginResults+1); !errors.Is(err, eventstore.ErrOversizeInput) { t.Fatalf("result err=%v", err) }
}

func TestJSEffectRejectsPlaintextAndInvalidRisk(t *testing.T) {
	_, err := BuildJSEffect(JSEffectRequest{EffectID: "effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "reply", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending})
	if err == nil { t.Fatal("plaintext effect accepted") }
	_, err = BuildJSEffect(JSEffectRequest{EffectID: "effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "reply", RiskClass: "unknown", Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"})
	if err == nil { t.Fatal("invalid risk accepted") }
	effect, err := BuildJSEffect(JSEffectRequest{EffectID: "effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "reply", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"})
	if err != nil || effect.PayloadCiphertext == nil { t.Fatalf("effect=%#v err=%v", effect, err) }
	if _, ok := any(effect).(interface{ Authority() any }); ok { t.Fatal("authority pointer exposed") }
}

func TestJSMutationCollectorConfigRequiresRegistration(t *testing.T) {
	collector := NewJSMutationCollector(messageflow.NewMutationCollector(eventstore.EventFactory{}), JSMutationScope{DiceID: "d", GroupID: "g"}, eventstore.Metadata{CommandID: "c", CorrelationID: "r", OccurredAt: time.Unix(1, 0).UTC()})
	if err := collector.CaptureConfig(JSConfigMutation{ExtensionID: "ext", Key: "missing", Value: "x"}); err == nil { t.Fatal("unregistered config accepted") }
	collector.RegisterConfig("ext", "name", func(value any) error { if value != "x" { return errors.New("bad") }; return nil })
	if err := collector.CaptureConfig(JSConfigMutation{ExtensionID: "ext", Key: "name", Value: "x"}); err != nil { t.Fatal(err) }
	if len(collector.ConfigMutations()) != 1 { t.Fatal("config mutation not recorded") }
}

func TestJSMutationCollectorRejectsUnsupportedGlobalOwners(t *testing.T) {
	collector := NewJSMutationCollector(messageflow.NewMutationCollector(eventstore.EventFactory{}), JSMutationScope{DiceID: "d", GroupID: "g", UserID: "u"}, eventstore.Metadata{CommandID: "c", CorrelationID: "r", OccurredAt: time.Unix(1, 0).UTC()})
	if err := collector.CaptureM(JSGroupUserAttrsMutation{Operation: "increment", Key: "score"}); !errors.Is(err, ErrJSUnsupportedOwner) {
		t.Fatalf("CaptureM err=%v", err)
	}
	if err := collector.CaptureG(JSGroupUserAttrsMutation{Operation: "increment", Key: "score"}); !errors.Is(err, ErrJSUnsupportedOwner) {
		t.Fatalf("CaptureG err=%v", err)
	}
}

func TestBuildJSEffectRejectsCallerOwnedFields(t *testing.T) {
	base := JSEffectRequest{EffectID: "effect", EndpointID: "endpoint", LaneHMAC: []byte("lane"), EffectType: "reply", RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending, PayloadCiphertext: []byte("cipher"), PayloadNonce: []byte("nonce"), PayloadEncryptionKeyID: "key"}
	for name, mutate := range map[string]func(*JSEffectRequest){
		"expected version": func(r *JSEffectRequest) { r.ExpectedVersion = 1 },
		"subject key":      func(r *JSEffectRequest) { r.SubjectKey = []byte("forged") },
		"principal":        func(r *JSEffectRequest) { r.PrincipalID = "forged" },
	} {
		t.Run(name, func(t *testing.T) {
			request := base
			mutate(&request)
			if _, err := BuildJSEffect(request); !errors.Is(err, ErrJSEffect) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestJSPluginKVOverlayCoalescesAgainstDurableBaseAndRetriesCommit(t *testing.T) {
	backend := &jsMutationBackendFake{items: map[string]eventstore.PluginKVItem{
		"extension\x00key": {ExtensionID: "extension", Key: "key", Value: []byte("old"), Version: 7},
	}}
	overlay, err := NewJSPluginKVOverlay("extension", &jsMutationCryptoFake{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := overlay.Put(context.Background(), "key", []byte("one"), 7); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Put(context.Background(), "key", []byte("two"), 8); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Delete(context.Background(), "key", 8); err != nil {
		t.Fatal(err)
	}
	backend.fail = errors.New("temporary backend failure")
	if err := overlay.Commit(context.Background()); !errors.Is(err, backend.fail) {
		t.Fatalf("first commit err=%v", err)
	}
	backend.fail = nil
	if err := overlay.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(backend.work) != 1 || len(backend.work[0].PluginKVUpdates) != 1 {
		t.Fatalf("commits=%#v", backend.work)
	}
	update := backend.work[0].PluginKVUpdates[0]
	if !update.Deleted || update.ExpectedVersion != 7 || update.Version != 8 {
		t.Fatalf("coalesced update=%#v", update)
	}
}

func TestJSPluginKVOverlayRejectsCollectorOnlyAndTypedNilDependencies(t *testing.T) {
	var backend *jsMutationBackendFake
	if _, err := NewJSPluginKVOverlay("extension", &jsMutationCryptoFake{}, backend); err == nil {
		t.Fatal("typed nil backend accepted")
	}
	collector := messageflow.NewMutationCollector(eventstore.EventFactory{})
	overlay, err := NewJSPluginKVOverlayForCollector("extension", &jsMutationCryptoFake{}, collector)
	if err != nil {
		t.Fatal(err)
	}
	if err := overlay.Put(context.Background(), "key", []byte("value"), 0); !errors.Is(err, ErrJSPluginKV) {
		t.Fatalf("collector-only put err=%v", err)
	}
}

func TestJSPluginKVOverlayFailsClosedOnTruncatedScan(t *testing.T) {
	backend := &jsMutationBackendFake{items: make(map[string]eventstore.PluginKVItem)}
	for i := range 1000 {
		key := "key-" + string(rune(i))
		backend.items["extension\x00"+key] = eventstore.PluginKVItem{ExtensionID: "extension", Key: key, Value: []byte("v"), Version: 1}
	}
	overlay, err := NewJSPluginKVOverlay("extension", &jsMutationCryptoFake{}, backend)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := overlay.List(context.Background(), "", 1); !errors.Is(err, eventstore.ErrOversizeInput) {
		t.Fatalf("truncated scan err=%v", err)
	}
}
