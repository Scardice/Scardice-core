package messageflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

func testAdapterEventInbound(raw string) adapterapi.InboundMessage {
	return adapterapi.InboundMessage{
		Platform:         "QQ",
		Sender:           "QQ:1001",
		Conversation:     "QQ-Group:2002",
		ConversationKind: adapterapi.ConversationKindGroup,
		Target:           "QQ-Group:2002",
		Kind:             adapterapi.InboundKindAdapterEvent,
		OccurredAt:       time.Unix(1700000000, 0).UTC(),
		AdapterEvent: &adapterapi.AdapterEvent{
			Protocol: "onebot11",
			Type:     "notice",
			RawJSON:  raw,
		},
	}
}

func TestInboundServicePreservesAdapterEventRawJSONInsideEncryptedPayload(t *testing.T) {
	const raw = " {\n \"post_type\":\"notice\", \"big\":900719925474099312345\n} "
	repo := &ingressRepoStub{}
	service, err := NewInboundService(repo, ingressCryptoStub{})
	if err != nil {
		t.Fatal(err)
	}
	fenced := testFencedMessage("opaque-raw-1", "")
	fenced.Message = testAdapterEventInbound(raw)
	fenced.Message.ProviderEventID = "opaque-raw-1"
	if _, err := service.HandleInbound(context.Background(), fenced); err != nil {
		t.Fatal(err)
	}

	repo.mu.Lock()
	ciphertext := append([]byte(nil), repo.updates[0].PayloadCiphertext...)
	repo.mu.Unlock()
	plaintext, ok := bytes.CutPrefix(ciphertext, []byte("sealed:"))
	if !ok {
		t.Fatalf("ciphertext does not contain test envelope: %q", ciphertext)
	}
	var payload ingressPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Message.AdapterEvent == nil || payload.Message.AdapterEvent.RawJSON != raw {
		t.Fatalf("raw JSON changed in durable payload: %#v", payload.Message.AdapterEvent)
	}
}

func TestInboundServiceDeduplicatesTypedLiveAndHistoryRepresentations(t *testing.T) {
	const liveRaw = " {\n  \"post_type\":\"message\", \"message_id\":9001, \"group_id\":2002, \"vendor_extra\":true\n} "
	const historyRaw = `{"post_type":"message","message_id":9001}`
	repo := &ingressRepoStub{}
	service, err := NewInboundService(repo, ingressCryptoStub{})
	if err != nil {
		t.Fatal(err)
	}

	live := testFencedMessage("onebot-message-9001", ".r d100")
	live.Message.MessageID = "9001"
	live.Message.Sequence = 10272
	live.Message.Segments = []adapterapi.InboundSegment{{Kind: "text", Text: ".r d100"}}
	live.Message.AdapterEvent = &adapterapi.AdapterEvent{
		Protocol: "onebot11",
		Type:     "message",
		RawJSON:  liveRaw,
	}
	history := live
	history.Message.AdapterEvent = &adapterapi.AdapterEvent{
		Protocol: "onebot11",
		Type:     "message",
		RawJSON:  historyRaw,
	}

	first, err := service.HandleInbound(context.Background(), live)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := service.HandleInbound(context.Background(), history)
	if err != nil {
		t.Fatal(err)
	}
	legacy := live
	legacy.Message.AdapterEvent = nil
	legacyDuplicate, err := service.HandleInbound(context.Background(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != adapterapi.IngressAccepted ||
		duplicate.Outcome != adapterapi.IngressDuplicate ||
		duplicate.InboxID != first.InboxID ||
		legacyDuplicate.Outcome != adapterapi.IngressDuplicate ||
		legacyDuplicate.InboxID != first.InboxID {
		t.Fatalf("typed representation receipts = %#v %#v %#v", first, duplicate, legacyDuplicate)
	}

	repo.mu.Lock()
	if len(repo.updates) != 1 {
		repo.mu.Unlock()
		t.Fatalf("live/history stored %d inbox rows", len(repo.updates))
	}
	ciphertext := append([]byte(nil), repo.updates[0].PayloadCiphertext...)
	repo.mu.Unlock()
	plaintext, ok := bytes.CutPrefix(ciphertext, []byte("sealed:"))
	if !ok {
		t.Fatalf("ciphertext does not contain test envelope: %q", ciphertext)
	}
	var payload ingressPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Message.AdapterEvent == nil || payload.Message.AdapterEvent.RawJSON != liveRaw {
		t.Fatalf("accepted callback lost its exact raw event: %#v", payload.Message.AdapterEvent)
	}
}

func TestInboundServiceOpaqueEventsAtSameSecondUseContentInFallbackIdentity(t *testing.T) {
	repo := &ingressRepoStub{}
	service, err := NewInboundService(repo, ingressCryptoStub{})
	if err != nil {
		t.Fatal(err)
	}
	first := testFencedMessage("", "")
	first.Message = testAdapterEventInbound(`{"post_type":"notice","notice_type":"group_admin","user_id":1001}`)
	second := first
	second.Message = testAdapterEventInbound(`{"post_type":"notice","notice_type":"group_title","user_id":1001}`)

	firstReceipt, err := service.HandleInbound(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	secondReceipt, err := service.HandleInbound(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	if firstReceipt.Outcome != adapterapi.IngressAccepted || secondReceipt.Outcome != adapterapi.IngressAccepted || firstReceipt.InboxID == secondReceipt.InboxID {
		t.Fatalf("opaque receipts collapsed: first=%#v second=%#v", firstReceipt, secondReceipt)
	}
}

func TestInboundServiceRejectsEscapeHeavyAdapterRawBeforeMarshal(t *testing.T) {
	repo := &ingressRepoStub{}
	service, err := NewInboundService(repo, ingressCryptoStub{})
	if err != nil {
		t.Fatal(err)
	}
	fenced := testFencedMessage("escape-heavy-adapter", "")
	fenced.Message = testAdapterEventInbound(`{"post_type":"notice","value":"` + strings.Repeat("<", 50*1024) + `"}`)
	fenced.Message.ProviderEventID = "escape-heavy-adapter"
	if _, err := service.HandleInbound(context.Background(), fenced); !errors.Is(err, ErrIngressPayload) {
		t.Fatalf("escape-heavy raw error = %v", err)
	}
	repo.mu.Lock()
	defer repo.mu.Unlock()
	if len(repo.updates) != 0 {
		t.Fatalf("oversized raw admitted %d updates", len(repo.updates))
	}
}

func TestInboundAdapterRawBoundFitsEventstoreLimitForSmallEvent(t *testing.T) {
	message := testAdapterEventInbound(`{"post_type":"notice","notice_type":"group_msg_emoji_like"}`)
	if got := inboundJSONUpperBound(message); got > eventstore.MaxEventPayloadBytes {
		t.Fatalf("small adapter event bound = %d", got)
	}
}

func TestInboundServiceTypedFallbackIdentityIgnoresAdapterMetadata(t *testing.T) {
	service, err := NewInboundService(&ingressRepoStub{}, ingressCryptoStub{})
	if err != nil {
		t.Fatal(err)
	}
	legacy := testFencedMessage("", "same message")
	first, err := service.HandleInbound(t.Context(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	current := legacy
	current.Message.AdapterEvent = &adapterapi.AdapterEvent{
		Protocol: "onebot11", Type: "message", RawJSON: `{"post_type":"message","vendor":true}`,
	}
	duplicate, err := service.HandleInbound(t.Context(), current)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != adapterapi.IngressAccepted || duplicate.Outcome != adapterapi.IngressDuplicate ||
		duplicate.InboxID != first.InboxID {
		t.Fatalf("raw metadata changed typed fallback identity: first=%#v duplicate=%#v", first, duplicate)
	}
}
