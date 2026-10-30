package dice

import (
	"testing"

	"Scardice-core/adapterapi"
)

// Telegram reports entity offsets in UTF-16 code units, so astral characters
// and emoji preceding a mention must not shift the resolved target.
func TestTelegramInboundSegmentsResolveTextMentionAfterAstralRunes(t *testing.T) {
	text := "🎲 hello @bob"
	if runes := len([]rune(text)); runes != 12 {
		t.Fatalf("unexpected fixture rune count %d", runes)
	}
	segments := telegramInboundSegments(text, []telegramEntity{
		{Type: "text_mention", Offset: 9, Length: 4, User: &telegramUser{ID: 555}},
	}, 100, "Scardice", nil)
	if len(segments) != 2 {
		t.Fatalf("segments = %#v", segments)
	}
	if segments[0].Kind != "text" || segments[0].Text != "🎲 hello " {
		t.Fatalf("leading text = %#v", segments[0])
	}
	if segments[1].Kind != "mention" || segments[1].ProviderID != "TG:555" {
		t.Fatalf("mention = %#v", segments[1])
	}
}

func TestTelegramInboundSegmentsResolveSelfUsernameMention(t *testing.T) {
	segments := telegramInboundSegments("/r 1d6 @Scardice", []telegramEntity{
		{Type: "mention", Offset: 7, Length: 9},
	}, 100, "Scardice", nil)
	if len(segments) != 2 || segments[1].Kind != "mention" || segments[1].ProviderID != "TG:100" {
		t.Fatalf("segments = %#v", segments)
	}
}

func TestTelegramInboundSegmentsPreserveUnresolvedUsernameMention(t *testing.T) {
	segments := telegramInboundSegments("hi @stranger", []telegramEntity{
		{Type: "mention", Offset: 3, Length: 9},
	}, 100, "Scardice", nil)
	if text := telegramSegmentsText(segments); text != "hi @stranger" {
		t.Fatalf("text = %q segments = %#v", text, segments)
	}
	for _, segment := range segments {
		if segment.Kind == "mention" {
			t.Fatalf("unresolved username produced a mention: %#v", segments)
		}
	}
}

func TestTelegramInboundSegmentsPreserveMentionOrderAndText(t *testing.T) {
	segments := telegramInboundSegments("a @Scardice b @bob c", []telegramEntity{
		{Type: "mention", Offset: 2, Length: 9},
		{Type: "text_mention", Offset: 14, Length: 4, User: &telegramUser{ID: 555}},
	}, 100, "Scardice", nil)
	want := []adapterapi.InboundSegment{
		{Kind: "text", Text: "a "},
		{Kind: "mention", ProviderID: "TG:100"},
		{Kind: "text", Text: " b "},
		{Kind: "mention", ProviderID: "TG:555"},
		{Kind: "text", Text: " c"},
	}
	if len(segments) != len(want) {
		t.Fatalf("segments = %#v", segments)
	}
	for i := range want {
		if segments[i] != want[i] {
			t.Fatalf("segment %d = %#v, want %#v", i, segments[i], want[i])
		}
	}
}

func TestTelegramSegmentsTextRendersCanonicalMentions(t *testing.T) {
	text := telegramSegmentsText([]adapterapi.InboundSegment{
		{Kind: "text", Text: "a "},
		{Kind: "mention", ProviderID: "TG:100"},
		{Kind: "text", Text: " b"},
	})
	if text != "a <@100> b" {
		t.Fatalf("text = %q", text)
	}
}

// handleUpdate is the production ingest path; a text_mention entity must reach
// Core as a structured mention segment instead of being flattened to text.
func TestTelegramHandleUpdateForwardsMentionEntity(t *testing.T) {
	runtime := &telegramRuntime{selfID: 100, selfName: "Scardice"}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 1), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	update := telegramUpdate{UpdateID: 9, Message: &telegramMessage{
		MessageID: 7, Date: 1_700_000_000, Text: "hello @bob",
		From:     telegramUser{ID: 101, Username: "alice"},
		Chat:     telegramChat{ID: -200, Type: "group"},
		Entities: []telegramEntity{{Type: "text_mention", Offset: 6, Length: 4, User: &telegramUser{ID: 555}}},
	}}
	if err := runtime.handleUpdate(t.Context(), core, update); err != nil {
		t.Fatalf("handle update: %v", err)
	}
	inbound := <-core.inboundCh
	if inbound.Text != "hello <@555>" {
		t.Fatalf("text = %q", inbound.Text)
	}
	if len(inbound.Segments) != 2 || inbound.Segments[0].Text != "hello " || inbound.Segments[1].Kind != "mention" || inbound.Segments[1].ProviderID != "TG:555" {
		t.Fatalf("segments = %#v", inbound.Segments)
	}
}

// Ordinary text messages without entities must keep behaving as a single text
// segment with the raw text preserved.
func TestTelegramHandleUpdateWithoutEntitiesKeepsPlainText(t *testing.T) {
	runtime := &telegramRuntime{selfID: 100, selfName: "Scardice"}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 1), inboundCh: make(chan adapterapi.InboundMessage, 1)}
	update := telegramUpdate{UpdateID: 10, Message: &telegramMessage{
		MessageID: 8, Date: 1_700_000_001, Text: "plain hi",
		From: telegramUser{ID: 101, Username: "alice"},
		Chat: telegramChat{ID: -200, Type: "group"},
	}}
	if err := runtime.handleUpdate(t.Context(), core, update); err != nil {
		t.Fatalf("handle update: %v", err)
	}
	inbound := <-core.inboundCh
	if inbound.Text != "plain hi" || len(inbound.Segments) != 1 || inbound.Segments[0] != (adapterapi.InboundSegment{Kind: "text", Text: "plain hi"}) {
		t.Fatalf("inbound = %#v", inbound)
	}
}

func TestTelegramInboundSegmentsResolveKnownUsernameFromCache(t *testing.T) {
	known := map[string]int64{"bob": 555}
	segments := telegramInboundSegments("hi @bob", []telegramEntity{
		{Type: "mention", Offset: 3, Length: 4},
	}, 100, "Scardice", known)
	if len(segments) != 2 || segments[1].Kind != "mention" || segments[1].ProviderID != "TG:555" {
		t.Fatalf("segments = %#v", segments)
	}
}

// A user who speaks first is cached; a later @username mention of that user
// resolves to their numeric id, matching the legacy UserIDCache behaviour.
func TestTelegramHandleUpdateResolvesMentionedUserAfterEarlierMessage(t *testing.T) {
	runtime := &telegramRuntime{selfID: 100, selfName: "Scardice", usernames: make(map[string]int64)}
	core := &onebotRuntimeCore{ch: make(chan adapterapi.LifecycleObservation, 1), inboundCh: make(chan adapterapi.InboundMessage, 2)}
	speak := telegramUpdate{UpdateID: 20, Message: &telegramMessage{
		MessageID: 20, Date: 1_700_000_010, Text: "i am bob",
		From: telegramUser{ID: 555, Username: "Bob"},
		Chat: telegramChat{ID: -200, Type: "group"},
	}}
	if err := runtime.handleUpdate(t.Context(), core, speak); err != nil {
		t.Fatalf("first update: %v", err)
	}
	<-core.inboundCh
	mention := telegramUpdate{UpdateID: 21, Message: &telegramMessage{
		MessageID: 21, Date: 1_700_000_011, Text: "hi @bob",
		From:     telegramUser{ID: 101, Username: "alice"},
		Chat:     telegramChat{ID: -200, Type: "group"},
		Entities: []telegramEntity{{Type: "mention", Offset: 3, Length: 4}},
	}}
	if err := runtime.handleUpdate(t.Context(), core, mention); err != nil {
		t.Fatalf("second update: %v", err)
	}
	inbound := <-core.inboundCh
	if inbound.Text != "hi <@555>" {
		t.Fatalf("text = %q", inbound.Text)
	}
	if len(inbound.Segments) != 2 || inbound.Segments[1].Kind != "mention" || inbound.Segments[1].ProviderID != "TG:555" {
		t.Fatalf("segments = %#v", inbound.Segments)
	}
}

func TestTelegramRememberUsernameIgnoresBlankAndDuplicates(t *testing.T) {
	runtime := &telegramRuntime{usernames: make(map[string]int64)}
	runtime.rememberUsername("", 5)
	runtime.rememberUsername("bob", 0)
	if len(runtime.usernames) != 0 {
		t.Fatalf("cache = %#v", runtime.usernames)
	}
	runtime.rememberUsername("Bob", 555)
	runtime.rememberUsername("bob", 999)
	if id := runtime.usernames["bob"]; id != 555 {
		t.Fatalf("cache = %#v", runtime.usernames)
	}
}
