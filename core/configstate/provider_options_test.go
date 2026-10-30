package configstate

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"Scardice-core/eventstore"
)

func TestJSChangedEventRoundTripsNestedProviderOptionNulls(t *testing.T) {
	payload := []byte(`{"jsRuntimeOptions":{"custom":{"optional":null,"nested":{"also":null},"list":[null]}}}`)

	decoded, err := DecodeTypedEvent(EventConfigJSChanged, payload)
	if err != nil {
		t.Fatalf("DecodeTypedEvent() error = %v", err)
	}
	jsEvent, ok := decoded.(*JSChangedV1)
	if !ok {
		t.Fatalf("decoded event type = %T, want *JSChangedV1", decoded)
	}

	persisted, err := MarshalTypedEvent(*jsEvent)
	if err != nil {
		t.Fatalf("MarshalTypedEvent() error = %v", err)
	}
	replayed, err := DecodeTypedEvent(EventConfigJSChanged, persisted)
	if err != nil {
		t.Fatalf("replay DecodeTypedEvent() error = %v", err)
	}

	got, err := json.Marshal(replayed.(*JSChangedV1).JsRuntimeOptions["custom"])
	if err != nil {
		t.Fatalf("marshal provider payload: %v", err)
	}
	want := json.RawMessage(`{"optional":null,"nested":{"also":null},"list":[null]}`)
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode replayed provider payload: %v", err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("replayed provider payload = %s, want %s", got, want)
	}
}

func TestDecodeJSChangedEventKeepsOuterNullAndShapeGuards(t *testing.T) {
	tests := []struct {
		name    string
		payload string
	}{
		{name: "malformed event JSON", payload: `{"jsRuntimeOptions":`},
		{name: "non-object event", payload: `null`},
		{name: "null config field", payload: `{"jsEnable":null,"jsRuntimeOptions":{"custom":{"optional":null}}}`},
		{name: "null runtime options field", payload: `{"jsRuntimeOptions":null}`},
		{name: "non-object runtime options field", payload: `{"jsRuntimeOptions":[]}`},
		{name: "null provider payload", payload: `{"jsRuntimeOptions":{"custom":null}}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeTypedEvent(EventConfigJSChanged, []byte(test.payload)); err == nil {
				t.Fatalf("DecodeTypedEvent(%s) unexpectedly succeeded", test.payload)
			}
		})
	}
}

func TestAppendTypedReplaysNestedProviderOptionNulls(t *testing.T) {
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/config-provider-options.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	store := eventstore.NewStore(database, eventstore.WithProjection(ConfigProjection()))
	repository := NewRepository(store)
	baseline := testBaseline()
	metadata := eventstore.Metadata{
		CommandID: "import-baseline", CorrelationID: "config-provider-options", OccurredAtUnixNanoUTC: 1, OccurredAtUnixNanoSet: true,
	}
	result, err := repository.DecideAndAppend(ctx, State{}, 0, metadata, Command{Kind: CommandImportBaseline, Baseline: &baseline})
	if err != nil {
		t.Fatal(err)
	}

	want := json.RawMessage(`{"optional":null,"nested":{"also":null},"list":[null]}`)
	_, err = repository.AppendTyped(ctx, baseline.DiceID, result.StreamVersions[ConfigStream(baseline.DiceID)], eventstore.Metadata{
		CommandID: "update-js-options", CorrelationID: "config-provider-options", OccurredAtUnixNanoUTC: 2, OccurredAtUnixNanoSet: true,
	}, []TypedEvent{JSChangedV1{JSConfig: JSConfig{JsRuntimeOptions: map[string]json.RawMessage{"custom": want}}}})
	if err != nil {
		t.Fatalf("AppendTyped() error = %v", err)
	}

	projected, err := ReadProjected(ctx, store, baseline.DiceID)
	if err != nil {
		t.Fatal(err)
	}
	got := projected.JS.JsRuntimeOptions["custom"]
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode projected provider payload: %v", err)
	}
	if err := json.Unmarshal(want, &wantValue); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("projected provider payload = %s, want %s", got, want)
	}
}
