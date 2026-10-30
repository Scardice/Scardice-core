package eventstore

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

type counterAggregate struct {
	value int
}

func (a *counterAggregate) Apply(event Envelope) error {
	switch event.SchemaVersion {
	case 1:
		var change struct {
			Delta int `json:"delta"`
		}
		if err := json.Unmarshal(event.Payload, &change); err != nil {
			return errors.Join(ErrInvalidEvent, err)
		}
		a.value += change.Delta
		return nil
	default:
		return ErrUnsupportedSchema
	}
}

type fixedClock struct{ now time.Time }

func (c fixedClock) Now() time.Time { return c.now }

type fixedIDs struct {
	ids []string
	i   int
}

func (g *fixedIDs) NewID() (string, error) {
	id := g.ids[g.i]
	g.i++
	return id, nil
}

func TestEventContract(t *testing.T) {
	const exactPayload = `{"delta":1,"raw":"  exact bytes  "}`
	clock := fixedClock{now: time.Date(2026, 9, 6, 12, 34, 56, 789, time.FixedZone("CST", 8*60*60))}
	ids := &fixedIDs{ids: []string{"event-1", "command-1", "correlation-1"}}
	factory := EventFactory{Clock: clock, IDs: ids}
	stream := StreamID{AggregateType: "counter", AggregateID: "counter-1"}

	event, eventErr := factory.NewEvent("counter.changed", 1, json.RawMessage(exactPayload), Metadata{})
	if eventErr != nil {
		t.Fatalf("NewEvent: %v", eventErr)
	}
	if event.Metadata.EventID != "event-1" || event.Metadata.CommandID != "command-1" || event.Metadata.CorrelationID != "correlation-1" {
		t.Fatalf("generated metadata IDs = %#v", event.Metadata)
	}
	if !event.Metadata.OccurredAt.Equal(clock.now.UTC()) {
		t.Fatalf("occurred at = %s, want %s", event.Metadata.OccurredAt, clock.now.UTC())
	}

	envelope, eventErr := factory.Envelope(stream, 1, 9, event)
	if eventErr != nil {
		t.Fatalf("Envelope: %v", eventErr)
	}
	if !reflect.DeepEqual([]byte(envelope.Payload), []byte(exactPayload)) {
		t.Fatalf("payload changed: got %q want %q", envelope.Payload, exactPayload)
	}
	if envelope.Checksum == (EventChecksum{}) {
		t.Fatal("event checksum was not assigned")
	}
	if got := ComputeEventChecksum(envelope); got != envelope.Checksum {
		t.Fatal("event checksum is not reproducible")
	}
	const wantChecksum = "738d44a6f3fc9e32fbb8db4c2f3b14444c8ec129d3cf129b6275540fb22fa13d"
	if got := envelope.Checksum.String(); got != wantChecksum {
		t.Fatalf("checksum = %s, want known vector %s", got, wantChecksum)
	}
	mutations := []struct {
		name string
		edit func(*Envelope)
	}{
		{"stream version", func(e *Envelope) { e.StreamVersion++ }},
		{"event type", func(e *Envelope) { e.EventType = "counter.other" }},
		{"schema version", func(e *Envelope) { e.SchemaVersion++ }},
		{"metadata event ID", func(e *Envelope) { e.Metadata.EventID = "event-2" }},
		{"payload bytes", func(e *Envelope) { e.Payload = json.RawMessage(`{"delta":2}`) }},
	}
	for _, mutation := range mutations {
		t.Run("checksum changes "+mutation.name, func(t *testing.T) {
			changed := envelope
			mutation.edit(&changed)
			if got := ComputeEventChecksum(changed); got == envelope.Checksum {
				t.Fatal("checksum did not change")
			}
		})
	}

	var aggregate counterAggregate
	if err := aggregate.Apply(envelope); err != nil {
		t.Fatalf("apply known schema: %v", err)
	}
	if aggregate.value != 1 {
		t.Fatalf("counter value = %d, want 1", aggregate.value)
	}

	unknown := envelope
	unknown.SchemaVersion = 2
	before := aggregate.value
	if err := aggregate.Apply(unknown); !errors.Is(err, ErrUnsupportedSchema) {
		t.Fatalf("unknown schema error = %v", err)
	}
	if aggregate.value != before {
		t.Fatalf("unknown schema mutated aggregate: before=%d after=%d", before, aggregate.value)
	}

	var store Store = contractStore{}
	if _, err := store.Commit(context.Background(), UnitOfWork{
		Streams:         []StreamAppend{{Stream: stream, ExpectedVersion: 0, Events: []NewEvent{event}}},
		Operations:      []OperationUpdate{{OperationID: "operation-1", ExpectedVersion: 0}},
		InboxUpdates:    []InboxUpdate{{InboxID: "inbox-1", ExpectedVersion: 0}},
		Effects:         []NewEffect{{EffectID: "effect-1", ExpectedVersion: 0}},
		ArtifactUpdates: []ArtifactUpdate{{ArtifactID: "artifact-1", ExpectedVersion: 0}},
		SecretUpdates:   []SecretUpdate{{SecretRef: "secret-1", ExpectedVersion: 0}},
		PluginKVUpdates: []PluginKVUpdate{{ExtensionID: "extension-1", KeyHMAC: []byte("key"), ExpectedVersion: 0}},
		FenceUpdates:    []SubjectFenceUpdate{{SubjectKey: []byte("subject"), ExpectedVersion: 0}},
	}); err != nil {
		t.Fatalf("contract store commit: %v", err)
	}

	if err := ValidateUnitOfWork(UnitOfWork{}); !errors.Is(err, ErrEmptyUnitOfWork) {
		t.Fatalf("empty UnitOfWork error = %v", err)
	}
	if err := ValidateUnitOfWork(UnitOfWork{Streams: []StreamAppend{
		{Stream: stream}, {Stream: stream},
	}}); !errors.Is(err, ErrDuplicateStream) {
		t.Fatalf("duplicate stream error = %v", err)
	}
	if got := reflect.TypeOf((*Store)(nil)).Elem().NumMethod(); got != 3 {
		t.Fatalf("Store exposes %d methods, want Commit, Load, Close only", got)
	}
	if _, err := (EventFactory{}).NewEvent("counter.changed", 1, json.RawMessage(`{"delta":1}`), Metadata{}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("invalid metadata error = %v", err)
	}
	epochMetadata := Metadata{
		EventID: "event-epoch", CommandID: "command-epoch", CorrelationID: "correlation-epoch",
		OccurredAt: time.Unix(0, 0).UTC(),
	}
	epochEvent, eventErr := (EventFactory{}).NewEvent("counter.changed", 1, json.RawMessage(`{"delta":1}`), epochMetadata)
	if eventErr != nil {
		t.Fatalf("Unix epoch metadata rejected: %v", eventErr)
	}
	if _, err := (EventFactory{}).Envelope(stream, 1, 10, epochEvent); err != nil {
		t.Fatalf("Unix epoch envelope rejected: %v", err)
	}
	conflictingMetadata := epochMetadata
	conflictingMetadata.OccurredAt = time.Unix(10, 0).UTC()
	conflictingMetadata.OccurredAtUnixNanoUTC = time.Unix(11, 0).UTC().UnixNano()
	conflictingMetadata.OccurredAtUnixNanoSet = true
	if _, err := (EventFactory{}).NewEvent("counter.changed", 1, json.RawMessage(`{"secret":"timestamp"}`), conflictingMetadata); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("conflicting timestamps error = %v", err)
	}
	conflictingEvent := NewEvent{EventType: "counter.changed", SchemaVersion: 1, Payload: json.RawMessage(`{"delta":1}`), Metadata: conflictingMetadata}
	if _, err := (EventFactory{}).Envelope(stream, 1, 11, conflictingEvent); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("conflicting timestamps accepted by Envelope: %v", err)
	}
	if err := ValidateUnitOfWork(UnitOfWork{Streams: []StreamAppend{{Stream: stream, Events: []NewEvent{conflictingEvent}}}}); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatalf("conflicting timestamps accepted by ValidateUnitOfWork: %v", err)
	}
	invalidWorkErr := ValidateUnitOfWork(UnitOfWork{Streams: []StreamAppend{{
		Stream: stream,
		Events: []NewEvent{{
			EventType:     "counter.changed",
			SchemaVersion: 1,
			Payload:       json.RawMessage(`{"secret":"must-not-leak"}`),
		}},
	}}})
	if !errors.Is(invalidWorkErr, ErrInvalidMetadata) {
		t.Fatalf("missing event metadata error = %v", invalidWorkErr)
	}
	if strings.Contains(invalidWorkErr.Error(), "must-not-leak") {
		t.Fatal("invalid metadata error leaked payload")
	}
}

type contractStore struct{}

func (contractStore) Commit(context.Context, UnitOfWork) (CommitResult, error) {
	return CommitResult{}, nil
}

func (contractStore) Load(context.Context, StreamID, uint64) ([]Envelope, error) { return nil, nil }
func (contractStore) Close() error                                               { return nil }
