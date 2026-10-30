package messageflow

import (
	"bytes"
	"context"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
)

// A callback's outputs belong to the subject of the message it handles, so a
// purge of that subject reaches everything derived from it. That has to hold for
// output addressed to another conversation too: a hidden roll answers a group
// command in the sender's private chat, and a notice goes to the owner's group.
// Rejecting those as "forged" made the bot log them as sent and never send them.
func TestCallbackOutboundInheritsTheMessageSubjectWhereverItIsAddressed(t *testing.T) {
	ctx := context.Background()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/subject.db"})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	source := defaultIntegrationKeySource()
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	if err := store.SetReadiness(ctx, eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "db-1", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC()}); err != nil {
		t.Fatal(err)
	}
	service, err := NewOutboundService(store, testResolver{snap: EndpointSnapshot{EndpointID: "endpoint-1", DesiredState: "enabled", ObservedState: adapterapi.ObservedStateConnected, Capabilities: adapterapi.CapabilityOutbound, Actions: adapterapi.ActionSet(0).With(adapterapi.ActionKindSendMessage), IndexRootID: "index-v1", IndexSigner: store}}, store, eventstore.UUIDGenerator{})
	if err != nil {
		t.Fatal(err)
	}
	messageSubject, _, err := store.KeyedDigest(ctx, "privacy-subject/v1", "group-1")
	if err != nil {
		t.Fatal(err)
	}
	collector := NewMutationCollector(eventstore.EventFactory{})
	collector.subjectKey = messageSubject
	root, _ := source.IndexRootMaterial(ctx)

	// The first effect answers the message in its own conversation, the second
	// goes elsewhere.
	for _, conversation := range []string{"group-1", "person-1"} {
		effect := testEffect()
		effect.ID, effect.OperationID = adapterapi.EffectID("effect-"+conversation), adapterapi.OperationID("op-"+conversation)
		effect.Payload.Target.Conversation = adapterapi.ConversationID(conversation)
		effect.Deadline = time.Now().Add(time.Minute).UTC()
		if effect.Lane, err = adapterapi.NewLaneMetadata(effect.EndpointID, effect.Payload.Target, root, 1); err != nil {
			t.Fatal(err)
		}
		prepared, err := service.Prepare(ctx, SubmitRequest{Effect: effect, CommandID: "command-" + conversation, PrincipalID: "principal"})
		if err != nil {
			t.Fatal(err)
		}
		if err := collector.AddPreparedOutbound(prepared); err != nil {
			t.Fatalf("effect addressed to %q was refused: %v", conversation, err)
		}
	}

	work, err := collector.UnitOfWork()
	if err != nil {
		t.Fatal(err)
	}
	if len(work.Effects) != 2 || len(work.Streams) != 2 {
		t.Fatalf("staged %d effects and %d streams, want two of each", len(work.Effects), len(work.Streams))
	}
	for _, effect := range work.Effects {
		if !bytes.Equal(effect.SubjectKey, messageSubject) {
			t.Fatalf("effect %s carries a subject other than the message's", effect.EffectID)
		}
	}
	for _, stream := range work.Streams {
		for _, event := range stream.Events {
			if !bytes.Equal(event.Metadata.SubjectKey, messageSubject) {
				t.Fatalf("stream %s event carries a subject other than the message's", stream.Stream.AggregateID)
			}
		}
	}
	if _, err := store.Commit(ctx, work); err != nil {
		t.Fatalf("commit: %v", err)
	}
}
