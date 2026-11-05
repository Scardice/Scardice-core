package eventsourcing

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing/v1reader"
)

func TestV1BaselineUsesCurrentGroupStateRatherThanHistory(t *testing.T) {
	state := groupstate.State{Version: 900, DiceID: "dice", GroupID: "QQ-Group:1", GroupName: "Current", Active: true,
		DiceIDActive: map[string]bool{"QQ:bot": true}, DiceIDExists: map[string]bool{"QQ:bot": true},
		ActivatedExtensions: []string{"log", "coc7"}, InactivatedExtensions: map[string]bool{"dnd5e": true},
		System: "coc7", DiceSideNum: 100, CocRuleIndex: 2, HelpPackages: []string{"coc"},
		PlayerGroups: map[string][]string{"party": {"QQ:player"}}, Privileges: map[string]int{"QQ:player": 50},
		BotList: map[string]bool{"QQ:other": true}, ShowGroupWelcome: true, GroupWelcomeMessage: "hello", EnteredAt: 123}
	payload, _ := json.Marshal(state)
	baseline := newV1Baseline()
	if err := baseline.addProjection(v1reader.ProjectionRow{Name: groupstate.GroupProjectionName, RowKey: groupstate.GroupStream(state.DiceID, state.GroupID).AggregateID, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	var events []groupstate.TypedEvent
	for _, record := range baseline.records {
		event, err := groupstate.DecodeTypedEvent(groupstate.EventType(record.Kind), record.Payload)
		if err != nil {
			t.Fatal(err)
		}
		events = append(events, event)
	}
	got, err := groupstate.Replay(events)
	if err != nil {
		t.Fatal(err)
	}
	state.Version = got.Version
	want, _ := json.Marshal(state)
	actual, _ := json.Marshal(got)
	if !sameJSON(want, actual) {
		t.Fatalf("current group state was lost: want %s, got %s", want, actual)
	}
	if got.Version >= 900 {
		t.Fatal("historical versions were retained instead of a baseline")
	}
}

func TestV1BaselineRenumbersReferencedCurrentSecrets(t *testing.T) {
	baseline := newV1Baseline()
	state := attributestate.State{Version: 24, SecretVersion: 24, DiceID: "dice", ID: "sheet", SecretRef: "vault:sheet", Name: "Hero"}
	payload, _ := json.Marshal(state)
	if err := baseline.addProjection(v1reader.ProjectionRow{Name: attributestate.ProjectionName, RowKey: attributestate.Stream(state.DiceID, state.ID).AggregateID, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	manager := managerstate.State{Version: 88, AuthSecretVersion: 88, AuthSecretRef: managerstate.AuthSecretRef}
	payload, _ = json.Marshal(manager)
	if err := baseline.addProjection(v1reader.ProjectionRow{Name: managerstate.ProjectionName, RowKey: managerstate.AggregateID, Payload: payload}); err != nil {
		t.Fatal(err)
	}
	if baseline.secretVersions[state.SecretRef] != 24 || baseline.secretVersions[managerstate.AuthSecretRef] != 88 {
		t.Fatal("source current references were not retained for verification")
	}
	for _, record := range baseline.records {
		var value map[string]any
		if err := json.Unmarshal(record.Payload, &value); err != nil {
			t.Fatal(err)
		}
		if version, ok := value["secretVersion"]; ok && version != float64(1) {
			t.Fatalf("attribute secret version = %v", version)
		}
		if version, ok := value["authSecretVersion"]; ok && version != float64(1) {
			t.Fatalf("manager auth version = %v", version)
		}
	}
}

func TestV1BaselineRejectsUnknownCurrentProjection(t *testing.T) {
	if err := newV1Baseline().addProjection(v1reader.ProjectionRow{Name: "future-domain", RowKey: "owner", Payload: []byte(`{}`)}); !errors.Is(err, ErrValidation) {
		t.Fatalf("unknown current projection: %v", err)
	}
}

func TestV1EndpointCanonicalSecretRefsRebaseWithoutChangingOtherNumbers(t *testing.T) {
	original := adapterapi.SecretRef{Ref: "vault:credential", Version: 17}
	replacement := adapterapi.SecretRef{Ref: original.Ref, Version: 1}
	raw := json.RawMessage(`{"appSecret":{"secretRef":"vault:credential","version":17},"credential":{"ref":"vault:credential","version":17},"providerId":9007199254740993,"version":17}`)
	got, err := rebaseV1ConfigSecretRefs(raw, map[adapterapi.SecretRef]adapterapi.SecretRef{original: replacement})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"appSecret":{"secretRef":"vault:credential","version":1},"credential":{"ref":"vault:credential","version":1},"providerId":9007199254740993,"version":17}`
	if string(got) != want {
		t.Fatalf("rebased config=%s", got)
	}
}

func TestV1ModerationBaselineRecomputesRuntimeHistoryDigest(t *testing.T) {
	baseline := newV1Baseline()
	state := playerstate.ModerationState{Version: 50, DiceID: "dice", GroupID: "global", SubjectID: "QQ:bad", Rank: 30, Score: 100, ReasonDigest: "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}
	stream := playerstate.ModerationStream(state.DiceID, state.GroupID, state.SubjectID)
	payload, _ := json.Marshal(state)
	row := v1reader.ProjectionRow{Name: playerstate.ModerationProjectionName, RowKey: stream.AggregateID, Payload: payload}
	if err := baseline.addProjection(row); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(stream.AggregateID))
	oldRef := "vault:moderation-details:" + hex.EncodeToString(digest[:16])
	if err := baseline.finishModeration(map[string]v1reader.Secret{oldRef: {Ref: oldRef, Plaintext: []byte(`{"times":[123],"reasons":["reason"],"places":["group"],"name":"not part of history"}`)}}); err != nil {
		t.Fatal(err)
	}
	var got playerstate.ModerationState
	if err := json.Unmarshal(baseline.projections[v1ProjectionKey{row.Name, row.RowKey}], &got); err != nil {
		t.Fatal(err)
	}
	want := hex.EncodeToString(eventstore.DigestBytes("moderation-history/v1", []byte(`{"times":[123],"reasons":["reason"],"places":["group"]}`)))
	if got.ReasonDigest != want || got.Version != 2 || baseline.secretAliases[oldRef] != "vault:moderation-details:"+stream.AggregateID {
		t.Fatalf("moderation baseline=%+v", got)
	}
}

func TestV1SemanticComparisonDoesNotRoundLargeJSONNumbers(t *testing.T) {
	if sameJSON([]byte(`{"id":9007199254740992}`), []byte(`{"id":9007199254740993}`)) {
		t.Fatal("distinct integer identities compared equal")
	}
	if !sameJSON([]byte(`{"a":1,"b":2}`), []byte(`{"b":2,"a":1}`)) {
		t.Fatal("object order changed semantic equality")
	}
}
