package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v4"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/core/privacypurge"
	"Scardice-core/dice"
	"Scardice-core/eventstore"
)

func TestGroupPrivacyAPIUsesRuntimeOwnersAndRejectsStaleConfirmation(t *testing.T) {
	fixture := newGroupListEventStoreFixture(t)
	fixture.manager.JustForTest = false
	previous := privacyPurgeService()
	RegisterPrivacyPurgeService(privacypurge.NewService(fixture.store))
	t.Cleanup(func() { RegisterPrivacyPurgeService(previous) })
	const groupID = "QQ-Group:privacy-api"
	fixture.createGroup(groupID)
	fixture.createPlayer(groupListEventStoreDiceID, groupID, "QQ:privacy-one")
	fixture.withDomainRoot("privacy-account-mapping", func(transaction *dice.DurableCallbackTransaction) error {
		group, err := transaction.Domain().Group(context.Background(), groupListEventStoreDiceID, groupID)
		if err != nil {
			return err
		}
		for _, command := range []groupstate.Command{
			{Kind: groupstate.CommandActivation, DiceIDForActivation: groupListEventStoreDiceID, Active: false, Exists: false},
			{Kind: groupstate.CommandActivation, DiceIDForActivation: "QQ:privacy-bot", Active: true, Exists: true},
		} {
			if err = group.Decide(command); err != nil {
				return err
			}
		}
		return nil
	})
	if _, err := fixture.store.AcceptOutbox(context.Background(), eventstore.NewEffect{
		EffectID: "privacy-api-effect", EndpointID: "privacy-api-endpoint",
		Lane: "privacy-api-lane", Subject: groupID, EffectType: "message",
		RiskClass: eventstore.RiskPreDispatchRetryable, Status: eventstore.OutboxStatusPending,
		Payload: []byte("queued group data"),
	}); err != nil {
		t.Fatal(err)
	}

	request := groupLocalDataDeleteRequest{GroupID: groupID, Scopes: []string{"group_record", "players", "attrs", "logs"}, DryRun: true}
	call := func(payload groupLocalDataDeleteRequest) (bool, groupLocalDataDeleteResult) {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/sd-api/group/local_data/delete", bytes.NewReader(body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		req.Header.Set("Token", groupListEventStoreToken)
		recorder := httptest.NewRecorder()
		if err := groupLocalDataDelete(echo.New().NewContext(req, recorder)); err != nil {
			t.Fatal(err)
		}
		var response struct {
			Result bool                       `json:"result"`
			Data   groupLocalDataDeleteResult `json:"data"`
		}
		if recorder.Code != http.StatusOK {
			t.Fatalf("privacy status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		return response.Result, response.Data
	}
	if accepted, _ := call(request); accepted {
		t.Fatal("active group dry-run bypassed allowActive")
	}
	request.AllowActive = true
	accepted, scan := call(request)
	if !accepted || scan.Counts.GroupRecord < 1 || scan.Counts.Players != 1 || scan.Completed {
		t.Fatalf("dry-run did not find runtime-owned data: accepted=%v data=%#v", accepted, scan)
	}
	digest, ok := scan.Confirmation["digest"].(string)
	if !ok || digest == "" {
		t.Fatalf("dry-run omitted confirmation: %#v", scan.Confirmation)
	}
	version, ok := scan.Confirmation["version"].(float64)
	if !ok {
		t.Fatalf("dry-run omitted confirmation version: %#v", scan.Confirmation)
	}
	fixture.createPlayer(groupListEventStoreDiceID, groupID, "QQ:privacy-two")
	request.DryRun, request.ConfirmDigest, request.ConfirmVersion = false, digest, uint64(version)
	if accepted, result := call(request); accepted || result.Completed {
		t.Fatalf("stale confirmation deleted data: accepted=%v result=%#v", accepted, result)
	}
	player, err := playerstate.NewRepository(fixture.store).LoadPlayer(context.Background(), groupListEventStoreDiceID, groupID, "QQ:privacy-one")
	if err != nil || player.Version == 0 || player.Deleted {
		t.Fatalf("stale confirmation changed existing player: %#v err=%v", player, err)
	}
	request.DryRun = true
	accepted, scan = call(request)
	if !accepted || scan.Counts.Players != 2 {
		t.Fatalf("updated dry-run = %#v accepted=%v", scan, accepted)
	}
	request.DryRun = false
	request.ConfirmDigest = scan.Confirmation["digest"].(string)
	request.ConfirmVersion = uint64(scan.Confirmation["version"].(float64))
	accepted, deleted := call(request)
	if accepted || !deleted.Completed || deleted.Status != "completed-uncovered" || len(deleted.UncoveredData) == 0 ||
		!deleted.Deleted.GroupRecord || deleted.Deleted.PlayerRows != 2 || deleted.Deleted.OutboxRows != 1 || deleted.Deleted.ProjectionRows < 1 {
		t.Fatalf("confirmed deletion did not preserve uncovered-data warning: data=%#v result=%v", deleted, accepted)
	}
	if _, err := groupstate.ReadProjected(context.Background(), fixture.store, groupListEventStoreDiceID, groupID); !errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("deleted group projection remains: %v", err)
	}
	if hasWork, err := fixture.store.HasOutboxWork(context.Background()); err != nil || hasWork {
		t.Fatalf("deleted group's queued body remains dispatchable: hasWork=%v err=%v", hasWork, err)
	}
	for _, userID := range []string{"QQ:privacy-one", "QQ:privacy-two"} {
		player, err := playerstate.NewRepository(fixture.store).LoadPlayer(context.Background(), groupListEventStoreDiceID, groupID, userID)
		if err != nil && !errors.Is(err, eventstore.ErrNotFound) {
			t.Fatal(err)
		}
		if player.Version != 0 {
			t.Fatalf("deleted player stream retained: %#v", player)
		}
	}
}
