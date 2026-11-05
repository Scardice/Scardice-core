package messageflow

import (
	"context"
	"testing"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
)

// The messages Core recovers from provider history only get recorded, and there
// can be hundreds. Behind the group's live lane they would hold that group's
// live messages back until every one of them was done, so they get a lane of
// their own. Messages that are processed like live ones change group and player
// state in order with the live ones and stay in the group's lane. Both belong
// to the same conversation, so privacy erasure still finds them together.
func TestInboundServiceGivesRecordOnlyHistoryItsOwnLane(t *testing.T) {
	repo := &ingressRepoStub{}
	svc, err := NewInboundService(repo)
	if err != nil {
		t.Fatal(err)
	}
	live := testFencedMessage("live-1", "live")
	executed := testFencedMessage("history-execute", "executed")
	executed.Message.History = adapterapi.InboundHistoryExecute
	recorded := testFencedMessage("history-record", "recorded")
	recorded.Message.History = adapterapi.InboundHistoryRecordOnly
	for _, fenced := range []endpoint.FencedInbound{live, executed, recorded} {
		if _, err := svc.HandleInbound(context.Background(), fenced); err != nil {
			t.Fatal(err)
		}
	}

	repo.mu.Lock()
	defer repo.mu.Unlock()
	liveLane, executedLane, recordedLane := repo.updates[0].Lane, repo.updates[1].Lane, repo.updates[2].Lane
	if liveLane != executedLane {
		t.Fatal("a recovered message that is processed like a live one left the group's lane")
	}
	if liveLane == recordedLane {
		t.Fatal("record-only history shares the live lane and would hold the group's live messages back")
	}
	if repo.updates[0].Subject != "QQ:group:9" || repo.updates[2].Subject != "QQ:group:9" {
		t.Fatal("record-only history is not part of the conversation's plaintext subject")
	}
	if recordedLane != `["ep-1","group","QQ:group:9","recorded-history"]` {
		t.Fatalf("record-only lane=%q", recordedLane)
	}
}
