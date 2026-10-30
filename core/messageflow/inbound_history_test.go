package messageflow

import (
	"bytes"
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
	svc, err := NewInboundService(repo, ingressCryptoStub{})
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
	liveLane, executedLane, recordedLane := repo.updates[0].LaneHMAC, repo.updates[1].LaneHMAC, repo.updates[2].LaneHMAC
	if !bytes.Equal(liveLane, executedLane) {
		t.Fatal("a recovered message that is processed like a live one left the group's lane")
	}
	if bytes.Equal(liveLane, recordedLane) {
		t.Fatal("record-only history shares the live lane and would hold the group's live messages back")
	}
	if !bytes.Equal(repo.updates[0].SubjectKey, repo.updates[2].SubjectKey) {
		t.Fatal("record-only history is not part of the conversation's privacy subject")
	}
}
