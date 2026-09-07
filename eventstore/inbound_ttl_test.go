package eventstore

import (
	"context"
	"testing"
	"time"
)

func TestInboxIngressAllowsExplicitReacceptAfterDedupeTTL(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	first := task5Inbox("ttl-reaccept-first", "ttl-reaccept-provider", "ttl-reaccept-lane")
	first.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	if _, err := store.AcceptInbox(ctx, first); err != nil { t.Fatal(err) }
	clock.Advance(7*24*time.Hour + time.Second)
	second := task5Inbox("ttl-reaccept-second", "ttl-reaccept-provider", "ttl-reaccept-lane")
	second.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	second.AllowExpiredDedupe = true
	result, err := store.AcceptInbox(ctx, second)
	if err != nil { t.Fatal(err) }
	if result.Deduplicated || len(result.InboxIDs) != 1 || result.InboxIDs[0] != second.InboxID {
		t.Fatalf("post-TTL result = %#v", result)
	}
}

func TestInboxIngressAllowsExplicitReacceptAfterTerminalDedupeTTL(t *testing.T) {
	store, db, clock := task5Store(t)
	defer db.Close()
	ctx := context.Background()
	first := task5Inbox("ttl-terminal-first", "ttl-terminal-provider", "ttl-terminal-lane")
	first.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	if _, err := store.AcceptInbox(ctx, first); err != nil { t.Fatal(err) }
	lease, err := store.ClaimInbox(ctx, InboxClaimRequest{WorkerID: "ttl-terminal-worker", LeaseDuration: time.Minute})
	if err != nil { t.Fatal(err) }
	if _, err := store.ResolveInbox(ctx, InboxResolutionRequest{InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Resolution: InboxResolutionConfirmedConsumed, PrincipalID: "test", Reason: "terminal"}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(7*24*time.Hour + time.Second)
	second := task5Inbox("ttl-terminal-second", "ttl-terminal-provider", "ttl-terminal-lane")
	second.PayloadExpiresAt = clock.Now().Add(7 * 24 * time.Hour)
	second.AllowExpiredDedupe = true
	result, err := store.AcceptInbox(ctx, second)
	if err != nil { t.Fatal(err) }
	if result.Deduplicated || len(result.InboxIDs) != 1 || result.InboxIDs[0] != second.InboxID {
		t.Fatalf("post-terminal-TTL result = %#v", result)
	}
}
