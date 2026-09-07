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
