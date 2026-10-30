package messageflow

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

func TestCallbackSQLiteA6RenewsAcrossCommitFenceAndCommitsHostMutation(t *testing.T) {
	// Keep lease deadlines independent of SQLite and race-instrumentation CPU time.
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		source := defaultIntegrationKeySource()
		db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
			Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-lease-fence.db"),
			KeySource: source, DatabaseIdentity: "callback-lease-fence",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := eventstore.NewStore(db)
		observedInbox := &callbackLeaseObservedInbox{InboxRepository: store}
		observedStore := &callbackLeaseObservedStore{Store: store}
		inbound, err := NewInboundService(observedInbox, store)
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"first", "successor"} {
			receipt, ingressErr := inbound.HandleInbound(ctx, endpoint.FencedInbound{
				EndpointID: "lease-endpoint", Generation: 1, DesiredVersion: 1,
				Message: adapterapi.InboundMessage{
					ProviderEventID: adapterapi.ProviderEventID(id), MessageID: adapterapi.MessageID(id),
					Platform: "test", Sender: "sender", Conversation: "group",
					ConversationKind: adapterapi.ConversationKindGroup, Target: "group",
					Kind: adapterapi.InboundKindMessage, Text: id,
				},
			})
			if ingressErr != nil {
				t.Fatal(ingressErr)
			}
			if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID == "" {
				t.Fatalf("ingress %q receipt=%#v", id, receipt)
			}
		}

		fence := newCallbackBlockingCommitFence()
		stream := eventstore.StreamID{AggregateType: "callback-lease-test", AggregateID: "host-mutation"}
		host := &callbackLeaseFenceHost{fence: fence, stream: stream, hookOrder: make(chan string, 2)}
		service, err := NewCallbackService(CallbackConfig{
			Inbox: observedInbox, Store: observedStore, BoundCodec: store,
			Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
			Host: host, WorkerID: "lease-worker", LeaseDuration: 300 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}

		type processResult struct {
			summary CallbackResultSummary
			err     error
		}
		done := make(chan processResult, 1)
		go func() {
			summary, processErr := service.ProcessOne(ctx)
			done <- processResult{summary: summary, err: processErr}
		}()
		defer fence.allowLock()

		select {
		case <-fence.entered:
		case result := <-done:
			t.Fatalf("callback ended before its commit fence: summary=%#v err=%v", result.summary, result.err)
		case <-time.After(2 * time.Second):
			t.Fatal("callback did not reach its commit fence")
		}
		timer := time.NewTimer(450 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-time.After(2 * time.Second):
			t.Fatal("callback fence wait did not cross the lease duration")
		}
		if renewals, _ := observedInbox.renewalSnapshot(); renewals == 0 {
			select {
			case result := <-done:
				t.Fatalf("callback ended without a successful renewal: summary=%#v err=%v", result.summary, result.err)
			default:
				t.Fatal("callback has no successful renewal while waiting at its commit fence")
			}
		}
		fence.allowLock()

		var first processResult
		select {
		case first = <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("callback did not finish after its commit fence opened")
		}
		if first.err != nil || first.summary.Status != eventstore.InboxStatusConfirmedConsumed {
			t.Fatalf("first callback summary=%#v err=%v", first.summary, first.err)
		}
		select {
		case <-fence.unlocked:
		default:
			t.Fatal("callback returned before releasing the commit fence")
		}
		if fence.locked.Load() {
			t.Fatal("commit fence remained locked after callback completion")
		}
		select {
		case got := <-host.hookOrder:
			if got != "after-commit" {
				t.Fatalf("first callback hook=%q, want after-commit", got)
			}
		case <-time.After(time.Second):
			t.Fatal("AfterCommit hook did not run")
		}
		select {
		case got := <-host.hookOrder:
			if got != "release" {
				t.Fatalf("second callback hook=%q, want release", got)
			}
		case <-time.After(time.Second):
			t.Fatal("Release hook did not run")
		}
		if host.afterCommit.Load() != 1 || host.releases.Load() != 1 {
			t.Fatalf("after-commit=%d releases=%d", host.afterCommit.Load(), host.releases.Load())
		}

		renewals, renewedVersion := observedInbox.renewalSnapshot()
		terminalCommits, terminalExpected, terminalVersion := observedStore.terminalSnapshot()
		if renewals == 0 || terminalCommits != 1 || terminalExpected != renewedVersion || terminalVersion != terminalExpected+1 {
			t.Fatalf("renewals=%d renewedVersion=%d terminal commits=%d expected=%d version=%d", renewals, renewedVersion, terminalCommits, terminalExpected, terminalVersion)
		}
		events, err := store.Load(ctx, stream, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 1 {
			t.Fatalf("Host mutation events=%d, want 1", len(events))
		}

		next, err := service.ProcessOne(ctx)
		if err != nil || next.Status != eventstore.InboxStatusConfirmedConsumed {
			t.Fatalf("successor summary=%#v err=%v", next, err)
		}
		if _, err := service.ProcessOne(ctx); !errors.Is(err, eventstore.ErrNotFound) {
			t.Fatalf("completed callback was replayed: %v", err)
		}
		if host.calls.Load() != 2 {
			t.Fatalf("Host calls=%d, want first callback and successor only", host.calls.Load())
		}
	})
}

func TestCallbackFenceCancellationReturnsWithoutLateCommit(t *testing.T) {
	inbox := &callbackCancellationInbox{callbackTestInbox: newCallbackTestInbox()}
	store := newCallbackRecordingStore()
	fence := newCallbackBlockingCommitFence()
	var afterCommit atomic.Int64
	released := make(chan struct{}, 1)
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		return CallbackResult{
			CommitFence: fence,
			AfterCommit: func() { afterCommit.Add(1) },
			Release:     func() { released <- struct{}{} },
		}, nil
	}}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: inbox, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{},
		Host: host, WorkerID: "worker", LeaseDuration: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	type processResult struct {
		summary CallbackResultSummary
		err     error
	}
	done := make(chan processResult, 1)
	go func() {
		summary, processErr := service.ProcessOne(ctx)
		done <- processResult{summary: summary, err: processErr}
	}()
	defer fence.allowLock()

	select {
	case <-fence.entered:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("callback did not begin waiting for the commit fence")
	}
	cancel()
	var result processResult
	select {
	case result = <-done:
	case <-time.After(250 * time.Millisecond):
		fence.allowLock()
		<-done
		t.Fatal("canceled callback remained blocked on the commit fence")
	}
	if !errors.Is(result.err, context.Canceled) || result.summary.Status != eventstore.InboxStatusAmbiguous {
		t.Fatalf("canceled callback summary=%#v err=%v", result.summary, result.err)
	}
	select {
	case <-released:
	default:
		t.Fatal("canceled callback returned without releasing Host state")
	}
	if afterCommit.Load() != 0 || store.commitCount() != 0 {
		t.Fatalf("canceled callback after-commit=%d commits=%d", afterCommit.Load(), store.commitCount())
	}
	ambiguousCalls, ambiguousContextErr := inbox.ambiguitySnapshot()
	if ambiguousCalls != 1 || ambiguousContextErr != nil {
		t.Fatalf("ambiguous calls=%d recovery context error=%v", ambiguousCalls, ambiguousContextErr)
	}
	if host.calls != 1 {
		t.Fatalf("Host calls=%d, want 1", host.calls)
	}

	fence.allowLock()
	timer := time.NewTimer(30 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-fence.unlocked:
		t.Fatal("canceled callback acquired the commit fence after returning")
	case <-timer.C:
	}
	if fence.locked.Load() || store.commitCount() != 0 || afterCommit.Load() != 0 {
		t.Fatalf("late fence state locked=%v commits=%d after-commit=%d", fence.locked.Load(), store.commitCount(), afterCommit.Load())
	}
}

func TestCallbackFenceHandoffUsesLastRenewedVersionWithoutTerminalRace(t *testing.T) {
	baseInbox := newCallbackTestInbox()
	inbox := &callbackHandoffInbox{
		callbackTestInbox: baseInbox,
		renewStarted:      make(chan struct{}),
		allowRenew:        make(chan struct{}),
	}
	store := newCallbackBlockingStore()
	fence := newCallbackBlockingCommitFence()
	host := &callbackTestHost{fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
		return CallbackResult{CommitFence: fence}, nil
	}}
	service, err := NewCallbackService(CallbackConfig{
		Inbox: inbox, Store: store, Codec: callbackTestCodec{}, AllowUnboundCodec: true,
		Resolver: callbackTestResolver{}, Group: callbackTestGroupLoader{}, Player: callbackTestPlayerLoader{},
		Host: host, WorkerID: "worker", LeaseDuration: 300 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	type processResult struct {
		summary CallbackResultSummary
		err     error
	}
	done := make(chan processResult, 1)
	go func() {
		summary, processErr := service.ProcessOne(context.Background())
		done <- processResult{summary: summary, err: processErr}
	}()
	defer fence.allowLock()
	defer inbox.allowRenewal()
	defer store.allowCommit()

	select {
	case <-fence.entered:
	case <-time.After(time.Second):
		t.Fatal("callback did not begin waiting for the commit fence")
	}
	select {
	case <-inbox.renewStarted:
	case <-time.After(time.Second):
		t.Fatal("callback did not renew while waiting for the commit fence")
	}
	fence.allowLock()
	inbox.allowRenewal()
	select {
	case <-store.entered:
	case <-time.After(time.Second):
		t.Fatal("callback did not hand the renewed version to terminal commit")
	}

	renewalsAtCommit := inbox.successfulRenewals.Load()
	timer := time.NewTimer(120 * time.Millisecond)
	<-timer.C
	if renewed := inbox.successfulRenewals.Load(); renewed != renewalsAtCommit {
		t.Fatalf("lease renewed after terminal ExpectedVersion was fixed: before=%d after=%d", renewalsAtCommit, renewed)
	}
	store.allowCommit()

	var result processResult
	select {
	case result = <-done:
	case <-time.After(time.Second):
		t.Fatal("callback did not finish terminal commit")
	}
	if result.err != nil || result.summary.Status != eventstore.InboxStatusConfirmedConsumed {
		t.Fatalf("callback summary=%#v err=%v", result.summary, result.err)
	}
	work, ok := store.onlyCommit()
	if !ok || len(work.InboxUpdates) != 1 {
		t.Fatalf("terminal commits=%#v", store.commitsSnapshot())
	}
	terminal := work.InboxUpdates[0]
	if terminal.ExpectedVersion != baseInbox.lease.Update.Version || terminal.Version != terminal.ExpectedVersion+1 {
		t.Fatalf("terminal expected=%d version=%d renewed lease version=%d", terminal.ExpectedVersion, terminal.Version, baseInbox.lease.Update.Version)
	}
	if len(baseInbox.updates) != 1 || baseInbox.updates[0].Status != eventstore.InboxStatusCallbackStarted {
		t.Fatalf("unexpected nonterminal inbox updates=%#v", baseInbox.updates)
	}
}

func TestCallbackSQLiteA6CommitConnectionWaitBecomesAmbiguousWithoutReplay(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		source := defaultIntegrationKeySource()
		db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{
			Type: "sqlite", DSN: filepath.Join(t.TempDir(), "callback-commit-wait.db"),
			KeySource: source, DatabaseIdentity: "callback-commit-wait",
		})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()

		store := eventstore.NewStore(db)
		inbound, err := NewInboundService(store, store)
		if err != nil {
			t.Fatal(err)
		}
		inboxIDs := make([]string, 0, 2)
		for _, id := range []string{"blocked-commit", "successor"} {
			receipt, ingressErr := inbound.HandleInbound(ctx, endpoint.FencedInbound{
				EndpointID: "commit-wait-endpoint", Generation: 1, DesiredVersion: 1,
				Message: adapterapi.InboundMessage{
					ProviderEventID: adapterapi.ProviderEventID(id), MessageID: adapterapi.MessageID(id),
					Platform: "test", Sender: "sender", Conversation: "group",
					ConversationKind: adapterapi.ConversationKindGroup, Target: "group",
					Kind: adapterapi.InboundKindMessage, Text: id,
				},
			})
			if ingressErr != nil {
				t.Fatal(ingressErr)
			}
			if receipt.Outcome != adapterapi.IngressAccepted || receipt.InboxID == "" {
				t.Fatalf("ingress %q receipt=%#v", id, receipt)
			}
			inboxIDs = append(inboxIDs, receipt.InboxID)
		}

		stream := eventstore.StreamID{AggregateType: "callback-lease-test", AggregateID: "blocked-host-mutation"}
		host := &callbackTestHost{}
		host.fn = func(_ context.Context, _ CallbackRequest, _ *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error) {
			if host.calls == 1 {
				if addErr := collector.AddStream(stream, 0, []eventstore.NewEvent{callbackEvent("callback.blocked-commit", `{"committed":true}`)}); addErr != nil {
					return CallbackResult{}, addErr
				}
			}
			return CallbackResult{}, nil
		}
		gatedStore := newCallbackConnectionWaitStore(store)
		service, err := NewCallbackService(CallbackConfig{
			Inbox: store, Store: gatedStore, BoundCodec: store,
			Resolver: callbackTestResolver{}, Group: groupstate.NewRepository(store), Player: playerstate.NewRepository(store),
			Host: host, WorkerID: "commit-wait-worker", LeaseDuration: 300 * time.Millisecond,
		})
		if err != nil {
			t.Fatal(err)
		}

		type processResult struct {
			summary CallbackResultSummary
			err     error
		}
		done := make(chan processResult, 1)
		go func() {
			summary, processErr := service.ProcessOne(ctx)
			done <- processResult{summary: summary, err: processErr}
		}()
		defer gatedStore.allowFirstCommit()

		select {
		case <-gatedStore.beforeFirstCommit:
		case result := <-done:
			t.Fatalf("callback ended before its first commit: summary=%#v err=%v", result.summary, result.err)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		heldConn, err := db.SQLDB().Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer heldConn.Close()
		gatedStore.allowFirstCommit()
		select {
		case <-gatedStore.firstCommitReturned:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if err := heldConn.Close(); err != nil {
			t.Fatal(err)
		}

		var first processResult
		select {
		case first = <-done:
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
		if first.err == nil || first.summary.Status != eventstore.InboxStatusAmbiguous {
			t.Fatalf("blocked commit summary=%#v err=%v", first.summary, first.err)
		}
		var row eventstoreInboxRowForTest
		if err := db.GORM().Table("inbox_messages").Where("inbox_id = ?", inboxIDs[0]).Scan(&row).Error; err != nil {
			t.Fatal(err)
		}
		if row.Status != eventstore.InboxStatusAmbiguous || len(row.PayloadCiphertext) != 0 {
			t.Fatalf("blocked commit inbox row=%#v", row)
		}
		events, err := store.Load(ctx, stream, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(events) != 0 {
			t.Fatalf("blocked Host mutation committed %d events", len(events))
		}

		next, err := service.ProcessOne(ctx)
		if err != nil || next.InboxID != inboxIDs[1] || next.Status != eventstore.InboxStatusConfirmedConsumed {
			t.Fatalf("successor summary=%#v err=%v", next, err)
		}
		if _, err := service.ProcessOne(ctx); !errors.Is(err, eventstore.ErrNotFound) {
			t.Fatalf("ambiguous callback was replayed: %v", err)
		}
		if host.calls != 2 {
			t.Fatalf("Host calls=%d, want blocked callback and successor only", host.calls)
		}
	})
}

type callbackBlockingCommitFence struct {
	entered     chan struct{}
	release     chan struct{}
	unlocked    chan struct{}
	lockOnce    sync.Once
	releaseOnce sync.Once
	unlockOnce  sync.Once
	locked      atomic.Bool
}

func newCallbackBlockingCommitFence() *callbackBlockingCommitFence {
	return &callbackBlockingCommitFence{entered: make(chan struct{}), release: make(chan struct{}), unlocked: make(chan struct{})}
}

func (f *callbackBlockingCommitFence) TryLock() bool {
	f.lockOnce.Do(func() { close(f.entered) })
	select {
	case <-f.release:
		return f.locked.CompareAndSwap(false, true)
	default:
		return false
	}
}

func (f *callbackBlockingCommitFence) Unlock() {
	f.locked.Store(false)
	f.unlockOnce.Do(func() { close(f.unlocked) })
}

func (f *callbackBlockingCommitFence) allowLock() {
	f.releaseOnce.Do(func() { close(f.release) })
}

type callbackLeaseObservedInbox struct {
	eventstore.InboxRepository
	mu                 sync.Mutex
	successfulRenewals int
	lastRenewedVersion uint64
}

func (i *callbackLeaseObservedInbox) RenewInbox(ctx context.Context, request eventstore.InboxRenewRequest) (eventstore.InboxLease, error) {
	lease, err := i.InboxRepository.RenewInbox(ctx, request)
	if err == nil {
		i.mu.Lock()
		i.successfulRenewals++
		i.lastRenewedVersion = lease.Update.Version
		i.mu.Unlock()
	}
	return lease, err
}

func (i *callbackLeaseObservedInbox) renewalSnapshot() (int, uint64) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.successfulRenewals, i.lastRenewedVersion
}

type callbackLeaseObservedStore struct {
	eventstore.Store
	mu               sync.Mutex
	terminalCommits  int
	terminalExpected uint64
	terminalVersion  uint64
}

func (s *callbackLeaseObservedStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	for _, update := range work.InboxUpdates {
		if update.Status == eventstore.InboxStatusConfirmedConsumed {
			s.mu.Lock()
			s.terminalCommits++
			s.terminalExpected = update.ExpectedVersion
			s.terminalVersion = update.Version
			s.mu.Unlock()
		}
	}
	return s.Store.Commit(ctx, work)
}

func (s *callbackLeaseObservedStore) terminalSnapshot() (int, uint64, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.terminalCommits, s.terminalExpected, s.terminalVersion
}

type callbackLeaseFenceHost struct {
	fence       *callbackBlockingCommitFence
	stream      eventstore.StreamID
	hookOrder   chan string
	calls       atomic.Int64
	afterCommit atomic.Int64
	releases    atomic.Int64
}

func (h *callbackLeaseFenceHost) HandleCallback(_ context.Context, _ CallbackRequest, _ *playerstate.LocalOverlay, collector *MutationCollector) (CallbackResult, error) {
	if h.calls.Add(1) != 1 {
		return CallbackResult{}, nil
	}
	if err := collector.AddStream(h.stream, 0, []eventstore.NewEvent{callbackEvent("callback.lease-fence-committed", `{"committed":true}`)}); err != nil {
		return CallbackResult{}, err
	}
	return CallbackResult{
		CommitFence: h.fence,
		AfterCommit: func() {
			if !h.fence.locked.Load() {
				panic("AfterCommit ran outside commit fence")
			}
			h.afterCommit.Add(1)
			h.hookOrder <- "after-commit"
		},
		Release: func() {
			h.releases.Add(1)
			h.hookOrder <- "release"
		},
	}, nil
}

type callbackCancellationInbox struct {
	*callbackTestInbox
	mu                  sync.Mutex
	ambiguousCalls      int
	ambiguousContextErr error
}

func (i *callbackCancellationInbox) UpdateInbox(ctx context.Context, update eventstore.InboxUpdate) (eventstore.CommitResult, error) {
	if update.Status == eventstore.InboxStatusAmbiguous {
		i.mu.Lock()
		i.ambiguousCalls++
		i.ambiguousContextErr = ctx.Err()
		i.mu.Unlock()
	}
	return i.callbackTestInbox.UpdateInbox(ctx, update)
}

func (i *callbackCancellationInbox) ambiguitySnapshot() (int, error) {
	i.mu.Lock()
	defer i.mu.Unlock()
	return i.ambiguousCalls, i.ambiguousContextErr
}

type callbackRecordingStore struct {
	mu      sync.Mutex
	commits []eventstore.UnitOfWork
}

func newCallbackRecordingStore() *callbackRecordingStore { return &callbackRecordingStore{} }

func (s *callbackRecordingStore) Commit(_ context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.mu.Lock()
	s.commits = append(s.commits, work)
	s.mu.Unlock()
	return eventstore.CommitResult{}, nil
}

func (*callbackRecordingStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, nil
}

func (*callbackRecordingStore) Close() error { return nil }

func (s *callbackRecordingStore) commitCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.commits)
}

type callbackHandoffInbox struct {
	*callbackTestInbox
	renewStarted       chan struct{}
	allowRenew         chan struct{}
	renewStartedOnce   sync.Once
	allowRenewOnce     sync.Once
	successfulRenewals atomic.Int64
}

func (i *callbackHandoffInbox) RenewInbox(ctx context.Context, request eventstore.InboxRenewRequest) (eventstore.InboxLease, error) {
	i.renewStartedOnce.Do(func() { close(i.renewStarted) })
	<-i.allowRenew
	lease, err := i.callbackTestInbox.RenewInbox(ctx, request)
	if err == nil {
		i.successfulRenewals.Add(1)
	}
	return lease, err
}

func (i *callbackHandoffInbox) allowRenewal() {
	i.allowRenewOnce.Do(func() { close(i.allowRenew) })
}

type callbackBlockingStore struct {
	mu        sync.Mutex
	commits   []eventstore.UnitOfWork
	entered   chan struct{}
	allow     chan struct{}
	enterOnce sync.Once
	allowOnce sync.Once
}

func newCallbackBlockingStore() *callbackBlockingStore {
	return &callbackBlockingStore{entered: make(chan struct{}), allow: make(chan struct{})}
}

func (s *callbackBlockingStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	s.enterOnce.Do(func() { close(s.entered) })
	select {
	case <-s.allow:
	case <-ctx.Done():
		return eventstore.CommitResult{}, ctx.Err()
	}
	s.mu.Lock()
	s.commits = append(s.commits, work)
	s.mu.Unlock()
	return eventstore.CommitResult{}, nil
}

func (*callbackBlockingStore) Load(context.Context, eventstore.StreamID, uint64) ([]eventstore.Envelope, error) {
	return nil, nil
}

func (*callbackBlockingStore) Close() error { return nil }

func (s *callbackBlockingStore) allowCommit() {
	s.allowOnce.Do(func() { close(s.allow) })
}

func (s *callbackBlockingStore) commitsSnapshot() []eventstore.UnitOfWork {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]eventstore.UnitOfWork(nil), s.commits...)
}

func (s *callbackBlockingStore) onlyCommit() (eventstore.UnitOfWork, bool) {
	commits := s.commitsSnapshot()
	if len(commits) != 1 {
		return eventstore.UnitOfWork{}, false
	}
	return commits[0], true
}

type callbackConnectionWaitStore struct {
	eventstore.Store
	beforeFirstCommit   chan struct{}
	firstCommitAllowed  chan struct{}
	firstCommitReturned chan struct{}
	calls               atomic.Int64
	beforeOnce          sync.Once
	allowOnce           sync.Once
	returnedOnce        sync.Once
}

func newCallbackConnectionWaitStore(store eventstore.Store) *callbackConnectionWaitStore {
	return &callbackConnectionWaitStore{
		Store: store, beforeFirstCommit: make(chan struct{}),
		firstCommitAllowed: make(chan struct{}), firstCommitReturned: make(chan struct{}),
	}
}

func (s *callbackConnectionWaitStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	if s.calls.Add(1) != 1 {
		return s.Store.Commit(ctx, work)
	}
	s.beforeOnce.Do(func() { close(s.beforeFirstCommit) })
	select {
	case <-s.firstCommitAllowed:
	case <-ctx.Done():
		s.returnedOnce.Do(func() { close(s.firstCommitReturned) })
		return eventstore.CommitResult{}, ctx.Err()
	}
	result, err := s.Store.Commit(ctx, work)
	s.returnedOnce.Do(func() { close(s.firstCommitReturned) })
	return result, err
}

func (s *callbackConnectionWaitStore) allowFirstCommit() {
	s.allowOnce.Do(func() { close(s.firstCommitAllowed) })
}
