package dice

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"

	"Scardice-core/core/execution"
	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
)

var ErrJSPluginKV = errors.New("dice: invalid JS plugin KV mutation")

func validateJSPluginExtension(extensionID string) error {
	if strings.TrimSpace(extensionID) == "" || strings.Contains(extensionID, "$t") {
		return ErrJSPluginKV
	}
	if len(extensionID) > eventstore.MaxPluginExtensionBytes {
		return &eventstore.OversizeError{Bound: "plugin extension bytes", Limit: eventstore.MaxPluginExtensionBytes, Actual: len(extensionID)}
	}
	return nil
}

func nextJSPluginVersion(version uint64) (uint64, error) {
	if version >= ^uint64(0)>>1 {
		return 0, eventstore.ErrVersionExhausted
	}
	return version + 1, nil
}

type callbackCommitFence interface {
	TryLock() bool
	Unlock()
}

// DurableCallbackTransaction is the controlled facade for exactly one
// DomainTx. Durable state is owned by typed DomainTx participants; this wrapper
// contains no parallel snapshots, overlays, or dirty-save queue.
type DurableCallbackTransaction struct {
	store               eventstore.Store
	collector           *execution.MutationCollector
	domain              *execution.DomainTx
	metadata            eventstore.Metadata
	executionContext    context.Context
	callbackCommitFence callbackCommitFence
	callbackPublication []func()
	callbackAfterCommit []func()

	finalizeMu sync.Mutex
	finalized  bool
}

func NewDurableCallbackTransaction(
	ctx context.Context,
	store eventstore.Store,
	collector *execution.MutationCollector,
	metadata eventstore.Metadata,
) (*DurableCallbackTransaction, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if store == nil || collector == nil {
		return nil, execution.ErrDomainTxUnavailable
	}
	domain, err := execution.NewDomainTx(ctx, store, collector, metadata)
	if err != nil {
		return nil, err
	}
	return &DurableCallbackTransaction{
		store: store, collector: collector, domain: domain, metadata: metadata, executionContext: ctx,
	}, nil
}

func (t *DurableCallbackTransaction) Domain() *execution.DomainTx {
	if t == nil {
		return nil
	}
	return t.domain
}

func (t *DurableCallbackTransaction) occurredAt() time.Time {
	if t != nil && !t.metadata.OccurredAt.IsZero() {
		return t.metadata.OccurredAt
	}
	return time.Now().UTC()
}

// Finalize closes mutation before contributing each canonical participant.
// The wrapper invokes DomainTx.Seal exactly once even when callers duplicate
// finalization or the first seal fails.
func (t *DurableCallbackTransaction) Finalize(ctx context.Context) error {
	if t == nil || t.domain == nil {
		return execution.ErrDomainTxUnavailable
	}
	t.finalizeMu.Lock()
	if t.finalized {
		t.finalizeMu.Unlock()
		return execution.ErrDomainTxClosed
	}
	t.finalized = true
	t.finalizeMu.Unlock()
	return t.domain.Seal(ctx)
}

func (t *DurableCallbackTransaction) AfterCommit(fn func()) error {
	if t == nil || t.domain == nil || fn == nil {
		return execution.ErrDomainTxUnavailable
	}
	t.finalizeMu.Lock()
	defer t.finalizeMu.Unlock()
	if t.finalized {
		return execution.ErrDomainTxClosed
	}
	t.callbackAfterCommit = append(t.callbackAfterCommit, fn)
	return nil
}

// AfterCommitPublication registers a trusted, nonblocking in-memory ownership
// handoff. It runs after durable success while the commit fence is still held;
// it must not perform I/O, call user code, or reload runtime state.
func (t *DurableCallbackTransaction) AfterCommitPublication(fn func()) error {
	if t == nil || t.domain == nil || fn == nil {
		return execution.ErrDomainTxUnavailable
	}
	t.finalizeMu.Lock()
	defer t.finalizeMu.Unlock()
	if t.finalized {
		return execution.ErrDomainTxClosed
	}
	if err := t.domain.CheckOpen(); err != nil {
		return err
	}
	t.callbackPublication = append(t.callbackPublication, fn)
	return nil
}

func (t *DurableCallbackTransaction) Abort() {
	if t == nil || t.domain == nil {
		return
	}
	t.finalizeMu.Lock()
	if !t.finalized {
		t.finalized = true
		t.domain.Abort()
	}
	t.finalizeMu.Unlock()
}

type pluginKVEntry struct {
	snapshot eventstore.PluginKVLookupSnapshot
	item     eventstore.PluginKVItem
	exists   bool
	update   *eventstore.PluginKVUpdate
	revision uint64
}

type pluginKVParticipant struct {
	mu        sync.RWMutex
	extension string
	entries   map[string]*pluginKVEntry
	namespace *eventstore.PluginKVListSnapshot
	// namespaceObserved records that the namespace revision is already a read
	// dependency of the unit of work (set by list reads only).
	namespaceObserved bool
}

func (p *pluginKVParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	updates := make([]eventstore.PluginKVUpdate, 0, len(p.entries))
	for _, entry := range p.entries {
		if entry.update != nil {
			updates = append(updates, *entry.update)
		}
	}
	sort.Slice(updates, func(i, j int) bool { return updates[i].Key < updates[j].Key })
	return eventstore.UnitOfWork{PluginKVUpdates: updates}, nil
}

func pluginKVParticipantKey(extensionID string) execution.ParticipantKey {
	return execution.ParticipantKey{Kind: "plugin-kv", ID: extensionID}
}

func (t *DurableCallbackTransaction) pluginParticipant(ctx context.Context, extensionID string) (*pluginKVParticipant, error) {
	if t == nil || t.domain == nil || validateJSPluginExtension(extensionID) != nil {
		return nil, ErrJSPluginKV
	}
	// Plugin values are persisted as plaintext in schema v2.
	key := pluginKVParticipantKey(extensionID)
	participant, err := t.domain.Owner(ctx, key, func(context.Context) (execution.Participant, execution.ReadDependencies, error) {
		return &pluginKVParticipant{extension: extensionID, entries: make(map[string]*pluginKVEntry)}, execution.ReadDependencies{}, nil
	})
	if err != nil {
		return nil, err
	}
	owner, ok := participant.(*pluginKVParticipant)
	if !ok {
		return nil, execution.ErrParticipantType
	}
	return owner, nil
}

func (t *DurableCallbackTransaction) ensurePluginKey(ctx context.Context, owner *pluginKVParticipant, key string) (*pluginKVEntry, error) {
	if strings.Contains(key, "$t") {
		return nil, ErrJSPluginKV
	}
	if len(key) > eventstore.MaxPluginKeyBytes {
		return nil, &eventstore.OversizeError{Bound: "plugin key bytes", Limit: eventstore.MaxPluginKeyBytes, Actual: len(key)}
	}
	owner.mu.RLock()
	entry := owner.entries[key]
	owner.mu.RUnlock()
	if entry != nil {
		return entry, nil
	}
	backend, ok := t.store.(eventstore.PluginKVSnapshotRepository)
	if !ok {
		return nil, ErrJSPluginKV
	}
	snapshot, err := backend.LookupPluginKVSnapshot(ctx, owner.extension, key)
	if err != nil {
		return nil, err
	}
	if err = t.domain.AddReadDependencies(execution.ReadDependencies{
		PluginKVReads: []eventstore.PluginKVReadExpectation{{
			Namespace: snapshot.Namespace, Key: snapshot.Key,
			ExpectedRevision: snapshot.KeyRevision, ExpectedExists: snapshot.Found,
		}},
		ProjectionReads: []eventstore.ProjectionReadExpectation{{
			Generation: snapshot.Snapshot.ProjectionGeneration,
		}},
	}); err != nil {
		return nil, err
	}
	participantKey := pluginKVParticipantKey(owner.extension)
	err = t.domain.Mutate(participantKey, func(participant execution.Participant) error {
		current, ok := participant.(*pluginKVParticipant)
		if !ok || current != owner {
			return execution.ErrParticipantType
		}
		current.mu.Lock()
		defer current.mu.Unlock()
		if current.entries[key] == nil {
			item := snapshot.Item
			item.Value = append([]byte(nil), item.Value...)
			current.entries[key] = &pluginKVEntry{snapshot: snapshot, item: item, exists: snapshot.Found}
		}
		entry = current.entries[key]
		return nil
	})
	return entry, err
}

// observePluginNamespace is the list path: the script observes the whole
// namespace, so the snapshot revision becomes a commit-time read dependency.
func (t *DurableCallbackTransaction) observePluginNamespace(ctx context.Context, owner *pluginKVParticipant) (*eventstore.PluginKVListSnapshot, error) {
	owner.mu.RLock()
	snapshot := owner.namespace
	depends := owner.namespaceObserved
	owner.mu.RUnlock()
	if snapshot != nil && depends {
		return snapshot, nil
	}
	if snapshot != nil {
		if err := t.addPluginNamespaceDependency(owner, snapshot); err != nil {
			return nil, err
		}
		return snapshot, nil
	}
	backend, ok := t.store.(eventstore.PluginKVSnapshotRepository)
	if !ok {
		return nil, ErrJSPluginKV
	}
	loaded, err := backend.ListPluginKVSnapshot(ctx, eventstore.PluginKVListRequest{
		ExtensionID: owner.extension, Limit: eventstore.MaxPluginResults,
	})
	if err != nil {
		return nil, err
	}
	participantKey := pluginKVParticipantKey(owner.extension)
	err = t.domain.Mutate(participantKey, func(participant execution.Participant) error {
		current, ok := participant.(*pluginKVParticipant)
		if !ok || current != owner {
			return execution.ErrParticipantType
		}
		current.mu.Lock()
		defer current.mu.Unlock()
		if current.namespace == nil {
			copySnapshot := loaded
			copySnapshot.Namespace = loaded.Namespace
			copySnapshot.Items = make([]eventstore.PluginKVItem, len(loaded.Items))
			for index, item := range loaded.Items {
				item.Value = append([]byte(nil), item.Value...)
				copySnapshot.Items[index] = item
			}
			current.namespace = &copySnapshot
		}
		snapshot = current.namespace
		return nil
	})
	if err != nil {
		return nil, err
	}
	if err = t.addPluginNamespaceDependency(owner, snapshot); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func (t *DurableCallbackTransaction) addPluginNamespaceDependency(owner *pluginKVParticipant, snapshot *eventstore.PluginKVListSnapshot) error {
	owner.mu.Lock()
	if owner.namespaceObserved {
		owner.mu.Unlock()
		return nil
	}
	owner.namespaceObserved = true
	owner.mu.Unlock()
	return t.domain.AddReadDependencies(execution.ReadDependencies{
		PluginKVNamespaceReads: []eventstore.PluginKVNamespaceReadExpectation{{
			Namespace: snapshot.Namespace, ExpectedRevision: snapshot.NamespaceRevision,
		}},
		ProjectionReads: []eventstore.ProjectionReadExpectation{{
			Generation: snapshot.Snapshot.ProjectionGeneration,
		}},
	})
}

func (t *DurableCallbackTransaction) pluginPut(ctx context.Context, extensionID, key string, value []byte) error {
	if len(value) > eventstore.MaxPluginValueBytes {
		return &eventstore.OversizeError{Bound: "plugin value bytes", Limit: eventstore.MaxPluginValueBytes, Actual: len(value)}
	}
	// The store checks namespace quotas atomically against the final batch.
	owner, err := t.pluginParticipant(ctx, extensionID)
	if err != nil {
		return err
	}
	entry, err := t.ensurePluginKey(ctx, owner, key)
	if err != nil {
		return err
	}
	owner.mu.RLock()
	baseVersion := uint64(0)
	if entry.snapshot.Found {
		baseVersion = entry.snapshot.Item.Version
	}
	revision := entry.revision
	owner.mu.RUnlock()
	version, err := nextJSPluginVersion(baseVersion)
	if err != nil {
		return err
	}
	update := eventstore.PluginKVUpdate{ExtensionID: extensionID, Key: key, ExpectedVersion: baseVersion, Version: version, Value: append([]byte(nil), value...), UpdatedAt: t.occurredAt()}
	ownedValue := append([]byte(nil), value...)
	return t.domain.Mutate(pluginKVParticipantKey(extensionID), func(participant execution.Participant) error {
		current, ok := participant.(*pluginKVParticipant)
		if !ok || current != owner {
			return execution.ErrParticipantType
		}
		current.mu.Lock()
		defer current.mu.Unlock()
		currentEntry := current.entries[key]
		if currentEntry == nil || currentEntry.revision != revision {
			return eventstore.ErrConflict
		}
		currentEntry.item = eventstore.PluginKVItem{ExtensionID: extensionID, Key: key, Value: ownedValue, Version: version}
		currentEntry.exists = true
		currentEntry.update = &update
		currentEntry.revision++
		return nil
	})
}

func (t *DurableCallbackTransaction) pluginDelete(ctx context.Context, extensionID, key string) error {
	owner, err := t.pluginParticipant(ctx, extensionID)
	if err != nil {
		return err
	}
	entry, err := t.ensurePluginKey(ctx, owner, key)
	if err != nil {
		return err
	}
	owner.mu.RLock()
	exists := entry.exists
	baseExists := entry.snapshot.Found
	baseVersion := uint64(0)
	if baseExists {
		baseVersion = entry.snapshot.Item.Version
	}
	revision := entry.revision
	owner.mu.RUnlock()
	version := uint64(0)
	var update *eventstore.PluginKVUpdate
	if exists {
		version, err = nextJSPluginVersion(baseVersion)
		if err != nil {
			return err
		}
		prepared := eventstore.PluginKVUpdate{ExtensionID: extensionID, Key: key, ExpectedVersion: baseVersion, Version: version, Deleted: true, UpdatedAt: t.occurredAt()}
		update = &prepared
	}
	return t.domain.Mutate(pluginKVParticipantKey(extensionID), func(participant execution.Participant) error {
		current, ok := participant.(*pluginKVParticipant)
		if !ok || current != owner {
			return execution.ErrParticipantType
		}
		current.mu.Lock()
		defer current.mu.Unlock()
		currentEntry := current.entries[key]
		if currentEntry == nil || currentEntry.revision != revision {
			return eventstore.ErrConflict
		}
		if !currentEntry.exists {
			return nil
		}
		currentEntry.exists = false
		currentEntry.item = eventstore.PluginKVItem{ExtensionID: extensionID, Key: key, Version: version}
		if baseExists {
			currentEntry.update = update
		} else {
			currentEntry.update = nil
		}
		currentEntry.revision++
		return nil
	})
}

func (t *DurableCallbackTransaction) pluginGet(ctx context.Context, extensionID, key string) (eventstore.PluginKVItem, error) {
	owner, err := t.pluginParticipant(ctx, extensionID)
	if err != nil {
		return eventstore.PluginKVItem{}, err
	}
	entry, err := t.ensurePluginKey(ctx, owner, key)
	if err != nil {
		return eventstore.PluginKVItem{}, err
	}
	owner.mu.RLock()
	defer owner.mu.RUnlock()
	if !entry.exists {
		return eventstore.PluginKVItem{}, eventstore.ErrPluginKVNotFound
	}
	item := entry.item
	item.Value = append([]byte(nil), item.Value...)
	return item, nil
}

func (t *DurableCallbackTransaction) pluginList(ctx context.Context, extensionID, prefix string, limit int) ([]eventstore.PluginKVItem, error) {
	if strings.Contains(prefix, "$t") || len(prefix) > eventstore.MaxPluginKeyBytes {
		return nil, ErrJSPluginKV
	}
	if limit <= 0 {
		limit = eventstore.MaxPluginResults
	}
	if limit > eventstore.MaxPluginResults {
		return nil, &eventstore.OversizeError{Bound: "plugin results", Limit: eventstore.MaxPluginResults, Actual: limit}
	}
	owner, err := t.pluginParticipant(ctx, extensionID)
	if err != nil {
		return nil, err
	}
	snapshot, err := t.observePluginNamespace(ctx, owner)
	if err != nil {
		return nil, err
	}
	owner.mu.RLock()
	merged := make(map[string]eventstore.PluginKVItem, len(snapshot.Items)+len(owner.entries))
	for _, item := range snapshot.Items {
		if strings.HasPrefix(item.Key, prefix) {
			item.Value = append([]byte(nil), item.Value...)
			merged[item.Key] = item
		}
	}
	for key, entry := range owner.entries {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if !entry.exists {
			delete(merged, key)
			continue
		}
		item := entry.item
		item.Value = append([]byte(nil), item.Value...)
		merged[key] = item
	}
	owner.mu.RUnlock()
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	items := make([]eventstore.PluginKVItem, 0, min(limit, len(keys)))
	responseBytes := 0
	for _, key := range keys {
		if len(items) == limit {
			break
		}
		item := merged[key]
		responseBytes += len(item.Key) + len(item.Value)
		if responseBytes > eventstore.MaxPluginResponseBytes {
			return nil, &eventstore.OversizeError{Bound: "plugin response bytes", Limit: eventstore.MaxPluginResponseBytes, Actual: responseBytes}
		}
		items = append(items, item)
	}
	return items, nil
}

func (t *DurableCallbackTransaction) StorageSet(ctx context.Context, extensionID, key, value string) error {
	return t.pluginPut(ctx, extensionID, key, []byte(value))
}

func (t *DurableCallbackTransaction) StorageGet(ctx context.Context, extensionID, key string) (string, error) {
	item, err := t.pluginGet(ctx, extensionID, key)
	if errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(item.Value), nil
}

func (t *DurableCallbackTransaction) StorageDelete(ctx context.Context, extensionID, key string) error {
	return t.pluginDelete(ctx, extensionID, key)
}

func (t *DurableCallbackTransaction) StorageList(ctx context.Context, extensionID string) ([]string, error) {
	items, err := t.pluginList(ctx, extensionID, "", eventstore.MaxPluginResults)
	if err != nil {
		return nil, err
	}
	keys := make([]string, len(items))
	for index, item := range items {
		keys[index] = item.Key
	}
	return keys, nil
}

func (ctx *MsgContext) ExtensionStorageSet(extensionID, key, value string) error {
	if err := ctx.checkExecution(); err != nil {
		return err
	}
	if ctx == nil || ctx.callbackTransaction == nil {
		return ErrDurableStateUnavailable
	}
	return ctx.callbackTransaction.StorageSet(context.Background(), extensionID, key, value)
}

func (ctx *MsgContext) ExtensionStorageGet(extensionID, key string) (string, error) {
	if err := ctx.checkExecution(); err != nil {
		return "", err
	}
	if ctx == nil || ctx.callbackTransaction == nil {
		return "", ErrDurableStateUnavailable
	}
	return ctx.callbackTransaction.StorageGet(context.Background(), extensionID, key)
}

func (ctx *MsgContext) ExtensionConfigSet(extensionID, key string, value any) error {
	if err := ctx.checkExecution(); err != nil {
		return err
	}
	if ctx == nil || ctx.Dice == nil || ctx.callbackTransaction == nil {
		return ErrDurableStateUnavailable
	}
	state, err := ctx.Dice.ExtensionStateForDomain(context.Background(), ctx.callbackTransaction.Domain())
	if err != nil {
		return err
	}
	definition, ok := state.ConfigDefinitions[extensionID][key]
	if !ok {
		return extensionstate.ErrUnknownConfig
	}
	configValue, err := durableConfigValue(definition.Type, value)
	if err != nil {
		return err
	}
	return ctx.Dice.ContributeExtensionCommand(context.Background(), ctx.callbackTransaction.Domain(), ctx.callbackMetadata, extensionstate.Command{
		Kind: extensionstate.CommandSetConfig, ExtensionID: extensionID, Key: key, Value: configValue,
	})
}

func (ctx *MsgContext) ExtensionConfigValue(extensionID, key string) (any, bool, error) {
	if err := ctx.checkExecution(); err != nil {
		return nil, false, err
	}
	if ctx == nil || ctx.Dice == nil || ctx.callbackTransaction == nil {
		return nil, false, ErrDurableStateUnavailable
	}
	state, err := ctx.Dice.ExtensionStateForDomain(context.Background(), ctx.callbackTransaction.Domain())
	if err != nil {
		return nil, false, err
	}
	_, ok := state.ConfigDefinitions[extensionID][key]
	if !ok {
		return nil, false, nil
	}
	value, ok := state.ConfigValues[extensionID][key]
	if !ok {
		return nil, false, nil
	}
	return durableLegacyValue(value), true, nil
}
