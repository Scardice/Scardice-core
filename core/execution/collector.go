package execution

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

var (
	ErrMutationUnavailable = errors.New("execution: mutation collector unavailable")
	ErrInvalidMutation     = errors.New("execution: invalid durable mutation")
)

// CollectorOption configures protocol-owned stream reservations without making
// the transaction-agnostic collector depend on the owning protocol package.
type CollectorOption func(*MutationCollector)

// WithReservedStreamTypes prevents callback/plugin code from staging streams
// owned by a surrounding protocol. The protocol may merge its validated work
// after host execution with MergeUnitOfWork.
func WithReservedStreamTypes(aggregateTypes ...string) CollectorOption {
	copied := append([]string(nil), aggregateTypes...)
	return func(c *MutationCollector) {
		if c.reservedStreamTypes == nil {
			c.reservedStreamTypes = make(map[string]struct{}, len(copied))
		}
		for _, aggregateType := range copied {
			if aggregateType != "" {
				c.reservedStreamTypes[aggregateType] = struct{}{}
			}
		}
	}
}

// OwnedWork is a prepared, callback-owned unit of work and its deduplication
// result. It deliberately contains no messageflow type.
type OwnedWork struct {
	work         eventstore.UnitOfWork
	deduplicated bool
}

func NewOwnedWork(work eventstore.UnitOfWork, deduplicated bool) OwnedWork {
	return OwnedWork{work: cloneUnitOfWork(work), deduplicated: deduplicated}
}

// MutationCollector is the sole durable mutation output for one execution. It
// owns all collected bytes and rejects conflicting identities before commit.
type MutationCollector struct {
	mu      sync.Mutex
	factory eventstore.EventFactory
	work    eventstore.UnitOfWork

	reservedStreamTypes map[string]struct{}

	streamVersions     map[eventstore.StreamID]uint64
	streamReadVersions map[eventstore.StreamID]uint64
	projectionRead     *eventstore.ProjectionReadExpectation
	pluginReads        map[[2]string]eventstore.PluginKVReadExpectation
	namespaceReads     map[string]eventstore.PluginKVNamespaceReadExpectation
	catalogReads       map[[2]string]eventstore.CatalogReadExpectation
	catalogUpdates     map[[2]string]eventstore.CatalogRevisionUpdate
	operationIDs       map[string]struct{}
	inboxIDs           map[string]struct{}
	effectIDs          map[string]struct{}
	artifactIDs        map[string]struct{}
	secretRefs         map[string]struct{}
	pluginUpdates      map[[2]string]struct{}
}

func NewMutationCollector(factory eventstore.EventFactory, options ...CollectorOption) *MutationCollector {
	if isNil(factory.Clock) {
		factory.Clock = eventstore.SystemClock{}
	}
	if isNil(factory.IDs) {
		factory.IDs = eventstore.UUIDGenerator{}
	}
	collector := &MutationCollector{
		factory:            factory,
		streamVersions:     make(map[eventstore.StreamID]uint64),
		streamReadVersions: make(map[eventstore.StreamID]uint64),
		pluginReads:        make(map[[2]string]eventstore.PluginKVReadExpectation),
		namespaceReads:     make(map[string]eventstore.PluginKVNamespaceReadExpectation),
		catalogReads:       make(map[[2]string]eventstore.CatalogReadExpectation),
		catalogUpdates:     make(map[[2]string]eventstore.CatalogRevisionUpdate),
		operationIDs:       make(map[string]struct{}),
		inboxIDs:           make(map[string]struct{}),
		effectIDs:          make(map[string]struct{}),
		artifactIDs:        make(map[string]struct{}),
		secretRefs:         make(map[string]struct{}),
		pluginUpdates:      make(map[[2]string]struct{}),
	}
	for _, option := range options {
		if option != nil {
			option(collector)
		}
	}
	return collector
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	return (reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface || reflected.Kind() == reflect.Func || reflected.Kind() == reflect.Map || reflected.Kind() == reflect.Slice) && reflected.IsNil()
}

// AddStream adds already-decided events to one non-reserved stream.
func (c *MutationCollector) AddStream(stream eventstore.StreamID, expectedVersion uint64, events []eventstore.NewEvent) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	if stream.AggregateType == "" || stream.AggregateID == "" || len(events) == 0 || containsTransientStream(stream) {
		return ErrInvalidMutation
	}
	c.mu.Lock()
	_, reserved := c.reservedStreamTypes[stream.AggregateType]
	c.mu.Unlock()
	if reserved {
		return ErrInvalidMutation
	}
	return c.AddUnitOfWork(eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{Stream: stream, ExpectedVersion: expectedVersion, Events: events}}})
}

func (c *MutationCollector) AddGroupEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []groupstate.TypedEvent) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := groupstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

func (c *MutationCollector) AddPlayerEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.PlayerEvent) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := playerstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

func (c *MutationCollector) AddModerationEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.ModerationEvent) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := playerstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

func (c *MutationCollector) AddGroupUserAttrsEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.GroupUserAttrsEvent) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	encoded := make([]eventstore.NewEvent, 0, len(events))
	for index, event := range events {
		itemMetadata := metadata
		if index > 0 {
			itemMetadata.EventID = ""
		}
		item, err := playerstate.NewEventWithFactory(c.factory, event, itemMetadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, item)
	}
	return c.AddStream(stream, expectedVersion, encoded)
}

func (c *MutationCollector) AddPluginKV(update eventstore.PluginKVUpdate) error {
	return c.AddPluginKVBatch([]eventstore.PluginKVUpdate{update})
}

func (c *MutationCollector) AddPluginKVBatch(updates []eventstore.PluginKVUpdate) error {
	if c == nil || len(updates) == 0 {
		return eventstore.ErrInvalidMetadata
	}
	return c.AddUnitOfWork(eventstore.UnitOfWork{PluginKVUpdates: updates})
}

func (c *MutationCollector) AddSecretUpdate(update eventstore.SecretUpdate) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	return c.AddUnitOfWork(eventstore.UnitOfWork{SecretUpdates: []eventstore.SecretUpdate{update}})
}

func (c *MutationCollector) AddEffect(effect eventstore.NewEffect) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	c.mu.Lock()
	_, exists := c.effectIDs[effect.EffectID]
	c.mu.Unlock()
	if exists {
		return eventstore.ErrDuplicateParticipant
	}
	return c.AddUnitOfWork(eventstore.UnitOfWork{Effects: []eventstore.NewEffect{effect}})
}

func (c *MutationCollector) AddLogUpdate(update eventstore.LogUpdate) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	return c.AddUnitOfWork(eventstore.UnitOfWork{LogUpdates: []eventstore.LogUpdate{update}})
}

func (c *MutationCollector) HasStoryLogStateUpdate(diceID, groupID string) bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, update := range c.work.LogUpdates {
		if update.IsStoryLogStateUpdate() && update.DiceID == diceID && update.GroupID == groupID {
			return true
		}
	}
	return false
}

// AddPreparedOutbound imports exactly one validated outbound stream, operation,
// and effect while rebinding all derived facts to the callback subject.
func (c *MutationCollector) AddPreparedOutbound(owned OwnedWork) error {
	if c == nil || owned.deduplicated {
		return eventstore.ErrInvalidMetadata
	}
	work := cloneUnitOfWork(owned.work)
	if len(work.Streams) != 1 || len(work.Operations) != 1 || len(work.Effects) != 1 || !unitOfWorkHasOnlyOutbound(work) {
		return eventstore.ErrInvalidMetadata
	}
	stream, operation, effect := work.Streams[0], work.Operations[0], work.Effects[0]
	if stream.Stream.AggregateType != "outbound-effect" || stream.Stream.AggregateID != effect.EffectID || operation.ResourceID != effect.EffectID || operation.OperationID == "" || operation.IdempotencyScope != "outbound" || operation.IdempotencyKey == "" {
		return eventstore.ErrInvalidMetadata
	}
	return c.AddUnitOfWork(work)
}

func unitOfWorkHasOnlyOutbound(work eventstore.UnitOfWork) bool {
	return len(work.StreamReads) == 0 && len(work.ProjectionReads) == 0 && len(work.PluginKVReads) == 0 && len(work.PluginKVNamespaceReads) == 0 && len(work.CatalogReads) == 0 && len(work.CatalogUpdates) == 0 && len(work.InboxUpdates) == 0 && len(work.ArtifactUpdates) == 0 && len(work.SecretUpdates) == 0 && len(work.PluginKVUpdates) == 0 && len(work.LogUpdates) == 0 && len(work.LogImports) == 0 && work.Execution == nil
}

func (c *MutationCollector) AddPreparedOutboundWithLog(owned OwnedWork, update eventstore.LogUpdate) error {
	if c == nil || owned.deduplicated {
		return eventstore.ErrInvalidMetadata
	}
	work := cloneUnitOfWork(owned.work)
	if len(work.Streams) != 1 || len(work.Operations) != 1 || len(work.Effects) != 1 || !unitOfWorkHasOnlyOutbound(work) {
		return eventstore.ErrInvalidMetadata
	}
	stream, operation, effect := work.Streams[0], work.Operations[0], work.Effects[0]
	if stream.Stream.AggregateType != "outbound-effect" || stream.Stream.AggregateID != effect.EffectID || operation.ResourceID != effect.EffectID || operation.OperationID == "" || operation.IdempotencyScope != "outbound" || operation.IdempotencyKey == "" {
		return eventstore.ErrInvalidMetadata
	}
	work.LogUpdates = append(work.LogUpdates, cloneLogUpdate(update))
	return c.AddUnitOfWork(work)
}

func (c *MutationCollector) HasPreparedOutboundOperation(operationID string) bool {
	if c == nil || operationID == "" {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, operation := range c.work.Operations {
		if operation.OperationID == operationID {
			return operation.Kind == "outbound-effect" && operation.IdempotencyScope == "outbound"
		}
	}
	return false
}

// AddUnitOfWork atomically contributes an owned fragment. Set-like read
// expectations are deduplicated only when the complete expectation is equal;
// conflicting observations fail rather than omitting a stale dependency.
func (c *MutationCollector) AddUnitOfWork(input eventstore.UnitOfWork) error {
	if c == nil {
		return ErrMutationUnavailable
	}
	work := cloneUnitOfWork(input)
	if err := validateCollectedWork(work); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.preflightLocked(work); err != nil {
		return err
	}
	c.installLocked(work)
	return nil
}

func validateCollectedWork(work eventstore.UnitOfWork) error {
	for _, appendStream := range work.Streams {
		if appendStream.Stream.AggregateType == "" || appendStream.Stream.AggregateID == "" || len(appendStream.Events) == 0 || containsTransientStream(appendStream.Stream) {
			return ErrInvalidMutation
		}
		for index, event := range appendStream.Events {
			var reason string
			switch {
			case event.EventType == "":
				reason = "missing event type"
			case event.SchemaVersion == 0:
				reason = "missing schema version"
			case len(event.Payload) > eventstore.MaxEventPayloadBytes:
				reason = "payload exceeds event bound"
			case event.Metadata.EventID == "" || event.Metadata.CommandID == "" || event.Metadata.CorrelationID == "":
				reason = "missing event, command or correlation ID"
			case containsTransientEvent(event):
				reason = "request-local identity/key or malformed JSON"
			}
			if reason != "" {
				return fmt.Errorf("%w: aggregate=%s event[%d]=%s: %s", eventstore.ErrInvalidEvent, appendStream.Stream.AggregateType, index, event.EventType, reason)
			}
		}
	}
	for _, update := range work.PluginKVUpdates {
		if strings.TrimSpace(update.ExtensionID) == "" || len(update.Value) > eventstore.MaxPluginValueBytes || containsTransientPlugin(update) {
			return eventstore.ErrInvalidMetadata
		}
	}
	for _, update := range work.SecretUpdates {
		if strings.TrimSpace(update.SecretRef) == "" || strings.TrimSpace(update.EndpointID) == "" || strings.TrimSpace(update.AdapterID) == "" || update.SecretVersion == 0 || len(update.Value) > eventstore.MaxSecretBytes || containsTransientSecret(update) {
			return eventstore.ErrInvalidMetadata
		}
	}
	for _, effect := range work.Effects {
		if strings.TrimSpace(effect.EffectID) == "" || strings.TrimSpace(effect.EndpointID) == "" || effect.Lane == "" || strings.TrimSpace(effect.EffectType) == "" || !validRisk(effect.RiskClass) || effect.Status != eventstore.OutboxStatusPending || len(effect.Payload) == 0 || containsTransientEffect(effect) {
			return eventstore.ErrInvalidMetadata
		}
		if effect.ExpectedVersion != 0 || effect.PrincipalID != "" {
			return eventstore.ErrInvalidMetadata
		}
	}
	return nil
}

func (c *MutationCollector) preflightLocked(work eventstore.UnitOfWork) error {
	if len(c.work.Streams)+len(work.Streams) > eventstore.MaxUnitOfWorkStreams {
		return &eventstore.OversizeError{Bound: "unit of work streams", Limit: eventstore.MaxUnitOfWorkStreams, Actual: len(c.work.Streams) + len(work.Streams)}
	}
	eventCount := 0
	for _, stream := range c.work.Streams {
		eventCount += len(stream.Events)
	}
	for _, stream := range work.Streams {
		eventCount += len(stream.Events)
	}
	if eventCount > eventstore.MaxUnitOfWorkEvents {
		return &eventstore.OversizeError{Bound: "unit of work events", Limit: eventstore.MaxUnitOfWorkEvents, Actual: eventCount}
	}

	streamWrites := make(map[eventstore.StreamID]struct{}, len(work.Streams))
	for _, appendStream := range work.Streams {
		if _, reserved := c.reservedStreamTypes[appendStream.Stream.AggregateType]; reserved {
			return ErrInvalidMutation
		}
		if _, exists := c.streamVersions[appendStream.Stream]; exists {
			return eventstore.ErrDuplicateStream
		}
		if _, exists := streamWrites[appendStream.Stream]; exists {
			return eventstore.ErrDuplicateStream
		}
		streamWrites[appendStream.Stream] = struct{}{}
		if expected, exists := c.streamReadVersions[appendStream.Stream]; exists && expected != appendStream.ExpectedVersion {
			return eventstore.ErrConflict
		}
	}
	streamReads := make(map[eventstore.StreamID]uint64, len(work.StreamReads))
	for _, read := range work.StreamReads {
		if read.Stream.AggregateType == "" || read.Stream.AggregateID == "" {
			return eventstore.ErrInvalidEvent
		}
		if expected, exists := c.streamReadVersions[read.Stream]; exists && expected != read.ExpectedVersion {
			return eventstore.ErrConflict
		}
		if expected, exists := c.streamVersions[read.Stream]; exists && expected != read.ExpectedVersion {
			return eventstore.ErrConflict
		}
		if expected, exists := streamReads[read.Stream]; exists && expected != read.ExpectedVersion {
			return eventstore.ErrConflict
		}
		streamReads[read.Stream] = read.ExpectedVersion
	}
	for _, appendStream := range work.Streams {
		if expected, exists := streamReads[appendStream.Stream]; exists && expected != appendStream.ExpectedVersion {
			return eventstore.ErrConflict
		}
	}

	for _, read := range work.ProjectionReads {
		if read.Generation == "" {
			return eventstore.ErrInvalidMetadata
		}
		if c.projectionRead != nil && *c.projectionRead != read {
			return eventstore.ErrConflict
		}
	}
	if len(work.ProjectionReads) > 1 {
		first := work.ProjectionReads[0]
		for _, read := range work.ProjectionReads[1:] {
			if read != first {
				return eventstore.ErrConflict
			}
		}
	}
	if err := preflightComparableReads(work.PluginKVReads, c.pluginReads, pluginReadKey, equalPluginRead); err != nil {
		return err
	}
	if err := preflightComparableReads(work.PluginKVNamespaceReads, c.namespaceReads, namespaceReadKey, equalNamespaceRead); err != nil {
		return err
	}
	if err := preflightComparableReads(work.CatalogReads, c.catalogReads, catalogReadKey, equalCatalogRead); err != nil {
		return err
	}
	if err := preflightComparableReads(work.CatalogUpdates, c.catalogUpdates, catalogUpdateKey, equalCatalogUpdate); err != nil {
		return err
	}

	if err := preflightIDs(work.Operations, c.operationIDs, func(item eventstore.OperationUpdate) string { return item.OperationID }); err != nil {
		return err
	}
	if err := preflightIDs(work.InboxUpdates, c.inboxIDs, func(item eventstore.InboxUpdate) string { return item.InboxID }); err != nil {
		return err
	}
	if err := preflightIDs(work.Effects, c.effectIDs, func(item eventstore.NewEffect) string { return item.EffectID }); err != nil {
		return err
	}
	if err := preflightIDs(work.ArtifactUpdates, c.artifactIDs, func(item eventstore.ArtifactUpdate) string { return item.ArtifactID }); err != nil {
		return err
	}
	if err := preflightIDs(work.SecretUpdates, c.secretRefs, func(item eventstore.SecretUpdate) string { return item.SecretRef }); err != nil {
		return err
	}
	if err := preflightIDs(work.PluginKVUpdates, c.pluginUpdates, pluginUpdateKey); err != nil {
		return err
	}
	if work.Execution != nil && c.work.Execution != nil {
		return eventstore.ErrDuplicateParticipant
	}
	return nil
}

func preflightIDs[T any, K comparable](items []T, existing map[K]struct{}, key func(T) K) error {
	seen := make(map[K]struct{}, len(items))
	var zero K
	for _, item := range items {
		identity := key(item)
		if identity == zero {
			return eventstore.ErrInvalidMetadata
		}
		if _, ok := existing[identity]; ok {
			return eventstore.ErrDuplicateParticipant
		}
		if _, ok := seen[identity]; ok {
			return eventstore.ErrDuplicateParticipant
		}
		seen[identity] = struct{}{}
	}
	return nil
}

func preflightComparableReads[T any, K comparable](items []T, existing map[K]T, key func(T) K, equal func(T, T) bool) error {
	batch := make(map[K]T, len(items))
	var zero K
	for _, item := range items {
		identity := key(item)
		if identity == zero {
			return eventstore.ErrInvalidMetadata
		}
		if current, ok := existing[identity]; ok && !equal(current, item) {
			return eventstore.ErrConflict
		}
		if current, ok := batch[identity]; ok && !equal(current, item) {
			return eventstore.ErrConflict
		}
		batch[identity] = item
	}
	return nil
}

func (c *MutationCollector) installLocked(work eventstore.UnitOfWork) {
	for _, read := range work.StreamReads {
		if _, exists := c.streamReadVersions[read.Stream]; !exists {
			c.streamReadVersions[read.Stream] = read.ExpectedVersion
			c.work.StreamReads = append(c.work.StreamReads, read)
		}
	}
	for _, read := range work.ProjectionReads {
		if c.projectionRead == nil {
			copyRead := read
			c.projectionRead = &copyRead
			c.work.ProjectionReads = append(c.work.ProjectionReads, read)
		}
	}
	installComparableReads(&c.work.PluginKVReads, work.PluginKVReads, c.pluginReads, pluginReadKey)
	installComparableReads(&c.work.PluginKVNamespaceReads, work.PluginKVNamespaceReads, c.namespaceReads, namespaceReadKey)
	installComparableReads(&c.work.CatalogReads, work.CatalogReads, c.catalogReads, catalogReadKey)
	installComparableReads(&c.work.CatalogUpdates, work.CatalogUpdates, c.catalogUpdates, catalogUpdateKey)
	for _, appendStream := range work.Streams {
		c.streamVersions[appendStream.Stream] = appendStream.ExpectedVersion
	}
	c.work.Streams = append(c.work.Streams, work.Streams...)
	installIDs(&c.work.Operations, work.Operations, c.operationIDs, func(item eventstore.OperationUpdate) string { return item.OperationID })
	installIDs(&c.work.InboxUpdates, work.InboxUpdates, c.inboxIDs, func(item eventstore.InboxUpdate) string { return item.InboxID })
	installIDs(&c.work.Effects, work.Effects, c.effectIDs, func(item eventstore.NewEffect) string { return item.EffectID })
	installIDs(&c.work.ArtifactUpdates, work.ArtifactUpdates, c.artifactIDs, func(item eventstore.ArtifactUpdate) string { return item.ArtifactID })
	installIDs(&c.work.SecretUpdates, work.SecretUpdates, c.secretRefs, func(item eventstore.SecretUpdate) string { return item.SecretRef })
	installIDs(&c.work.PluginKVUpdates, work.PluginKVUpdates, c.pluginUpdates, pluginUpdateKey)
	c.work.LogUpdates = append(c.work.LogUpdates, work.LogUpdates...)
	c.work.LogImports = append(c.work.LogImports, work.LogImports...)
	if work.Execution != nil {
		copyExecution := *work.Execution
		copyExecution.RequestDigest = slices.Clone(work.Execution.RequestDigest)
		c.work.Execution = &copyExecution
	}
}

func installComparableReads[T any, K comparable](target *[]T, items []T, index map[K]T, key func(T) K) {
	for _, item := range items {
		identity := key(item)
		if _, exists := index[identity]; exists {
			continue
		}
		index[identity] = item
		*target = append(*target, item)
	}
}

func installIDs[T any, K comparable](target *[]T, items []T, index map[K]struct{}, key func(T) K) {
	for _, item := range items {
		index[key(item)] = struct{}{}
		*target = append(*target, item)
	}
}

func pluginReadKey(read eventstore.PluginKVReadExpectation) [2]string {
	return [2]string{read.Namespace, read.Key}
}
func namespaceReadKey(read eventstore.PluginKVNamespaceReadExpectation) string {
	return read.Namespace
}
func catalogReadKey(read eventstore.CatalogReadExpectation) [2]string {
	return [2]string{read.Catalog, read.Owner}
}
func catalogUpdateKey(update eventstore.CatalogRevisionUpdate) [2]string {
	return [2]string{update.Catalog, update.Owner}
}
func pluginUpdateKey(update eventstore.PluginKVUpdate) [2]string {
	return [2]string{update.ExtensionID, update.Key}
}
func equalPluginRead(left, right eventstore.PluginKVReadExpectation) bool {
	return left.Namespace == right.Namespace && left.Key == right.Key && left.ExpectedRevision == right.ExpectedRevision && left.ExpectedExists == right.ExpectedExists
}
func equalNamespaceRead(left, right eventstore.PluginKVNamespaceReadExpectation) bool {
	return left.Namespace == right.Namespace && left.ExpectedRevision == right.ExpectedRevision
}
func equalCatalogRead(left, right eventstore.CatalogReadExpectation) bool {
	return left.Catalog == right.Catalog && left.Owner == right.Owner && left.ExpectedRevision == right.ExpectedRevision
}
func equalCatalogUpdate(left, right eventstore.CatalogRevisionUpdate) bool {
	return left.Catalog == right.Catalog && left.Owner == right.Owner && left.ExpectedRevision == right.ExpectedRevision
}

// UnitOfWork returns a detached, deterministically ordered snapshot. Effect,
// log-update, and log-import order is intentionally preserved because it is
// business order rather than set order.
func (c *MutationCollector) UnitOfWork() (eventstore.UnitOfWork, error) {
	if c == nil {
		return eventstore.UnitOfWork{}, ErrMutationUnavailable
	}
	c.mu.Lock()
	work := cloneUnitOfWork(c.work)
	c.mu.Unlock()
	normalizeUnitOfWork(&work)
	return work, nil
}

// MergeUnitOfWork validates, owns, and deterministically merges independent
// fragments without exposing a second collector implementation.
func MergeUnitOfWork(parts ...eventstore.UnitOfWork) (eventstore.UnitOfWork, error) {
	collector := NewMutationCollector(eventstore.EventFactory{})
	for _, part := range parts {
		if err := collector.AddUnitOfWork(part); err != nil {
			return eventstore.UnitOfWork{}, err
		}
	}
	return collector.UnitOfWork()
}

func normalizeUnitOfWork(work *eventstore.UnitOfWork) {
	sort.Slice(work.StreamReads, func(i, j int) bool { return streamLess(work.StreamReads[i].Stream, work.StreamReads[j].Stream) })
	sort.Slice(work.ProjectionReads, func(i, j int) bool {
		if work.ProjectionReads[i].Generation != work.ProjectionReads[j].Generation {
			return work.ProjectionReads[i].Generation < work.ProjectionReads[j].Generation
		}
		return false
	})
	sort.Slice(work.PluginKVReads, func(i, j int) bool {
		return identityPairLess(pluginReadKey(work.PluginKVReads[i]), pluginReadKey(work.PluginKVReads[j]))
	})
	sort.Slice(work.PluginKVNamespaceReads, func(i, j int) bool {
		return namespaceReadKey(work.PluginKVNamespaceReads[i]) < namespaceReadKey(work.PluginKVNamespaceReads[j])
	})
	sort.Slice(work.CatalogReads, func(i, j int) bool {
		return identityPairLess(catalogReadKey(work.CatalogReads[i]), catalogReadKey(work.CatalogReads[j]))
	})
	sort.Slice(work.CatalogUpdates, func(i, j int) bool {
		return identityPairLess(catalogUpdateKey(work.CatalogUpdates[i]), catalogUpdateKey(work.CatalogUpdates[j]))
	})
	sort.Slice(work.Streams, func(i, j int) bool { return streamLess(work.Streams[i].Stream, work.Streams[j].Stream) })
	sort.Slice(work.Operations, func(i, j int) bool { return work.Operations[i].OperationID < work.Operations[j].OperationID })
	sort.Slice(work.InboxUpdates, func(i, j int) bool { return work.InboxUpdates[i].InboxID < work.InboxUpdates[j].InboxID })
	sort.Slice(work.ArtifactUpdates, func(i, j int) bool { return work.ArtifactUpdates[i].ArtifactID < work.ArtifactUpdates[j].ArtifactID })
	sort.Slice(work.SecretUpdates, func(i, j int) bool { return work.SecretUpdates[i].SecretRef < work.SecretUpdates[j].SecretRef })
	sort.Slice(work.PluginKVUpdates, func(i, j int) bool {
		return identityPairLess(pluginUpdateKey(work.PluginKVUpdates[i]), pluginUpdateKey(work.PluginKVUpdates[j]))
	})
}

func identityPairLess(left, right [2]string) bool {
	if left[0] != right[0] {
		return left[0] < right[0]
	}
	return left[1] < right[1]
}

func streamLess(left, right eventstore.StreamID) bool {
	if left.AggregateType != right.AggregateType {
		return left.AggregateType < right.AggregateType
	}
	return left.AggregateID < right.AggregateID
}

func cloneUnitOfWork(work eventstore.UnitOfWork) eventstore.UnitOfWork {
	cloned := work
	cloned.StreamReads = append([]eventstore.StreamReadExpectation(nil), work.StreamReads...)
	cloned.ProjectionReads = append([]eventstore.ProjectionReadExpectation(nil), work.ProjectionReads...)
	cloned.PluginKVReads = clonePluginReads(work.PluginKVReads)
	cloned.PluginKVNamespaceReads = clonePluginNamespaceReads(work.PluginKVNamespaceReads)
	cloned.CatalogReads = cloneCatalogReads(work.CatalogReads)
	cloned.CatalogUpdates = cloneCatalogUpdates(work.CatalogUpdates)
	cloned.Streams = make([]eventstore.StreamAppend, len(work.Streams))
	for i := range work.Streams {
		cloned.Streams[i] = cloneStreamAppend(work.Streams[i])
	}
	cloned.Operations = make([]eventstore.OperationUpdate, len(work.Operations))
	for i := range work.Operations {
		cloned.Operations[i] = cloneOperation(work.Operations[i])
	}
	cloned.InboxUpdates = make([]eventstore.InboxUpdate, len(work.InboxUpdates))
	for i := range work.InboxUpdates {
		cloned.InboxUpdates[i] = cloneInbox(work.InboxUpdates[i])
	}
	cloned.Effects = make([]eventstore.NewEffect, len(work.Effects))
	for i := range work.Effects {
		cloned.Effects[i] = cloneEffect(work.Effects[i])
	}
	cloned.ArtifactUpdates = make([]eventstore.ArtifactUpdate, len(work.ArtifactUpdates))
	for i := range work.ArtifactUpdates {
		cloned.ArtifactUpdates[i] = cloneArtifact(work.ArtifactUpdates[i])
	}
	cloned.SecretUpdates = make([]eventstore.SecretUpdate, len(work.SecretUpdates))
	for i := range work.SecretUpdates {
		cloned.SecretUpdates[i] = cloneSecret(work.SecretUpdates[i])
	}
	cloned.PluginKVUpdates = make([]eventstore.PluginKVUpdate, len(work.PluginKVUpdates))
	for i := range work.PluginKVUpdates {
		cloned.PluginKVUpdates[i] = clonePlugin(work.PluginKVUpdates[i])
	}
	cloned.LogUpdates = make([]eventstore.LogUpdate, len(work.LogUpdates))
	for i := range work.LogUpdates {
		cloned.LogUpdates[i] = cloneLogUpdate(work.LogUpdates[i])
	}
	cloned.LogImports = make([]eventstore.StoryLogImportRecord, len(work.LogImports))
	for i := range work.LogImports {
		cloned.LogImports[i] = cloneLogImport(work.LogImports[i])
	}
	if work.Execution != nil {
		execution := *work.Execution
		execution.RequestDigest = slices.Clone(work.Execution.RequestDigest)
		cloned.Execution = &execution
	}
	return cloned
}

func clonePluginReads(reads []eventstore.PluginKVReadExpectation) []eventstore.PluginKVReadExpectation {
	return slices.Clone(reads)
}
func clonePluginNamespaceReads(reads []eventstore.PluginKVNamespaceReadExpectation) []eventstore.PluginKVNamespaceReadExpectation {
	return slices.Clone(reads)
}
func cloneCatalogReads(reads []eventstore.CatalogReadExpectation) []eventstore.CatalogReadExpectation {
	return slices.Clone(reads)
}
func cloneCatalogUpdates(updates []eventstore.CatalogRevisionUpdate) []eventstore.CatalogRevisionUpdate {
	return slices.Clone(updates)
}
func cloneNewEvent(event eventstore.NewEvent) eventstore.NewEvent {
	event.Payload = slices.Clone(event.Payload)
	return event
}
func cloneStreamAppend(item eventstore.StreamAppend) eventstore.StreamAppend {
	events := item.Events
	item.Events = make([]eventstore.NewEvent, len(events))
	for i := range events {
		item.Events[i] = cloneNewEvent(events[i])
	}
	return item
}
func cloneOperation(item eventstore.OperationUpdate) eventstore.OperationUpdate {
	item.RequestDigest = slices.Clone(item.RequestDigest)
	item.PrivateContext = slices.Clone(item.PrivateContext)
	return item
}
func cloneInbox(item eventstore.InboxUpdate) eventstore.InboxUpdate {
	item.Payload = slices.Clone(item.Payload)
	item.ContentDigest = slices.Clone(item.ContentDigest)
	return item
}
func cloneEffect(item eventstore.NewEffect) eventstore.NewEffect {
	item.Payload = slices.Clone(item.Payload)
	item.ContentDigest = slices.Clone(item.ContentDigest)
	return item
}
func cloneArtifact(item eventstore.ArtifactUpdate) eventstore.ArtifactUpdate {
	item.Data = slices.Clone(item.Data)
	return item
}
func cloneSecret(item eventstore.SecretUpdate) eventstore.SecretUpdate {
	item.Value = slices.Clone(item.Value)
	return item
}
func clonePlugin(item eventstore.PluginKVUpdate) eventstore.PluginKVUpdate {
	item.Value = slices.Clone(item.Value)
	return item
}
func cloneStoryLogEntry(entry eventstore.StoryLogEntry) eventstore.StoryLogEntry {
	entry.CommandInfo = slices.Clone(entry.CommandInfo)
	if entry.Seq != nil {
		value := *entry.Seq
		entry.Seq = &value
	}
	if entry.Removed != nil {
		value := *entry.Removed
		entry.Removed = &value
	}
	if entry.ParentID != nil {
		value := *entry.ParentID
		entry.ParentID = &value
	}
	return entry
}
func cloneLogUpdate(update eventstore.LogUpdate) eventstore.LogUpdate {
	update.Entry = cloneStoryLogEntry(update.Entry)
	update.Intent.Entry = cloneStoryLogEntry(update.Intent.Entry)
	return update
}
func cloneLogImport(record eventstore.StoryLogImportRecord) eventstore.StoryLogImportRecord {
	if record.Session != nil {
		session := *record.Session
		if record.Session.Extra != nil {
			extra := *record.Session.Extra
			session.Extra = &extra
		}
		record.Session = &session
	}
	if record.Entry != nil {
		entry := cloneStoryLogEntry(*record.Entry)
		record.Entry = &entry
	}
	if record.State != nil {
		state := *record.State
		record.State = &state
	}
	return record
}

func validRisk(value string) bool {
	return value == eventstore.RiskPreDispatchRetryable || value == eventstore.RiskProviderIdempotent || value == eventstore.RiskNonIdempotentAfterDispatch
}

// ContainsTransientText reports request-local overlay identity. It is exported
// so messageflow can apply the same rule to protocol-owned workflow facts.
func ContainsTransientText(value string) bool { return strings.Contains(value, "$t") }

// ContainsTransientEvent reports transient durable identity/key facts or
// malformed/duplicate-key JSON. String values under payload identity fields
// (id/key/ref and their camel-case suffix forms) are request-local only when
// they start with the DiceScript temporary-variable prefix "$t"; ordinary
// durable text, including identity values that merely contain "$t", is accepted.
// Payload object keys containing "$t" remain rejected.
func ContainsTransientEvent(event eventstore.NewEvent) bool { return containsTransientEvent(event) }

func containsTransientStream(stream eventstore.StreamID) bool {
	return ContainsTransientText(stream.AggregateType) || ContainsTransientText(stream.AggregateID)
}
func containsTransientMetadata(metadata eventstore.Metadata) bool {
	return ContainsTransientText(metadata.EventID) || ContainsTransientText(metadata.CommandID) || ContainsTransientText(metadata.CorrelationID) || ContainsTransientText(metadata.CausationID) || ContainsTransientText(metadata.PrincipalID) || ContainsTransientText(metadata.Producer)
}
func containsTransientEvent(event eventstore.NewEvent) bool {
	return ContainsTransientText(event.EventType) || containsTransientMetadata(event.Metadata) || containsTransientPayload(event.Payload)
}
func containsTransientPlugin(update eventstore.PluginKVUpdate) bool {
	return ContainsTransientText(update.ExtensionID) || ContainsTransientText(update.Key)
}
func containsTransientSecret(update eventstore.SecretUpdate) bool {
	return ContainsTransientText(update.SecretRef) || ContainsTransientText(update.EndpointID) || ContainsTransientText(update.AdapterID)
}
func containsTransientEffect(effect eventstore.NewEffect) bool {
	return ContainsTransientText(effect.EffectID) || ContainsTransientText(effect.EndpointID) || ContainsTransientText(effect.EffectType) || ContainsTransientText(effect.RiskClass) || ContainsTransientText(effect.Status) || ContainsTransientText(effect.AttemptID) || ContainsTransientText(effect.LeaseOwner) || ContainsTransientText(effect.ProviderMessageID) || ContainsTransientText(effect.ResultCode) || ContainsTransientText(effect.ErrorCode) || ContainsTransientText(effect.Resolution) || ContainsTransientText(effect.PrincipalID) || ContainsTransientText(effect.Reason)
}
func containsTransientPayload(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	transient, err := scanJSONValue(decoder, false)
	if err != nil {
		return true
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return true
	}
	return transient
}

func transientIdentityField(key string) bool {
	switch key {
	case "id", "ids", "key", "keys", "ref", "refs", "members", "helpPackages":
		return true
	}
	return strings.HasSuffix(key, "Id") ||
		strings.HasSuffix(key, "ID") ||
		strings.HasSuffix(key, "Ids") ||
		strings.HasSuffix(key, "IDs") ||
		strings.HasSuffix(key, "Key") ||
		strings.HasSuffix(key, "Keys") ||
		strings.HasSuffix(key, "Ref") ||
		strings.HasSuffix(key, "Refs")
}

// scanJSONValue reports request-local payload content. identityValue marks
// values below an identity field, where only a "$t" prefix is request-local.
func scanJSONValue(decoder *json.Decoder, identityValue bool) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	switch value := token.(type) {
	case string:
		return identityValue && strings.HasPrefix(value, "$t"), nil
	case json.Delim:
		switch value {
		case '{':
			seen := make(map[string]struct{})
			transient := false
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return false, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return false, errors.New("invalid JSON object key")
				}
				if _, duplicate := seen[key]; duplicate {
					return false, errors.New("duplicate JSON object key")
				}
				seen[key] = struct{}{}
				child, err := scanJSONValue(decoder, identityValue || transientIdentityField(key))
				if err != nil {
					return false, err
				}
				transient = transient || ContainsTransientText(key) || child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				if err == nil {
					err = errors.New("invalid JSON object")
				}
				return false, err
			}
			return transient, nil
		case '[':
			transient := false
			for decoder.More() {
				child, err := scanJSONValue(decoder, identityValue)
				if err != nil {
					return false, err
				}
				transient = transient || child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				if err == nil {
					err = errors.New("invalid JSON array")
				}
				return false, err
			}
			return transient, nil
		}
		return false, errors.New("unexpected JSON delimiter")
	default:
		return false, nil
	}
}
