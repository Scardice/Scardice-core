package messageflow

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

const (
	CallbackMaxPreMarkerAttempts       = 3
	MessageWorkflowAggregateType       = "message-workflow"
	MessageWorkflowTerminatedEventType = "message-workflow.terminated"
	MaxWorkflowIDBytes                 = 255
)

var (
	ErrCallbackUnavailable = errors.New("messageflow: callback service unavailable")
	ErrCallbackPayload     = errors.New("messageflow: invalid callback payload")
	ErrCallbackScope       = errors.New("messageflow: invalid callback scope")
	ErrCallbackWorkflow    = errors.New("messageflow: invalid callback workflow")
	ErrCallbackLease       = errors.New("messageflow: callback lease is invalid")
)

// CallbackScope is the provider-neutral owner lookup result for one message.
type CallbackScope struct {
	DiceID  string
	GroupID string
	UserID  string
}

// CallbackGroupLoader loads an immutable copy of the group-record read model.
type CallbackGroupLoader interface {
	Load(context.Context, string, string) (groupstate.State, error)
}

// CallbackPlayerLoader loads the player and group-user attribute read models.
type CallbackPlayerLoader interface {
	LoadPlayer(context.Context, string, string, string) (playerstate.PlayerState, error)
	LoadGroupUserAttrs(context.Context, string, string, string) (playerstate.GroupUserAttrsState, error)
}

// CallbackScopeResolver maps normalized ingress facts to durable state owners.
type CallbackScopeResolver interface {
	Resolve(context.Context, string, adapterapi.InboundMessage) (CallbackScope, error)
}

// CallbackRequest contains only copied provider-neutral facts and read models.
// It deliberately contains no encrypted ingress bytes, SDK pointers, or runtime
// compatibility objects.
type CallbackRequest struct {
	InboxID        string
	EndpointID     string
	Generation     uint64
	DesiredVersion uint64
	Message        adapterapi.InboundMessage
	Scope          CallbackScope
	Group          groupstate.CompatibilityView
	Player         playerstate.PlayerCompatibilityView
	Attrs          playerstate.GroupUserAttrsCompatibilityView
}

// WorkflowResult is returned only for a named asynchronous callback. The
// event must be the terminal event for the named message-workflow stream.
type WorkflowResult struct {
	ID              string
	ExpectedVersion uint64
	Event           eventstore.NewEvent
}

// CallbackResult is the compatibility host's durable decision. Mutations are
// collected through the supplied MutationCollector; only an explicit Workflow
// creates a message-workflow stream.
type CallbackResult struct {
	Workflow *WorkflowResult
}

// CompatibilityHost is the one mutable legacy seam. The service calls it only
// after the inbox row has durably entered callback-started.
type CompatibilityHost interface {
	HandleCallback(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error)
}

// CallbackConfig wires the narrow durable callback service.
type CallbackConfig struct {
	Inbox    eventstore.InboxRepository
	Store    eventstore.Store
	Codec    eventstore.PayloadCodec
	Resolver CallbackScopeResolver
	Group    CallbackGroupLoader
	Player   CallbackPlayerLoader
	Host     CompatibilityHost
	WorkerID string

	LeaseDuration time.Duration
	Clock         eventstore.Clock
	Factory       eventstore.EventFactory
}

// CallbackResultSummary reports the durable terminal outcome of ProcessOne.
type CallbackResultSummary struct {
	InboxID    string
	WorkflowID string
	Attempts   int
	Status     string
}

// CallbackService claims and executes one inbox callback at a time.
type CallbackService struct {
	inbox    eventstore.InboxRepository
	store    eventstore.Store
	codec    eventstore.PayloadCodec
	resolver CallbackScopeResolver
	group    CallbackGroupLoader
	player   CallbackPlayerLoader
	host     CompatibilityHost
	workerID string
	lease    time.Duration
	clock    eventstore.Clock
	factory  eventstore.EventFactory
}

// NewCallbackService validates and constructs the durable callback service.
func NewCallbackService(config CallbackConfig) (*CallbackService, error) {
	if config.Inbox == nil || config.Store == nil || config.Codec == nil || config.Resolver == nil || config.Group == nil || config.Player == nil || config.Host == nil || strings.TrimSpace(config.WorkerID) == "" {
		return nil, ErrCallbackUnavailable
	}
	if config.LeaseDuration <= 0 {
		config.LeaseDuration = time.Minute
	}
	if config.Clock == nil {
		config.Clock = eventstore.SystemClock{}
	}
	if config.Factory.Clock == nil {
		config.Factory.Clock = config.Clock
	}
	if config.Factory.IDs == nil {
		config.Factory.IDs = eventstore.UUIDGenerator{}
	}
	return &CallbackService{
		inbox: config.Inbox, store: config.Store, codec: config.Codec, resolver: config.Resolver,
		group: config.Group, player: config.Player, host: config.Host, workerID: config.WorkerID,
		lease: config.LeaseDuration, clock: config.Clock, factory: config.Factory,
	}, nil
}

// ProcessOne claims the earliest unresolved lane item and either commits one
// atomic callback UnitOfWork or leaves the row failed/ambiguous. Host execution
// is never retried after callback-started.
func (s *CallbackService) ProcessOne(ctx context.Context) (summary CallbackResultSummary, err error) {
	if s == nil || s.inbox == nil || s.store == nil || s.codec == nil || s.resolver == nil || s.group == nil || s.player == nil || s.host == nil {
		return summary, ErrCallbackUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	for attempt := 1; attempt <= CallbackMaxPreMarkerAttempts; attempt++ {
		summary.Attempts = attempt
		lease, claimErr := s.inbox.ClaimInbox(ctx, eventstore.InboxClaimRequest{WorkerID: s.workerID, LeaseDuration: s.lease})
		if claimErr != nil {
			return summary, claimErr
		}
		if err := validateClaimAt(lease.Update, s.clock.Now(), s.workerID); err != nil {
			return summary, err
		}
		payload, decodeErr := s.decodeClaimed(ctx, lease.Update)
		if decodeErr != nil {
			_ = s.failLease(ctx, lease.Update)
			return summary, decodeErr
		}
		scope, group, player, attrs, loadErr := s.loadCallbackState(ctx, lease.Update.EndpointID, payload)
		if loadErr != nil {
			_ = s.failLease(ctx, lease.Update)
			return summary, loadErr
		}
		startedVersion, versionErr := nextCallbackVersion(lease.Update.Version)
		if versionErr != nil {
			_ = s.failLease(ctx, lease.Update)
			return summary, versionErr
		}
		marker := eventstore.InboxUpdate{
			InboxID: lease.Update.InboxID, ExpectedVersion: lease.Update.Version, Version: lease.Update.Version,
			Status: eventstore.InboxStatusCallbackStarted, LeaseOwner: lease.Update.LeaseOwner,
			LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
			LeaseExpiresAt: lease.Update.LeaseExpiresAt,
		}
		if _, markerErr := s.inbox.UpdateInbox(ctx, marker); markerErr != nil {
			if isPreMarkerConflict(markerErr) && attempt < CallbackMaxPreMarkerAttempts {
				continue
			}
			_ = s.failLease(ctx, lease.Update)
			return summary, markerErr
		}

		request := CallbackRequest{
			InboxID: lease.Update.InboxID, EndpointID: lease.Update.EndpointID,
			Generation: payload.Generation, DesiredVersion: payload.DesiredVersion,
			Message: cloneInboundMessage(payload.Message), Scope: scope,
			Group: group.CompatibilityView(), Player: player.CompatibilityView(), Attrs: attrs.CompatibilityView(),
		}
		overlay := playerstate.NewLocalOverlay()
		collector := NewMutationCollector(s.factory)
		callbackResult, hostErr := invokeCallbackHost(ctx, s.host, request, overlay, collector)
		if hostErr != nil {
			_ = s.markAmbiguous(ctx, lease.Update, startedVersion)
			return summary, hostErr
		}
		if workflowErr := validateWorkflowResult(callbackResult.Workflow); workflowErr != nil {
			_ = s.markAmbiguous(ctx, lease.Update, startedVersion)
			return summary, workflowErr
		}
		work, buildErr := collector.unitOfWork()
		if buildErr != nil {
			_ = s.markAmbiguous(ctx, lease.Update, startedVersion)
			return summary, buildErr
		}
		if callbackResult.Workflow != nil {
			if err := collector.addWorkflow(*callbackResult.Workflow); err != nil {
				_ = s.markAmbiguous(ctx, lease.Update, startedVersion)
				return summary, err
			}
			work, buildErr = collector.unitOfWork()
			if buildErr != nil {
				_ = s.markAmbiguous(ctx, lease.Update, startedVersion)
				return summary, buildErr
			}
		}
		completedAt := s.clock.Now().UTC()
		terminal := eventstore.InboxUpdate{
			InboxID: lease.Update.InboxID, ExpectedVersion: startedVersion, Version: startedVersion + 1,
			Status: eventstore.InboxStatusConfirmedConsumed, LeaseOwner: lease.Update.LeaseOwner,
			LeaseEpoch: lease.Update.LeaseEpoch, AttemptID: lease.Update.AttemptID,
			LeaseExpiresAt: lease.Update.LeaseExpiresAt, CompletedAt: completedAt,
		}
		if callbackResult.Workflow != nil {
			terminal.WorkflowID = callbackResult.Workflow.ID
		}
		work.InboxUpdates = append(work.InboxUpdates, terminal)
		if commitErr := eventstore.ValidateUnitOfWork(work); commitErr != nil {
			_ = s.markAmbiguous(ctx, lease.Update, startedVersion)
			return summary, commitErr
		}
		if _, commitErr := s.store.Commit(ctx, work); commitErr != nil {
			_ = s.markAmbiguous(ctx, lease.Update, startedVersion)
			return summary, commitErr
		}
		summary.InboxID, summary.Status = lease.Update.InboxID, eventstore.InboxStatusConfirmedConsumed
		if callbackResult.Workflow != nil {
			summary.WorkflowID = callbackResult.Workflow.ID
		}
		return summary, nil
	}
	return summary, eventstore.ErrConflict
}

func (s *CallbackService) decodeClaimed(ctx context.Context, update eventstore.InboxUpdate) (ingressPayload, error) {
	plaintext, err := s.codec.Decrypt(ctx, append([]byte(nil), update.PayloadCiphertext...), append([]byte(nil), update.PayloadNonce...), update.PayloadEncryptionKeyID)
	if err != nil {
		return ingressPayload{}, err
	}
	return decodeIngressPayload(plaintext)
}

func decodeIngressPayload(payload []byte) (ingressPayload, error) {
	if len(payload) == 0 || len(payload) > eventstore.MaxEventPayloadBytes {
		return ingressPayload{}, fmt.Errorf("%w: payload bound", ErrCallbackPayload)
	}
	var shape any
	decoder := json.NewDecoder(bytes.NewReader(payload))
	if err := decoder.Decode(&shape); err != nil || shape == nil {
		return ingressPayload{}, fmt.Errorf("%w: payload object", ErrCallbackPayload)
	}
	if _, ok := shape.(map[string]any); !ok || containsNull(shape) {
		return ingressPayload{}, fmt.Errorf("%w: null or non-object payload", ErrCallbackPayload)
	}
	decoder = json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var decoded ingressPayload
	if err := decoder.Decode(&decoded); err != nil {
		return ingressPayload{}, fmt.Errorf("%w: %v", ErrCallbackPayload, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ingressPayload{}, fmt.Errorf("%w: trailing payload", ErrCallbackPayload)
	}
	if decoded.Status != eventstore.InboxStatusPending || decoded.Generation == 0 || decoded.DesiredVersion == 0 || !decoded.EndpointID.Valid() || len(decoded.ContentDigest) == 0 || len(decoded.ContentDigest) > eventstore.MaxEventPayloadBytes {
		return ingressPayload{}, fmt.Errorf("%w: envelope fields", ErrCallbackPayload)
	}
	if err := decoded.Message.Validate(); err != nil {
		return ingressPayload{}, fmt.Errorf("%w: message", ErrCallbackPayload)
	}
	return decoded, nil
}

func containsNull(value any) bool {
	switch item := value.(type) {
	case nil:
		return true
	case []any:
		for _, child := range item {
			if containsNull(child) {
				return true
			}
		}
	case map[string]any:
		for _, child := range item {
			if containsNull(child) {
				return true
			}
		}
	}
	return false
}

func (s *CallbackService) loadCallbackState(ctx context.Context, endpoint string, payload ingressPayload) (CallbackScope, groupstate.State, playerstate.PlayerState, playerstate.GroupUserAttrsState, error) {
	scope, err := s.resolver.Resolve(ctx, endpoint, cloneInboundMessage(payload.Message))
	if err != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, err
	}
	if err := validateCallbackScope(scope); err != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, err
	}
	group, err := s.group.Load(ctx, scope.DiceID, scope.GroupID)
	if err != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, err
	}
	player, err := s.player.LoadPlayer(ctx, scope.DiceID, scope.GroupID, scope.UserID)
	if err != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, err
	}
	attrs, err := s.player.LoadGroupUserAttrs(ctx, scope.DiceID, scope.GroupID, scope.UserID)
	if err != nil {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, err
	}
	if group.Version > 0 && (group.DiceID != scope.DiceID || group.GroupID != scope.GroupID) {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, ErrCallbackScope
	}
	if player.Version > 0 && (player.DiceID != scope.DiceID || player.GroupID != scope.GroupID || player.UserID != scope.UserID) {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, ErrCallbackScope
	}
	if attrs.Version > 0 && (attrs.DiceID != scope.DiceID || attrs.GroupID != scope.GroupID || attrs.UserID != scope.UserID) {
		return CallbackScope{}, groupstate.State{}, playerstate.PlayerState{}, playerstate.GroupUserAttrsState{}, ErrCallbackScope
	}
	return scope, group.Clone(), player.Clone(), attrs.Clone(), nil
}

func validateCallbackScope(scope CallbackScope) error {
	if err := groupstate.ValidateIdentity(scope.DiceID, scope.GroupID); err != nil {
		return ErrCallbackScope
	}
	if err := groupstate.ValidatePlayerIdentity(scope.DiceID, scope.GroupID, scope.UserID); err != nil {
		return ErrCallbackScope
	}
	return nil
}

func validateClaimAt(update eventstore.InboxUpdate, now time.Time, workerID string) error {
	if update.InboxID == "" || update.Status != eventstore.InboxStatusLeased || update.Version == 0 || strings.TrimSpace(update.LeaseOwner) == "" || update.LeaseOwner != workerID || update.LeaseEpoch == 0 || strings.TrimSpace(update.AttemptID) == "" || len(update.PayloadCiphertext) == 0 || len(update.PayloadNonce) == 0 || strings.TrimSpace(update.PayloadEncryptionKeyID) == "" {
		return ErrCallbackLease
	}
	if !update.LeaseExpiresAt.IsZero() && !update.LeaseExpiresAt.After(now.UTC()) {
		return ErrCallbackLease
	}
	if !update.PayloadExpiresAt.IsZero() && !update.PayloadExpiresAt.After(now.UTC()) {
		return eventstore.ErrPayloadExpired
	}
	return nil
}

func nextCallbackVersion(version uint64) (uint64, error) {
	if version == ^uint64(0) {
		return 0, eventstore.ErrVersionExhausted
	}
	return version + 1, nil
}

func isPreMarkerConflict(err error) bool {
	return errors.Is(err, eventstore.ErrConflict) || errors.Is(err, eventstore.ErrParticipantConflict) || errors.Is(err, eventstore.ErrStaleLease)
}

func (s *CallbackService) failLease(ctx context.Context, lease eventstore.InboxUpdate) error {
	_, err := s.inbox.UpdateInbox(ctx, eventstore.InboxUpdate{
		InboxID: lease.InboxID, ExpectedVersion: lease.Version, Version: lease.Version,
		Status: eventstore.InboxStatusFailed, LeaseOwner: lease.LeaseOwner, LeaseEpoch: lease.LeaseEpoch,
		AttemptID: lease.AttemptID, LeaseExpiresAt: lease.LeaseExpiresAt,
	})
	return err
}

func (s *CallbackService) markAmbiguous(ctx context.Context, lease eventstore.InboxUpdate, version uint64) error {
	_, err := s.inbox.UpdateInbox(ctx, eventstore.InboxUpdate{
		InboxID: lease.InboxID, ExpectedVersion: version, Version: version,
		Status: eventstore.InboxStatusAmbiguous, LeaseOwner: lease.LeaseOwner, LeaseEpoch: lease.LeaseEpoch,
		AttemptID: lease.AttemptID, LeaseExpiresAt: lease.LeaseExpiresAt,
	})
	return err
}

func invokeCallbackHost(ctx context.Context, host CompatibilityHost, request CallbackRequest, overlay *playerstate.LocalOverlay, collector *MutationCollector) (result CallbackResult, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("messageflow: callback host panic")
		}
	}()
	return host.HandleCallback(ctx, request, overlay, collector)
}

func cloneInboundMessage(message adapterapi.InboundMessage) adapterapi.InboundMessage {
	message.Segments = append([]adapterapi.InboundSegment(nil), message.Segments...)
	return message
}

func validateWorkflowResult(workflow *WorkflowResult) error {
	if workflow == nil {
		return nil
	}
	if !validWorkflowID(workflow.ID) || workflow.ExpectedVersion == ^uint64(0) {
		return ErrCallbackWorkflow
	}
	if workflow.Event.EventType != MessageWorkflowTerminatedEventType || workflow.Event.SchemaVersion == 0 || workflow.Event.Metadata.EventID == "" || workflow.Event.Metadata.CommandID == "" || workflow.Event.Metadata.CorrelationID == "" || len(workflow.Event.Payload) == 0 || len(workflow.Event.Payload) > eventstore.MaxEventPayloadBytes {
		return ErrCallbackWorkflow
	}
	if containsOverlayBytes(workflow.Event.Payload) {
		return ErrCallbackWorkflow
	}
	return nil
}

func validWorkflowID(value string) bool {
	if strings.TrimSpace(value) == "" || len(value) > MaxWorkflowIDBytes {
		return false
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}

func containsOverlayBytes(value []byte) bool { return bytes.Contains(value, []byte("$t")) }

// MutationCollector is the sole callback mutation output. It owns copied
// event/effect/KV bytes and rejects duplicate participants before commit.
type MutationCollector struct {
	factory  eventstore.EventFactory
	streams  map[eventstore.StreamID]eventstore.StreamAppend
	plugins  map[string]eventstore.PluginKVUpdate
	effects  map[string]eventstore.NewEffect
	workflow *eventstore.StreamAppend
}

func NewMutationCollector(factory eventstore.EventFactory) *MutationCollector {
	if factory.Clock == nil {
		factory.Clock = eventstore.SystemClock{}
	}
	if factory.IDs == nil {
		factory.IDs = eventstore.UUIDGenerator{}
	}
	return &MutationCollector{factory: factory, streams: map[eventstore.StreamID]eventstore.StreamAppend{}, plugins: map[string]eventstore.PluginKVUpdate{}, effects: map[string]eventstore.NewEffect{}}
}

// AddStream adds already-decided events to one non-workflow stream.
func (c *MutationCollector) AddStream(stream eventstore.StreamID, expectedVersion uint64, events []eventstore.NewEvent) error {
	if c == nil || stream.AggregateType == "" || stream.AggregateID == "" || len(events) == 0 || stream.AggregateType == MessageWorkflowAggregateType {
		return ErrCallbackWorkflow
	}
	if _, exists := c.streams[stream]; exists {
		return eventstore.ErrDuplicateStream
	}
	if len(c.streams) >= eventstore.MaxUnitOfWorkStreams {
		return &eventstore.OversizeError{Bound: "unit of work streams", Limit: eventstore.MaxUnitOfWorkStreams, Actual: len(c.streams) + 1}
	}
	eventCount := len(events)
	for _, item := range c.streams {
		eventCount += len(item.Events)
	}
	if eventCount > eventstore.MaxUnitOfWorkEvents {
		return &eventstore.OversizeError{Bound: "unit of work events", Limit: eventstore.MaxUnitOfWorkEvents, Actual: eventCount}
	}
	copied := make([]eventstore.NewEvent, len(events))
	for i, event := range events {
		if event.EventType == "" || event.SchemaVersion == 0 || len(event.Payload) > eventstore.MaxEventPayloadBytes || event.Metadata.EventID == "" || event.Metadata.CommandID == "" || event.Metadata.CorrelationID == "" || containsOverlayBytes(event.Payload) {
			return eventstore.ErrInvalidEvent
		}
		copied[i] = cloneNewEvent(event)
	}
	c.streams[stream] = eventstore.StreamAppend{Stream: stream, ExpectedVersion: expectedVersion, Events: copied}
	return nil
}

// AddGroupEvents serializes typed Group facts with the injected event factory.
func (c *MutationCollector) AddGroupEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []groupstate.TypedEvent) error {
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

// AddPlayerEvents serializes typed Player facts with the injected event factory.
func (c *MutationCollector) AddPlayerEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.PlayerEvent) error {
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

// AddGroupUserAttrsEvents serializes typed group-user attribute facts.
func (c *MutationCollector) AddGroupUserAttrsEvents(stream eventstore.StreamID, expectedVersion uint64, metadata eventstore.Metadata, events []playerstate.GroupUserAttrsEvent) error {
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

// AddPluginKV adds an already encrypted plugin state update. Plaintext key or
// value APIs are intentionally absent.
func (c *MutationCollector) AddPluginKV(update eventstore.PluginKVUpdate) error {
	if c == nil || strings.TrimSpace(update.ExtensionID) == "" || len(update.KeyHMAC) == 0 || update.ValueSize < 0 || update.ValueSize > eventstore.MaxPluginValueBytes || containsOverlayBytes(update.KeyCiphertext) || containsOverlayBytes(update.ValueCiphertext) {
		return eventstore.ErrInvalidMetadata
	}
	if !update.Deleted && (len(update.KeyCiphertext) == 0 || len(update.KeyNonce) == 0 || len(update.ValueCiphertext) == 0 || len(update.ValueNonce) == 0 || strings.TrimSpace(update.EncryptionKeyID) == "") {
		return eventstore.ErrInvalidMetadata
	}
	if _, exists := c.plugins[pluginKey(update)]; exists {
		return eventstore.ErrDuplicateParticipant
	}
	update.KeyHMAC = append([]byte(nil), update.KeyHMAC...)
	update.KeyCiphertext = append([]byte(nil), update.KeyCiphertext...)
	update.KeyNonce = append([]byte(nil), update.KeyNonce...)
	update.ValueCiphertext = append([]byte(nil), update.ValueCiphertext...)
	update.ValueNonce = append([]byte(nil), update.ValueNonce...)
	c.plugins[pluginKey(update)] = update
	return nil
}

// AddEffect adds a prevalidated encrypted outbound intent.
func (c *MutationCollector) AddEffect(effect eventstore.NewEffect) error {
	if c == nil || strings.TrimSpace(effect.EffectID) == "" || strings.TrimSpace(effect.EndpointID) == "" || len(effect.LaneHMAC) == 0 || strings.TrimSpace(effect.EffectType) == "" || !validRisk(effect.RiskClass) || effect.Status != eventstore.OutboxStatusPending || len(effect.PayloadCiphertext) == 0 || len(effect.PayloadNonce) == 0 || strings.TrimSpace(effect.PayloadEncryptionKeyID) == "" || containsOverlayBytes(effect.PayloadCiphertext) {
		return eventstore.ErrInvalidMetadata
	}
	if _, exists := c.effects[effect.EffectID]; exists {
		return eventstore.ErrDuplicateParticipant
	}
	effect.LaneHMAC = append([]byte(nil), effect.LaneHMAC...)
	effect.PayloadCiphertext = append([]byte(nil), effect.PayloadCiphertext...)
	effect.PayloadNonce = append([]byte(nil), effect.PayloadNonce...)
	effect.ContentDigest = append([]byte(nil), effect.ContentDigest...)
	c.effects[effect.EffectID] = effect
	return nil
}

func (c *MutationCollector) addWorkflow(workflow WorkflowResult) error {
	if err := validateWorkflowResult(&workflow); err != nil {
		return err
	}
	stream := eventstore.StreamID{AggregateType: MessageWorkflowAggregateType, AggregateID: workflow.ID}
	if _, exists := c.streams[stream]; exists || c.workflow != nil {
		return eventstore.ErrDuplicateStream
	}
	c.workflow = &eventstore.StreamAppend{Stream: stream, ExpectedVersion: workflow.ExpectedVersion, Events: []eventstore.NewEvent{cloneNewEvent(workflow.Event)}}
	return nil
}

func (c *MutationCollector) unitOfWork() (eventstore.UnitOfWork, error) {
	if c == nil {
		return eventstore.UnitOfWork{}, ErrCallbackUnavailable
	}
	streams := make([]eventstore.StreamAppend, 0, len(c.streams)+1)
	for _, item := range c.streams {
		streams = append(streams, cloneStreamAppend(item))
	}
	if c.workflow != nil {
		streams = append(streams, cloneStreamAppend(*c.workflow))
	}
	sort.Slice(streams, func(i, j int) bool {
		if streams[i].Stream.AggregateType != streams[j].Stream.AggregateType {
			return streams[i].Stream.AggregateType < streams[j].Stream.AggregateType
		}
		return streams[i].Stream.AggregateID < streams[j].Stream.AggregateID
	})
	plugins := make([]eventstore.PluginKVUpdate, 0, len(c.plugins))
	for _, update := range c.plugins {
		plugins = append(plugins, clonePlugin(update))
	}
	sort.Slice(plugins, func(i, j int) bool {
		if plugins[i].ExtensionID != plugins[j].ExtensionID {
			return plugins[i].ExtensionID < plugins[j].ExtensionID
		}
		return bytes.Compare(plugins[i].KeyHMAC, plugins[j].KeyHMAC) < 0
	})
	effects := make([]eventstore.NewEffect, 0, len(c.effects))
	for _, effect := range c.effects {
		effects = append(effects, cloneEffect(effect))
	}
	sort.Slice(effects, func(i, j int) bool { return effects[i].EffectID < effects[j].EffectID })
	return eventstore.UnitOfWork{Streams: streams, PluginKVUpdates: plugins, Effects: effects}, nil
}

func pluginKey(update eventstore.PluginKVUpdate) string {
	return update.ExtensionID + "\x00" + string(update.KeyHMAC)
}
func validRisk(value string) bool {
	return value == eventstore.RiskPreDispatchRetryable || value == eventstore.RiskProviderIdempotent || value == eventstore.RiskNonIdempotentAfterDispatch
}
func cloneNewEvent(event eventstore.NewEvent) eventstore.NewEvent {
	event.Payload = append([]byte(nil), event.Payload...)
	return event
}
func cloneStreamAppend(item eventstore.StreamAppend) eventstore.StreamAppend {
	item.Events = append([]eventstore.NewEvent(nil), item.Events...)
	for i := range item.Events {
		item.Events[i] = cloneNewEvent(item.Events[i])
	}
	return item
}
func clonePlugin(item eventstore.PluginKVUpdate) eventstore.PluginKVUpdate {
	item.KeyHMAC = append([]byte(nil), item.KeyHMAC...)
	item.KeyCiphertext = append([]byte(nil), item.KeyCiphertext...)
	item.KeyNonce = append([]byte(nil), item.KeyNonce...)
	item.ValueCiphertext = append([]byte(nil), item.ValueCiphertext...)
	item.ValueNonce = append([]byte(nil), item.ValueNonce...)
	return item
}
func cloneEffect(item eventstore.NewEffect) eventstore.NewEffect {
	item.LaneHMAC = append([]byte(nil), item.LaneHMAC...)
	item.PayloadCiphertext = append([]byte(nil), item.PayloadCiphertext...)
	item.PayloadNonce = append([]byte(nil), item.PayloadNonce...)
	item.ContentDigest = append([]byte(nil), item.ContentDigest...)
	return item
}
