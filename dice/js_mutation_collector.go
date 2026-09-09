package dice

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

var (
	ErrJSMutationUnavailable = errors.New("dice: JS mutation collector unavailable")
	ErrJSConfigMutation      = errors.New("dice: invalid JS configuration mutation")
	ErrJSPluginKV            = errors.New("dice: invalid JS plugin KV mutation")
	ErrJSUnsupportedOwner    = errors.New("dice: JS mutation owner unavailable")
)

// JSMutationScope is the only durable ownership information accepted from JS.
// It contains identifiers, never authoritative runtime pointers.
type JSMutationScope struct {
	DiceID                  string
	GroupID                 string
	UserID                  string
	SubjectID               string
	GroupExpectedVersion    uint64
	PlayerExpectedVersion   uint64
	AttrsExpectedVersion    uint64
	ModerationExpectedVersion uint64
}

// JSMutationCollector adapts explicit JS decisions to sealed core events.
type JSMutationCollector struct {
	core      *messageflow.MutationCollector
	scope     JSMutationScope
	metadata  eventstore.Metadata
	configs   map[string]JSConfigMutation
	validators map[string]func(any) error
}

func NewJSMutationCollector(core *messageflow.MutationCollector, scope JSMutationScope, metadata eventstore.Metadata) *JSMutationCollector {
	metadata.SubjectKey = append([]byte(nil), metadata.SubjectKey...)
	return &JSMutationCollector{core: core, scope: scope, metadata: metadata, configs: map[string]JSConfigMutation{}, validators: map[string]func(any) error{}}
}

func (c *JSMutationCollector) validMetadata() error {
	if c == nil || c.core == nil || strings.TrimSpace(c.scope.DiceID) == "" || strings.TrimSpace(c.scope.GroupID) == "" {
		return ErrJSMutationUnavailable
	}
	if strings.Contains(c.scope.DiceID, "$t") || strings.Contains(c.scope.GroupID, "$t") || strings.Contains(c.scope.UserID, "$t") || strings.Contains(c.scope.SubjectID, "$t") {
		return ErrJSMutationUnavailable
	}
	if strings.Contains(c.metadata.CommandID, "$t") || strings.Contains(c.metadata.CorrelationID, "$t") {
		return eventstore.ErrInvalidMetadata
	}
	if c.metadata.Producer == "" {
		c.metadata.Producer = "dice/js"
	}
	if !c.metadata.OccurredAt.IsZero() && (c.metadata.OccurredAtUnixNanoSet || c.metadata.OccurredAtUnixNanoUTC != 0) && c.metadata.OccurredAt.UTC().UnixNano() != c.metadata.OccurredAtUnixNanoUTC {
		return eventstore.ErrInvalidMetadata
	}
	return nil
}

func (c *JSMutationCollector) metadataFor() eventstore.Metadata {
	metadata := c.metadata
	metadata.SubjectKey = append([]byte(nil), metadata.SubjectKey...)
	return metadata
}

func validateJSMutationStream(stream eventstore.StreamID, aggregateType string) error {
	if stream.AggregateType != aggregateType || strings.TrimSpace(stream.AggregateID) == "" || strings.Contains(stream.AggregateType, "$t") || strings.Contains(stream.AggregateID, "$t") {
		return eventstore.ErrInvalidMetadata
	}
	return nil
}

func (c *JSMutationCollector) CaptureGroup(events ...groupstate.TypedEvent) error {
	if err := c.validMetadata(); err != nil {
		return err
	}
	if err := groupstate.ValidateIdentity(c.scope.DiceID, c.scope.GroupID); err != nil {
		return eventstore.ErrInvalidMetadata
	}
	if len(events) == 0 {
		return eventstore.ErrInvalidEvent
	}
	stream := groupstate.GroupStream(c.scope.DiceID, c.scope.GroupID)
	if err := validateJSMutationStream(stream, groupstate.GroupAggregateType); err != nil {
		return err
	}
	for _, event := range events {
		switch value := event.(type) {
		case groupstate.GroupCreatedV1:
			if value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID {
				return eventstore.ErrInvalidMetadata
			}
		case *groupstate.GroupCreatedV1:
			if value == nil || value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID {
				return eventstore.ErrInvalidMetadata
			}
		case groupstate.GroupActivationChangedV1:
			if value.DiceID != c.scope.DiceID {
				return eventstore.ErrInvalidMetadata
			}
		case *groupstate.GroupActivationChangedV1:
			if value == nil || value.DiceID != c.scope.DiceID {
				return eventstore.ErrInvalidMetadata
			}
		}
	}
	return c.core.AddGroupEvents(stream, c.scope.GroupExpectedVersion, c.metadataFor(), events)
}

func (c *JSMutationCollector) CapturePlayer(events ...playerstate.PlayerEvent) error {
	if err := c.validMetadata(); err != nil {
		return err
	}
	stream := playerstate.PlayerStream(c.scope.DiceID, c.scope.GroupID, c.scope.UserID)
	if err := validateJSMutationStream(stream, playerstate.PlayerAggregateType); err != nil {
		return err
	}
	if len(events) == 0 {
		return eventstore.ErrInvalidEvent
	}
	for _, event := range events {
		switch value := event.(type) {
		case playerstate.PlayerCreatedV1:
			if value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID || value.UserID != c.scope.UserID {
				return eventstore.ErrInvalidMetadata
			}
		case *playerstate.PlayerCreatedV1:
			if value == nil || value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID || value.UserID != c.scope.UserID {
				return eventstore.ErrInvalidMetadata
			}
		}
	}
	return c.core.AddPlayerEvents(stream, c.scope.PlayerExpectedVersion, c.metadataFor(), events)
}

func (c *JSMutationCollector) CaptureGroupUserAttrs(events []playerstate.GroupUserAttrsEvent, transient map[string]any) error {
	if err := c.validMetadata(); err != nil {
		return err
	}
	stream := playerstate.GroupUserAttrsStream(c.scope.DiceID, c.scope.GroupID, c.scope.UserID)
	if err := validateJSMutationStream(stream, playerstate.GroupUserAttrsAggregateType); err != nil {
		return err
	}
	if len(events) == 0 {
		return eventstore.ErrInvalidEvent
	}
	for _, event := range events {
		switch value := event.(type) {
		case playerstate.GroupUserAttrsCreatedV1:
			if value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID || value.UserID != c.scope.UserID {
				return eventstore.ErrInvalidMetadata
			}
		case *playerstate.GroupUserAttrsCreatedV1:
			if value == nil || value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID || value.UserID != c.scope.UserID {
				return eventstore.ErrInvalidMetadata
			}
		}
	}
	_ = transient
	return c.core.AddGroupUserAttrsEvents(stream, c.scope.AttrsExpectedVersion, c.metadataFor(), events)
}


// JSGroupUserAttrsMutation is the closed operation vocabulary used by public
// $m/$g/player-attrs compatibility shims.
type JSGroupUserAttrsMutation struct {
	Operation  string
	Key        string
	Delta      int64
	Ciphertext []byte
	KeyID      string
}

func (c *JSMutationCollector) CaptureGroupUserAttrsMutation(mutation JSGroupUserAttrsMutation) error {
	if c == nil {
		return ErrJSMutationUnavailable
	}
	if strings.Contains(mutation.Key, "$t") {
		return eventstore.ErrInvalidMetadata
	}
	var event playerstate.GroupUserAttrsEvent
	switch mutation.Operation {
	case "create":
		event = playerstate.NewGroupUserAttrsCreatedV1(c.scope.DiceID, c.scope.GroupID, c.scope.UserID)
	case "set":
		event = playerstate.NewGroupUserAttrsSetV1(mutation.Key, mutation.Ciphertext, mutation.KeyID)
	case "increment":
		event = playerstate.NewGroupUserAttrsIncrementedV1(mutation.Key, mutation.Delta)
	case "delete":
		event = playerstate.NewGroupUserAttrsDeletedV1(mutation.Key)
	case "clear":
		event = playerstate.NewGroupUserAttrsClearedV1()
	case "binding":
		event = playerstate.NewGroupUserAttrsBindingChangedV1(mutation.Key)
	default:
		return eventstore.ErrInvalidEvent
	}
	return c.CaptureGroupUserAttrs([]playerstate.GroupUserAttrsEvent{event}, nil)
}

func (c *JSMutationCollector) CaptureM(JSGroupUserAttrsMutation) error {
	return ErrJSUnsupportedOwner
}

func (c *JSMutationCollector) CaptureG(JSGroupUserAttrsMutation) error {
	return ErrJSUnsupportedOwner
}

func (c *JSMutationCollector) CaptureModeration(events ...playerstate.ModerationEvent) error {
	if err := c.validMetadata(); err != nil {
		return err
	}
	subject := c.scope.SubjectID
	if subject == "" {
		subject = c.scope.UserID
	}
	stream := playerstate.ModerationStream(c.scope.DiceID, c.scope.GroupID, subject)
	if err := validateJSMutationStream(stream, playerstate.ModerationAggregateType); err != nil {
		return err
	}
	if len(events) == 0 {
		return eventstore.ErrInvalidEvent
	}
	for _, event := range events {
		switch value := event.(type) {
		case playerstate.ModerationCreatedV1:
			if value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID || value.SubjectID != subject {
				return eventstore.ErrInvalidMetadata
			}
		case *playerstate.ModerationCreatedV1:
			if value == nil || value.DiceID != c.scope.DiceID || value.GroupID != c.scope.GroupID || value.SubjectID != subject {
				return eventstore.ErrInvalidMetadata
			}
		}
	}
	return c.core.AddModerationEvents(stream, c.scope.ModerationExpectedVersion, c.metadataFor(), events)
}

// JSConfigMutation is a request record consumed later by ExtensionState. It is
// not a YAML/config-manager operation and is never persisted as an event here.
type JSConfigMutation struct { ExtensionID string; Key string; Value any }
func (c *JSMutationCollector) RegisterConfig(extensionID, key string, validate func(any) error) {
	if c == nil { return }
	if c.validators == nil { c.validators = map[string]func(any) error{} }
	c.validators[extensionID+"\x00"+key] = validate
}
func (c *JSMutationCollector) CaptureConfig(mutation JSConfigMutation) error {
	if c == nil || strings.TrimSpace(mutation.ExtensionID) == "" || strings.TrimSpace(mutation.Key) == "" || strings.Contains(mutation.ExtensionID, "$t") || strings.Contains(mutation.Key, "$t") {
		return ErrJSConfigMutation
	}
	validate, ok := c.validators[mutation.ExtensionID+"\x00"+mutation.Key]
	if !ok || validate == nil || !jsonSafeConfigValue(reflect.ValueOf(mutation.Value), 0) {
		return ErrJSConfigMutation
	}
	if validate(mutation.Value) != nil {
		return ErrJSConfigMutation
	}
	payload, err := json.Marshal(mutation.Value)
	if err != nil {
		return ErrJSConfigMutation
	}
	var snapshot any
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return ErrJSConfigMutation
	}
	if c.configs == nil {
		c.configs = map[string]JSConfigMutation{}
	}
	c.configs[mutation.ExtensionID+"\x00"+mutation.Key] = JSConfigMutation{ExtensionID: mutation.ExtensionID, Key: mutation.Key, Value: snapshot}
	return nil
}

func (c *JSMutationCollector) ConfigMutations() []JSConfigMutation {
	if c == nil {
		return nil
	}
	keys := make([]string, 0, len(c.configs))
	for key := range c.configs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]JSConfigMutation, 0, len(keys))
	for _, key := range keys {
		item := c.configs[key]
		payload, err := json.Marshal(item.Value)
		if err != nil {
			continue
		}
		var snapshot any
		if json.Unmarshal(payload, &snapshot) == nil {
			item.Value = snapshot
		}
		out = append(out, item)
	}
	return out
}
func jsonSafeConfigValue(value reflect.Value, depth int) bool {
	if depth > 32 || !value.IsValid() {
		return value.IsValid()
	}
	switch value.Kind() {
	case reflect.Interface:
		return value.IsNil() || jsonSafeConfigValue(value.Elem(), depth+1)
	case reflect.Pointer, reflect.Func, reflect.Chan, reflect.UnsafePointer:
		return false
	case reflect.Map:
		if value.Type().Key().Kind() != reflect.String {
			return false
		}
		for _, key := range value.MapKeys() {
			if !jsonSafeConfigValue(value.MapIndex(key), depth+1) {
				return false
			}
		}
		return true
	case reflect.Slice, reflect.Array:
		for i := 0; i < value.Len(); i++ {
			if !jsonSafeConfigValue(value.Index(i), depth+1) {
				return false
			}
		}
		return true
	case reflect.Struct:
		return value.Type() == reflect.TypeOf(time.Time{})
	default:
		return true
	}
}

func (c *JSMutationCollector) AddPluginKVBatch(updates []eventstore.PluginKVUpdate) error {
	if c == nil || c.core == nil {
		return ErrJSMutationUnavailable
	}
	return c.core.AddPluginKVBatch(updates)
}

func (c *JSMutationCollector) AddEffect(effect eventstore.NewEffect) error {
	if effect.ExpectedVersion != 0 || len(effect.SubjectKey) != 0 || effect.PrincipalID != "" {
		return ErrJSEffect
	}
	if c == nil || c.core == nil {
		return ErrJSMutationUnavailable
	}
	return c.core.AddEffect(effect)
}
func (c *JSMutationCollector) CaptureEffect(request JSEffectRequest) error {
	if err := c.validMetadata(); err != nil { return err }
	effect, err := BuildJSEffect(request)
	if err != nil { return err }
	return c.AddEffect(effect)
}
func (c *JSMutationCollector) CaptureReply(request JSEffectRequest) error {
	request.EffectType = "reply"
	return c.CaptureEffect(request)
}
func (c *JSMutationCollector) CaptureNotice(request JSEffectRequest) error {
	request.EffectType = "notice"
	return c.CaptureEffect(request)
}

func (c *JSMutationCollector) UnitOfWork() (eventstore.UnitOfWork, error) { if c == nil || c.core == nil { return eventstore.UnitOfWork{}, ErrJSMutationUnavailable }; return c.core.UnitOfWork() }

// JSPluginKVReadBackend is the minimum durable read surface required to build
// an overlay without treating unknown existing keys as absent.
type JSPluginKVReadBackend interface {
	GetPluginKV(context.Context, string, string) (eventstore.PluginKVItem, error)
	ListPluginKV(context.Context, eventstore.PluginKVListRequest) ([]eventstore.PluginKVItem, error)
}

// JSPluginKVBackend is deliberately explicit: plugin storage is used only when
// supplied by the caller, never discovered from Dice or a database pointer.
type JSPluginKVBackend interface {
	JSPluginKVReadBackend
	eventstore.Store
}

// JSPluginKVScanProof is optional. Backends that cap a list response at the
// result bound must provide a proof that the scan was complete.
type JSPluginKVScanProof interface {
	PluginKVScanComplete(context.Context, eventstore.PluginKVListRequest) (bool, error)
}

type JSPluginKVSealer interface {
	KeyedDigest(context.Context, string, ...string) ([]byte, string, error)
	EncryptBound(context.Context, string, string, string, uint64, []byte) ([]byte, []byte, string, error)
}

type JSPluginKVCollector interface {
	AddPluginKV(eventstore.PluginKVUpdate) error
}

type JSPluginKVBatchCollector interface {
	AddPluginKVBatch([]eventstore.PluginKVUpdate) error
}

type JSPluginKVPending struct {
	base       eventstore.PluginKVItem
	baseExists bool
	item       eventstore.PluginKVItem
	update     eventstore.PluginKVUpdate
	deleted    bool
}

type JSPluginKVOverlay struct {
	extension string
	crypto    JSPluginKVSealer
	backend   JSPluginKVReadBackend
	collector JSPluginKVCollector
	pending   map[string]JSPluginKVPending
	committed bool
}

func jsInterfaceNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

func validateJSPluginExtension(extensionID string) error {
	if strings.TrimSpace(extensionID) == "" || strings.Contains(extensionID, "$t") {
		return ErrJSPluginKV
	}
	if len(extensionID) > eventstore.MaxPluginExtensionBytes {
		return &eventstore.OversizeError{Bound: "plugin extension bytes", Limit: eventstore.MaxPluginExtensionBytes, Actual: len(extensionID)}
	}
	return nil
}

func NewJSPluginKVOverlay(extensionID string, crypto JSPluginKVSealer, backend JSPluginKVBackend) (*JSPluginKVOverlay, error) {
	if validateJSPluginExtension(extensionID) != nil || jsInterfaceNil(crypto) || jsInterfaceNil(backend) {
		return nil, ErrJSPluginKV
	}
	return &JSPluginKVOverlay{extension: extensionID, crypto: crypto, backend: backend, pending: map[string]JSPluginKVPending{}}, nil
}

// NewJSPluginKVOverlayForCollector is retained as a fail-closed constructor:
// without a read backend it cannot distinguish an existing durable key.
func NewJSPluginKVOverlayForCollector(extensionID string, crypto JSPluginKVSealer, collector JSPluginKVCollector) (*JSPluginKVOverlay, error) {
	if validateJSPluginExtension(extensionID) != nil || jsInterfaceNil(crypto) || jsInterfaceNil(collector) {
		return nil, ErrJSPluginKV
	}
	return &JSPluginKVOverlay{extension: extensionID, crypto: crypto, collector: collector, pending: map[string]JSPluginKVPending{}}, nil
}

func NewJSPluginKVOverlayForCollectorWithBackend(extensionID string, crypto JSPluginKVSealer, collector JSPluginKVCollector, backend JSPluginKVReadBackend) (*JSPluginKVOverlay, error) {
	if validateJSPluginExtension(extensionID) != nil || jsInterfaceNil(crypto) || jsInterfaceNil(collector) || jsInterfaceNil(backend) {
		return nil, ErrJSPluginKV
	}
	return &JSPluginKVOverlay{extension: extensionID, crypto: crypto, collector: collector, backend: backend, pending: map[string]JSPluginKVPending{}}, nil
}

func (o *JSPluginKVOverlay) base(ctx context.Context, key string) (eventstore.PluginKVItem, error) {
	if o.backend == nil {
		return eventstore.PluginKVItem{}, ErrJSPluginKV
	}
	item, err := o.backend.GetPluginKV(ctx, o.extension, key)
	if err != nil {
		return eventstore.PluginKVItem{}, err
	}
	item.Value = append([]byte(nil), item.Value...)
	return item, nil
}

func (o *JSPluginKVOverlay) loadBase(ctx context.Context, key string) (eventstore.PluginKVItem, bool, error) {
	item, err := o.base(ctx, key)
	if errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return eventstore.PluginKVItem{ExtensionID: o.extension, Key: key}, false, nil
	}
	if err != nil {
		return eventstore.PluginKVItem{}, false, err
	}
	return item, true, nil
}

func nextJSPluginVersion(version uint64) (uint64, error) {
	if version >= uint64(^uint64(0)>>1) {
		return 0, eventstore.ErrVersionExhausted
	}
	return version + 1, nil
}

func (o *JSPluginKVOverlay) Put(ctx context.Context, key string, value []byte, expected uint64) error {
	if o == nil || jsInterfaceNil(o.crypto) || strings.TrimSpace(key) == "" || strings.Contains(key, "$t") {
		return ErrJSPluginKV
	}
	if len(key) > eventstore.MaxPluginKeyBytes {
		return &eventstore.OversizeError{Bound: "plugin key bytes", Limit: eventstore.MaxPluginKeyBytes, Actual: len(key)}
	}
	if len(value) > eventstore.MaxPluginValueBytes {
		return &eventstore.OversizeError{Bound: "plugin value bytes", Limit: eventstore.MaxPluginValueBytes, Actual: len(value)}
	}
	if o.committed {
		return ErrJSPluginKV
	}
	pending, exists := o.pending[key]
	if !exists {
		base, baseExists, err := o.loadBase(ctx, key)
		if err != nil {
			return err
		}
		if expected != 0 && expected != base.Version {
			return eventstore.ErrConflict
		}
		pending = JSPluginKVPending{base: base, baseExists: baseExists}
	} else if expected != 0 && expected != pending.item.Version {
		return eventstore.ErrConflict
	}
	version, err := nextJSPluginVersion(pending.base.Version)
	if err != nil {
		return err
	}
	if err := o.checkQuota(ctx, key, value); err != nil {
		return err
	}
	index, _, err := o.crypto.KeyedDigest(ctx, "plugin-key-index/v1", o.extension, key)
	if err != nil {
		return err
	}
	if len(index) != 32 {
		return ErrJSPluginKV
	}
	keyCipher, keyNonce, keyID, err := o.crypto.EncryptBound(ctx, "plugin-kv-key/v1", string(index), o.extension, version, []byte(key))
	if err != nil {
		return err
	}
	valueCipher, valueNonce, valueKeyID, err := o.crypto.EncryptBound(ctx, "plugin-kv-value/v1", string(index), o.extension, version, value)
	if err != nil {
		return err
	}
	if keyID == "" || keyID != valueKeyID {
		return eventstore.ErrEncryptionUnavailable
	}
	pending.item = eventstore.PluginKVItem{ExtensionID: o.extension, Key: key, Value: append([]byte(nil), value...), Version: version}
	pending.update = eventstore.PluginKVUpdate{ExtensionID: o.extension, KeyHMAC: append([]byte(nil), index...), ExpectedVersion: pending.base.Version, Version: version, KeyCiphertext: append([]byte(nil), keyCipher...), KeyNonce: append([]byte(nil), keyNonce...), ValueCiphertext: append([]byte(nil), valueCipher...), ValueNonce: append([]byte(nil), valueNonce...), EncryptionKeyID: keyID, ValueSize: int64(len(value))}
	pending.deleted = false
	o.pending[key] = pending
	return nil
}

func (o *JSPluginKVOverlay) checkQuota(ctx context.Context, key string, value []byte) error {
	if o.backend == nil {
		return ErrJSPluginKV
	}
	items, err := o.scan(ctx, "")
	if err != nil {
		return err
	}
	state := make(map[string]eventstore.PluginKVItem, len(items)+len(o.pending))
	for _, item := range items {
		state[item.Key] = item
	}
	for pendingKey, pending := range o.pending {
		if pending.deleted {
			delete(state, pendingKey)
		} else {
			state[pendingKey] = pending.item
		}
	}
	state[key] = eventstore.PluginKVItem{ExtensionID: o.extension, Key: key, Value: value}
	if len(state) > eventstore.MaxPluginKeys {
		return &eventstore.OversizeError{Bound: "plugin keys", Limit: eventstore.MaxPluginKeys, Actual: len(state)}
	}
	var total int
	for _, item := range state {
		total += len(item.Value)
		if total > eventstore.MaxPluginBytes {
			return &eventstore.OversizeError{Bound: "plugin bytes", Limit: eventstore.MaxPluginBytes, Actual: total}
		}
	}
	return nil
}

func (o *JSPluginKVOverlay) Get(ctx context.Context, key string) (eventstore.PluginKVItem, error) {
	if o == nil || strings.TrimSpace(key) == "" || strings.Contains(key, "$t") {
		return eventstore.PluginKVItem{}, ErrJSPluginKV
	}
	if len(key) > eventstore.MaxPluginKeyBytes {
		return eventstore.PluginKVItem{}, &eventstore.OversizeError{Bound: "plugin key bytes", Limit: eventstore.MaxPluginKeyBytes, Actual: len(key)}
	}
	if pending, ok := o.pending[key]; ok {
		if pending.deleted {
			return eventstore.PluginKVItem{}, eventstore.ErrPluginKVNotFound
		}
		item := pending.item
		item.Value = append([]byte(nil), item.Value...)
		return item, nil
	}
	return o.base(ctx, key)
}

func (o *JSPluginKVOverlay) Delete(ctx context.Context, key string, expected uint64) error {
	if o == nil || jsInterfaceNil(o.crypto) || strings.TrimSpace(key) == "" || strings.Contains(key, "$t") {
		return ErrJSPluginKV
	}
	if len(key) > eventstore.MaxPluginKeyBytes {
		return &eventstore.OversizeError{Bound: "plugin key bytes", Limit: eventstore.MaxPluginKeyBytes, Actual: len(key)}
	}
	if o.committed {
		return ErrJSPluginKV
	}
	pending, exists := o.pending[key]
	if !exists {
		base, baseExists, err := o.loadBase(ctx, key)
		if err != nil {
			return err
		}
		if !baseExists {
			return eventstore.ErrPluginKVNotFound
		}
		if expected != 0 && expected != base.Version {
			return eventstore.ErrConflict
		}
		pending = JSPluginKVPending{base: base, baseExists: true}
	} else {
		if expected != 0 && expected != pending.item.Version {
			return eventstore.ErrConflict
		}
		if !pending.baseExists {
			delete(o.pending, key)
			return nil
		}
	}
	version, err := nextJSPluginVersion(pending.base.Version)
	if err != nil {
		return err
	}
	index, _, err := o.crypto.KeyedDigest(ctx, "plugin-key-index/v1", o.extension, key)
	if err != nil {
		return err
	}
	if len(index) != 32 {
		return ErrJSPluginKV
	}
	pending.item = eventstore.PluginKVItem{ExtensionID: o.extension, Key: key, Version: version}
	pending.update = eventstore.PluginKVUpdate{ExtensionID: o.extension, KeyHMAC: append([]byte(nil), index...), ExpectedVersion: pending.base.Version, Version: version, Deleted: true}
	pending.deleted = true
	o.pending[key] = pending
	return nil
}
func (o *JSPluginKVOverlay) scan(ctx context.Context, prefix string) ([]eventstore.PluginKVItem, error) {
	if o.backend == nil {
		return nil, ErrJSPluginKV
	}
	req := eventstore.PluginKVListRequest{ExtensionID: o.extension, Prefix: prefix, Limit: eventstore.MaxPluginScan + 1}
	items, err := o.backend.ListPluginKV(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(items) > eventstore.MaxPluginScan {
		return nil, &eventstore.OversizeError{Bound: "plugin scan", Limit: eventstore.MaxPluginScan, Actual: len(items)}
	}
	if len(items) >= eventstore.MaxPluginResults {
		proof, ok := o.backend.(JSPluginKVScanProof)
		if !ok {
			return nil, &eventstore.OversizeError{Bound: "plugin scan", Limit: eventstore.MaxPluginScan, Actual: len(items)}
		}
		complete, err := proof.PluginKVScanComplete(ctx, req)
		if err != nil {
			return nil, err
		}
		if !complete {
			return nil, &eventstore.OversizeError{Bound: "plugin scan", Limit: eventstore.MaxPluginScan, Actual: len(items)}
		}
	}
	for i := range items {
		item := &items[i]
		if item.ExtensionID != o.extension || strings.TrimSpace(item.Key) == "" || strings.Contains(item.Key, "$t") {
			return nil, eventstore.ErrInvalidMetadata
		}
		if len(item.Key) > eventstore.MaxPluginKeyBytes {
			return nil, &eventstore.OversizeError{Bound: "plugin key bytes", Limit: eventstore.MaxPluginKeyBytes, Actual: len(item.Key)}
		}
		if len(item.Value) > eventstore.MaxPluginValueBytes {
			return nil, &eventstore.OversizeError{Bound: "plugin value bytes", Limit: eventstore.MaxPluginValueBytes, Actual: len(item.Value)}
		}
		item.Value = append([]byte(nil), item.Value...)
	}
	return items, nil
}
func (o *JSPluginKVOverlay) List(ctx context.Context, prefix string, limit int) ([]eventstore.PluginKVItem, error) {

	if o == nil || strings.Contains(prefix, "$t") {
		return nil, ErrJSPluginKV
	}
	if len(prefix) > eventstore.MaxPluginKeyBytes {
		return nil, &eventstore.OversizeError{Bound: "plugin prefix bytes", Limit: eventstore.MaxPluginKeyBytes, Actual: len(prefix)}
	}
	if limit <= 0 {
		limit = eventstore.MaxPluginResults
	}
	if limit > eventstore.MaxPluginResults {
		return nil, &eventstore.OversizeError{Bound: "plugin results", Limit: eventstore.MaxPluginResults, Actual: limit}
	}
	items, err := o.scan(ctx, prefix)
	if err != nil {
		return nil, err
	}
	merged := make(map[string]eventstore.PluginKVItem, len(items)+len(o.pending))
	for _, item := range items {
		merged[item.Key] = item
	}
	for key, pending := range o.pending {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if pending.deleted {
			delete(merged, key)
		} else {
			merged[key] = pending.item
		}
	}
	if len(merged) > eventstore.MaxPluginScan {
		return nil, &eventstore.OversizeError{Bound: "plugin scan", Limit: eventstore.MaxPluginScan, Actual: len(merged)}
	}
	keys := make([]string, 0, len(merged))
	for key := range merged {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]eventstore.PluginKVItem, 0, minInt(limit, len(keys)))
	responseBytes := 0
	for _, key := range keys {
		if len(out) >= limit {
			break
		}
		item := merged[key]
		responseBytes += len(item.Key) + len(item.Value)
		if responseBytes > eventstore.MaxPluginResponseBytes {
			return nil, &eventstore.OversizeError{Bound: "plugin response bytes", Limit: eventstore.MaxPluginResponseBytes, Actual: responseBytes}
		}
		item.Value = append([]byte(nil), item.Value...)
		out = append(out, item)
	}
	return out, nil
}

func (o *JSPluginKVOverlay) Commit(ctx context.Context) error {
	if o == nil {
		return ErrJSPluginKV
	}
	if o.committed {
		return nil
	}
	updates := make([]eventstore.PluginKVUpdate, 0, len(o.pending))
	for _, pending := range o.pending {
		updates = append(updates, clonePluginUpdate(pending.update))
	}
	sort.Slice(updates, func(i, j int) bool { return string(updates[i].KeyHMAC) < string(updates[j].KeyHMAC) })
	if len(updates) == 0 {
		o.committed = true
		return nil
	}
	if o.collector != nil {
		batcher, ok := o.collector.(JSPluginKVBatchCollector)
		if !ok {
			return ErrJSPluginKV
		}
		if err := batcher.AddPluginKVBatch(updates); err != nil {
			return err
		}
		o.committed = true
		return nil
	}
	if o.backend == nil {
		return ErrJSPluginKV
	}
	store, ok := o.backend.(eventstore.Store)
	if !ok || jsInterfaceNil(store) {
		return ErrJSPluginKV
	}
	if _, err := store.Commit(ctx, eventstore.UnitOfWork{PluginKVUpdates: updates}); err != nil {
		return err
	}
	o.committed = true
	return nil
}

func clonePluginUpdate(update eventstore.PluginKVUpdate) eventstore.PluginKVUpdate {
	update.KeyHMAC = append([]byte(nil), update.KeyHMAC...)
	update.KeyCiphertext = append([]byte(nil), update.KeyCiphertext...)
	update.KeyNonce = append([]byte(nil), update.KeyNonce...)
	update.ValueCiphertext = append([]byte(nil), update.ValueCiphertext...)
	update.ValueNonce = append([]byte(nil), update.ValueNonce...)
	return update
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
