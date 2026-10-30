package dice

import (
	"context"
	"errors"
	"sort"

	"Scardice-core/core/attributestate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"

	ds "github.com/sealdice/dicescript"
)

type stagedExtensionState struct {
	state    extensionstate.State
	expected uint64
	metadata eventstore.Metadata
	events   []extensionstate.TypedEvent
}

type stagedAttributeSnapshot struct {
	state    attributestate.State
	event    eventstore.NewEvent
	secret   eventstore.SecretUpdate
	expected uint64
}

type stagedAttributeOverlay struct {
	state    attributestate.State
	item     *AttributesItem
	metadata eventstore.Metadata
}

type stagedDelegatedPlayer struct {
	state                      playerstate.PlayerState
	player                     *GroupPlayerInfo
	scope                      messageflow.CallbackScope
	metadata                   eventstore.Metadata
	found                      bool
	initialName                string
	initialAutoSetNameTemplate string
	initialLastCommandTime     int64
	initialDiceSideNum         int
}

type stagedCallbackGroupEvents struct {
	expected uint64
	metadata eventstore.Metadata
	events   []groupstate.TypedEvent
	terminal []groupstate.TypedEvent
}

type preparedGroupMembershipRemoval struct {
	stream   eventstore.StreamID
	expected uint64
	metadata eventstore.Metadata
	event    groupstate.TypedEvent
}

type callbackCommitFence interface {
	TryLock() bool
	Unlock()
}

// DurableCallbackTransaction stages callback-owned mutations for the callback
// service's terminal UnitOfWork. It never commits the store directly.
type DurableCallbackTransaction struct {
	store                eventstore.Store
	collector            *messageflow.MutationCollector
	callbackCommitFence  callbackCommitFence
	callbackAfterCommit  []func()
	overlays             map[string]*JSPluginKVOverlay
	attributes           map[string]stagedAttributeSnapshot
	attributeOverlays    map[string]stagedAttributeOverlay
	delegatedPlayers     map[string]stagedDelegatedPlayer
	delegatedPlayerError error
	groups               map[eventstore.StreamID]*stagedCallbackGroupEvents
	groupError           error
	extension            *stagedExtensionState
	finalized            bool
	executionContext     context.Context
}

func NewDurableCallbackTransaction(store eventstore.Store, collector *messageflow.MutationCollector) (*DurableCallbackTransaction, error) {
	if store == nil || collector == nil {
		return nil, ErrJSPluginKV
	}
	if _, ok := store.(JSPluginKVReadBackend); !ok {
		return nil, ErrJSPluginKV
	}
	if _, ok := store.(JSPluginKVSealer); !ok {
		return nil, ErrJSPluginKV
	}
	return &DurableCallbackTransaction{
		store: store, collector: collector,
		overlays: map[string]*JSPluginKVOverlay{}, attributes: map[string]stagedAttributeSnapshot{},
		attributeOverlays: map[string]stagedAttributeOverlay{}, delegatedPlayers: map[string]stagedDelegatedPlayer{},
		groups: map[eventstore.StreamID]*stagedCallbackGroupEvents{},
	}, nil
}

// ChangedAttributeIDs returns the unique, sorted IDs staged by this callback.
func (t *DurableCallbackTransaction) ChangedAttributeIDs() []string {
	if t == nil {
		return nil
	}
	unique := make(map[string]struct{}, len(t.attributes)+len(t.attributeOverlays))
	for _, attribute := range t.attributes {
		unique[attribute.state.ID] = struct{}{}
	}
	for _, overlay := range t.attributeOverlays {
		unique[overlay.state.ID] = struct{}{}
	}
	ids := make([]string, 0, len(unique))
	for id := range unique {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (t *DurableCallbackTransaction) resolveDelegatedPlayer(
	ctx context.Context,
	scope messageflow.CallbackScope,
	cached *GroupPlayerInfo,
	metadata eventstore.Metadata,
) (*GroupPlayerInfo, bool) {
	if t == nil {
		return cached, cached != nil
	}
	if t.finalized || t.collector == nil {
		t.delegatedPlayerError = errors.Join(t.delegatedPlayerError, eventstore.ErrConflict)
		return cached, cached != nil
	}
	if t.store == nil {
		t.delegatedPlayerError = errors.Join(t.delegatedPlayerError, playerstate.ErrRepositoryUnavailable)
		return cached, cached != nil
	}
	stream := playerstate.PlayerStream(scope.DiceID, scope.GroupID, scope.UserID)
	if stream.AggregateID == "" {
		t.delegatedPlayerError = errors.Join(t.delegatedPlayerError, playerstate.ErrInvalidIdentity)
		return cached, cached != nil
	}
	if staged, ok := t.delegatedPlayers[stream.AggregateID]; ok {
		return staged.player, staged.found
	}
	state, err := playerstate.NewRepository(t.store).LoadPlayer(ctx, scope.DiceID, scope.GroupID, scope.UserID)
	if err != nil {
		t.delegatedPlayerError = errors.Join(t.delegatedPlayerError, err)
		return cached, cached != nil
	}
	found := state.Version > 0 || cached != nil
	if state.DiceID == "" {
		state.DiceID = scope.DiceID
	}
	if state.GroupID == "" {
		state.GroupID = scope.GroupID
	}
	if state.UserID == "" {
		state.UserID = scope.UserID
	}
	player := cached
	if player == nil {
		player = compatibilityPlayerFromState(state)
	} else {
		if player.UserID == "" {
			player.UserID = scope.UserID
		}
		if player.ValueMapTemp == nil {
			player.ValueMapTemp = &ds.ValueMap{}
		}
	}
	if t.delegatedPlayers == nil {
		t.delegatedPlayers = map[string]stagedDelegatedPlayer{}
	}
	t.delegatedPlayers[stream.AggregateID] = stagedDelegatedPlayer{
		state: state, player: player, scope: scope, metadata: metadata, found: found,
		initialName: player.Name, initialAutoSetNameTemplate: player.AutoSetNameTemplate,
		initialLastCommandTime: player.LastCommandTime, initialDiceSideNum: player.DiceSideNum,
	}
	return player, found
}

func (t *DurableCallbackTransaction) AddLogUpdate(update eventstore.LogUpdate) error {
	if t == nil || t.finalized || t.collector == nil {
		return eventstore.ErrConflict
	}
	return t.collector.AddLogUpdate(update)
}

func (t *DurableCallbackTransaction) HasStoryLogStateUpdate(diceID, groupID string) bool {
	return t != nil && t.collector != nil && t.collector.HasStoryLogStateUpdate(diceID, groupID)
}

func (t *DurableCallbackTransaction) StorageSet(ctx context.Context, extensionID, key, value string) error {
	if t == nil || t.finalized {
		return ErrJSPluginKV
	}
	if err := validateDurablePublicStorageExtensionID(extensionID); err != nil {
		return err
	}
	overlay, err := t.pluginOverlay(extensionID)
	if err != nil {
		return err
	}
	return overlay.Put(ctx, key, []byte(value), 0)
}

func (t *DurableCallbackTransaction) StorageGet(ctx context.Context, extensionID, key string) (string, error) {
	if t == nil || t.finalized {
		return "", ErrJSPluginKV
	}
	if err := validateDurablePublicStorageExtensionID(extensionID); err != nil {
		return "", err
	}
	overlay, err := t.pluginOverlay(extensionID)
	if err != nil {
		return "", err
	}
	item, err := overlay.Get(ctx, key)
	if errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return string(item.Value), nil
}

func (t *DurableCallbackTransaction) StorageList(ctx context.Context, extensionID string) ([]string, error) {
	if t == nil || t.finalized {
		return nil, ErrJSPluginKV
	}
	if err := validateDurablePublicStorageExtensionID(extensionID); err != nil {
		return nil, err
	}
	overlay, err := t.pluginOverlay(extensionID)
	if err != nil {
		return nil, err
	}
	items, err := overlay.List(ctx, "", eventstore.MaxPluginResults)
	if err != nil {
		return nil, err
	}
	keys := make([]string, len(items))
	for index, item := range items {
		keys[index] = item.Key
	}
	return keys, nil
}

func (t *DurableCallbackTransaction) encryptedConfigSet(
	ctx context.Context,
	pluginName string,
	key string,
	typ extensionstate.ConfigType,
	value any,
) error {
	if t == nil || t.finalized {
		return ErrJSPluginKV
	}
	payload, err := durableEncryptedConfigPayload(pluginName, key, typ, value)
	if err != nil {
		return err
	}
	overlay, err := t.pluginOverlay(durableConfigStorageExtensionID(pluginName))
	if err != nil {
		return err
	}
	return overlay.Put(ctx, durableConfigStorageKey(key), payload, 0)
}

func (t *DurableCallbackTransaction) encryptedConfigValue(
	ctx context.Context,
	pluginName string,
	key string,
	typ extensionstate.ConfigType,
) (any, bool, error) {
	if t == nil || t.finalized {
		return nil, false, ErrJSPluginKV
	}
	overlay, err := t.pluginOverlay(durableConfigStorageExtensionID(pluginName))
	if err != nil {
		return nil, false, err
	}
	item, err := overlay.Get(ctx, durableConfigStorageKey(key))
	if errors.Is(err, eventstore.ErrPluginKVNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	value, err := durableDecodeEncryptedConfigValue(item.Value, pluginName, key, typ)
	if err != nil {
		return nil, false, err
	}
	return value, true, nil
}

func (ctx *MsgContext) ExtensionStorageSet(extensionID, key, value string) error {
	if err := ctx.checkExecution(); err != nil {
		return err
	}
	if ctx != nil && ctx.callbackTransaction != nil {
		return ctx.callbackTransaction.StorageSet(context.Background(), extensionID, key, value)
	}
	if ctx == nil || ctx.Dice == nil {
		return ErrDurableStateUnavailable
	}
	return ctx.Dice.durableStorageSet(extensionID, key, value)
}

func (ctx *MsgContext) ExtensionStorageGet(extensionID, key string) (string, error) {
	if err := ctx.checkExecution(); err != nil {
		return "", err
	}
	if ctx != nil && ctx.callbackTransaction != nil {
		return ctx.callbackTransaction.StorageGet(context.Background(), extensionID, key)
	}
	if ctx == nil || ctx.Dice == nil {
		return "", ErrDurableStateUnavailable
	}
	return ctx.Dice.durableStorageGet(extensionID, key)
}

func (t *DurableCallbackTransaction) AttributeOverlay(state attributestate.State, source *AttributesItem, metadata eventstore.Metadata) (*AttributesItem, error) {
	if t == nil || t.finalized || source == nil || source.valueMap == nil || !source.IsSaved {
		return nil, eventstore.ErrConflict
	}
	key := state.DiceID + "\x00" + state.ID
	if existing, ok := t.attributeOverlays[key]; ok {
		return existing.item, nil
	}
	values := &ds.ValueMap{}
	source.Range(func(name string, value *ds.VMValue) bool {
		values.Store(name, value.Clone())
		return true
	})
	item := &AttributesItem{
		ID: source.ID, valueMap: values, LastModifiedTime: source.LastModifiedTime,
		LastUsedTime: source.LastUsedTime, IsSaved: true, Name: source.Name, SheetType: source.SheetType,
	}
	t.attributeOverlays[key] = stagedAttributeOverlay{state: state, item: item, metadata: metadata}
	return item, nil
}

func (t *DurableCallbackTransaction) AttributeState(diceID, id string) (attributestate.State, bool) {
	if t == nil {
		return attributestate.State{}, false
	}
	overlay, ok := t.attributeOverlays[diceID+"\x00"+id]
	return overlay.state, ok
}

func (t *DurableCallbackTransaction) AttributeIDsWithBinding(diceID, bindingID string) []string {
	if t == nil {
		return nil
	}
	ids := make([]string, 0)
	for _, overlay := range t.attributeOverlays {
		if overlay.state.DiceID == diceID && overlay.state.BindingSheetID == bindingID {
			ids = append(ids, overlay.state.ID)
		}
	}
	sort.Strings(ids)
	return ids
}

func (t *DurableCallbackTransaction) SetAttributeBinding(diceID, id, bindingID string) error {
	if t == nil || t.finalized {
		return eventstore.ErrConflict
	}
	key := diceID + "\x00" + id
	overlay, ok := t.attributeOverlays[key]
	if !ok {
		return eventstore.ErrConflict
	}
	overlay.state.BindingSheetID = bindingID
	overlay.item.SetModified()
	t.attributeOverlays[key] = overlay
	return nil
}

func (t *DurableCallbackTransaction) SetAttributeMetadata(diceID, id, name, sheetType string) error {
	if t == nil || t.finalized {
		return eventstore.ErrConflict
	}
	key := diceID + "\x00" + id
	overlay, ok := t.attributeOverlays[key]
	if !ok {
		return eventstore.ErrConflict
	}
	overlay.state.Name = name
	overlay.state.SheetType = sheetType

	overlay.item.SetModified()
	t.attributeOverlays[key] = overlay
	return nil
}
func (t *DurableCallbackTransaction) ExtensionState() (extensionstate.State, bool) {
	if t == nil || t.extension == nil {
		return extensionstate.State{}, false
	}
	return t.extension.state.Clone(), true
}

func (ctx *MsgContext) ExtensionConfigSet(extensionID, key string, value any) error {
	if ctx == nil || ctx.Dice == nil {
		return ErrDurableStateUnavailable
	}
	if ctx.callbackTransaction == nil {
		return ctx.Dice.durableSetConfigByName(context.Background(), extensionID, key, value)
	}
	var state extensionstate.State
	if staged, ok := ctx.callbackTransaction.ExtensionState(); ok {
		state = staged
	}
	if state.DiceID == "" {
		repository, diceID, err := ctx.Dice.durableExtensionRepository()
		if err != nil {
			return err
		}
		loaded, err := repository.Load(context.Background(), diceID)
		if err != nil {
			return err
		}
		state = loaded
	}
	definition, ok := state.ConfigDefinitions[extensionID][key]
	if !ok {
		return extensionstate.ErrUnknownConfig
	}
	if durableEncryptedConfig(definition.Type, key) {
		return ctx.callbackTransaction.encryptedConfigSet(context.Background(), extensionID, key, definition.Type, value)
	}
	configValue, err := durableConfigValue(definition.Type, value, key)
	if err != nil {
		return err
	}
	return ctx.callbackTransaction.StageExtensionCommand(state, extensionstate.Command{
		Kind: extensionstate.CommandSetConfig, ExtensionID: extensionID, Key: key, Value: configValue,
	}, ctx.callbackMetadata)
}

func (ctx *MsgContext) ExtensionConfigValue(extensionID, key string) (any, bool, error) {
	if ctx == nil || ctx.Dice == nil {
		return nil, false, ErrDurableStateUnavailable
	}
	var state extensionstate.State
	if ctx.callbackTransaction != nil {
		if staged, ok := ctx.callbackTransaction.ExtensionState(); ok {
			state = staged
		}
	}
	if state.DiceID == "" {
		repository, diceID, err := ctx.Dice.durableExtensionRepository()
		if err != nil {
			return nil, false, err
		}
		loaded, err := repository.Load(context.Background(), diceID)
		if err != nil {
			return nil, false, err
		}
		state = loaded
	}
	definition, ok := state.ConfigDefinitions[extensionID][key]
	if !ok {
		return nil, false, nil
	}
	if durableEncryptedConfig(definition.Type, key) {
		if ctx.callbackTransaction != nil {
			return ctx.callbackTransaction.encryptedConfigValue(context.Background(), extensionID, key, definition.Type)
		}
		return ctx.Dice.durableEncryptedConfigValue(context.Background(), extensionID, key, definition.Type)
	}
	value, ok := state.ConfigValues[extensionID][key]
	if !ok {
		return nil, false, nil
	}
	return durableLegacyValue(value), true, nil
}

func (t *DurableCallbackTransaction) DeleteAttribute(diceID, id string) error {
	if t == nil || t.finalized {
		return eventstore.ErrConflict
	}
	key := diceID + "\x00" + id
	overlay, ok := t.attributeOverlays[key]
	if !ok {
		return eventstore.ErrConflict
	}
	overlay.state.AttrsType = ""
	overlay.state.BindingSheetID = ""
	overlay.state.Name = ""
	overlay.state.SheetType = ""
	overlay.item.Clear()
	overlay.item.Name = ""
	overlay.item.SheetType = ""
	t.attributeOverlays[key] = overlay
	return nil
}

func (t *DurableCallbackTransaction) StageAttributeSnapshot(ctx context.Context, state attributestate.State, plaintext []byte, metadata eventstore.Metadata) error {
	if t == nil || t.finalized || len(plaintext) == 0 {
		return ErrJSPluginKV
	}
	if state.SecretRef == "" {
		state.SecretRef = attributestate.SecretRef(state.DiceID, state.ID)
	}
	nextVersion := state.Version + 1
	if nextVersion == 0 {
		return eventstore.ErrVersionExhausted
	}
	state.SecretVersion = nextVersion
	payload, err := attributestate.MarshalBaselineImportedV1(attributestate.NewBaselineImportedV1(state))
	if err != nil {
		return err
	}
	eventType := attributestate.EventSnapshotReplaced
	if state.Version == 0 {
		eventType = attributestate.EventBaselineImported
	}
	event, err := (eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}).NewEvent(eventType, attributestate.EventSchemaVersion, payload, metadata)
	if err != nil {
		return err
	}
	preparer, ok := t.store.(interface {
		PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error)
	})
	if !ok {
		return attributestate.ErrRepositoryUnavailable
	}
	secret, err := preparer.PrepareSecretUpdate(ctx, eventstore.SecretPutRequest{
		SecretRef: state.SecretRef, EndpointID: state.ID, AdapterID: attributestate.AggregateType,
		SecretVersion: nextVersion, ExpectedVersion: state.Version, Plaintext: plaintext,
	})
	if err != nil {
		return err
	}
	key := state.DiceID + "\x00" + state.ID
	if _, exists := t.attributes[key]; exists {
		return eventstore.ErrDuplicateParticipant
	}
	t.attributes[key] = stagedAttributeSnapshot{state: state, event: event, secret: secret, expected: state.Version}
	return nil
}

func (t *DurableCallbackTransaction) StageExtensionCommand(state extensionstate.State, command extensionstate.Command, metadata eventstore.Metadata) error {
	if t == nil || t.finalized {
		return ErrJSPluginKV
	}
	staged := t.extension
	if staged == nil {
		staged = &stagedExtensionState{state: state.Clone(), expected: state.Version, metadata: metadata}
		t.extension = staged
	}
	decision, err := extensionstate.Decide(staged.state, command)
	if err != nil {
		return err
	}
	for _, event := range decision.Events {
		staged.state, err = extensionstate.Reduce(staged.state, event)
		if err != nil {
			return err
		}
		staged.events = append(staged.events, event)
	}
	return nil
}

func (t *DurableCallbackTransaction) prepareGroupMembershipRemoval(ctx context.Context, diceID, groupID, endpointID string, metadata eventstore.Metadata) (preparedGroupMembershipRemoval, error) {
	if t == nil || t.finalized || t.store == nil || t.collector == nil {
		return preparedGroupMembershipRemoval{}, ErrJSPluginKV
	}
	state, err := groupstate.NewRepository(t.store).Load(ctx, diceID, groupID)
	if err != nil {
		return preparedGroupMembershipRemoval{}, err
	}
	if state.Version == 0 {
		return preparedGroupMembershipRemoval{}, eventstore.ErrNotFound
	}
	if state.Deleted {
		return preparedGroupMembershipRemoval{}, groupstate.ErrDeletedGroup
	}
	stream := groupstate.GroupStream(diceID, groupID)
	if staged := t.groups[stream]; staged != nil && staged.expected != state.Version {
		return preparedGroupMembershipRemoval{}, eventstore.ErrConflict
	}
	prepared := preparedGroupMembershipRemoval{stream: stream, expected: state.Version, metadata: metadata}
	if state.DiceIDExists[endpointID] {
		prepared.event = groupstate.NewGroupActivationChangedV1(endpointID, state.DiceIDActive[endpointID], false)
	}
	return prepared, nil
}

func (t *DurableCallbackTransaction) stageGroupMembershipRemoval(prepared preparedGroupMembershipRemoval, afterCommit func()) {
	if prepared.event != nil {
		staged, err := t.callbackGroupEvents(prepared.stream, prepared.expected, prepared.metadata)
		if err != nil {
			t.groupError = err
		} else {
			staged.terminal = append(staged.terminal, prepared.event)
		}
	}
	if afterCommit != nil {
		t.callbackAfterCommit = append(t.callbackAfterCommit, afterCommit)
	}
}

func (t *DurableCallbackTransaction) stageGroupEvents(stream eventstore.StreamID, expected uint64, metadata eventstore.Metadata, events []groupstate.TypedEvent) error {
	if t == nil || t.finalized || t.collector == nil {
		return ErrJSPluginKV
	}
	if len(events) == 0 {
		return nil
	}
	staged, err := t.callbackGroupEvents(stream, expected, metadata)
	if err != nil {
		return err
	}
	staged.events = append(staged.events, events...)
	return nil
}

func (t *DurableCallbackTransaction) callbackGroupEvents(stream eventstore.StreamID, expected uint64, metadata eventstore.Metadata) (*stagedCallbackGroupEvents, error) {
	if t.groups == nil {
		t.groups = map[eventstore.StreamID]*stagedCallbackGroupEvents{}
	}
	if staged := t.groups[stream]; staged != nil {
		if staged.expected != expected {
			return nil, eventstore.ErrConflict
		}
		return staged, nil
	}
	staged := &stagedCallbackGroupEvents{expected: expected, metadata: metadata}
	t.groups[stream] = staged
	return staged, nil
}

func (t *DurableCallbackTransaction) Finalize(ctx context.Context) error {
	if t == nil || t.finalized {
		return ErrJSPluginKV
	}
	if t.delegatedPlayerError != nil {
		return t.delegatedPlayerError
	}
	if t.groupError != nil {
		return t.groupError
	}
	if err := t.flushGroupEvents(); err != nil {
		return err
	}
	if err := t.flushDelegatedPlayers(); err != nil {
		return err
	}
	if err := t.flushAttributeOverlays(ctx); err != nil {
		return err
	}
	if err := t.flushAttributeSnapshots(); err != nil {
		return err
	}
	if err := t.flushExtensionState(); err != nil {
		return err
	}
	ids := make([]string, 0, len(t.overlays))
	for id := range t.overlays {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if err := t.overlays[id].Commit(ctx); err != nil {
			return err
		}
	}
	t.finalized = true
	return nil
}

func (t *DurableCallbackTransaction) flushGroupEvents() error {
	streams := make([]eventstore.StreamID, 0, len(t.groups))
	for stream := range t.groups {
		streams = append(streams, stream)
	}
	sort.Slice(streams, func(i, j int) bool {
		if streams[i].AggregateType != streams[j].AggregateType {
			return streams[i].AggregateType < streams[j].AggregateType
		}
		return streams[i].AggregateID < streams[j].AggregateID
	})
	for _, stream := range streams {
		staged := t.groups[stream]
		events := make([]groupstate.TypedEvent, 0, len(staged.events)+len(staged.terminal))
		events = append(events, staged.events...)
		events = append(events, staged.terminal...)
		if len(events) == 0 {
			continue
		}
		if err := t.collector.AddGroupEvents(stream, staged.expected, staged.metadata, events); err != nil {
			return err
		}
	}
	return nil
}

func (t *DurableCallbackTransaction) flushDelegatedPlayers() error {
	keys := make([]string, 0, len(t.delegatedPlayers))
	for key := range t.delegatedPlayers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		staged := t.delegatedPlayers[key]
		if staged.state.Version == 0 &&
			staged.initialName == staged.player.Name &&
			staged.initialAutoSetNameTemplate == staged.player.AutoSetNameTemplate &&
			staged.initialLastCommandTime == staged.player.LastCommandTime &&
			staged.initialDiceSideNum == staged.player.DiceSideNum {
			continue
		}
		events := compatibilityPlayerEvents(staged.state, staged.scope, staged.player)
		if len(events) == 0 {
			continue
		}
		stream := playerstate.PlayerStream(staged.scope.DiceID, staged.scope.GroupID, staged.scope.UserID)
		if err := t.collector.AddPlayerEvents(stream, staged.state.Version, staged.metadata, events); err != nil {
			return err
		}
	}
	return nil
}

func (t *DurableCallbackTransaction) flushAttributeOverlays(ctx context.Context) error {
	keys := make([]string, 0, len(t.attributeOverlays))
	for key := range t.attributeOverlays {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		overlay := t.attributeOverlays[key]
		if overlay.item.IsSaved {
			continue
		}
		plaintext, err := ds.NewDictVal(overlay.item.valueMap).V().ToJSON()
		if err != nil {
			return err
		}
		if err := t.StageAttributeSnapshot(ctx, overlay.state, plaintext, overlay.metadata); err != nil {
			return err
		}
		overlay.item.IsSaved = true
	}
	return nil
}

func (t *DurableCallbackTransaction) flushAttributeSnapshots() error {
	keys := make([]string, 0, len(t.attributes))
	for key := range t.attributes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := t.attributes[key]
		if err := t.collector.AddStream(attributestate.Stream(item.state.DiceID, item.state.ID), item.expected, []eventstore.NewEvent{item.event}); err != nil {
			return err
		}
		if err := t.collector.AddSecretUpdate(item.secret); err != nil {
			return err
		}
	}
	return nil
}

func (t *DurableCallbackTransaction) flushExtensionState() error {
	staged := t.extension
	if staged == nil || len(staged.events) == 0 {
		return nil
	}
	encoded := make([]eventstore.NewEvent, 0, len(staged.events))
	factory := eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}
	for index, typed := range staged.events {
		metadata := staged.metadata
		if index > 0 {
			metadata.EventID = ""
		}
		event, err := extensionstate.NewEventWithFactory(factory, typed, metadata)
		if err != nil {
			return err
		}
		encoded = append(encoded, event)
	}
	return t.collector.AddStream(extensionstate.ExtensionStream(staged.state.DiceID), staged.expected, encoded)
}

func (t *DurableCallbackTransaction) pluginOverlay(extensionID string) (*JSPluginKVOverlay, error) {
	if overlay := t.overlays[extensionID]; overlay != nil {
		return overlay, nil
	}
	backend, ok := t.store.(JSPluginKVReadBackend)
	if !ok {
		return nil, ErrJSPluginKV
	}
	sealer, ok := t.store.(JSPluginKVSealer)
	if !ok {
		return nil, ErrJSPluginKV
	}
	overlay, err := NewJSPluginKVOverlayForCollectorWithBackend(extensionID, sealer, t.collector, backend)
	if err != nil {
		return nil, err
	}
	t.overlays[extensionID] = overlay
	return overlay, nil
}
