package dice

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/core/attributestate"
	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
	"Scardice-core/model"
	"Scardice-core/utils"
)

var ErrAttributeExecutionUnavailable = errors.New("dice: attribute execution unavailable")

type AttrsManager struct {
	durable *attributestate.Repository
	store   eventstore.Store
	diceID  string
}

func (am *AttrsManager) Stop() {}

// Init retains only enough information for startup compatibility. Attribute
// mutation is available after InitDurable and always requires a DomainTx root.
func (am *AttrsManager) Init(d *Dice) {
	if am == nil || d == nil {
		return
	}
	am.store = d.DurableStore
	am.diceID = d.BaseConfig.Name
}

func (am *AttrsManager) InitDurable(d *Dice) error {
	if am == nil || d == nil || d.DurableStore == nil || strings.TrimSpace(d.BaseConfig.Name) == "" {
		return ErrAttributeExecutionUnavailable
	}
	repository, err := attributestate.NewRepository(d.DurableStore)
	if err != nil {
		return err
	}
	if _, ok := d.DurableStore.(eventstore.ProjectionDependencyRepository); !ok {
		return ErrAttributeExecutionUnavailable
	}
	am.durable = repository
	am.store = d.DurableStore
	am.diceID = d.BaseConfig.Name
	return nil
}

func (am *AttrsManager) UIDConvert(userID string) string { return userID }

func (am *AttrsManager) transaction(ctx *MsgContext) (*DurableCallbackTransaction, error) {
	if ctx == nil || ctx.callbackTransaction == nil || ctx.callbackTransaction.Domain() == nil {
		return nil, ErrAttributeExecutionUnavailable
	}
	if err := ctx.callbackTransaction.Domain().CheckOpen(); err != nil {
		return nil, err
	}
	return ctx.callbackTransaction, nil
}

func (am *AttrsManager) LoadByCtx(ctx *MsgContext) (*AttributesItem, error) {
	tx, err := am.transaction(ctx)
	if err != nil || ctx.Group == nil || ctx.Player == nil {
		if err != nil {
			return nil, err
		}
		return nil, ErrAttributeExecutionUnavailable
	}
	return am.LoadForTransaction(ctx.domainContext(), tx, ctx.Group.GroupID(), ctx.Player.UserID())
}

func (am *AttrsManager) LoadForCtx(ctx *MsgContext, groupID, userID string) (*AttributesItem, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return nil, err
	}
	return am.LoadForTransaction(ctx.domainContext(), tx, groupID, userID)
}

func (am *AttrsManager) LoadForTransaction(ctx context.Context, tx *DurableCallbackTransaction, groupID, userID string) (*AttributesItem, error) {
	userID = am.UIDConvert(userID)
	id := fmt.Sprintf("%s-%s", groupID, userID)
	item, err := am.LoadByTransaction(ctx, tx, id)
	if err != nil {
		return nil, err
	}
	bindingID := item.BindingSheetID()
	if bindingID == "" {
		return item, nil
	}
	return am.LoadByTransaction(ctx, tx, bindingID)
}

func (am *AttrsManager) LoadByIdForCtx(ctx *MsgContext, id string) (*AttributesItem, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return nil, err
	}
	return am.LoadByTransaction(ctx.domainContext(), tx, id)
}

func attributeParticipantKey(diceID, id string) execution.ParticipantKey {
	return execution.StreamParticipantKey(attributestate.Stream(diceID, id))
}

func (am *AttrsManager) LoadByTransaction(ctx context.Context, tx *DurableCallbackTransaction, id string) (*AttributesItem, error) {
	if am == nil || am.durable == nil || am.store == nil || am.diceID == "" || tx == nil || tx.Domain() == nil {
		return nil, ErrAttributeExecutionUnavailable
	}
	key := attributeParticipantKey(am.diceID, id)
	participant, err := tx.Domain().Owner(ctx, key, func(loadCtx context.Context) (execution.Participant, execution.ReadDependencies, error) {
		loaded, err := am.durable.LoadForExecution(loadCtx, am.diceID, id)
		if err != nil {
			return nil, execution.ReadDependencies{}, err
		}
		state := loaded.State
		values := &ds.ValueMap{}
		if loaded.Found {
			value, decodeErr := ds.VMValueFromJSON(loaded.Plaintext)
			clear(loaded.Plaintext)
			if decodeErr != nil {
				return nil, execution.ReadDependencies{}, decodeErr
			}
			dict, ok := value.ReadDictData()
			if !ok {
				return nil, execution.ReadDependencies{}, errors.New("角色数据类型不正确")
			}
			values = dict.Dict
		} else {
			now := tx.occurredAt().Unix()
			state = attributestate.State{
				DiceID: am.diceID, ID: id, AttrsType: inferDurableAttrsType(id),
				SecretRef: attributestate.SecretRef(am.diceID, id), CreatedAt: now, UpdatedAt: now,
			}
		}
		reads := execution.ReadDependencies{
			StreamReads:     []eventstore.StreamReadExpectation{{Stream: attributestate.Stream(am.diceID, id), ExpectedVersion: loaded.StreamVersion}},
			ProjectionReads: []eventstore.ProjectionReadExpectation{{Generation: loaded.Snapshot.ProjectionGeneration}},
		}
		owner := &attributeParticipant{
			repository: am.durable, metadata: tx.metadata, state: cloneAttributeState(state), values: values,
		}
		owner.item = &AttributesItem{ID: id, manager: am, tx: tx.Domain(), key: key, owner: owner, ctx: loadCtx}
		return owner, reads, nil
	})
	if err != nil {
		return nil, err
	}
	owner, ok := participant.(*attributeParticipant)
	if !ok || owner.item == nil {
		return nil, eventstore.ErrDuplicateParticipant
	}
	return owner.item, nil
}

func (am *AttrsManager) GetCharacterListForCtx(ctx *MsgContext, userID string) ([]*model.AttributesItemModel, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return nil, err
	}
	return am.GetCharacterListForTransaction(ctx.domainContext(), tx, userID)
}

func (am *AttrsManager) GetCharacterListForTransaction(ctx context.Context, tx *DurableCallbackTransaction, userID string) ([]*model.AttributesItemModel, error) {
	catalog, err := am.attributeCatalog(ctx, tx, attributestate.CharacterCatalog, am.UIDConvert(userID))
	if err != nil {
		return nil, err
	}
	states := catalog.snapshotStates()
	result := make([]*model.AttributesItemModel, 0, len(states))
	for _, state := range states {
		if state.AttrsType != attributestate.AttrsTypeCharacter || state.OwnerID != userID {
			continue
		}
		binding, bindingErr := am.attributeCatalog(ctx, tx, attributestate.BindingCatalog, state.ID)
		if bindingErr != nil {
			return nil, bindingErr
		}
		result = append(result, &model.AttributesItemModel{
			Id: state.ID, AttrsType: state.AttrsType, BindingSheetId: state.BindingSheetID,
			Name: state.Name, OwnerId: state.OwnerID, SheetType: state.SheetType, IsHidden: state.Hidden,
			CreatedAt: state.CreatedAt, UpdatedAt: state.UpdatedAt, BindingGroupsNum: int64(binding.len()),
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Id < result[j].Id })
	return result, nil
}

func (am *AttrsManager) CharIdGetByNameForCtx(ctx *MsgContext, userID, name string) (string, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return "", err
	}
	return am.CharIdGetByNameForTransaction(ctx.domainContext(), tx, userID, name)
}

func (am *AttrsManager) CharIdGetByNameForTransaction(ctx context.Context, tx *DurableCallbackTransaction, userID, name string) (string, error) {
	catalog, err := am.attributeCatalog(ctx, tx, attributestate.CharacterCatalog, am.UIDConvert(userID))
	if err != nil {
		return "", err
	}
	for _, state := range catalog.snapshotStates() {
		if state.AttrsType == attributestate.AttrsTypeCharacter && state.OwnerID == userID && state.Name == name {
			return state.ID, nil
		}
	}
	return "", nil
}

func (am *AttrsManager) CharCheckExistsForCtx(ctx *MsgContext, userID, name string) (bool, error) {
	id, err := am.CharIdGetByNameForCtx(ctx, userID, name)
	return id != "", err
}

func (am *AttrsManager) CharNewForCtx(ctx *MsgContext, userID, name, sheetType string) (*model.AttributesItemModel, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return nil, err
	}
	return am.CharNewForTransaction(ctx.domainContext(), tx, userID, name, sheetType)
}

func (am *AttrsManager) CharNewForTransaction(ctx context.Context, tx *DurableCallbackTransaction, userID, name, sheetType string) (*model.AttributesItemModel, error) {
	userID = am.UIDConvert(userID)
	catalog, err := am.attributeCatalog(ctx, tx, attributestate.CharacterCatalog, userID)
	if err != nil {
		return nil, err
	}
	for _, state := range catalog.snapshotStates() {
		if state.Name == name {
			return nil, errors.New("character already exists")
		}
	}
	var id string
	var item *AttributesItem
	for {
		id = utils.NewID()
		item, err = am.LoadByTransaction(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if item.State().Version == 0 {
			break
		}
	}
	now := tx.occurredAt().Unix()
	if err = item.mutate(func(state *attributestate.State) {
		state.AttrsType = attributestate.AttrsTypeCharacter
		state.Name = name
		state.OwnerID = userID
		state.SheetType = sheetType
		state.CreatedAt = now
		state.UpdatedAt = now
	}, func(values *ds.ValueMap) { values.Clear() }, false); err != nil {
		return nil, err
	}
	return &model.AttributesItemModel{
		Id: id, AttrsType: attributestate.AttrsTypeCharacter, Name: name, OwnerId: userID,
		SheetType: sheetType, CreatedAt: now, UpdatedAt: now,
	}, nil
}

func (am *AttrsManager) CharDeleteForCtx(ctx *MsgContext, id string) error {
	tx, err := am.transaction(ctx)
	if err != nil {
		return err
	}
	return am.CharDeleteForTransaction(ctx.domainContext(), tx, id)
}

func (am *AttrsManager) CharDeleteForTransaction(ctx context.Context, tx *DurableCallbackTransaction, id string) error {
	item, err := am.LoadByTransaction(ctx, tx, id)
	if err != nil {
		return err
	}
	state := item.State()
	if state.AttrsType == "" {
		return eventstore.ErrNotFound
	}
	return item.mutate(func(state *attributestate.State) {
		state.AttrsType = ""
		state.BindingSheetID = ""
		state.Name = ""
		state.OwnerID = ""
		state.SheetType = ""
		state.Hidden = false
	}, nil, true)
}

func (am *AttrsManager) CharBindForCtx(ctx *MsgContext, characterID, groupID, userID string) error {
	tx, err := am.transaction(ctx)
	if err != nil {
		return err
	}
	return am.CharBindForTransaction(ctx.domainContext(), tx, characterID, groupID, userID)
}

func (am *AttrsManager) CharBindForTransaction(ctx context.Context, tx *DurableCallbackTransaction, characterID, groupID, userID string) error {
	item, err := am.LoadByTransaction(ctx, tx, fmt.Sprintf("%s-%s", groupID, am.UIDConvert(userID)))
	if err != nil {
		return err
	}
	return item.SetBindingSheetID(characterID)
}

func (am *AttrsManager) CharGetBindingIdForCtx(ctx *MsgContext, groupID, userID string) (string, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return "", err
	}
	return am.CharGetBindingIDForTransaction(ctx.domainContext(), tx, groupID, userID)
}

func (am *AttrsManager) CharGetBindingIDForTransaction(ctx context.Context, tx *DurableCallbackTransaction, groupID, userID string) (string, error) {
	item, err := am.LoadByTransaction(ctx, tx, fmt.Sprintf("%s-%s", groupID, am.UIDConvert(userID)))
	if err != nil {
		return "", err
	}
	return item.BindingSheetID(), nil
}

func (am *AttrsManager) CharGetBindingGroupIDListForCtx(ctx *MsgContext, id string) ([]string, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return nil, err
	}
	return am.CharGetBindingGroupIDListForTransaction(ctx.domainContext(), tx, id)
}

func (am *AttrsManager) CharGetBindingGroupIDListForTransaction(ctx context.Context, tx *DurableCallbackTransaction, id string) ([]string, error) {
	catalog, err := am.attributeCatalog(ctx, tx, attributestate.BindingCatalog, id)
	if err != nil {
		return nil, err
	}
	groups := make([]string, 0, catalog.len())
	for _, state := range catalog.snapshotStates() {
		groupID, userID, _ := UnpackGroupUserId(state.ID)
		if userID != "" {
			groups = append(groups, groupID)
		}
	}
	sort.Strings(groups)
	return groups, nil
}

func (am *AttrsManager) CharUnbindAllForCtx(ctx *MsgContext, id string) ([]string, error) {
	tx, err := am.transaction(ctx)
	if err != nil {
		return nil, err
	}
	return am.CharUnbindAllForTransaction(ctx.domainContext(), tx, id)
}

func (am *AttrsManager) CharUnbindAllForTransaction(ctx context.Context, tx *DurableCallbackTransaction, id string) ([]string, error) {
	catalog, err := am.attributeCatalog(ctx, tx, attributestate.BindingCatalog, id)
	if err != nil {
		return nil, err
	}
	states := catalog.snapshotStates()
	items := make([]*AttributesItem, 0, len(states))
	groups := make([]string, 0, len(states))
	for _, state := range states {
		item, loadErr := am.LoadByTransaction(ctx, tx, state.ID)
		if loadErr != nil {
			return nil, loadErr
		}
		items = append(items, item)
		groupID, userID, _ := UnpackGroupUserId(state.ID)
		if userID != "" {
			groups = append(groups, groupID)
		}
	}
	for _, item := range items {
		if setErr := item.SetBindingSheetID(""); setErr != nil {
			return nil, setErr
		}
	}
	sort.Strings(groups)
	return groups, nil
}

func inferDurableAttrsType(id string) string {
	if strings.HasPrefix(id, "PG-") || strings.HasPrefix(id, "OpenQQCH-Channel:") {
		if _, userID, ok := UnpackGroupUserId(id); ok && userID != "" {
			return attributestate.AttrsTypeGroupUser
		}
		return attributestate.AttrsTypeGroup
	}
	if strings.Contains(id, "-Group:") {
		if strings.Count(id, ":") > 1 {
			return attributestate.AttrsTypeGroupUser
		}
		return attributestate.AttrsTypeGroup
	}
	if strings.Contains(id, ":") {
		return attributestate.AttrsTypeUser
	}
	return attributestate.AttrsTypeCharacter
}

func cloneAttributeState(state attributestate.State) attributestate.State {
	return state
}

type attributeParticipant struct {
	mu         sync.RWMutex
	repository *attributestate.Repository
	metadata   eventstore.Metadata
	state      attributestate.State
	values     *ds.ValueMap
	dirty      bool
	revision   uint64
	item       *AttributesItem
}

func (p *attributeParticipant) Contribute(ctx context.Context) (eventstore.UnitOfWork, error) {
	p.mu.RLock()
	if !p.dirty {
		p.mu.RUnlock()
		return eventstore.UnitOfWork{}, nil
	}
	state := cloneAttributeState(p.state)
	plaintext, err := ds.NewDictVal(p.values).V().ToJSON()
	p.mu.RUnlock()
	if err != nil {
		return eventstore.UnitOfWork{}, err
	}
	prepared, err := p.repository.PrepareSnapshot(ctx, state, plaintext, p.metadata)
	clear(plaintext)
	if err != nil {
		return eventstore.UnitOfWork{}, err
	}
	return prepared.Work, nil
}

type attributeCatalogParticipant struct {
	mu       sync.RWMutex
	catalog  string
	ownerID  string
	snapshot attributestate.CatalogSnapshot
	states   map[string]attributestate.State
	write    bool
}

func (p *attributeCatalogParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if !p.write {
		return eventstore.UnitOfWork{}, nil
	}
	return eventstore.UnitOfWork{CatalogUpdates: []eventstore.CatalogRevisionUpdate{p.snapshot.CatalogUpdate()}}, nil
}

func (p *attributeCatalogParticipant) snapshotStates() []attributestate.State {
	p.mu.RLock()
	defer p.mu.RUnlock()
	states := make([]attributestate.State, 0, len(p.states))
	for _, state := range p.states {
		states = append(states, cloneAttributeState(state))
	}
	sort.Slice(states, func(i, j int) bool { return states[i].ID < states[j].ID })
	return states
}

func (p *attributeCatalogParticipant) len() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.states)
}

func (p *attributeCatalogParticipant) accepts(state attributestate.State) bool {
	switch p.catalog {
	case attributestate.CharacterCatalog:
		return state.AttrsType == attributestate.AttrsTypeCharacter && state.OwnerID == p.ownerID
	case attributestate.BindingCatalog:
		return state.BindingSheetID == p.ownerID
	default:
		return false
	}
}

func (p *attributeCatalogParticipant) upsert(state attributestate.State) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accepts(state) {
		p.states[state.ID] = cloneAttributeState(state)
	} else {
		delete(p.states, state.ID)
	}
}

func catalogParticipantKey(diceID, catalog, ownerID string) execution.ParticipantKey {
	return execution.ParticipantKey{Kind: "attribute-catalog:" + catalog, ID: attributestate.CatalogOwner(diceID, ownerID)}
}

func (am *AttrsManager) attributeCatalog(ctx context.Context, tx *DurableCallbackTransaction, catalog, ownerID string) (*attributeCatalogParticipant, error) {
	if tx == nil {
		return nil, ErrAttributeExecutionUnavailable
	}
	return am.attributeCatalogDomain(ctx, tx.Domain(), catalog, ownerID)
}

func (am *AttrsManager) attributeCatalogDomain(ctx context.Context, domain *execution.DomainTx, catalog, ownerID string) (*attributeCatalogParticipant, error) {
	if am == nil || domain == nil || ownerID == "" {
		return nil, ErrAttributeExecutionUnavailable
	}
	key := catalogParticipantKey(am.diceID, catalog, ownerID)
	participant, err := domain.Owner(ctx, key, func(loadCtx context.Context) (execution.Participant, execution.ReadDependencies, error) {
		snapshot, loadErr := attributestate.ListCatalogProjected(loadCtx, am.store, am.diceID, catalog, ownerID)
		if loadErr != nil {
			return nil, execution.ReadDependencies{}, loadErr
		}
		owner := &attributeCatalogParticipant{
			catalog: catalog, ownerID: ownerID, snapshot: snapshot, states: make(map[string]attributestate.State),
		}
		for _, state := range snapshot.States {
			if owner.accepts(state) {
				owner.states[state.ID] = cloneAttributeState(state)
			}
		}
		return owner, execution.ReadDependencies{
			CatalogReads:    []eventstore.CatalogReadExpectation{snapshot.CatalogRead()},
			ProjectionReads: []eventstore.ProjectionReadExpectation{snapshot.ProjectionRead()},
		}, nil
	})
	if err != nil {
		return nil, err
	}
	owner, ok := participant.(*attributeCatalogParticipant)
	if !ok {
		return nil, eventstore.ErrDuplicateParticipant
	}
	return owner, nil
}

func (am *AttrsManager) markCatalogWrite(domain *execution.DomainTx, owner *attributeCatalogParticipant) error {
	key := catalogParticipantKey(am.diceID, owner.catalog, owner.ownerID)
	return domain.Mutate(key, func(participant execution.Participant) error {
		catalog, ok := participant.(*attributeCatalogParticipant)
		if !ok {
			return eventstore.ErrDuplicateParticipant
		}
		catalog.mu.Lock()
		catalog.write = true
		catalog.mu.Unlock()
		return nil
	})
}

type catalogChange struct {
	owner *attributeCatalogParticipant
	key   execution.ParticipantKey
}

func (am *AttrsManager) prepareCatalogChanges(ctx context.Context, domain *execution.DomainTx, before, after attributestate.State) ([]catalogChange, error) {
	type identity struct{ catalog, owner string }
	identities := map[identity]struct{}{}
	if before.AttrsType == attributestate.AttrsTypeCharacter && before.OwnerID != "" {
		identities[identity{attributestate.CharacterCatalog, before.OwnerID}] = struct{}{}
	}
	if after.AttrsType == attributestate.AttrsTypeCharacter && after.OwnerID != "" {
		identities[identity{attributestate.CharacterCatalog, after.OwnerID}] = struct{}{}
	}
	if before.BindingSheetID != "" {
		identities[identity{attributestate.BindingCatalog, before.BindingSheetID}] = struct{}{}
	}
	if after.BindingSheetID != "" {
		identities[identity{attributestate.BindingCatalog, after.BindingSheetID}] = struct{}{}
	}
	changes := make([]catalogChange, 0, len(identities))
	for identity := range identities {
		owner, err := am.attributeCatalogDomain(ctx, domain, identity.catalog, identity.owner)
		if err != nil {
			return nil, err
		}
		changes = append(changes, catalogChange{owner: owner, key: catalogParticipantKey(am.diceID, identity.catalog, identity.owner)})
	}
	for _, change := range changes {
		if err := am.markCatalogWrite(domain, change.owner); err != nil {
			return nil, err
		}
	}
	return changes, nil
}

// AttributesItem is an invocation-scoped controlled facade over the one
// attribute participant in DomainTx. It contains no second metadata or value
// copy and cannot outlive the transaction as a writable handle.
type AttributesItem struct {
	ID      string
	manager *AttrsManager
	tx      *execution.DomainTx
	key     execution.ParticipantKey
	owner   *attributeParticipant
	ctx     context.Context
}

func (i *AttributesItem) State() attributestate.State {
	if i == nil || i.owner == nil {
		return attributestate.State{}
	}
	i.owner.mu.RLock()
	defer i.owner.mu.RUnlock()
	return cloneAttributeState(i.owner.state)
}

func (i *AttributesItem) Name() string {
	if i == nil || i.owner == nil {
		return ""
	}
	i.owner.mu.RLock()
	defer i.owner.mu.RUnlock()
	return i.owner.state.Name
}

func (i *AttributesItem) SheetType() string {
	if i == nil || i.owner == nil {
		return ""
	}
	i.owner.mu.RLock()
	defer i.owner.mu.RUnlock()
	return i.owner.state.SheetType
}

func (i *AttributesItem) BindingSheetID() string {
	if i == nil || i.owner == nil {
		return ""
	}
	i.owner.mu.RLock()
	defer i.owner.mu.RUnlock()
	return i.owner.state.BindingSheetID
}

func (i *AttributesItem) mutate(stateChange func(*attributestate.State), valueChange func(*ds.ValueMap), clearValues bool) error {
	if i == nil || i.owner == nil || i.tx == nil || i.manager == nil {
		return ErrAttributeExecutionUnavailable
	}
	i.owner.mu.RLock()
	before := cloneAttributeState(i.owner.state)
	revision := i.owner.revision
	after := cloneAttributeState(before)
	if stateChange != nil {
		stateChange(&after)
	}
	i.owner.mu.RUnlock()
	now := time.Now().Unix()
	if !i.owner.metadata.OccurredAt.IsZero() {
		now = i.owner.metadata.OccurredAt.Unix()
	}
	after.UpdatedAt = now
	changes, err := i.manager.prepareCatalogChanges(i.ctx, i.tx, before, after)
	if err != nil {
		return err
	}
	err = i.tx.Mutate(i.key, func(participant execution.Participant) error {
		owner, ok := participant.(*attributeParticipant)
		if !ok {
			return eventstore.ErrDuplicateParticipant
		}
		owner.mu.Lock()
		defer owner.mu.Unlock()
		if owner.revision != revision {
			return eventstore.ErrConflict
		}
		if clearValues {
			owner.values.Clear()
		}
		if stateChange != nil {
			stateChange(&owner.state)
		}
		if valueChange != nil {
			valueChange(owner.values)
		}
		owner.state.UpdatedAt = now
		owner.dirty = true
		owner.revision++
		after = cloneAttributeState(owner.state)
		return nil
	})
	if err != nil {
		return err
	}
	for _, catalog := range changes {
		if err = i.tx.Mutate(catalog.key, func(participant execution.Participant) error {
			owner, ok := participant.(*attributeCatalogParticipant)
			if !ok {
				return eventstore.ErrDuplicateParticipant
			}
			owner.upsert(after)
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

func (i *AttributesItem) SetName(name string) error {
	return i.mutate(func(state *attributestate.State) { state.Name = name }, nil, false)
}

func (i *AttributesItem) SetOwnerID(ownerID string) error {
	return i.mutate(func(state *attributestate.State) { state.OwnerID = ownerID }, nil, false)
}

func (i *AttributesItem) SetSheetType(sheetType string) error {
	return i.mutate(func(state *attributestate.State) { state.SheetType = sheetType }, nil, false)
}

func (i *AttributesItem) SetBindingSheetID(bindingID string) error {
	return i.mutate(func(state *attributestate.State) { state.BindingSheetID = bindingID }, nil, false)
}

func (i *AttributesItem) MutateValues(change func(*ds.ValueMap)) error {
	if change == nil {
		return ErrAttributeExecutionUnavailable
	}
	return i.mutate(nil, change, false)
}

func mutableAttributeValue(value *ds.VMValue) bool {
	if value == nil {
		return false
	}
	return value.TypeId == ds.VMTypeArray || value.TypeId == ds.VMTypeDict || value.TypeId == ds.VMTypeComputedValue
}

func cloneAttributeValue(value *ds.VMValue) *ds.VMValue {
	if value == nil {
		return nil
	}
	if !mutableAttributeValue(value) {
		return value.Clone()
	}
	encoded, err := value.ToJSON()
	if err == nil {
		if cloned, decodeErr := ds.VMValueFromJSON(encoded); decodeErr == nil {
			return cloned
		}
	}
	return value.Clone()
}

func (i *AttributesItem) Load(name string) *ds.VMValue {
	value, _ := i.LoadX(name)
	return value
}

func (i *AttributesItem) LoadX(name string) (*ds.VMValue, bool) {
	if i == nil || i.owner == nil {
		return nil, false
	}
	i.owner.mu.RLock()
	value, ok := i.owner.values.Load(name)
	i.owner.mu.RUnlock()
	if !ok {
		return nil, false
	}
	if !mutableAttributeValue(value) {
		return cloneAttributeValue(value), true
	}
	if i.tx.CheckOpen() != nil {
		return cloneAttributeValue(value), true
	}
	// A nested DiceScript value has no mutation hook. Marking the participant
	// before exposing it ensures in-place dict/array/computed changes are sealed.
	if err := i.mutate(nil, nil, false); err != nil {
		return cloneAttributeValue(value), true
	}
	i.owner.mu.RLock()
	value, ok = i.owner.values.Load(name)
	i.owner.mu.RUnlock()
	return value, ok
}

func (i *AttributesItem) Store(name string, value *ds.VMValue) error {
	owned := cloneAttributeValue(value)
	return i.mutate(nil, func(values *ds.ValueMap) { values.Store(name, owned) }, false)
}

func (i *AttributesItem) Delete(name string) error {
	return i.mutate(nil, func(values *ds.ValueMap) { values.Delete(name) }, false)
}

func (i *AttributesItem) Clear() int {
	if i == nil || i.owner == nil {
		return 0
	}
	i.owner.mu.RLock()
	count := i.owner.values.Length()
	i.owner.mu.RUnlock()
	if err := i.mutate(nil, nil, true); err != nil {
		return 0
	}
	return count
}

func (i *AttributesItem) Range(fn func(key string, value *ds.VMValue) bool) {
	if i == nil || i.owner == nil || fn == nil {
		return
	}
	i.owner.mu.RLock()
	values := make([]struct {
		key   string
		value *ds.VMValue
	}, 0, i.owner.values.Length())
	i.owner.values.Range(func(key string, value *ds.VMValue) bool {
		values = append(values, struct {
			key   string
			value *ds.VMValue
		}{key: key, value: cloneAttributeValue(value)})
		return true
	})
	i.owner.mu.RUnlock()
	for _, value := range values {
		if !fn(value.key, value.value) {
			return
		}
	}
}

func (i *AttributesItem) ToArrayKeys() []*ds.VMValue {
	items := make([]*ds.VMValue, 0, i.Len())
	i.Range(func(key string, _ *ds.VMValue) bool {
		items = append(items, ds.NewStrVal(key))
		return true
	})
	return items
}

func (i *AttributesItem) ToArrayValues() []*ds.VMValue {
	items := make([]*ds.VMValue, 0, i.Len())
	i.Range(func(_ string, value *ds.VMValue) bool {
		items = append(items, value)
		return true
	})
	return items
}

func (i *AttributesItem) ToArrayItems() []*ds.VMValue {
	items := make([]*ds.VMValue, 0, i.Len())
	i.Range(func(key string, value *ds.VMValue) bool {
		items = append(items, ds.NewArrayVal(ds.NewStrVal(key), value))
		return true
	})
	return items
}

func (i *AttributesItem) Len() int {
	if i == nil || i.owner == nil {
		return 0
	}
	i.owner.mu.RLock()
	defer i.owner.mu.RUnlock()
	return i.owner.values.Length()
}
