package dice

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"

	"Scardice-core/core/configstate"
	"Scardice-core/core/execution"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/eventstore"
)

var ErrConfigCommittedRuntimeApply = errors.New("dice: configuration committed but runtime view apply failed")

type ConfigRuntimeApplyError struct {
	Err error
}

func (e *ConfigRuntimeApplyError) Error() string {
	if e == nil || e.Err == nil {
		return ErrConfigCommittedRuntimeApply.Error()
	}
	return ErrConfigCommittedRuntimeApply.Error() + ": " + e.Err.Error()
}

func (e *ConfigRuntimeApplyError) Unwrap() error {
	if e == nil {
		return ErrConfigCommittedRuntimeApply
	}
	return errors.Join(ErrConfigCommittedRuntimeApply, e.Err)
}

// maxFreshDomainExecutionAttempts bounds how often a fresh root is rebuilt
// after another writer advanced one of its read dependencies. A conflict is
// an atomic non-commit, so every retry starts a new execution identity and
// re-reads all owners.
const maxFreshDomainExecutionAttempts = 4

func (d *Dice) withFreshDomainExecution(
	ctx context.Context,
	operation string,
	request any,
	run func(*DurableCallbackTransaction, eventstore.Metadata) error,
) error {
	if d == nil || run == nil {
		return ErrDurableStateUnavailable
	}
	return withFreshDomainExecution(ctx, operation, request, d.WithDomainExecution, run)
}

func (dm *DiceManager) withFreshDomainExecution(
	ctx context.Context,
	operation string,
	request any,
	run func(*DurableCallbackTransaction, eventstore.Metadata) error,
) error {
	if dm == nil || dm.durableStore == nil || run == nil {
		return ErrDurableStateUnavailable
	}
	return withFreshDomainExecution(ctx, operation, request, func(
		ctx context.Context,
		identity string,
		canonical []byte,
		invoke func(*DurableCallbackTransaction) error,
	) error {
		return withDomainExecution(ctx, dm.durableStore, identity, canonical, invoke)
	}, run)
}

func withFreshDomainExecution(
	ctx context.Context,
	operation string,
	request any,
	execute func(context.Context, string, []byte, func(*DurableCallbackTransaction) error) error,
	run func(*DurableCallbackTransaction, eventstore.Metadata) error,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	canonical, err := json.Marshal(struct {
		Operation string `json:"operation"`
		Request   any    `json:"request"`
	}{Operation: operation, Request: request})
	if err != nil {
		return err
	}
	for attempt := 1; ; attempt++ {
		identity, idErr := (eventstore.UUIDGenerator{}).NewID()
		if idErr != nil {
			return idErr
		}
		metadata := eventstore.Metadata{CommandID: identity, CorrelationID: identity, Producer: "dice/" + operation}
		err = execute(ctx, identity, canonical, func(transaction *DurableCallbackTransaction) error {
			return run(transaction, metadata)
		})
		if err == nil || !errors.Is(err, eventstore.ErrConflict) || attempt >= maxFreshDomainExecutionAttempts || ctx.Err() != nil {
			return err
		}
	}
}

// DurableCommitConfigSnapshot applies one detached configuration DTO through
// the canonical config participant. It never diffs a mutable runtime mirror.
func (d *Dice) DurableCommitConfigSnapshot(ctx context.Context, config Config, commandPrefix, diceMasters []string, mailPasswordRef *string) error {
	request := struct {
		Config          Config   `json:"config"`
		CommandPrefix   []string `json:"commandPrefix"`
		DiceMasters     []string `json:"diceMasters"`
		MailPasswordRef *string  `json:"mailPasswordRef,omitempty"`
	}{
		Config: config, CommandPrefix: commandPrefix, DiceMasters: diceMasters, MailPasswordRef: mailPasswordRef,
	}
	err := d.withFreshDomainExecution(ctx, "config-snapshot", request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		participant, _, stateErr := d.configOwner(ctx, transaction.Domain())
		if stateErr != nil {
			return stateErr
		}
		if !configSourceMatchesParticipant(config.source, participant) {
			return ErrConfigViewChanged
		}
		state := participant.state.Clone()
		patch, patchErr := durableConfigPatch(state, config, commandPrefix, diceMasters, mailPasswordRef)
		if patchErr != nil {
			return patchErr
		}
		return d.ContributeConfigCommand(ctx, transaction.Domain(), metadata, configstate.Command{
			Kind: configstate.CommandPatch, Patch: &patch,
		})
	})
	if err != nil {
		return err
	}
	if err = d.ReloadConfigView(ctx); err != nil {
		return &ConfigRuntimeApplyError{Err: err}
	}
	return nil
}

// DurableMutateConfig runs a pure mutation against the config state selected
// inside one root. The callback receives a detached DTO; it must not retain it
// or perform I/O. This is for focused business commands that cannot safely
// construct a whole replacement from a pre-root snapshot.
func (d *Dice) DurableMutateConfig(
	ctx context.Context,
	operation string,
	request any,
	mutate func(*Config) error,
) error {
	if strings.TrimSpace(operation) == "" || mutate == nil {
		return errors.New("dice: invalid config mutation")
	}
	err := d.withFreshDomainExecution(ctx, "config-"+operation, request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		state, stateErr := d.ConfigStateForDomain(ctx, transaction.Domain())
		if stateErr != nil {
			return stateErr
		}
		config, _, stateErr := d.legacyConfigViewFromState(state)
		if stateErr != nil {
			return stateErr
		}
		if stateErr = mutate(&config); stateErr != nil {
			return stateErr
		}
		patch, stateErr := durableConfigPatch(
			state,
			config,
			config.CommandPrefix,
			config.DiceMasters,
			nil,
		)
		if stateErr != nil {
			return stateErr
		}
		return d.ContributeConfigCommand(ctx, transaction.Domain(), metadata, configstate.Command{
			Kind:  configstate.CommandPatch,
			Patch: &patch,
		})
	})
	if err != nil {
		return err
	}
	if err = d.ReloadConfigView(ctx); err != nil {
		return &ConfigRuntimeApplyError{Err: err}
	}
	return nil
}

type DurableManagerConfigPatch struct {
	ServeAddress   *string
	TrayTooltip    *string
	UIPasswordHash *string
	DiceRandomMode *string
}

type DurableExtensionDefault struct {
	ExtensionID      string
	AutoActive       bool
	DisabledCommands []string
}

type DurableConfigRequest struct {
	Config                   Config
	CommandPrefix            []string
	DiceMasters              []string
	MailPasswordRef          *string
	PersistDiceConfig        bool
	Manager                  *DurableManagerConfigPatch
	ExtensionDefaults        []DurableExtensionDefault
	PersistExtensionDefaults bool
}

type configParticipant struct {
	store           eventstore.Store
	base            configstate.State
	state           configstate.State
	dependency      eventstore.DependencySnapshot
	reloadScheduled bool
	events          []configstate.TypedEvent
	metadata        eventstore.Metadata
}

func (p *configParticipant) Contribute(context.Context) (eventstore.UnitOfWork, error) {
	if p == nil || len(p.events) == 0 {
		return eventstore.UnitOfWork{}, nil
	}
	factory := eventstore.EventFactory{Clock: eventstore.SystemClock{}, IDs: eventstore.UUIDGenerator{}}
	metadata := p.metadata
	events := make([]eventstore.NewEvent, 0, len(p.events))
	for _, typed := range p.events {
		event, err := configstate.NewEventWithFactory(factory, typed, metadata)
		if err != nil {
			return eventstore.UnitOfWork{}, err
		}
		events = append(events, event)
		metadata.EventID = ""
	}
	return eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{{
		Stream:          configstate.ConfigStream(p.base.DiceID),
		ExpectedVersion: p.base.Version,
		Events:          events,
	}}}, nil
}

func (p *configParticipant) decide(command configstate.Command, metadata eventstore.Metadata) error {
	if p == nil {
		return execution.ErrInvalidParticipant
	}
	command.ExpectedVersion = p.state.Version
	command.ExpectedVersionSet = true
	decision, err := configstate.Decide(p.state, command)
	if err != nil {
		return err
	}
	next := p.state
	for _, event := range decision.Events {
		next, err = configstate.Reduce(next, event)
		if err != nil {
			return err
		}
	}
	p.state = next
	p.events = append(p.events, decision.Events...)
	if p.metadata.CommandID == "" {
		p.metadata = metadata
	}
	return nil
}

func (d *Dice) configOwner(ctx context.Context, tx *execution.DomainTx) (*configParticipant, execution.ParticipantKey, error) {
	return d.configOwnerFromView(ctx, tx, d.currentConfigView())
}

func (d *Dice) configOwnerFromView(
	ctx context.Context,
	tx *execution.DomainTx,
	view *configReadView,
) (*configParticipant, execution.ParticipantKey, error) {
	if d == nil || tx == nil {
		return nil, execution.ParticipantKey{}, execution.ErrDomainTxUnavailable
	}
	if view == nil || view.state.Version == 0 || view.dependency.ProjectionGeneration == "" {
		return nil, execution.ParticipantKey{}, ErrConfigViewUnavailable
	}
	stream := configstate.ConfigStream(d.BaseConfig.Name)
	key := execution.StreamParticipantKey(stream)
	participant, err := tx.Owner(ctx, key, func(context.Context) (execution.Participant, execution.ReadDependencies, error) {
		installed := &configParticipant{
			store:      d.DurableStore,
			base:       view.state.Clone(),
			state:      view.state.Clone(),
			dependency: view.dependency,
		}
		return installed, execution.ReadDependenciesFromStream(eventstore.StreamSnapshot{
			Stream: stream, Version: view.version, Snapshot: view.dependency,
		}), nil
	})
	if err != nil {
		return nil, execution.ParticipantKey{}, err
	}
	typed, ok := participant.(*configParticipant)
	if !ok {
		return nil, execution.ParticipantKey{}, execution.ErrInvalidParticipant
	}
	return typed, key, nil
}

func (d *Dice) ContributeConfigCommand(
	ctx context.Context,
	tx *execution.DomainTx,
	metadata eventstore.Metadata,
	command configstate.Command,
) error {
	_, key, err := d.configOwner(ctx, tx)
	if err != nil {
		return err
	}
	return tx.Mutate(key, func(participant execution.Participant) error {
		typed, ok := participant.(*configParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		return typed.decide(command, metadata)
	})
}

func (d *Dice) ConfigStateForDomain(ctx context.Context, tx *execution.DomainTx) (configstate.State, error) {
	participant, _, err := d.configOwner(ctx, tx)
	if err != nil {
		return configstate.State{}, err
	}
	return participant.state.Clone(), nil
}

func configSourceMatchesParticipant(source configViewSource, participant *configParticipant) bool {
	return participant != nil &&
		source.version != 0 &&
		source.version == participant.base.Version &&
		source.dependency == participant.dependency
}

func (d *Dice) scheduleConfigViewReloadAfterCommit(ctx context.Context, transaction *DurableCallbackTransaction) error {
	if transaction == nil {
		return execution.ErrDomainTxUnavailable
	}
	_, key, err := d.configOwner(ctx, transaction.Domain())
	if err != nil {
		return err
	}
	schedule := false
	if err = transaction.Domain().Mutate(key, func(participant execution.Participant) error {
		config, ok := participant.(*configParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		if !config.reloadScheduled {
			config.reloadScheduled = true
			schedule = true
		}
		return nil
	}); err != nil || !schedule {
		return err
	}
	return transaction.AfterCommit(func() {
		if reloadErr := d.ReloadConfigView(context.Background()); reloadErr != nil && d.Logger != nil {
			d.Logger.Errorf("配置已提交但运行时视图刷新失败: %v", reloadErr)
		}
	})
}

func (d *Dice) ContributeDiceMasterMutation(
	ctx context.Context,
	tx *execution.DomainTx,
	metadata eventstore.Metadata,
	uid string,
	enabled bool,
) (bool, error) {
	if strings.TrimSpace(uid) == "" {
		return false, errors.New("dice: master ID is empty")
	}
	state, err := d.ConfigStateForDomain(ctx, tx)
	if err != nil {
		return false, err
	}
	index := -1
	for position, current := range state.Outer.DiceMasters {
		if current == uid {
			index = position
			break
		}
	}
	if enabled == (index >= 0) {
		return false, nil
	}
	outer := state.Outer
	outer.CommandPrefix = append([]string(nil), state.Outer.CommandPrefix...)
	if enabled {
		outer.DiceMasters = append(append([]string(nil), state.Outer.DiceMasters...), uid)
	} else {
		outer.DiceMasters = make([]string, 0, len(state.Outer.DiceMasters)-1)
		outer.DiceMasters = append(outer.DiceMasters, state.Outer.DiceMasters[:index]...)
		outer.DiceMasters = append(outer.DiceMasters, state.Outer.DiceMasters[index+1:]...)
	}
	if err = d.ContributeConfigCommand(ctx, tx, metadata, configstate.Command{
		Kind:  configstate.CommandPatch,
		Patch: &configstate.ConfigPatch{Outer: &outer},
	}); err != nil {
		return false, err
	}
	return true, nil
}

func (d *Dice) SetDiceMasterForContext(ctx *MsgContext, uid string, enabled bool) (bool, error) {
	if ctx == nil || ctx.callbackTransaction == nil {
		return false, execution.ErrDomainTxUnavailable
	}
	if ctx.Dice != nil && ctx.Dice != d {
		return false, errors.New("dice: message context belongs to another dice")
	}
	changed, err := d.ContributeDiceMasterMutation(
		ctx.domainContext(),
		ctx.callbackTransaction.Domain(),
		ctx.callbackMetadata,
		uid,
		enabled,
	)
	if err != nil || !changed {
		return changed, err
	}
	if err = d.scheduleConfigViewReloadAfterCommit(ctx.domainContext(), ctx.callbackTransaction); err != nil {
		return false, err
	}
	return true, nil
}

// ConfigStateForContext returns the transaction-local config state when the
// caller is already inside a durable message root. This makes write-then-read
// behavior observe prior mutations in the same root.
func (d *Dice) ConfigStateForContext(ctx *MsgContext) (configstate.State, error) {
	if d == nil {
		return configstate.State{}, ErrDurableStateUnavailable
	}
	if ctx != nil && ctx.callbackTransaction != nil {
		if ctx.Dice != nil && ctx.Dice != d {
			return configstate.State{}, errors.New("dice: message context belongs to another dice")
		}
		return d.ConfigStateForDomain(ctx.domainContext(), ctx.callbackTransaction.Domain())
	}
	return d.ConfigStateSnapshot(), nil
}

func (d *Dice) DiceMasterIDsForContext(ctx *MsgContext) ([]string, error) {
	if d == nil {
		return nil, ErrDurableStateUnavailable
	}
	if ctx == nil || ctx.callbackTransaction == nil {
		return d.DiceMasterIDs(), nil
	}
	if ctx.Dice != nil && ctx.Dice != d {
		return nil, errors.New("dice: message context belongs to another dice")
	}
	participant, _, err := d.configOwner(ctx.domainContext(), ctx.callbackTransaction.Domain())
	if err != nil {
		return nil, err
	}
	return append([]string(nil), participant.state.Outer.DiceMasters...), nil
}

func (d *Dice) IsDiceMasterForContext(ctx *MsgContext, uid string) (bool, error) {
	if d == nil {
		return false, ErrDurableStateUnavailable
	}
	if ctx == nil || ctx.callbackTransaction == nil {
		for _, master := range d.DiceMasterIDs() {
			if master == uid {
				return true, nil
			}
		}
		return false, nil
	}
	if ctx.Dice != nil && ctx.Dice != d {
		return false, errors.New("dice: message context belongs to another dice")
	}
	participant, _, err := d.configOwner(ctx.domainContext(), ctx.callbackTransaction.Domain())
	if err != nil {
		return false, err
	}
	for _, master := range participant.state.Outer.DiceMasters {
		if master == uid {
			return true, nil
		}
	}
	return false, nil
}

func (d *Dice) ContributeUpgradeTarget(
	ctx context.Context,
	tx *execution.DomainTx,
	metadata eventstore.Metadata,
	windowID, endpointID string,
) error {
	state, err := d.ConfigStateForDomain(ctx, tx)
	if err != nil {
		return err
	}
	outer := state.Outer
	outer.CommandPrefix = append([]string(nil), state.Outer.CommandPrefix...)
	outer.DiceMasters = append([]string(nil), state.Outer.DiceMasters...)
	outer.UpgradeWindowID = windowID
	outer.UpgradeEndpointID = endpointID
	return d.ContributeConfigCommand(ctx, tx, metadata, configstate.Command{
		Kind:  configstate.CommandPatch,
		Patch: &configstate.ConfigPatch{Outer: &outer},
	})
}

func (d *Dice) SetUpgradeTargetForContext(ctx *MsgContext, windowID, endpointID string) error {
	if ctx == nil || ctx.callbackTransaction == nil {
		return execution.ErrDomainTxUnavailable
	}
	if ctx.Dice != nil && ctx.Dice != d {
		return errors.New("dice: message context belongs to another dice")
	}
	if err := d.ContributeUpgradeTarget(
		ctx.domainContext(),
		ctx.callbackTransaction.Domain(),
		ctx.callbackMetadata,
		windowID,
		endpointID,
	); err != nil {
		return err
	}
	return d.scheduleConfigViewReloadAfterCommit(ctx.domainContext(), ctx.callbackTransaction)
}

func (d *Dice) DurableSetUpgradeTarget(ctx context.Context, windowID, endpointID string) error {
	request := struct {
		WindowID   string `json:"windowId"`
		EndpointID string `json:"endpointId"`
	}{windowID, endpointID}
	err := d.withFreshDomainExecution(ctx, "config-upgrade-target", request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		return d.ContributeUpgradeTarget(ctx, transaction.Domain(), metadata, windowID, endpointID)
	})
	if err != nil {
		return err
	}
	return d.ReloadConfigView(ctx)
}

type managerParticipant struct {
	repository *managerstate.Repository
	base       managerstate.State
	public     managerstate.PublicConfig
	auth       managerstate.Auth
	dirty      bool
}

func (p *managerParticipant) Contribute(ctx context.Context) (eventstore.UnitOfWork, error) {
	if p == nil || !p.dirty {
		return eventstore.UnitOfWork{}, nil
	}
	prepared, err := p.repository.PrepareSave(ctx, p.base, p.public, p.auth)
	if err != nil {
		return eventstore.UnitOfWork{}, err
	}
	return eventstore.UnitOfWork{
		Streams:       []eventstore.StreamAppend{prepared.Stream},
		SecretUpdates: []eventstore.SecretUpdate{prepared.Secret},
	}, nil
}

type secretResolver interface {
	ResolveSecret(ctx context.Context, ref string, version uint64) (eventstore.SecretResolution, error)
}

func (dm *DiceManager) managerOwner(ctx context.Context, tx *execution.DomainTx) (*managerParticipant, execution.ParticipantKey, error) {
	if dm == nil || dm.durableStore == nil || tx == nil {
		return nil, execution.ParticipantKey{}, execution.ErrDomainTxUnavailable
	}
	stream := managerstate.Stream()
	key := execution.StreamParticipantKey(stream)
	participant, err := tx.Owner(ctx, key, func(loadCtx context.Context) (execution.Participant, execution.ReadDependencies, error) {
		reader, ok := dm.durableStore.(eventstore.ProjectionDependencyRepository)
		if !ok {
			return nil, execution.ReadDependencies{}, managerstate.ErrRepositoryUnavailable
		}
		resolver, ok := dm.durableStore.(secretResolver)
		if !ok {
			return nil, execution.ReadDependencies{}, managerstate.ErrRepositoryUnavailable
		}
		snapshot, readErr := reader.ReadProjectionDependency(loadCtx, managerstate.ProjectionName, managerstate.AggregateID, stream)
		if readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		if !snapshot.Found || snapshot.StreamVersion == 0 {
			return nil, execution.ReadDependencies{}, managerstate.ErrInvalidState
		}
		var state managerstate.State
		if readErr = json.Unmarshal(snapshot.Row.Payload, &state); readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		if readErr = managerstate.ValidateState(state); readErr != nil || state.Version != snapshot.StreamVersion {
			if readErr != nil {
				return nil, execution.ReadDependencies{}, readErr
			}
			return nil, execution.ReadDependencies{}, execution.ErrDomainSnapshotChanged
		}
		secret, readErr := resolver.ResolveSecret(loadCtx, state.AuthSecretRef, state.AuthSecretVersion)
		if readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		auth, readErr := managerstate.DecodeAuth(secret.Value)
		if readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		repository, readErr := managerstate.NewRepository(dm.durableStore)
		if readErr != nil {
			return nil, execution.ReadDependencies{}, readErr
		}
		installed := &managerParticipant{
			repository: repository,
			base:       state,
			public:     state.Public,
			auth:       auth,
		}
		return installed, execution.ReadDependenciesFromStream(eventstore.StreamSnapshot{
			Stream: stream, Version: snapshot.StreamVersion, Snapshot: snapshot.Snapshot,
		}), nil
	})
	if err != nil {
		return nil, execution.ParticipantKey{}, err
	}
	typed, ok := participant.(*managerParticipant)
	if !ok {
		return nil, execution.ParticipantKey{}, execution.ErrInvalidParticipant
	}
	return typed, key, nil
}

func (dm *DiceManager) contributeManagerPatch(ctx context.Context, tx *execution.DomainTx, patch *DurableManagerConfigPatch) error {
	if !durableManagerPatchRequested(patch) {
		return nil
	}
	_, key, err := dm.managerOwner(ctx, tx)
	if err != nil {
		return err
	}
	return tx.Mutate(key, func(participant execution.Participant) error {
		manager, ok := participant.(*managerParticipant)
		if !ok {
			return execution.ErrInvalidParticipant
		}
		if patch.ServeAddress != nil {
			manager.public.ServeAddress = *patch.ServeAddress
		}
		if patch.TrayTooltip != nil {
			manager.public.TrayTooltip = NormalizeTrayTooltipPrefix(*patch.TrayTooltip)
		}
		if patch.DiceRandomMode != nil {
			manager.public.DiceRandomMode = *patch.DiceRandomMode
		}
		if patch.UIPasswordHash != nil {
			manager.auth.UIPasswordHash = *patch.UIPasswordHash
			manager.auth.AccessTokens = nil
		}
		manager.dirty = true
		return nil
	})
}

func (dm *DiceManager) reloadManagerRuntime(ctx context.Context) error {
	if dm == nil || dm.durableStore == nil {
		return managerstate.ErrRepositoryUnavailable
	}
	repository, err := managerstate.NewRepository(dm.durableStore)
	if err != nil {
		return err
	}
	state, auth, err := repository.Load(ctx)
	if err != nil {
		return err
	}
	dm.publishManagerRuntime(state, auth)
	return nil
}

func (dm *DiceManager) publishManagerRuntime(state managerstate.State, auth managerstate.Auth) bool {
	if dm == nil {
		return false
	}
	published := false
	dm.managerStateMu.Lock()
	if dm.managerState.Version <= state.Version {
		dm.managerState = state
		dm.applyEventSourcedManager(state.Public, auth)
		published = true
	}
	dm.managerStateMu.Unlock()
	return published
}

func cloneManagerPublicConfig(public managerstate.PublicConfig) managerstate.PublicConfig {
	if public.DiceDataDirs == nil {
		return public
	}
	dirs := make(map[string]string, len(public.DiceDataDirs))
	for diceID, dataDir := range public.DiceDataDirs {
		dirs[diceID] = dataDir
	}
	public.DiceDataDirs = dirs
	return public
}

func (dm *DiceManager) ManagerPublicConfigSnapshot() (managerstate.PublicConfig, bool) {
	if dm == nil {
		return managerstate.PublicConfig{}, false
	}
	dm.managerStateMu.Lock()
	public := cloneManagerPublicConfig(dm.managerState.Public)
	passwordConfigured := dm.UIPasswordHash != ""
	dm.managerStateMu.Unlock()
	return public, passwordConfigured
}

// DurableMutateManagerConfig runs a pure mutation against canonical manager
// public state selected inside a fresh root. The callback must not retain the
// detached DTO or perform I/O.
func (dm *DiceManager) DurableMutateManagerConfig(
	ctx context.Context,
	operation string,
	request any,
	mutate func(*managerstate.PublicConfig) error,
) error {
	if strings.TrimSpace(operation) == "" || mutate == nil {
		return errors.New("dice: invalid manager config mutation")
	}
	randomModeChanged := false
	err := dm.withFreshDomainExecution(ctx, "manager-"+operation, request, func(transaction *DurableCallbackTransaction, _ eventstore.Metadata) error {
		randomModeChanged = false
		_, key, ownerErr := dm.managerOwner(ctx, transaction.Domain())
		if ownerErr != nil {
			return ownerErr
		}
		return transaction.Domain().Mutate(key, func(participant execution.Participant) error {
			manager, ok := participant.(*managerParticipant)
			if !ok {
				return execution.ErrInvalidParticipant
			}
			public := cloneManagerPublicConfig(manager.public)
			if mutateErr := mutate(&public); mutateErr != nil {
				return mutateErr
			}
			if public.DiceRandomMode != manager.public.DiceRandomMode {
				effective, validateErr := dm.ValidateDiceRandomMode(DiceRandomMode(public.DiceRandomMode))
				if validateErr != nil {
					return validateErr
				}
				public.DiceRandomMode = string(effective)
				randomModeChanged = true
			}
			manager.public = cloneManagerPublicConfig(public)
			manager.dirty = true
			return nil
		})
	})
	if err != nil {
		return err
	}
	if err = dm.reloadManagerRuntime(ctx); err != nil {
		return &ConfigRuntimeApplyError{Err: err}
	}
	if randomModeChanged {
		if err = dm.ActivateDiceRandomMode(); err != nil {
			return &ConfigRuntimeApplyError{Err: err}
		}
	}
	return nil
}

func (dm *DiceManager) DurableAuthenticateAndStoreAccessToken(ctx context.Context, password, token string) (bool, error) {
	if strings.TrimSpace(token) == "" {
		return false, errors.New("manager access token is empty")
	}
	request := struct {
		Token string `json:"token"`
	}{Token: token}
	authenticated := false
	changed := false
	err := dm.withFreshDomainExecution(ctx, "manager-auth-token", request, func(transaction *DurableCallbackTransaction, _ eventstore.Metadata) error {
		authenticated, changed = false, false
		_, key, ownerErr := dm.managerOwner(ctx, transaction.Domain())
		if ownerErr != nil {
			return ownerErr
		}
		return transaction.Domain().Mutate(key, func(participant execution.Participant) error {
			manager, ok := participant.(*managerParticipant)
			if !ok {
				return execution.ErrInvalidParticipant
			}
			if manager.auth.UIPasswordHash != "" && manager.auth.UIPasswordHash != password {
				return nil
			}
			authenticated = true
			for _, existing := range manager.auth.AccessTokens {
				if existing == token {
					return nil
				}
			}
			manager.auth.AccessTokens = append(manager.auth.AccessTokens, token)
			manager.dirty = true
			changed = true
			return nil
		})
	})
	if err != nil || !changed {
		return authenticated, err
	}
	if err = dm.reloadManagerRuntime(ctx); err != nil {
		return true, &ConfigRuntimeApplyError{Err: err}
	}
	return true, nil
}

// DurableCommitConfigRequest contributes every addressed owner to one root.
// Runtime publications occur only after that root has atomically committed.
func (d *Dice) DurableCommitConfigRequest(ctx context.Context, request DurableConfigRequest) error {
	randomModeChanged := request.Manager != nil && request.Manager.DiceRandomMode != nil
	if randomModeChanged {
		if d == nil || d.Parent == nil {
			return ErrDurableStateUnavailable
		}
		effective, validateErr := d.Parent.ValidateDiceRandomMode(DiceRandomMode(*request.Manager.DiceRandomMode))
		if validateErr != nil {
			return validateErr
		}
		managerPatch := *request.Manager
		validatedMode := string(effective)
		managerPatch.DiceRandomMode = &validatedMode
		request.Manager = &managerPatch
	}
	err := d.withFreshDomainExecution(ctx, "config-request", request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		tx := transaction.Domain()
		if request.PersistDiceConfig {
			participant, _, stateErr := d.configOwner(ctx, tx)
			if stateErr != nil {
				return stateErr
			}
			if !configSourceMatchesParticipant(request.Config.source, participant) {
				return ErrConfigViewChanged
			}
			state := participant.state.Clone()
			patch, patchErr := durableConfigPatch(
				state, request.Config, request.CommandPrefix, request.DiceMasters, request.MailPasswordRef,
			)
			if patchErr != nil {
				return patchErr
			}
			if patchErr = d.ContributeConfigCommand(ctx, tx, metadata, configstate.Command{
				Kind: configstate.CommandPatch, Patch: &patch,
			}); patchErr != nil {
				return patchErr
			}
		}

		if request.PersistExtensionDefaults {
			state, stateErr := d.ExtensionStateForDomain(ctx, tx)
			if stateErr != nil {
				return stateErr
			}
			desired := make(map[string]struct{}, len(request.ExtensionDefaults))
			for _, defaults := range request.ExtensionDefaults {
				desired[defaults.ExtensionID] = struct{}{}
				if stateErr = d.ContributeExtensionCommand(ctx, tx, metadata, extensionstate.Command{
					Kind:             extensionstate.CommandSetDefaults,
					ExtensionID:      defaults.ExtensionID,
					AutoActive:       defaults.AutoActive,
					DisabledCommands: append([]string(nil), defaults.DisabledCommands...),
				}); stateErr != nil {
					return stateErr
				}
			}
			removed := make([]string, 0, len(state.DefaultCommands))
			for extensionID := range state.DefaultCommands {
				if _, keep := desired[extensionID]; !keep {
					removed = append(removed, extensionID)
				}
			}
			sort.Strings(removed)
			for _, extensionID := range removed {
				if stateErr = d.ContributeExtensionCommand(ctx, tx, metadata, extensionstate.Command{
					Kind: extensionstate.CommandClearDefaults, ExtensionID: extensionID,
				}); stateErr != nil {
					return stateErr
				}
			}
		}

		return d.Parent.contributeManagerPatch(ctx, tx, request.Manager)
	})
	if err != nil {
		return err
	}

	var applyErr error
	if request.PersistDiceConfig {
		applyErr = errors.Join(applyErr, d.ReloadConfigView(ctx))
	}
	if durableManagerPatchRequested(request.Manager) {
		reloadErr := d.Parent.reloadManagerRuntime(ctx)
		applyErr = errors.Join(applyErr, reloadErr)
		if reloadErr == nil && randomModeChanged {
			applyErr = errors.Join(applyErr, d.Parent.ActivateDiceRandomMode())
		}
	}
	if applyErr != nil {
		return &ConfigRuntimeApplyError{Err: applyErr}
	}
	return nil
}

func durableManagerPatchRequested(patch *DurableManagerConfigPatch) bool {
	return patch != nil &&
		(patch.ServeAddress != nil || patch.TrayTooltip != nil ||
			patch.UIPasswordHash != nil || patch.DiceRandomMode != nil)
}

// DurableCommitAdvancedSnapshot persists advanced settings while retaining the
// existing token reference unless the request explicitly changes it.
func (d *Dice) DurableCommitAdvancedSnapshot(ctx context.Context, advanced AdvancedConfig, tokenRef *string) error {
	request := struct {
		Advanced AdvancedConfig `json:"advanced"`
		TokenRef *string        `json:"tokenRef,omitempty"`
	}{Advanced: advanced, TokenRef: tokenRef}
	err := d.withFreshDomainExecution(ctx, "advanced-config", request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		participant, _, stateErr := d.configOwner(ctx, transaction.Domain())
		if stateErr != nil {
			return stateErr
		}
		if !configSourceMatchesParticipant(advanced.source, participant) {
			return ErrConfigViewChanged
		}
		if advanced.ExposeDangerousSealInst {
			return ErrDangerousSealInstUnsupported
		}
		state := participant.state.Clone()
		ref := state.Advanced.StoryLogBackendTokenRef
		if tokenRef != nil {
			if *tokenRef != "" && !durableConfigSecretReference(*tokenRef) {
				return errors.New("dice: advanced token must be a vault: or sha256: reference")
			}
			ref = strings.TrimSpace(*tokenRef)
		}
		group := configstate.AdvancedConfig{
			Show:                              advanced.Show,
			Enable:                            advanced.Enable,
			StoryLogBackendURL:                advanced.StoryLogBackendUrl,
			StoryLogAPIVersion:                advanced.StoryLogApiVersion,
			StoryLogBackendTokenRef:           ref,
			CustomReplyCooldown:               advanced.CustomReplyCooldown,
			ExposeDangerousSealInst:           advanced.ExposeDangerousSealInst,
			AllowFilesystemUnrestrictedAccess: advanced.AllowFilesystemUnrestrictedAccess,
		}
		return d.ContributeConfigCommand(ctx, transaction.Domain(), metadata, configstate.Command{
			Kind: configstate.CommandPatch, Patch: &configstate.ConfigPatch{Advanced: &group},
		})
	})
	if err != nil {
		return err
	}
	if err = d.ReloadConfigView(ctx); err != nil {
		return &ConfigRuntimeApplyError{Err: err}
	}
	return nil
}

// DurableSetExtensionDefaults changes one extension's default command policy
// through the extension aggregate instead of a Config slice.
func (d *Dice) DurableSetExtensionDefaults(ctx context.Context, extensionID string, autoActive bool, disabledCommands []string) error {
	request := DurableExtensionDefault{
		ExtensionID: extensionID, AutoActive: autoActive,
		DisabledCommands: append([]string(nil), disabledCommands...),
	}
	return d.withFreshDomainExecution(ctx, "extension-defaults", request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		return d.ContributeExtensionCommand(ctx, transaction.Domain(), metadata, extensionstate.Command{
			Kind:             extensionstate.CommandSetDefaults,
			ExtensionID:      extensionID,
			AutoActive:       autoActive,
			DisabledCommands: append([]string(nil), disabledCommands...),
		})
	})
}

func durableConfigSecretReference(value string) bool {
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, "sha256:")
}

func durableConfigPatch(state configstate.State, config Config, commandPrefix, diceMasters []string, mailPasswordRef *string) (configstate.ConfigPatch, error) {
	mailRef := state.Mail.MailPasswordRef
	if mailPasswordRef != nil {
		if *mailPasswordRef != "" && !durableConfigSecretReference(*mailPasswordRef) {
			return configstate.ConfigPatch{}, errors.New("dice: mail password must be a vault: or sha256: reference")
		}
		mailRef = strings.TrimSpace(*mailPasswordRef)
	}

	base := configstate.BaseConfig{
		CommandCompatibleMode:   config.CommandCompatibleMode,
		NoticeIDs:               append([]string(nil), config.NoticeIDs...),
		OnlyLogCommandInGroup:   config.OnlyLogCommandInGroup,
		OnlyLogCommandInPrivate: config.OnlyLogCommandInPrivate,
		VersionCode:             config.VersionCode,
		MessageDelayRangeStart:  config.MessageDelayRangeStart,
		MessageDelayRangeEnd:    config.MessageDelayRangeEnd,
		WorkInQQChannel:         config.WorkInQQChannel,
		QQChannelAutoOn:         config.QQChannelAutoOn,
		QQChannelLogMessage:     config.QQChannelLogMessage,
		QQEnablePoke:            config.QQEnablePoke,
		TextCmdTrustOnly:        config.TextCmdTrustOnly,
		IgnoreUnaddressedBotCmd: config.IgnoreUnaddressedBotCmd,
		UILogLimit:              config.UILogLimit,
		FriendAddComment:        config.FriendAddComment,
		CustomReplyConfigEnable: config.CustomReplyConfigEnable,
		AutoReloginEnable:       config.AutoReloginEnable,
		RefuseGroupInvite:       config.RefuseGroupInvite,
		BotExtFreeSwitch:        config.BotExtFreeSwitch,
		BotExitWithoutAt:        config.BotExitWithoutAt,
		TrustOnlyMode:           config.TrustOnlyMode,
		AliveNoticeEnable:       config.AliveNoticeEnable,
		AliveNoticeValue:        config.AliveNoticeValue,
		ReplyDebugMode:          config.ReplyDebugMode,
		PlayerNameWrapEnable:    config.PlayerNameWrapEnable,
		DiceRandomMode:          config.DiceRandomMode,
		VMVersionForReply:       config.VMVersionForReply,
		VMVersionForDeck:        config.VMVersionForDeck,
		VMVersionForCustomText:  config.VMVersionForCustomText,
		VMVersionForMsg:         config.VMVersionForMsg,
	}
	rateConfig := configstate.RateConfig{
		RateLimitEnabled:          config.RateLimitEnabled,
		PersonalReplenishRate:     config.PersonalReplenishRateStr,
		GroupReplenishRate:        config.GroupReplenishRateStr,
		PersonalBurst:             config.PersonalBurst,
		GroupBurst:                config.GroupBurst,
		SpamSameCommandWindowSec:  config.SpamSameCommandWindowSec,
		SpamRecoveryMultiplierMax: config.SpamRecoveryMultiplierMax,
	}
	quitConfig := configstate.QuitConfig{
		QuitInactiveThreshold:         config.QuitInactiveThreshold.String(),
		QuitInactiveNoticeSummaryMode: config.QuitInactiveNoticeSummaryMode,
		QuitInactiveBatchSize:         config.QuitInactiveBatchSize,
		QuitInactiveBatchWait:         config.QuitInactiveBatchWait,
	}
	extensionConfig := configstate.ExtensionConfig{
		DefaultCocRuleIndex: config.DefaultCocRuleIndex,
		MaxExecuteTime:      config.MaxExecuteTime,
		MaxCocCardGen:       config.MaxCocCardGen,
		CocCardMergeForward: config.CocCardMergeForward,
	}
	banConfig := configstate.BanConfig{}
	if config.BanList != nil {
		banConfig = configstate.BanConfig{
			RefuseReply:                 config.BanList.BanBehaviorRefuseReply,
			RefuseInvite:                config.BanList.BanBehaviorRefuseInvite,
			QuitLastPlace:               config.BanList.BanBehaviorQuitLastPlace,
			QuitPlaceImmediately:        config.BanList.BanBehaviorQuitPlaceImmediately,
			QuitIfAdmin:                 config.BanList.BanBehaviorQuitIfAdmin,
			QuitIfAdminSilentIfNotAdmin: config.BanList.BanBehaviorQuitIfAdminSilentIfNotAdmin,
			ThresholdWarn:               config.BanList.ThresholdWarn,
			ThresholdBan:                config.BanList.ThresholdBan,
			AutoBanMinutes:              config.BanList.AutoBanMinutes,
			ScoreReducePerMinute:        config.BanList.ScoreReducePerMinute,
			ScoreGroupMuted:             config.BanList.ScoreGroupMuted,
			ScoreGroupKicked:            config.BanList.ScoreGroupKicked,
			ScoreTooManyCommand:         config.BanList.ScoreTooManyCommand,
			BanNotifyIntervalMinutes:    config.BanList.BanNotifyIntervalMinutes,
			JointScorePercentOfGroup:    config.BanList.JointScorePercentOfGroup,
			JointScorePercentOfInviter:  config.BanList.JointScorePercentOfInviter,
		}
	}
	jsConfig := configstate.JSConfig{
		JsEnable:                       config.JsEnable,
		JsEngine:                       config.JsEngine,
		JsRuntimeOptions:               cloneJSRuntimeOptions(config.JsRuntimeOptions),
		JsRuntimeRoutes:                cloneJSRuntimeRoutes(config.JsRuntimeRoutes),
		DisabledJsScripts:              cloneDisabledJsScripts(config.DisabledJsScripts),
		QuickJSMemoryLimitMiB:          config.QuickJSMemoryLimitMiB,
		QuickJSGCThresholdMiB:          config.QuickJSGCThresholdMiB,
		QuickJSMaxStackSizeKiB:         config.QuickJSMaxStackSizeKiB,
		QuickJSExecuteTimeoutSeconds:   config.QuickJSExecuteTimeoutSeconds,
		QuickJSMaxFetchConcurrent:      config.QuickJSMaxFetchConcurrent,
		QuickJSMaxFetchResponseMiB:     config.QuickJSMaxFetchResponseMiB,
		QuickJSMaxWebSocketConnections: config.QuickJSMaxWebSocketConnections,
		QuickJSMaxWebSocketMessageMiB:  config.QuickJSMaxWebSocketMessageMiB,
		QuickJSMaxFilesystemReadMiB:    config.QuickJSMaxFilesystemReadMiB,
		QuickJSMaxFilesystemWriteMiB:   config.QuickJSMaxFilesystemWriteMiB,
		QuickJSMaxPBKDF2Iterations:     config.QuickJSMaxPBKDF2Iterations,
		QuickJSMaxPBKDF2OutputBytes:    config.QuickJSMaxPBKDF2OutputBytes,
	}
	storyLogConfig := configstate.StoryLogConfig{LogSizeNoticeEnable: config.LogSizeNoticeEnable, LogSizeNoticeCount: config.LogSizeNoticeCount}
	mailConfig := configstate.MailConfig{MailEnable: config.MailEnable, MailFrom: config.MailFrom, MailPasswordRef: mailRef, MailSMTP: config.MailSMTP}
	newsConfig := configstate.NewsConfig{NewsMark: config.NewsMark}
	publicDiceConfig := configstate.PublicDiceConfig{
		Enable: config.Enable, ID: config.ID, Name: config.PublicDiceConfig.Name,
		Brief: config.Brief, Note: config.Note, Avatar: config.Avatar,
		EndpointIDs: append([]string(nil), config.EndpointIDs...),
	}
	censorConfig := configstate.CensorConfig{Enable: config.EnableCensor, Mode: int(config.CensorMode), CaseSensitive: config.CensorCaseSensitive, MatchPinyin: config.CensorMatchPinyin, FilterRegex: config.CensorFilterRegexStr, Thresholds: map[string]int{}, Handlers: map[string]uint8{}, Scores: map[string]int{}}
	for level, value := range config.CensorThresholds {
		censorConfig.Thresholds[strconv.Itoa(int(level))] = value
	}
	for level, value := range config.CensorHandlers {
		censorConfig.Handlers[strconv.Itoa(int(level))] = value
	}
	for level, value := range config.CensorScores {
		censorConfig.Scores[strconv.Itoa(int(level))] = value
	}
	storeConfig := configstate.StoreConfig{BackendURLs: append([]string(nil), config.BackendUrls...), DisabledBackendURLs: append([]string(nil), config.DisabledBackendUrls...)}
	outerConfig := configstate.OuterConfig{
		CommandPrefix:     append([]string(nil), commandPrefix...),
		DiceMasters:       append([]string(nil), diceMasters...),
		UpgradeWindowID:   config.UpgradeWindowID,
		UpgradeEndpointID: config.UpgradeEndpointID,
	}
	return configstate.ConfigPatch{
		Base:             &base,
		Rate:             &rateConfig,
		Quit:             &quitConfig,
		Extension:        &extensionConfig,
		Ban:              &banConfig,
		JS:               &jsConfig,
		StoryLog:         &storyLogConfig,
		Mail:             &mailConfig,
		News:             &newsConfig,
		PublicDice:       &publicDiceConfig,
		Censor:           &censorConfig,
		Store:            &storeConfig,
		Outer:            &outerConfig,
		SetCommandPrefix: true,
		SetDiceMasters:   true,
	}, nil
}

// LegacyConfigBaseline converts one stopped legacy Dice configuration into
// the explicit event-sourced baseline used by the hard-cut importer.
func LegacyConfigBaseline(diceID string, config Config, advanced AdvancedConfig, commandPrefix, diceMasters []string, mailPasswordRef, storyLogTokenRef string) (configstate.Baseline, error) {
	patch, err := durableConfigPatch(configstate.State{}, config, commandPrefix, diceMasters, &mailPasswordRef)
	if err != nil {
		return configstate.Baseline{}, err
	}
	patch.Advanced = &configstate.AdvancedConfig{
		Show:                              advanced.Show,
		Enable:                            advanced.Enable,
		StoryLogBackendURL:                advanced.StoryLogBackendUrl,
		StoryLogAPIVersion:                advanced.StoryLogApiVersion,
		StoryLogBackendTokenRef:           storyLogTokenRef,
		CustomReplyCooldown:               advanced.CustomReplyCooldown,
		ExposeDangerousSealInst:           advanced.ExposeDangerousSealInst,
		AllowFilesystemUnrestrictedAccess: advanced.AllowFilesystemUnrestrictedAccess,
	}
	return baselineFromConfigPatch(diceID, config.ConfigVersion, patch, commandPrefix, diceMasters), nil
}

// LegacyExtensionBaseline preserves the extension defaults serialized in
// serve.yaml without loading scripts or executing callbacks.
func LegacyExtensionBaseline(config Config) extensionstate.Baseline {
	baseline := extensionstate.Baseline{}
	for _, item := range config.ExtDefaultSettings {
		if item == nil || strings.TrimSpace(item.Name) == "" {
			continue
		}
		disabled := make([]string, 0, len(item.DisabledCommand))
		for command, value := range item.DisabledCommand {
			if value {
				disabled = append(disabled, command)
			}
		}
		sort.Strings(disabled)
		baseline.Extensions = append(baseline.Extensions, extensionstate.ExtensionIdentity{
			ID: item.Name, Name: item.Name, Version: "legacy", Source: "legacy",
		})
		baseline.Defaults = append(baseline.Defaults, extensionstate.DefaultCommandUpdate{
			ExtensionID: item.Name, AutoActive: item.AutoActive, DisabledCommands: disabled,
		})
		if item.AutoActive {
			baseline.Enable = append(baseline.Enable, item.Name)
		} else {
			baseline.Disable = append(baseline.Disable, item.Name)
		}
	}
	return baseline
}
