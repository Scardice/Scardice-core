package extensionstate

import (
	"fmt"

	"Scardice-core/eventstore"
)

type State struct {
	Version           uint64                                 `json:"version"`
	DiceID            string                                 `json:"diceId"`
	ExtensionOrder    []string                               `json:"extensionOrder,omitempty"`
	Extensions        map[string]ExtensionIdentity           `json:"extensions,omitempty"`
	EnabledExtensions map[string]bool                        `json:"enabledExtensions,omitempty"`
	DisabledScripts   map[string]bool                        `json:"disabledScripts,omitempty"`
	DefaultCommands   map[string]DefaultCommandConfig        `json:"defaultCommands,omitempty"`
	ConfigDefinitions map[string]map[string]ConfigDefinition `json:"configDefinitions,omitempty"`
	ConfigValues      map[string]map[string]ConfigValue      `json:"configValues,omitempty"`
}
type Aggregate = State
type ExtensionState = State
type Baseline struct {
	Extensions      []ExtensionIdentity    `json:"extensions"`
	Enable          []string               `json:"enable,omitempty"`
	Disable         []string               `json:"disable,omitempty"`
	Defaults        []DefaultCommandUpdate `json:"defaults,omitempty"`
	Definitions     []ConfigDefinition     `json:"definitions,omitempty"`
	Values          []ConfigUpdate         `json:"values,omitempty"`
	DisabledScripts []string               `json:"disabledScripts,omitempty"`
}
type DefaultCommandUpdate struct {
	ExtensionID      string
	AutoActive       bool
	DisabledCommands []string
}
type ConfigUpdate struct {
	ExtensionID string      `json:"extensionId"`
	Key         string      `json:"key"`
	Value       ConfigValue `json:"value"`
}

type CommandKind string

const (
	CommandDiscover         CommandKind = "discover"
	CommandEnable           CommandKind = "enable"
	CommandDisable          CommandKind = "disable"
	CommandSetDefaults      CommandKind = "set_defaults"
	CommandRegisterConfig   CommandKind = "register_config"
	CommandUnregisterConfig CommandKind = "unregister_config"
	CommandSetConfig        CommandKind = "set_config"
	CommandDisableScript    CommandKind = "disable_script"
	CommandImportBaseline   CommandKind = "import_baseline"
)
const (
	Discover         = CommandDiscover
	Enable           = CommandEnable
	Disable          = CommandDisable
	SetDefaults      = CommandSetDefaults
	RegisterConfig   = CommandRegisterConfig
	UnregisterConfig = CommandUnregisterConfig
	SetConfig        = CommandSetConfig
	DisableScript    = CommandDisableScript
	ImportBaseline   = CommandImportBaseline
)

type Command struct {
	Kind               CommandKind
	Type               CommandKind
	DiceID             string
	Identity           ExtensionIdentity
	ExtensionID        string
	Key                string
	Value              ConfigValue
	Definition         ConfigDefinition
	Disabled           bool
	ScriptID           string
	AutoActive         bool
	DisabledCommands   []string
	Baseline           *Baseline
	ExpectedVersion    uint64
	ExpectedVersionSet bool
}
type Decision struct {
	Events []TypedEvent
	Replay bool
}
type ExtensionCommand = Command
type ExtensionDecision = Decision

func (s State) Clone() State {
	out := s
	out.ExtensionOrder = append([]string(nil), s.ExtensionOrder...)
	if s.Extensions != nil {
		out.Extensions = make(map[string]ExtensionIdentity, len(s.Extensions))
		for k, v := range s.Extensions {
			out.Extensions[k] = v.Clone()
		}
	}
	if s.EnabledExtensions != nil {
		out.EnabledExtensions = make(map[string]bool, len(s.EnabledExtensions))
		for k, v := range s.EnabledExtensions {
			out.EnabledExtensions[k] = v
		}
	}
	if s.DisabledScripts != nil {
		out.DisabledScripts = make(map[string]bool, len(s.DisabledScripts))
		for k, v := range s.DisabledScripts {
			out.DisabledScripts[k] = v
		}
	}
	if s.DefaultCommands != nil {
		out.DefaultCommands = make(map[string]DefaultCommandConfig, len(s.DefaultCommands))
		for ext, config := range s.DefaultCommands {
			out.DefaultCommands[ext] = config.Clone()
		}
	}
	if s.ConfigDefinitions != nil {
		out.ConfigDefinitions = make(map[string]map[string]ConfigDefinition, len(s.ConfigDefinitions))
		for ext, defs := range s.ConfigDefinitions {
			out.ConfigDefinitions[ext] = make(map[string]ConfigDefinition, len(defs))
			for key, def := range defs {
				out.ConfigDefinitions[ext][key] = def.Clone()
			}
		}
	}
	if s.ConfigValues != nil {
		out.ConfigValues = make(map[string]map[string]ConfigValue, len(s.ConfigValues))
		for ext, values := range s.ConfigValues {
			out.ConfigValues[ext] = make(map[string]ConfigValue, len(values))
			for key, value := range values {
				out.ConfigValues[ext][key] = value.Clone()
			}
		}
	}
	return out
}
func (s State) CompatibilityView() State { return s.Clone() }

func Reduce(state State, event TypedEvent) (State, error) {
	if isNilEvent(event) || !event.EventType().Valid() {
		return State{}, ErrInvalidEvent
	}
	if err := event.validate(); err != nil {
		return State{}, err
	}
	if state.Version == ^uint64(0) {
		return State{}, ErrInvalidState
	}
	next := state.Clone()
	if err := event.apply(&next); err != nil {
		return State{}, err
	}
	next.Version++
	if err := ValidateState(next); err != nil {
		return State{}, err
	}
	return next, nil
}
func Replay(events []TypedEvent) (State, error) {
	state := State{}
	for _, event := range events {
		var err error
		state, err = Reduce(state, event)
		if err != nil {
			return State{}, err
		}
	}
	return state, nil
}
func ApplyEnvelope(state State, envelope eventstore.Envelope) (State, error) {
	if envelope.Stream.AggregateType != ExtensionAggregateType || envelope.SchemaVersion != ExtensionEventSchemaVersion {
		return State{}, fmt.Errorf("%w: schema or aggregate type", ErrInvalidEvent)
	}
	if envelope.StreamVersion != state.Version+1 {
		return State{}, ErrInvalidState
	}
	if len(envelope.Payload) > MaxExtensionEventPayloadBytes {
		return State{}, &eventstore.OversizeError{Bound: "extensionstate event payload", Limit: MaxExtensionEventPayloadBytes, Actual: len(envelope.Payload)}
	}
	event, err := DecodeEvent(EventType(envelope.EventType), envelope.Payload)
	if err != nil {
		return State{}, err
	}
	next, err := Reduce(state, event)
	if err != nil {
		return State{}, err
	}
	if next.DiceID == "" || ExtensionStream(next.DiceID).AggregateID != envelope.Stream.AggregateID {
		return State{}, ErrInvalidIdentity
	}
	return next, nil
}
func ReplayEnvelopes(events []eventstore.Envelope) (State, error) {
	state := State{}
	for _, event := range events {
		var err error
		state, err = ApplyEnvelope(state, event)
		if err != nil {
			return State{}, err
		}
	}
	return state, nil
}

func ValidateState(state State) error {
	if state.Version == 0 {
		return nil
	}
	if err := validateIdentity(state.DiceID); err != nil {
		return ErrInvalidState
	}
	if len(state.ExtensionOrder) != len(state.Extensions) {
		return ErrInvalidState
	}
	seen := map[string]bool{}
	for _, id := range state.ExtensionOrder {
		if err := validateIdentifier(id); err != nil || seen[id] {
			return ErrInvalidState
		}
		seen[id] = true
		if _, ok := state.Extensions[id]; !ok {
			return ErrInvalidState
		}
	}
	for id, identity := range state.Extensions {
		if id != identity.ID {
			return ErrInvalidState
		}
		if err := validateExtensionIdentity(identity); err != nil {
			return ErrInvalidState
		}
	}
	for id, enabled := range state.EnabledExtensions {
		if !enabled {
			return ErrInvalidState
		}
		if _, ok := state.Extensions[id]; !ok {
			return ErrInvalidState
		}
	}
	for ext, config := range state.DefaultCommands {
		if _, ok := state.Extensions[ext]; !ok || validateDefaultCommandConfig(config) != nil {
			return ErrInvalidState
		}
	}
	for ext, defs := range state.ConfigDefinitions {
		if _, ok := state.Extensions[ext]; !ok {
			return ErrInvalidState
		}
		for key, def := range defs {
			if key != def.Key || def.ExtensionID != ext || validateDefinition(def) != nil {
				return ErrInvalidState
			}
		}
	}
	for ext, values := range state.ConfigValues {
		defs, ok := state.ConfigDefinitions[ext]
		if !ok {
			return ErrInvalidState
		}
		for key, value := range values {
			def, ok := defs[key]
			if !ok || validateConfigValue(value, def) != nil {
				return ErrInvalidState
			}
		}
	}
	for id := range state.DisabledScripts {
		if validateIdentifier(id) != nil {
			return ErrInvalidState
		}
	}
	return nil
}

func Decide(state State, command Command) (Decision, error) {
	if command.ExpectedVersionSet && command.ExpectedVersion != state.Version {
		return Decision{}, ErrStaleVersion
	}
	kind := command.Kind
	if kind == "" {
		kind = command.Type
	}
	switch kind {
	case CommandImportBaseline:
		return decideBaseline(state, command)
	case CommandDiscover:
		if err := validateIdentity(command.DiceID); err != nil || validateExtensionIdentity(command.Identity) != nil {
			return Decision{}, ErrInvalidCommand
		}
		if state.Version > 0 && state.DiceID != command.DiceID {
			return Decision{}, ErrInvalidIdentity
		}
		if existing, ok := state.Extensions[command.Identity.ID]; ok {
			if reflectIdentityEqual(existing, command.Identity) {
				return Decision{}, nil
			}
			return Decision{}, ErrInvalidState
		}
		return Decision{Events: []TypedEvent{NewExtensionDiscoveredV1(command.DiceID, command.Identity)}}, nil
	}
	if state.Version == 0 {
		return Decision{}, ErrInvalidState
	}
	if err := validateIdentity(state.DiceID); err != nil {
		return Decision{}, ErrInvalidState
	}
	switch kind {
	case CommandEnable, CommandDisable:
		if err := validateIdentifier(command.ExtensionID); err != nil {
			return Decision{}, ErrInvalidCommand
		}
		if _, ok := state.Extensions[command.ExtensionID]; !ok {
			return Decision{}, ErrUnknownExtension
		}
		enabled := kind == CommandEnable
		if state.EnabledExtensions[command.ExtensionID] == enabled {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewExtensionEnablementChangedV1(command.ExtensionID, enabled)}}, nil
	case CommandSetDefaults:
		if err := validateIdentifier(command.ExtensionID); err != nil {
			return Decision{}, ErrInvalidCommand
		}
		if _, ok := state.Extensions[command.ExtensionID]; !ok {
			return Decision{}, ErrUnknownExtension
		}
		config := DefaultCommandConfig{AutoActive: command.AutoActive, DisabledCommands: map[string]bool{}}
		for _, item := range command.DisabledCommands {
			if err := validateIdentifier(item); err != nil {
				return Decision{}, ErrInvalidCommand
			}
			if config.DisabledCommands[item] {
				return Decision{}, ErrInvalidCommand
			}
			config.DisabledCommands[item] = true
		}
		if previous, ok := state.DefaultCommands[command.ExtensionID]; ok && reflectDefaultConfigEqual(previous, config) {
			return Decision{}, nil
		}
		disabled := make([]string, 0, len(config.DisabledCommands))
		for item := range config.DisabledCommands {
			disabled = append(disabled, item)
		}
		sortStrings(disabled)
		return Decision{Events: []TypedEvent{NewExtensionDefaultsChangedV1(command.ExtensionID, config.AutoActive, disabled)}}, nil
	case CommandRegisterConfig:
		def := command.Definition
		if def.ExtensionID == "" {
			def.ExtensionID = command.ExtensionID
		}
		if err := validateDefinition(def); err != nil {
			return Decision{}, err
		}
		if _, ok := state.Extensions[def.ExtensionID]; !ok {
			return Decision{}, ErrUnknownExtension
		}
		if existing, ok := state.ConfigDefinitions[def.ExtensionID][def.Key]; ok {
			if reflectDefinitionEqual(existing, def) {
				return Decision{}, nil
			}
			return Decision{}, ErrInvalidState
		}
		events := []TypedEvent{NewConfigDefinitionRegisteredV1(def)}
		if def.DefaultSet {
			events = append(events, NewConfigValueChangedV1(def.ExtensionID, def.Key, def.Default))
		}
		return Decision{Events: events}, nil
	case CommandUnregisterConfig:
		if err := validateIdentifier(command.ExtensionID); err != nil || validateIdentifier(command.Key) != nil {
			return Decision{}, ErrInvalidCommand
		}
		if _, ok := state.Extensions[command.ExtensionID]; !ok {
			return Decision{}, ErrUnknownExtension
		}
		if _, ok := state.ConfigDefinitions[command.ExtensionID][command.Key]; !ok {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewConfigDefinitionRemovedV1(command.ExtensionID, command.Key)}}, nil
	case CommandSetConfig:
		if err := validateIdentifier(command.ExtensionID); err != nil || validateIdentifier(command.Key) != nil {
			return Decision{}, ErrInvalidCommand
		}
		if _, ok := state.Extensions[command.ExtensionID]; !ok {
			return Decision{}, ErrUnknownExtension
		}
		def, ok := state.ConfigDefinitions[command.ExtensionID][command.Key]
		if !ok {
			return Decision{}, ErrUnknownConfig
		}
		if err := validateConfigValue(command.Value, def); err != nil {
			return Decision{}, err
		}
		if previous, exists := state.ConfigValues[command.ExtensionID][command.Key]; exists && reflectConfigValueEqual(previous, command.Value) {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewConfigValueChangedV1(command.ExtensionID, command.Key, command.Value)}}, nil
	case CommandDisableScript:
		scriptID := command.ScriptID
		if scriptID == "" {
			scriptID = command.ExtensionID
		}
		if err := validateIdentifier(scriptID); err != nil {
			return Decision{}, ErrInvalidCommand
		}
		if state.DisabledScripts[scriptID] == command.Disabled {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewScriptDisablementChangedV1(scriptID, command.Disabled)}}, nil
	default:
		return Decision{}, ErrInvalidCommand
	}
}

func decideBaseline(state State, command Command) (Decision, error) {
	if state.Version != 0 || command.Baseline == nil || validateIdentity(command.DiceID) != nil {
		return Decision{}, ErrInvalidCommand
	}
	baseline := command.Baseline
	events := make([]TypedEvent, 0, len(baseline.Extensions)+len(baseline.Definitions)+len(baseline.Values))
	seenExt := map[string]bool{}
	for _, identity := range baseline.Extensions {
		if seenExt[identity.ID] || validateExtensionIdentity(identity) != nil {
			return Decision{}, ErrInvalidCommand
		}
		seenExt[identity.ID] = true
		events = append(events, NewExtensionDiscoveredV1(command.DiceID, identity))
	}
	seenEnabled := map[string]bool{}
	for _, id := range baseline.Enable {
		if !seenExt[id] || seenEnabled[id] {
			return Decision{}, ErrInvalidCommand
		}
		seenEnabled[id] = true
		events = append(events, NewExtensionEnablementChangedV1(id, true))
	}
	seenDisabled := map[string]bool{}
	for _, id := range baseline.Disable {
		if !seenExt[id] || seenDisabled[id] || seenEnabled[id] {
			return Decision{}, ErrInvalidCommand
		}
		seenDisabled[id] = true
		events = append(events, NewExtensionEnablementChangedV1(id, false))
	}
	seenDefaults := map[string]bool{}
	for _, update := range baseline.Defaults {
		if !seenExt[update.ExtensionID] || seenDefaults[update.ExtensionID] {
			return Decision{}, ErrInvalidCommand
		}
		seenDefaults[update.ExtensionID] = true
		config := DefaultCommandConfig{AutoActive: update.AutoActive, DisabledCommands: map[string]bool{}}
		for _, command := range update.DisabledCommands {
			if err := validateIdentifier(command); err != nil || config.DisabledCommands[command] {
				return Decision{}, ErrInvalidCommand
			}
			config.DisabledCommands[command] = true
		}
		disabled := append([]string(nil), update.DisabledCommands...)
		sortStrings(disabled)
		events = append(events, NewExtensionDefaultsChangedV1(update.ExtensionID, update.AutoActive, disabled))
	}
	seenDef := map[string]bool{}
	for _, definition := range baseline.Definitions {
		if !seenExt[definition.ExtensionID] || seenDef[definition.ExtensionID+"\x00"+definition.Key] || validateDefinition(definition) != nil {
			return Decision{}, ErrInvalidCommand
		}
		seenDef[definition.ExtensionID+"\x00"+definition.Key] = true
		events = append(events, NewConfigDefinitionRegisteredV1(definition))
	}
	for _, update := range baseline.Values {
		definition, ok := findDefinition(baseline.Definitions, update.ExtensionID, update.Key)
		if !ok || validateConfigValue(update.Value, definition) != nil {
			return Decision{}, ErrInvalidConfigValue
		}
		events = append(events, NewConfigValueChangedV1(update.ExtensionID, update.Key, update.Value))
	}
	seenScript := map[string]bool{}
	for _, id := range baseline.DisabledScripts {
		if validateIdentifier(id) != nil || seenScript[id] {
			return Decision{}, ErrInvalidCommand
		}
		seenScript[id] = true
		events = append(events, NewScriptDisablementChangedV1(id, true))
	}
	return Decision{Events: events, Replay: true}, nil
}
func findDefinition(definitions []ConfigDefinition, extensionID, key string) (ConfigDefinition, bool) {
	for _, definition := range definitions {
		if definition.ExtensionID == extensionID && definition.Key == key {
			return definition, true
		}
	}
	return ConfigDefinition{}, false
}
func reflectConfigValueEqual(a, b ConfigValue) bool {
	if a.Type != b.Type || a.String != b.String || a.Bool != b.Bool || a.Int != b.Int || a.Float != b.Float || a.SecretRef != b.SecretRef || len(a.Strings) != len(b.Strings) {
		return false
	}
	for i := range a.Strings {
		if a.Strings[i] != b.Strings[i] {
			return false
		}
	}
	return true
}
func reflectIdentityEqual(a, b ExtensionIdentity) bool {
	if a.ID != b.ID || a.Name != b.Name || a.Version != b.Version || a.Source != b.Source || len(a.Aliases) != len(b.Aliases) {
		return false
	}
	for i := range a.Aliases {
		if a.Aliases[i] != b.Aliases[i] {
			return false
		}
	}
	return true
}
func reflectDefinitionEqual(a, b ConfigDefinition) bool {
	if a.ExtensionID != b.ExtensionID || a.Key != b.Key || a.Type != b.Type || a.Description != b.Description || a.Group != b.Group || a.DefaultSet != b.DefaultSet || a.Deprecated != b.Deprecated || !reflectConfigValueEqual(a.Default, b.Default) || len(a.Options) != len(b.Options) {
		return false
	}
	for i := range a.Options {
		if a.Options[i] != b.Options[i] {
			return false
		}
	}
	return true
}
func reflectDefaultConfigEqual(a, b DefaultCommandConfig) bool {
	if a.AutoActive != b.AutoActive || len(a.DisabledCommands) != len(b.DisabledCommands) {
		return false
	}
	for key, value := range a.DisabledCommands {
		if !value || !b.DisabledCommands[key] {
			return false
		}
	}
	return true
}
func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
