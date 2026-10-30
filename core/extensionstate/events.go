package extensionstate

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"strings"

	"Scardice-core/eventstore"
)

type EventType string

const (
	EventExtensionDiscovered        EventType = "extension_discovered"
	EventExtensionIdentityChanged   EventType = "extension_identity_changed"
	EventExtensionEnablementChanged EventType = "extension_enablement_changed"
	EventExtensionDefaultsChanged   EventType = "extension_defaults_changed"
	EventExtensionDefaultsCleared   EventType = "extension_defaults_cleared"
	EventConfigDefinitionRegistered EventType = "config_definition_registered"
	EventConfigDefinitionRemoved    EventType = "config_definition_removed"
	EventConfigValueChanged         EventType = "config_value_changed"
	EventScriptDisablementChanged   EventType = "script_disablement_changed"
)
const (
	EventExtensionDefaultSettingsChanged   = EventExtensionDefaultsChanged
	EventExtensionDefaultSettingsChangedV1 = EventExtensionDefaultsChanged
)

func (e EventType) Valid() bool {
	switch e {
	case EventExtensionDiscovered, EventExtensionIdentityChanged, EventExtensionEnablementChanged, EventExtensionDefaultsChanged, EventExtensionDefaultsCleared, EventConfigDefinitionRegistered, EventConfigDefinitionRemoved, EventConfigValueChanged, EventScriptDisablementChanged:
		return true
	}
	return false
}

var (
	ErrInvalidIdentity       = errors.New("extensionstate: invalid identity")
	ErrInvalidEvent          = errors.New("extensionstate: invalid event")
	ErrInvalidState          = errors.New("extensionstate: invalid state")
	ErrInvalidCommand        = errors.New("extensionstate: invalid command")
	ErrUnknownExtension      = errors.New("extensionstate: unknown extension")
	ErrUnknownConfig         = errors.New("extensionstate: unknown config")
	ErrInvalidConfigValue    = errors.New("extensionstate: invalid config value")
	ErrUnsupportedConfigType = errors.New("extensionstate: unsupported config type")
	ErrStaleVersion          = errors.New("extensionstate: stale expected version")
)

const (
	ExtensionAggregateType               = "extension-state"
	ExtensionStateAggregateType          = ExtensionAggregateType
	ExtensionEventSchemaVersion   uint16 = 1
	EventSchemaVersion                   = ExtensionEventSchemaVersion
	MaxExtensionIdentityPartBytes        = 255
	MaxExtensionEventPayloadBytes        = eventstore.MaxEventPayloadBytes
	MaxEventPayloadBytes                 = MaxExtensionEventPayloadBytes
)

type ConfigType string

const (
	ConfigString    ConfigType = "string"
	ConfigBool      ConfigType = "bool"
	ConfigFloat     ConfigType = "float"
	ConfigInt       ConfigType = "int"
	ConfigTemplate  ConfigType = "template"
	ConfigOption    ConfigType = "option"
	ConfigSecret    ConfigType = "secret"
	ConfigTaskCron  ConfigType = "task:cron"
	ConfigTaskDaily ConfigType = "task:daily"
	ConfigTaskOnce  ConfigType = "task:once"
)
const (
	TypeString   = ConfigString
	TypeBool     = ConfigBool
	TypeFloat    = ConfigFloat
	TypeInt      = ConfigInt
	TypeTemplate = ConfigTemplate
	TypeOption   = ConfigOption
	TypeSecret   = ConfigSecret
)

type ConfigValue struct {
	Type      ConfigType `json:"type"`
	String    string     `json:"string,omitempty"`
	Bool      bool       `json:"bool,omitempty"`
	Int       int64      `json:"int,omitempty"`
	Float     float64    `json:"float,omitempty"`
	Strings   []string   `json:"strings,omitempty"`
	SecretRef string     `json:"secretRef,omitempty"`
}

func StringValue(value string) ConfigValue { return ConfigValue{Type: ConfigString, String: value} }
func BoolValue(value bool) ConfigValue     { return ConfigValue{Type: ConfigBool, Bool: value} }
func IntValue(value int64) ConfigValue     { return ConfigValue{Type: ConfigInt, Int: value} }
func FloatValue(value float64) ConfigValue { return ConfigValue{Type: ConfigFloat, Float: value} }
func TemplateValue(value []string) ConfigValue {
	return ConfigValue{Type: ConfigTemplate, Strings: append([]string(nil), value...)}
}
func OptionValue(value string) ConfigValue { return ConfigValue{Type: ConfigOption, String: value} }
func SecretValue(reference string) ConfigValue {
	return ConfigValue{Type: ConfigSecret, SecretRef: reference}
}
func (v ConfigValue) Clone() ConfigValue { v.Strings = append([]string(nil), v.Strings...); return v }

type DefaultCommandConfig struct {
	AutoActive       bool            `json:"autoActive"`
	DisabledCommands map[string]bool `json:"disabledCommands,omitempty"`
}

func (c DefaultCommandConfig) Clone() DefaultCommandConfig {
	out := c
	if c.DisabledCommands != nil {
		out.DisabledCommands = map[string]bool{}
		for key, value := range c.DisabledCommands {
			out.DisabledCommands[key] = value
		}
	}
	return out
}

// ConfigDefinition is Core-owned metadata. It contains no runtime schema or callbacks.
type ConfigDefinition struct {
	ExtensionID string      `json:"extensionId"`
	Key         string      `json:"key"`
	Type        ConfigType  `json:"type"`
	Description string      `json:"description,omitempty"`
	Group       string      `json:"group,omitempty"`
	Default     ConfigValue `json:"default"`
	DefaultSet  bool        `json:"defaultSet,omitempty"`
	Options     []string    `json:"options,omitempty"`
	Deprecated  bool        `json:"deprecated,omitempty"`
}

func (d ConfigDefinition) Clone() ConfigDefinition {
	d.Options = append([]string(nil), d.Options...)
	d.Default = d.Default.Clone()
	return d
}

type ExtensionIdentity struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	Version string   `json:"version"`
	Source  string   `json:"source"`
}

func (e ExtensionIdentity) Clone() ExtensionIdentity {
	e.Aliases = append([]string(nil), e.Aliases...)
	return e
}

type ExtensionDiscoveredV1 struct {
	DiceID   string            `json:"diceId"`
	Identity ExtensionIdentity `json:"identity"`
}

func NewExtensionDiscoveredV1(diceID string, identity ExtensionIdentity) ExtensionDiscoveredV1 {
	return ExtensionDiscoveredV1{DiceID: diceID, Identity: identity.Clone()}
}
func (ExtensionDiscoveredV1) EventType() EventType { return EventExtensionDiscovered }
func (e ExtensionDiscoveredV1) validate() error {
	if err := validateIdentity(e.DiceID); err != nil {
		return err
	}
	return validateExtensionIdentity(e.Identity)
}
func (e ExtensionDiscoveredV1) apply(s *State) error {
	if s.Version > 0 && s.DiceID != e.DiceID {
		return ErrInvalidIdentity
	}
	if _, ok := s.Extensions[e.Identity.ID]; ok {
		return ErrInvalidState
	}
	if s.DiceID == "" {
		s.DiceID = e.DiceID
	}
	if s.Extensions == nil {
		s.Extensions = map[string]ExtensionIdentity{}
	}
	s.Extensions[e.Identity.ID] = e.Identity.Clone()
	s.ExtensionOrder = append(s.ExtensionOrder, e.Identity.ID)
	return nil
}

type ExtensionIdentityChangedV1 struct {
	Previous ExtensionIdentity `json:"previous"`
	Identity ExtensionIdentity `json:"identity"`
}

func NewExtensionIdentityChangedV1(previous, identity ExtensionIdentity) ExtensionIdentityChangedV1 {
	return ExtensionIdentityChangedV1{Previous: previous.Clone(), Identity: identity.Clone()}
}
func (ExtensionIdentityChangedV1) EventType() EventType { return EventExtensionIdentityChanged }
func (e ExtensionIdentityChangedV1) validate() error {
	if validateExtensionIdentity(e.Previous) != nil || validateExtensionIdentity(e.Identity) != nil ||
		!allowedExtensionIdentityTransition(e.Previous, e.Identity) {
		return ErrInvalidIdentity
	}
	return nil
}
func (e ExtensionIdentityChangedV1) apply(s *State) error {
	existing, ok := s.Extensions[e.Identity.ID]
	if !ok || !reflectIdentityEqual(existing, e.Previous) {
		return ErrInvalidState
	}
	s.Extensions[e.Identity.ID] = e.Identity.Clone()
	return nil
}

func allowedExtensionIdentityTransition(previous, next ExtensionIdentity) bool {
	if previous.ID != next.ID {
		return false
	}
	if previous.Source == "legacy" && previous.Version == "legacy" {
		return true
	}
	return previous.Source == next.Source
}

type ExtensionEnablementChangedV1 struct {
	ExtensionID string `json:"extensionId"`
	Enabled     bool   `json:"enabled"`
}

func NewExtensionEnablementChangedV1(id string, enabled bool) ExtensionEnablementChangedV1 {
	return ExtensionEnablementChangedV1{ExtensionID: id, Enabled: enabled}
}
func (ExtensionEnablementChangedV1) EventType() EventType { return EventExtensionEnablementChanged }
func (e ExtensionEnablementChangedV1) validate() error    { return validateIdentifier(e.ExtensionID) }
func (e ExtensionEnablementChangedV1) apply(s *State) error {
	if _, ok := s.Extensions[e.ExtensionID]; !ok {
		return ErrUnknownExtension
	}
	if e.Enabled {
		if s.EnabledExtensions == nil {
			s.EnabledExtensions = map[string]bool{}
		}
		s.EnabledExtensions[e.ExtensionID] = true
	} else {
		delete(s.EnabledExtensions, e.ExtensionID)
	}
	return nil
}

type ExtensionDefaultsChangedV1 struct {
	ExtensionID      string   `json:"extensionId"`
	AutoActive       bool     `json:"autoActive"`
	DisabledCommands []string `json:"disabledCommands,omitempty"`
}

func NewExtensionDefaultsChangedV1(id string, autoActive bool, disabledCommands []string) ExtensionDefaultsChangedV1 {
	return ExtensionDefaultsChangedV1{
		ExtensionID:      id,
		AutoActive:       autoActive,
		DisabledCommands: append([]string(nil), disabledCommands...),
	}
}
func (ExtensionDefaultsChangedV1) EventType() EventType { return EventExtensionDefaultsChanged }
func (e ExtensionDefaultsChangedV1) validate() error {
	if err := validateIdentifier(e.ExtensionID); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, command := range e.DisabledCommands {
		if err := validateIdentifier(command); err != nil || seen[command] {
			return ErrInvalidState
		}
		seen[command] = true
	}
	return nil
}
func (e ExtensionDefaultsChangedV1) apply(s *State) error {
	if _, ok := s.Extensions[e.ExtensionID]; !ok {
		return ErrUnknownExtension
	}
	if s.DefaultCommands == nil {
		s.DefaultCommands = map[string]DefaultCommandConfig{}
	}
	disabled := map[string]bool{}
	for _, command := range e.DisabledCommands {
		disabled[command] = true
	}
	s.DefaultCommands[e.ExtensionID] = DefaultCommandConfig{AutoActive: e.AutoActive, DisabledCommands: disabled}
	return nil
}
func NewExtensionDefaultSettingsChangedV1(id string, autoActive bool, disabledCommands []string) ExtensionDefaultsChangedV1 {
	return NewExtensionDefaultsChangedV1(id, autoActive, disabledCommands)
}

type ExtensionDefaultsClearedV1 struct {
	ExtensionID string `json:"extensionId"`
}

func NewExtensionDefaultsClearedV1(id string) ExtensionDefaultsClearedV1 {
	return ExtensionDefaultsClearedV1{ExtensionID: id}
}
func (ExtensionDefaultsClearedV1) EventType() EventType { return EventExtensionDefaultsCleared }
func (e ExtensionDefaultsClearedV1) validate() error    { return validateIdentifier(e.ExtensionID) }
func (e ExtensionDefaultsClearedV1) apply(s *State) error {
	if _, ok := s.Extensions[e.ExtensionID]; !ok {
		return ErrUnknownExtension
	}
	delete(s.DefaultCommands, e.ExtensionID)
	return nil
}

type ConfigDefinitionRegisteredV1 struct {
	Definition ConfigDefinition `json:"definition"`
}

func NewConfigDefinitionRegisteredV1(definition ConfigDefinition) ConfigDefinitionRegisteredV1 {
	return ConfigDefinitionRegisteredV1{Definition: definition.Clone()}
}
func (ConfigDefinitionRegisteredV1) EventType() EventType { return EventConfigDefinitionRegistered }
func (e ConfigDefinitionRegisteredV1) validate() error    { return validateDefinition(e.Definition) }
func (e ConfigDefinitionRegisteredV1) apply(s *State) error {
	if _, ok := s.Extensions[e.Definition.ExtensionID]; !ok {
		return ErrUnknownExtension
	}
	if s.ConfigDefinitions == nil {
		s.ConfigDefinitions = map[string]map[string]ConfigDefinition{}
	}
	if s.ConfigDefinitions[e.Definition.ExtensionID] == nil {
		s.ConfigDefinitions[e.Definition.ExtensionID] = map[string]ConfigDefinition{}
	}
	if _, ok := s.ConfigDefinitions[e.Definition.ExtensionID][e.Definition.Key]; ok {
		return ErrInvalidState
	}
	s.ConfigDefinitions[e.Definition.ExtensionID][e.Definition.Key] = e.Definition.Clone()
	return nil
}

type ConfigDefinitionRemovedV1 struct {
	ExtensionID string `json:"extensionId"`
	Key         string `json:"key"`
}

func NewConfigDefinitionRemovedV1(extensionID, key string) ConfigDefinitionRemovedV1 {
	return ConfigDefinitionRemovedV1{ExtensionID: extensionID, Key: key}
}
func (ConfigDefinitionRemovedV1) EventType() EventType { return EventConfigDefinitionRemoved }
func (e ConfigDefinitionRemovedV1) validate() error {
	if err := validateIdentifier(e.ExtensionID); err != nil {
		return err
	}
	return validateIdentifier(e.Key)
}
func (e ConfigDefinitionRemovedV1) apply(s *State) error {
	if _, ok := s.Extensions[e.ExtensionID]; !ok {
		return ErrUnknownExtension
	}
	defs := s.ConfigDefinitions[e.ExtensionID]
	if _, ok := defs[e.Key]; !ok {
		return ErrUnknownConfig
	}
	delete(defs, e.Key)
	if len(defs) == 0 {
		delete(s.ConfigDefinitions, e.ExtensionID)
	}
	if values := s.ConfigValues[e.ExtensionID]; values != nil {
		delete(values, e.Key)
		if len(values) == 0 {
			delete(s.ConfigValues, e.ExtensionID)
		}
	}
	return nil
}

type ConfigValueChangedV1 struct {
	ExtensionID string      `json:"extensionId"`
	Key         string      `json:"key"`
	Value       ConfigValue `json:"value"`
}

func NewConfigValueChangedV1(extensionID, key string, value ConfigValue) ConfigValueChangedV1 {
	return ConfigValueChangedV1{ExtensionID: extensionID, Key: key, Value: value.Clone()}
}
func (ConfigValueChangedV1) EventType() EventType { return EventConfigValueChanged }
func (e ConfigValueChangedV1) validate() error {
	if err := validateIdentifier(e.ExtensionID); err != nil {
		return err
	}
	return validateIdentifier(e.Key)
}
func (e ConfigValueChangedV1) apply(s *State) error {
	defs := s.ConfigDefinitions[e.ExtensionID]
	def, ok := defs[e.Key]
	if !ok {
		return ErrUnknownConfig
	}
	if err := validateConfigValue(e.Value, def); err != nil {
		return err
	}
	if s.ConfigValues == nil {
		s.ConfigValues = map[string]map[string]ConfigValue{}
	}
	if s.ConfigValues[e.ExtensionID] == nil {
		s.ConfigValues[e.ExtensionID] = map[string]ConfigValue{}
	}
	s.ConfigValues[e.ExtensionID][e.Key] = e.Value.Clone()
	return nil
}

type ScriptDisablementChangedV1 struct {
	ScriptID string `json:"scriptId"`
	Disabled bool   `json:"disabled"`
}

func NewScriptDisablementChangedV1(scriptID string, disabled bool) ScriptDisablementChangedV1 {
	return ScriptDisablementChangedV1{ScriptID: scriptID, Disabled: disabled}
}
func (ScriptDisablementChangedV1) EventType() EventType { return EventScriptDisablementChanged }
func (e ScriptDisablementChangedV1) validate() error    { return validateIdentifier(e.ScriptID) }
func (e ScriptDisablementChangedV1) apply(s *State) error {
	if s.DisabledScripts == nil {
		s.DisabledScripts = map[string]bool{}
	}
	if e.Disabled {
		s.DisabledScripts[e.ScriptID] = true
	} else {
		delete(s.DisabledScripts, e.ScriptID)
	}
	return nil
}

type TypedEvent interface {
	EventType() EventType
	validate() error
	apply(*State) error
}
type ExtensionEvent = TypedEvent

func isNilEvent(event TypedEvent) bool {
	if event == nil {
		return true
	}
	value := reflect.ValueOf(event)
	return (value.Kind() == reflect.Pointer || value.Kind() == reflect.Interface) && value.IsNil()
}
func derefEvent(value any) any {
	if value == nil {
		return nil
	}
	v := reflect.ValueOf(value)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		return v.Elem().Interface()
	}
	return value
}
func MarshalEvent(event TypedEvent) ([]byte, error) {
	if isNilEvent(event) {
		return nil, ErrInvalidEvent
	}
	var value = derefEvent(event)
	switch e := value.(type) {
	case ExtensionDiscoveredV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ExtensionIdentityChangedV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ExtensionEnablementChangedV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ExtensionDefaultsChangedV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ExtensionDefaultsClearedV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ConfigDefinitionRegisteredV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ConfigDefinitionRemovedV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ConfigValueChangedV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	case ScriptDisablementChangedV1:
		if err := e.validate(); err != nil {
			return nil, err
		}
		value = e
	default:
		return nil, ErrInvalidEvent
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxExtensionEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "extensionstate event payload", Limit: MaxExtensionEventPayloadBytes, Actual: len(payload)}
	}
	return payload, nil
}
func MarshalEvents(events []TypedEvent) ([]byte, error) {
	type wire struct {
		Type    EventType       `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	encoded := make([]wire, 0, len(events))
	for _, event := range events {
		payload, err := MarshalEvent(event)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, wire{Type: event.EventType(), Payload: payload})
	}
	payload, err := json.Marshal(encoded)
	if err != nil {
		return nil, err
	}
	if len(payload) > MaxExtensionEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "extensionstate event payload", Limit: MaxExtensionEventPayloadBytes, Actual: len(payload)}
	}
	return payload, nil
}
func decodeObject(payload []byte, out any) error {
	if len(payload) > MaxExtensionEventPayloadBytes {
		return &eventstore.OversizeError{Bound: "extensionstate event payload", Limit: MaxExtensionEventPayloadBytes, Actual: len(payload)}
	}
	var raw any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return ErrInvalidEvent
	}
	if raw == nil {
		return ErrInvalidEvent
	}
	if _, ok := raw.(map[string]any); !ok {
		return ErrInvalidEvent
	}
	if containsNull(raw) {
		return ErrInvalidEvent
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return ErrInvalidEvent
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidEvent
	}
	return nil
}
func containsNull(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case map[string]any:
		for _, item := range v {
			if containsNull(item) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if containsNull(item) {
				return true
			}
		}
	}
	return false
}
func DecodeEvent(typ EventType, payload []byte) (TypedEvent, error) {
	switch typ {
	case EventExtensionDiscovered:
		var e ExtensionDiscoveredV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventExtensionIdentityChanged:
		var e ExtensionIdentityChangedV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventExtensionEnablementChanged:
		var e ExtensionEnablementChangedV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventExtensionDefaultsChanged:
		var e ExtensionDefaultsChangedV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventExtensionDefaultsCleared:
		var e ExtensionDefaultsClearedV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventConfigDefinitionRegistered:
		var e ConfigDefinitionRegisteredV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventConfigDefinitionRemoved:
		var e ConfigDefinitionRemovedV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventConfigValueChanged:
		var e ConfigValueChangedV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	case EventScriptDisablementChanged:
		var e ScriptDisablementChangedV1
		if err := decodeObject(payload, &e); err != nil {
			return nil, err
		}
		if err := e.validate(); err != nil {
			return nil, err
		}
		return e, nil
	default:
		return nil, ErrInvalidEvent
	}
}
func DecodeEvents(payload []byte) ([]TypedEvent, error) {
	if len(payload) > MaxExtensionEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "extensionstate event payload", Limit: MaxExtensionEventPayloadBytes, Actual: len(payload)}
	}
	type wire struct {
		Type    EventType       `json:"type"`
		Payload json.RawMessage `json:"payload"`
	}
	var raw []wire
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, ErrInvalidEvent
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrInvalidEvent
	}
	events := make([]TypedEvent, 0, len(raw))
	for _, item := range raw {
		if !item.Type.Valid() || len(item.Payload) == 0 {
			return nil, ErrInvalidEvent
		}
		event, err := DecodeEvent(item.Type, item.Payload)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, nil
}

func validateIdentifier(value string) error {
	if strings.TrimSpace(value) == "" || len(value) > MaxExtensionIdentityPartBytes {
		return ErrInvalidIdentity
	}
	return nil
}
func validateIdentity(value string) error { return validateIdentifier(value) }
func validateExtensionIdentity(identity ExtensionIdentity) error {
	if err := validateIdentifier(identity.ID); err != nil {
		return err
	}
	if err := validateIdentifier(identity.Name); err != nil {
		return err
	}
	if err := validateIdentifier(identity.Version); err != nil {
		return err
	}
	if err := validateIdentifier(identity.Source); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, alias := range identity.Aliases {
		if err := validateIdentifier(alias); err != nil {
			return err
		}
		if seen[alias] {
			return ErrInvalidState
		}
		seen[alias] = true
	}
	return nil
}
func supportedConfigType(value ConfigType) bool {
	switch value {
	case ConfigString, ConfigBool, ConfigFloat, ConfigInt, ConfigTemplate, ConfigOption, ConfigSecret, ConfigTaskCron, ConfigTaskDaily, ConfigTaskOnce:
		return true
	}
	return false
}
func validateDefinition(def ConfigDefinition) error {
	if err := validateIdentifier(def.ExtensionID); err != nil {
		return err
	}
	if err := validateIdentifier(def.Key); err != nil {
		return err
	}
	if !supportedConfigType(def.Type) {
		return ErrUnsupportedConfigType
	}
	if def.Type == ConfigOption {
		if len(def.Options) == 0 {
			return ErrInvalidConfigValue
		}
		seen := map[string]bool{}
		for _, option := range def.Options {
			if err := validateIdentifier(option); err != nil {
				return err
			}
			if seen[option] {
				return ErrInvalidConfigValue
			}
			seen[option] = true
		}
	}
	if def.DefaultSet {
		if err := validateConfigValue(def.Default, def); err != nil {
			return err
		}
	}
	return nil
}
func validateDefaultCommandConfig(config DefaultCommandConfig) error {
	for command, disabled := range config.DisabledCommands {
		if !disabled {
			return ErrInvalidConfigValue
		}
		if err := validateIdentifier(command); err != nil {
			return err
		}
	}
	return nil
}
func validateConfigValue(value ConfigValue, def ConfigDefinition) error {
	if value.Type != def.Type || !configValueShapeValid(value) {
		return ErrInvalidConfigValue
	}
	switch value.Type {
	case ConfigString, ConfigTaskCron, ConfigTaskDaily, ConfigTaskOnce:
		return nil
	case ConfigBool:
		return nil
	case ConfigFloat:
		if math.IsNaN(value.Float) || math.IsInf(value.Float, 0) {
			return ErrInvalidConfigValue
		}
		return nil
	case ConfigInt:
		return nil
	case ConfigTemplate:
		if len(value.Strings) > 1024 {
			return ErrInvalidConfigValue
		}
		return nil
	case ConfigOption:
		for _, option := range def.Options {
			if option == value.String {
				return nil
			}
		}
		return ErrInvalidConfigValue
	case ConfigSecret:
		return validateSecretRef(value.SecretRef)
	}
	return ErrUnsupportedConfigType
}
func configValueShapeValid(value ConfigValue) bool {
	switch value.Type {
	case ConfigString, ConfigTaskCron, ConfigTaskDaily, ConfigTaskOnce:
		return !value.Bool && value.Int == 0 && value.Float == 0 && len(value.Strings) == 0 && value.SecretRef == ""
	case ConfigBool:
		return value.String == "" && value.Int == 0 && value.Float == 0 && len(value.Strings) == 0 && value.SecretRef == ""
	case ConfigFloat:
		return value.String == "" && !value.Bool && value.Int == 0 && len(value.Strings) == 0 && value.SecretRef == ""
	case ConfigInt:
		return value.String == "" && !value.Bool && value.Float == 0 && len(value.Strings) == 0 && value.SecretRef == ""
	case ConfigTemplate:
		return value.String == "" && !value.Bool && value.Int == 0 && value.Float == 0 && value.SecretRef == ""
	case ConfigOption:
		return !value.Bool && value.Int == 0 && value.Float == 0 && len(value.Strings) == 0 && value.SecretRef == ""
	case ConfigSecret:
		return value.String == "" && !value.Bool && value.Int == 0 && value.Float == 0 && len(value.Strings) == 0
	default:
		return false
	}
}
func validateSecretRef(value string) error {
	if strings.HasPrefix(value, "vault:") {
		if len(value) <= len("vault:") || len(value) > MaxExtensionIdentityPartBytes {
			return ErrInvalidConfigValue
		}
		return nil
	}
	if strings.HasPrefix(value, "sha256:") {
		digest := strings.TrimPrefix(value, "sha256:")
		if len(digest) != 64 {
			return ErrInvalidConfigValue
		}
		if _, err := hex.DecodeString(digest); err != nil {
			return ErrInvalidConfigValue
		}
		return nil
	}
	return ErrInvalidConfigValue
}
