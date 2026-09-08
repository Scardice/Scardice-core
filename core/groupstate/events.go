package groupstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"

	"Scardice-core/eventstore"
)
// EventType is the closed set of durable group-record facts. Attribute and
// moderation values deliberately have no event type here: they have separate
// aggregate owners and deletion scopes.
type EventType string

const (
	EventGroupCreated             EventType = "group.created"
	EventGroupActivationChanged   EventType = "group.activation_changed"
	EventGroupIdentityChanged     EventType = "group.identity_changed"
	EventGroupNameChanged         EventType = "group.name_changed"
	EventGroupExtensionChanged    EventType = "group.extension_changed"
	EventGroupSystemChanged       EventType = "group.system_changed"
	EventGroupTemplateChanged     EventType = "group.template_changed"
	EventGroupHelpChanged         EventType = "group.help_changed"
	EventGroupWelcomeChanged      EventType = "group.welcome_changed"
	EventGroupBotListChanged      EventType = "group.bot_list_changed"
	EventGroupPrivilegeChanged    EventType = "group.privilege_changed"
	EventGroupRecordDeleted       EventType = "group.record_deleted"
)
const (
	GroupCreated           = EventGroupCreated
	GroupActivationChanged = EventGroupActivationChanged
	GroupIdentityChanged   = EventGroupIdentityChanged
	GroupNameChanged       = EventGroupNameChanged
	GroupExtensionChanged  = EventGroupExtensionChanged
	GroupSystemChanged     = EventGroupSystemChanged
	GroupTemplateChanged   = EventGroupTemplateChanged
	GroupHelpChanged       = EventGroupHelpChanged
	GroupWelcomeChanged    = EventGroupWelcomeChanged
	GroupBotListChanged    = EventGroupBotListChanged
	GroupPrivilegeChanged  = EventGroupPrivilegeChanged
	GroupRecordDeleted     = EventGroupRecordDeleted
)

func (e EventType) Valid() bool {
	switch e {
	case EventGroupCreated, EventGroupActivationChanged, EventGroupIdentityChanged, EventGroupNameChanged,
		EventGroupExtensionChanged, EventGroupSystemChanged, EventGroupTemplateChanged,
		EventGroupHelpChanged, EventGroupWelcomeChanged, EventGroupBotListChanged,
		EventGroupPrivilegeChanged, EventGroupRecordDeleted:
		return true
	default:
		return false
	}
}

var (
	ErrInvalidEvent       = errors.New("groupstate: invalid event")
	ErrUnsupportedSchema  = errors.New("groupstate: unsupported event schema")
	ErrInvalidState       = errors.New("groupstate: invalid state")
	ErrDeletedGroup       = errors.New("groupstate: group record is deleted")
)

// TypedEvent is the reducer boundary. Implementations are closed to this
// package so arbitrary callers cannot smuggle attrs or moderation into the
// Group stream.
type TypedEvent interface {
	EventType() EventType
	apply(*State) error
	validate() error
}

type GroupCreatedV1 struct {
	DiceID string `json:"diceId"`
	GroupID string `json:"groupId"`
	GroupName string `json:"groupName,omitempty"`
	InviteUserID string `json:"inviteUserId,omitempty"`
	EnteredAt int64 `json:"enteredAt,omitempty"`
}
func NewGroupCreatedV1(diceID, groupID, groupName string, enteredAt int64) GroupCreatedV1 {
	return GroupCreatedV1{DiceID: diceID, GroupID: groupID, GroupName: groupName, EnteredAt: enteredAt}
}
func NewGroupCreatedWithInviteV1(diceID, groupID, groupName, inviteUserID string, enteredAt int64) GroupCreatedV1 {
	return GroupCreatedV1{DiceID: diceID, GroupID: groupID, GroupName: groupName, InviteUserID: inviteUserID, EnteredAt: enteredAt}
}
func (GroupCreatedV1) EventType() EventType { return EventGroupCreated }
func (e GroupCreatedV1) apply(s *State) error {
	if s.Version != 0 || ValidateIdentity(e.DiceID, e.GroupID) != nil {
		return ErrInvalidState
	}
	s.DiceID, s.GroupID, s.GroupName, s.InviteUserID, s.EnteredAt = e.DiceID, e.GroupID, e.GroupName, e.InviteUserID, e.EnteredAt
	s.DiceIDActive, s.DiceIDExists, s.BotList, s.InactivatedExtensions, s.Privileges = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]int{}
	return nil
}

type GroupActivationChangedV1 struct {
	DiceID string `json:"diceId"`
	Active bool   `json:"active"`
	Exists bool   `json:"exists"`
}
func NewGroupActivationChangedV1(diceID string, active, exists bool) GroupActivationChangedV1 {
	return GroupActivationChangedV1{DiceID: diceID, Active: active, Exists: exists}
}
func (GroupActivationChangedV1) EventType() EventType { return EventGroupActivationChanged }
func (e GroupActivationChangedV1) apply(s *State) error {
	if s.Version == 0 || s.Deleted || !validScopedIdentifier(e.DiceID) { return ErrInvalidState }
	if e.Exists { s.DiceIDExists[e.DiceID] = true } else { delete(s.DiceIDExists, e.DiceID) }
	if e.Active { s.DiceIDActive[e.DiceID] = true } else { delete(s.DiceIDActive, e.DiceID) }
	s.Active = len(s.DiceIDActive) > 0
	return nil
}

type GroupIdentityChangedV1 struct { GuildID string `json:"guildId"`; ChannelID string `json:"channelId"` }
func NewGroupIdentityChangedV1(guildID, channelID string) GroupIdentityChangedV1 {
	return GroupIdentityChangedV1{GuildID: guildID, ChannelID: channelID}
}
func (GroupIdentityChangedV1) EventType() EventType { return EventGroupIdentityChanged }
func (e GroupIdentityChangedV1) apply(s *State) error {
	if s.Version == 0 || s.Deleted || !validOptionalScopedIdentifier(e.GuildID) || !validOptionalScopedIdentifier(e.ChannelID) { return ErrInvalidState }
	s.GuildID, s.ChannelID = e.GuildID, e.ChannelID
	return nil
}

type GroupNameChangedV1 struct { GroupName string `json:"groupName"` }
func NewGroupNameChangedV1(name string) GroupNameChangedV1 { return GroupNameChangedV1{GroupName: name} }
func (GroupNameChangedV1) EventType() EventType { return EventGroupNameChanged }
func (e GroupNameChangedV1) apply(s *State) error { if s.Version == 0 || s.Deleted { return ErrInvalidState }; s.GroupName = e.GroupName; return nil }

type GroupExtensionChangedV1 struct { ExtensionID string `json:"extensionId"`; Enabled bool `json:"enabled"`; Inactivated bool `json:"inactivated"` }
func NewGroupExtensionChangedV1(id string, enabled bool) GroupExtensionChangedV1 { return GroupExtensionChangedV1{ExtensionID: id, Enabled: enabled, Inactivated: !enabled} }
func (GroupExtensionChangedV1) EventType() EventType { return EventGroupExtensionChanged }
func (e GroupExtensionChangedV1) apply(s *State) error {
	if s.Version == 0 || s.Deleted || !validScopedIdentifier(e.ExtensionID) { return ErrInvalidState }
	if e.Enabled { s.addExtension(e.ExtensionID); delete(s.InactivatedExtensions, e.ExtensionID) } else { s.removeExtension(e.ExtensionID); s.InactivatedExtensions[e.ExtensionID] = true }
	return nil
}

type GroupSystemChangedV1 struct { System string `json:"system"` }
func NewGroupSystemChangedV1(system string) GroupSystemChangedV1 { return GroupSystemChangedV1{System: system} }
func (GroupSystemChangedV1) EventType() EventType { return EventGroupSystemChanged }
func (e GroupSystemChangedV1) apply(s *State) error { if s.Version == 0 || s.Deleted { return ErrInvalidState }; s.System = e.System; return nil }

type GroupTemplateChangedV1 struct { DiceSideNum int64 `json:"diceSideNum"`; DiceSideExpr string `json:"diceSideExpr"`; RollShaperMode string `json:"rollShaperMode"`; CocRuleIndex int `json:"cocRuleIndex"` }
func NewGroupTemplateChangedV1(num int64, expr, mode string) GroupTemplateChangedV1 { return GroupTemplateChangedV1{DiceSideNum: num, DiceSideExpr: expr, RollShaperMode: mode} }
func NewGroupTemplateWithCocRuleV1(num int64, expr, mode string, index int) GroupTemplateChangedV1 { return GroupTemplateChangedV1{DiceSideNum: num, DiceSideExpr: expr, RollShaperMode: mode, CocRuleIndex: index} }
func (GroupTemplateChangedV1) EventType() EventType { return EventGroupTemplateChanged }
func (e GroupTemplateChangedV1) apply(s *State) error { if s.Version == 0 || s.Deleted { return ErrInvalidState }; s.DiceSideNum, s.DiceSideExpr, s.RollShaperMode, s.CocRuleIndex = e.DiceSideNum, e.DiceSideExpr, e.RollShaperMode, e.CocRuleIndex; return nil }

type GroupHelpChangedV1 struct { DefaultHelpGroup string `json:"defaultHelpGroup"`; HelpPackages []string `json:"helpPackages,omitempty"` }
func NewGroupHelpChangedV1(group string, packages []string) GroupHelpChangedV1 { return GroupHelpChangedV1{DefaultHelpGroup: group, HelpPackages: append([]string(nil), packages...)} }
func (GroupHelpChangedV1) EventType() EventType { return EventGroupHelpChanged }
func (e GroupHelpChangedV1) apply(s *State) error {
	if s.Version == 0 || s.Deleted || !validOptionalScopedIdentifier(e.DefaultHelpGroup) { return ErrInvalidState }
	for _, item := range e.HelpPackages { if !validOptionalScopedIdentifier(item) { return ErrInvalidState } }
	s.DefaultHelpGroup, s.HelpPackages = e.DefaultHelpGroup, append([]string(nil), e.HelpPackages...)
	return nil
}

type GroupWelcomeChangedV1 struct { Enabled bool `json:"enabled"`; Message string `json:"message,omitempty"` }
func NewGroupWelcomeChangedV1(enabled bool, message string) GroupWelcomeChangedV1 { return GroupWelcomeChangedV1{Enabled: enabled, Message: message} }
func (GroupWelcomeChangedV1) EventType() EventType { return EventGroupWelcomeChanged }
func (e GroupWelcomeChangedV1) apply(s *State) error { if s.Version == 0 || s.Deleted { return ErrInvalidState }; s.ShowGroupWelcome, s.GroupWelcomeMessage = e.Enabled, e.Message; return nil }

type GroupBotListChangedV1 struct { UserID string `json:"userId"`; Enabled bool `json:"enabled"` }
func NewGroupBotListChangedV1(userID string, enabled bool) GroupBotListChangedV1 { return GroupBotListChangedV1{UserID: userID, Enabled: enabled} }
func (GroupBotListChangedV1) EventType() EventType { return EventGroupBotListChanged }
func (e GroupBotListChangedV1) apply(s *State) error { if s.Version == 0 || s.Deleted || !validScopedIdentifier(e.UserID) { return ErrInvalidState }; if e.Enabled { s.BotList[e.UserID] = true } else { delete(s.BotList, e.UserID) }; return nil }

type GroupPrivilegeChangedV1 struct { UserID string `json:"userId"`; Level int `json:"level"` }
func NewGroupPrivilegeChangedV1(userID string, level int) GroupPrivilegeChangedV1 { return GroupPrivilegeChangedV1{UserID: userID, Level: level} }
func (GroupPrivilegeChangedV1) EventType() EventType { return EventGroupPrivilegeChanged }
func (e GroupPrivilegeChangedV1) apply(s *State) error { if s.Version == 0 || s.Deleted || !validScopedIdentifier(e.UserID) || e.Level < -30 || e.Level > 100 { return ErrInvalidState }; s.Privileges[e.UserID] = e.Level; return nil }

type GroupRecordDeletedV1 struct{}
func NewGroupRecordDeletedV1() GroupRecordDeletedV1 { return GroupRecordDeletedV1{} }
func (GroupRecordDeletedV1) EventType() EventType { return EventGroupRecordDeleted }
func (GroupRecordDeletedV1) apply(s *State) error { if s.Version == 0 || s.Deleted { return ErrInvalidState }; s.Deleted, s.Active, s.DiceIDActive = true, false, map[string]bool{}; return nil }

func (s *State) addExtension(id string) { for _, current := range s.ActivatedExtensions { if current == id { return } }; s.ActivatedExtensions = append(s.ActivatedExtensions, id) }
func (e GroupCreatedV1) validate() error {
	if ValidateIdentity(e.DiceID, e.GroupID) != nil || !validOptionalScopedIdentifier(e.InviteUserID) { return ErrInvalidIdentity }
	return nil
}
func (e GroupActivationChangedV1) validate() error {
	if !validScopedIdentifier(e.DiceID) { return ErrInvalidIdentity }
	return nil
}
func (e GroupIdentityChangedV1) validate() error {
	if !validOptionalScopedIdentifier(e.GuildID) || !validOptionalScopedIdentifier(e.ChannelID) { return ErrInvalidIdentity }
	return nil
}
func (e GroupNameChangedV1) validate() error { return nil }
func (e GroupExtensionChangedV1) validate() error {
	if !validScopedIdentifier(e.ExtensionID) { return ErrInvalidIdentity }
	return nil
}
func (e GroupSystemChangedV1) validate() error { return nil }
func (e GroupTemplateChangedV1) validate() error { return nil }
func (e GroupHelpChangedV1) validate() error {
	if !validOptionalScopedIdentifier(e.DefaultHelpGroup) { return ErrInvalidIdentity }
	for _, item := range e.HelpPackages {
		if !validOptionalScopedIdentifier(item) { return ErrInvalidIdentity }
	}
	return nil
}
func (e GroupWelcomeChangedV1) validate() error { return nil }
func (e GroupBotListChangedV1) validate() error {
	if !validScopedIdentifier(e.UserID) { return ErrInvalidIdentity }
	return nil
}
func (e GroupPrivilegeChangedV1) validate() error {
	if !validScopedIdentifier(e.UserID) || e.Level < -30 || e.Level > 100 { return ErrInvalidIdentity }
	return nil
}
func (GroupRecordDeletedV1) validate() error { return nil }

func (s *State) removeExtension(id string) { for i, current := range s.ActivatedExtensions { if current == id { s.ActivatedExtensions = append(s.ActivatedExtensions[:i], s.ActivatedExtensions[i+1:]...); return } } }
func isNilTypedEvent(event TypedEvent) bool {
	if event == nil { return true }
	value := reflect.ValueOf(event)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
func MarshalTypedEvent(event TypedEvent) ([]byte, error) {
	if isNilTypedEvent(event) || !event.EventType().Valid() { return nil, ErrInvalidEvent }
	if err := event.validate(); err != nil { return nil, err }
	payload, err := json.Marshal(event)
	if err != nil { return nil, err }
	if len(payload) > MaxGroupEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "group event payload", Limit: MaxGroupEventPayloadBytes, Actual: len(payload)}
	}
	return payload, nil
}
func MarshalTypedEvents(events []TypedEvent) ([]byte, error) {
	encoded := make([]json.RawMessage, 0, len(events))
	for _, event := range events { payload, err := MarshalTypedEvent(event); if err != nil { return nil, err }; encoded = append(encoded, payload) }
	return json.Marshal(encoded)
}
func containsJSONNull(value any) bool {
	switch item := value.(type) {
	case nil:
		return true
	case []any:
		for _, child := range item { if containsJSONNull(child) { return true } }
	case map[string]any:
		for _, child := range item { if containsJSONNull(child) { return true } }
	}
	return false
}
func DecodeTypedEvent(eventType EventType, payload []byte) (TypedEvent, error) {
	if len(payload) > MaxGroupEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "group event payload", Limit: MaxGroupEventPayloadBytes, Actual: len(payload)}
	}
	var value any
	if err := json.Unmarshal(payload, &value); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON payload", ErrInvalidEvent)
	}
	if _, ok := value.(map[string]any); !ok || containsJSONNull(value) {
		return nil, fmt.Errorf("%w: payload must be a non-null JSON object", ErrInvalidEvent)
	}
	var event TypedEvent
	switch eventType {
	case EventGroupCreated: event = &GroupCreatedV1{}
	case EventGroupActivationChanged: event = &GroupActivationChangedV1{}
	case EventGroupIdentityChanged: event = &GroupIdentityChangedV1{}
	case EventGroupNameChanged: event = &GroupNameChangedV1{}
	case EventGroupExtensionChanged: event = &GroupExtensionChangedV1{}
	case EventGroupSystemChanged: event = &GroupSystemChangedV1{}
	case EventGroupTemplateChanged: event = &GroupTemplateChangedV1{}
	case EventGroupHelpChanged: event = &GroupHelpChangedV1{}
	case EventGroupWelcomeChanged: event = &GroupWelcomeChangedV1{}
	case EventGroupBotListChanged: event = &GroupBotListChangedV1{}
	case EventGroupPrivilegeChanged: event = &GroupPrivilegeChangedV1{}
	case EventGroupRecordDeleted: event = &GroupRecordDeletedV1{}
	default: return nil, fmt.Errorf("%w: %s", ErrInvalidEvent, eventType)
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(event); err != nil { return nil, fmt.Errorf("%w: %v", ErrInvalidEvent, err) }
	if err := decoder.Decode(&struct{}{}); err != io.EOF { return nil, fmt.Errorf("%w: trailing JSON payload", ErrInvalidEvent) }
	if err := event.validate(); err != nil { return nil, err }
	return event, nil
}
