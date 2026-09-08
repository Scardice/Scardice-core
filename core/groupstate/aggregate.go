package groupstate

import (
	"fmt"
	"strings"

	"Scardice-core/eventstore"
)

// State is the complete Group-stream record. It intentionally contains no
// group attrs, group-user attrs, player bindings, moderation, runtime maps, or
// provider pointers.
type State struct {
	Version               uint64            `json:"version"`
	DiceID                string            `json:"diceId"`
	GroupID               string            `json:"groupId"`
	GroupName             string            `json:"groupName,omitempty"`
	InviteUserID          string            `json:"inviteUserId,omitempty"`
	GuildID               string            `json:"guildId,omitempty"`
	ChannelID             string            `json:"channelId,omitempty"`
	Active                bool              `json:"active"`
	DiceIDActive          map[string]bool   `json:"diceIdActive,omitempty"`
	DiceIDExists          map[string]bool   `json:"diceIdExists,omitempty"`
	ActivatedExtensions   []string          `json:"activatedExtensions,omitempty"`
	InactivatedExtensions map[string]bool   `json:"inactivatedExtensions,omitempty"`
	System                string            `json:"system,omitempty"`
	DiceSideNum           int64             `json:"diceSideNum,omitempty"`
	DiceSideExpr          string            `json:"diceSideExpr,omitempty"`
	RollShaperMode        string            `json:"rollShaperMode,omitempty"`
	CocRuleIndex          int               `json:"cocRuleIndex,omitempty"`
	HelpPackages          []string          `json:"helpPackages,omitempty"`
	DefaultHelpGroup      string            `json:"defaultHelpGroup,omitempty"`
	ShowGroupWelcome      bool              `json:"showGroupWelcome"`
	GroupWelcomeMessage   string            `json:"groupWelcomeMessage,omitempty"`
	BotList               map[string]bool   `json:"botList,omitempty"`
	Privileges            map[string]int    `json:"privileges,omitempty"`
	EnteredAt             int64             `json:"enteredAt,omitempty"`
	Deleted               bool              `json:"deleted"`
}
// GroupRecord and Aggregate are aliases for callers that name the ownership
// boundary explicitly. They remain value state, never mutable compatibility
// pointers.
type GroupRecord = State
type Aggregate = State
type GroupState = State
type GroupAggregate = State
type GroupEvent = TypedEvent


func (s State) Clone() State {

	copyState := s
	copyState.DiceIDActive = cloneBoolMap(s.DiceIDActive)
	copyState.DiceIDExists = cloneBoolMap(s.DiceIDExists)
	copyState.BotList = cloneBoolMap(s.BotList)
	copyState.InactivatedExtensions = cloneBoolMap(s.InactivatedExtensions)
	copyState.Privileges = cloneIntMap(s.Privileges)
	copyState.ActivatedExtensions = append([]string(nil), s.ActivatedExtensions...)
	copyState.HelpPackages = append([]string(nil), s.HelpPackages...)
	return copyState
}

func cloneBoolMap(input map[string]bool) map[string]bool {
	if input == nil { return nil }
	output := make(map[string]bool, len(input)); for key, value := range input { output[key] = value }; return output
}
func cloneIntMap(input map[string]int) map[string]int {
	if input == nil { return nil }
	output := make(map[string]int, len(input)); for key, value := range input { output[key] = value }; return output
}
func (s *State) ensureMaps() {
	if s.DiceIDActive == nil { s.DiceIDActive = map[string]bool{} }
	if s.DiceIDExists == nil { s.DiceIDExists = map[string]bool{} }
	if s.BotList == nil { s.BotList = map[string]bool{} }
	if s.InactivatedExtensions == nil { s.InactivatedExtensions = map[string]bool{} }
	if s.Privileges == nil { s.Privileges = map[string]int{} }
}

// Reduce applies one typed fact to a copied state. The input state's maps are
// never mutated, which keeps compatibility reads from becoming authorities.
func Reduce(state State, event TypedEvent) (State, error) {
	if isNilTypedEvent(event) || !event.EventType().Valid() { return State{}, ErrInvalidEvent }
	next := state.Clone()
	if next.Version > 0 { next.ensureMaps() }
	if err := event.apply(&next); err != nil { return State{}, err }
	if next.Version == ^uint64(0) { return State{}, ErrInvalidState }
	next.Version++
	return next, nil
}

func Replay(events []TypedEvent) (State, error) {
	state := State{}
	for _, event := range events { var err error; state, err = Reduce(state, event); if err != nil { return State{}, err } }
	return state, nil
}

// ApplyEnvelope decodes and applies one persisted event, checking schema and
// stream version so replay cannot silently skip or reorder facts.
func ApplyEnvelope(state State, envelope eventstore.Envelope) (State, error) {
	if envelope.Stream.AggregateType != GroupAggregateType || envelope.SchemaVersion != GroupEventSchemaVersion {
		return State{}, fmt.Errorf("%w: schema or aggregate type", ErrUnsupportedSchema)
	}
	if envelope.StreamVersion != state.Version+1 { return State{}, ErrInvalidState }
	if len(envelope.Payload) > MaxGroupEventPayloadBytes {
		return State{}, &eventstore.OversizeError{Bound: "group event payload", Limit: MaxGroupEventPayloadBytes, Actual: len(envelope.Payload)}
	}
	event, err := DecodeTypedEvent(EventType(envelope.EventType), envelope.Payload)
	if err != nil { return State{}, err }
	next, err := Reduce(state, event)
	if err != nil { return State{}, err }
	if next.DiceID == "" || next.GroupID == "" || canonicalAggregateID(next.DiceID, next.GroupID) != envelope.Stream.AggregateID { return State{}, ErrInvalidState }
	return next, nil
}

func ReplayEnvelopes(envelopes []eventstore.Envelope) (State, error) {
	state := State{}
	for _, envelope := range envelopes { var err error; state, err = ApplyEnvelope(state, envelope); if err != nil { return State{}, err } }
	return state, nil
}

const (
	GroupAggregateType = "group"
	GroupEventSchemaVersion = uint16(1)
	MaxGroupIdentityPartBytes = 255
	MaxGroupEventPayloadBytes = eventstore.MaxEventPayloadBytes
)

var ErrInvalidIdentity = fmt.Errorf("groupstate: invalid group identity")

func ValidateIdentity(diceID, groupID string) error {
	if strings.TrimSpace(diceID) == "" || strings.TrimSpace(groupID) == "" ||
		len(diceID) > MaxGroupIdentityPartBytes || len(groupID) > MaxGroupIdentityPartBytes {
		return ErrInvalidIdentity
	}
	return nil
}
func canonicalAggregateID(diceID, groupID string) string {
	return canonicalAggregateParts(diceID, groupID)
}
func canonicalAggregateParts(parts ...string) string {
	var encoded string
	for _, part := range parts { encoded += fmt.Sprintf("%d:%s", len(part), part) }
	return encoded
}
func GroupStream(diceID, groupID string) eventstore.StreamID {
	return eventstore.StreamID{AggregateType: GroupAggregateType, AggregateID: canonicalAggregateID(diceID, groupID)}
}
func eventMetadataValid(metadata eventstore.Metadata) bool {
	return metadata.EventID != "" && metadata.CommandID != "" && metadata.CorrelationID != "" && (!metadata.OccurredAt.IsZero() || metadata.OccurredAtUnixNanoSet || metadata.OccurredAtUnixNanoUTC != 0)
}

// NewEvent serializes one typed Group fact into the domain-neutral eventstore
// contract. Callers that need generated IDs/timestamps should use
// NewEventWithFactory.
func NewEvent(event TypedEvent, metadata eventstore.Metadata) (eventstore.NewEvent, error) {
	if !eventMetadataValid(metadata) { return eventstore.NewEvent{}, eventstore.ErrInvalidMetadata }
	payload, err := MarshalTypedEvent(event); if err != nil { return eventstore.NewEvent{}, err }
	return eventstore.NewEvent{EventType: string(event.EventType()), SchemaVersion: GroupEventSchemaVersion, Payload: payload, Metadata: metadata}, nil
}
func NewEventWithFactory(factory eventstore.EventFactory, event TypedEvent, metadata eventstore.Metadata) (eventstore.NewEvent, error) {
	payload, err := MarshalTypedEvent(event); if err != nil { return eventstore.NewEvent{}, err }
	return factory.NewEvent(string(event.EventType()), GroupEventSchemaVersion, payload, metadata)
}

// CompatibilityView is a deep-copy read DTO. Mutating it cannot affect the
// reducer state or any repository cache.
type CompatibilityView struct {
	State
}
func (s State) CompatibilityView() CompatibilityView { return CompatibilityView{State: s.Clone()} }
func ValidateState(state State) error {
	if state.Version == 0 { return nil }
	if ValidateIdentity(state.DiceID, state.GroupID) != nil { return ErrInvalidState }
	if state.Deleted && state.Active { return ErrDeletedGroup }
	return nil
}

