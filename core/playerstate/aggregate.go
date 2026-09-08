package playerstate

import (
	"fmt"
	"reflect"
	"strings"

	"Scardice-core/eventstore"
)

const (
	PlayerAggregateType = "player"
	GroupUserAttrsAggregateType = "attrs/group-user"
	CharacterAggregateType = "character"
	ModerationAggregateType = "moderation/group"
	EventSchemaVersion uint16 = 1
	MaxIdentityPartBytes = 255
)

type PlayerState struct { Version uint64 `json:"version"`; DiceID string `json:"diceId"`; GroupID string `json:"groupId"`; UserID string `json:"userId"`; Name string `json:"name,omitempty"`; Privilege int `json:"privilege"`; AutoSetNameTemplate string `json:"autoSetNameTemplate,omitempty"`; LastCommandAt int64 `json:"lastCommandAt,omitempty"`; Deleted bool `json:"deleted"` }
type Player = PlayerState
type GroupUserAttrsState struct { Version uint64 `json:"version"`; DiceID string `json:"diceId"`; GroupID string `json:"groupId"`; UserID string `json:"userId"`; BindingSheetID string `json:"bindingSheetId,omitempty"`; Values map[string]EncryptedValue `json:"values,omitempty"`; Operations []AttributeOperation `json:"operations,omitempty"`; Deleted bool `json:"deleted"` }
type GroupUserAttrs = GroupUserAttrsState
type AttributeOperation struct { Kind string `json:"kind"`; Key string `json:"key,omitempty"`; Delta int64 `json:"delta,omitempty"` }
const ( OperationSet = "set"; OperationIncrement = "increment"; OperationDelete = "delete"; OperationClear = "clear" )
type CharacterState struct { Version uint64 `json:"version"`; DiceID string `json:"diceId"`; UserID string `json:"userId"`; CharacterID string `json:"characterId"`; Name string `json:"name"`; SheetType string `json:"sheetType,omitempty"`; Sheet EncryptedValue `json:"sheet,omitempty"`; Deleted bool `json:"deleted"` }
type Character = CharacterState
type ModerationState struct { Version uint64 `json:"version"`; DiceID string `json:"diceId"`; GroupID string `json:"groupId"`; SubjectID string `json:"subjectId"`; Rank int `json:"rank"`; Score int64 `json:"score"`; ReasonDigest string `json:"reasonDigest,omitempty"`; Deleted bool `json:"deleted"` }
type Moderation = ModerationState

func (s PlayerState) Clone() PlayerState{return s}
func (s GroupUserAttrsState) Clone() GroupUserAttrsState{out:=s;out.Values=cloneValues(s.Values);out.Operations=append([]AttributeOperation(nil),s.Operations...);return out}
func (s CharacterState) Clone() CharacterState { out:=s; out.Sheet=s.Sheet.Clone(); return out }
func (s ModerationState) Clone() ModerationState{return s}
func cloneValues(in map[string]EncryptedValue)map[string]EncryptedValue{if in==nil{return nil};out:=make(map[string]EncryptedValue,len(in));for k,v:=range in{out[k]=v.Clone()};return out}

type PlayerCompatibilityView struct{ PlayerState }
type GroupUserAttrsCompatibilityView struct{ GroupUserAttrsState }
type CharacterCompatibilityView struct{ CharacterState }
type ModerationCompatibilityView struct{ ModerationState }
func(s PlayerState)CompatibilityView()PlayerCompatibilityView{return PlayerCompatibilityView{s.Clone()}}
func(s GroupUserAttrsState)CompatibilityView()GroupUserAttrsCompatibilityView{return GroupUserAttrsCompatibilityView{s.Clone()}}
func(s CharacterState)CompatibilityView()CharacterCompatibilityView{return CharacterCompatibilityView{s.Clone()}}
func(s ModerationState)CompatibilityView()ModerationCompatibilityView{return ModerationCompatibilityView{s.Clone()}}

func isNilEvent(event any) bool { if event == nil { return true }; value := reflect.ValueOf(event); return (value.Kind() == reflect.Ptr || value.Kind() == reflect.Interface) && value.IsNil() }
func ReducePlayer(state PlayerState,event PlayerEvent)(PlayerState,error){if isNilEvent(event)||state.Version==^uint64(0){if state.Version==^uint64(0){return PlayerState{},ErrInvalidState};return PlayerState{},ErrInvalidEvent};if err:=event.playerValidate();err!=nil{return PlayerState{},err};next:=state.Clone();if err:=event.playerApply(&next);err!=nil{return PlayerState{},err};next.Version++;return next,nil}
func ReplayPlayer(events []PlayerEvent)(PlayerState,error){var state PlayerState;for _,e:=range events{var err error;state,err=ReducePlayer(state,e);if err!=nil{return PlayerState{},err}};return state,nil}
func ReduceGroupUserAttrs(state GroupUserAttrsState,event GroupUserAttrsEvent)(GroupUserAttrsState,error){if isNilEvent(event)||state.Version==^uint64(0){if state.Version==^uint64(0){return GroupUserAttrsState{},ErrInvalidState};return GroupUserAttrsState{},ErrInvalidEvent};if err:=event.attrsValidate();err!=nil{return GroupUserAttrsState{},err};next:=state.Clone();if err:=event.attrsApply(&next);err!=nil{return GroupUserAttrsState{},err};next.Version++;return next,nil}
func ReplayGroupUserAttrs(events []GroupUserAttrsEvent)(GroupUserAttrsState,error){var state GroupUserAttrsState;for _,e:=range events{var err error;state,err=ReduceGroupUserAttrs(state,e);if err!=nil{return GroupUserAttrsState{},err}};return state,nil}
func ReduceCharacter(state CharacterState,event CharacterEvent)(CharacterState,error){if isNilEvent(event)||state.Version==^uint64(0){if state.Version==^uint64(0){return CharacterState{},ErrInvalidState};return CharacterState{},ErrInvalidEvent};if err:=event.characterValidate();err!=nil{return CharacterState{},err};next:=state.Clone();if err:=event.characterApply(&next);err!=nil{return CharacterState{},err};next.Version++;return next,nil}
func ReplayCharacters(events []CharacterEvent)(CharacterState,error){var state CharacterState;for _,e:=range events{var err error;state,err=ReduceCharacter(state,e);if err!=nil{return CharacterState{},err}};return state,nil}
func ReduceModeration(state ModerationState,event ModerationEvent)(ModerationState,error){if isNilEvent(event)||state.Version==^uint64(0){if state.Version==^uint64(0){return ModerationState{},ErrInvalidState};return ModerationState{},ErrInvalidEvent};if err:=event.moderationValidate();err!=nil{return ModerationState{},err};next:=state.Clone();if err:=event.moderationApply(&next);err!=nil{return ModerationState{},err};next.Version++;return next,nil}
func ReplayModeration(events []ModerationEvent)(ModerationState,error){var state ModerationState;for _,e:=range events{var err error;state,err=ReduceModeration(state,e);if err!=nil{return ModerationState{},err}};return state,nil}

func validateEnvelope(stateVersion uint64,envelope eventstore.Envelope,stream eventstore.StreamID, expectedType string)error{if stateVersion==^uint64(0){return ErrInvalidState};if envelope.Stream!=stream||envelope.Stream.AggregateType!=expectedType||envelope.SchemaVersion!=EventSchemaVersion{return ErrUnsupportedSchema};if envelope.StreamVersion!=stateVersion+1{return ErrInvalidState};if len(envelope.Payload)>eventstore.MaxEventPayloadBytes{return &eventstore.OversizeError{Bound:"playerstate event payload",Limit:eventstore.MaxEventPayloadBytes,Actual:len(envelope.Payload)}};return nil}
func ApplyPlayerEnvelope(state PlayerState,e eventstore.Envelope,stream eventstore.StreamID)(PlayerState,error){if err:=validateEnvelope(state.Version,e,stream,PlayerAggregateType);err!=nil{return PlayerState{},err};typed,err:=DecodePlayerEvent(EventType(e.EventType),e.Payload);if err!=nil{return PlayerState{},err};next,err:=ReducePlayer(state,typed);if err!=nil{return PlayerState{},err};if PlayerStream(next.DiceID,next.GroupID,next.UserID)!=stream{return PlayerState{},ErrInvalidState};return next,nil}
func ApplyGroupUserAttrsEnvelope(state GroupUserAttrsState,e eventstore.Envelope,stream eventstore.StreamID)(GroupUserAttrsState,error){if err:=validateEnvelope(state.Version,e,stream,GroupUserAttrsAggregateType);err!=nil{return GroupUserAttrsState{},err};typed,err:=DecodeGroupUserAttrsEvent(EventType(e.EventType),e.Payload);if err!=nil{return GroupUserAttrsState{},err};next,err:=ReduceGroupUserAttrs(state,typed);if err!=nil{return GroupUserAttrsState{},err};if GroupUserAttrsStream(next.DiceID,next.GroupID,next.UserID)!=stream{return GroupUserAttrsState{},ErrInvalidState};return next,nil}
func ApplyCharacterEnvelope(state CharacterState,e eventstore.Envelope,stream eventstore.StreamID)(CharacterState,error){if err:=validateEnvelope(state.Version,e,stream,CharacterAggregateType);err!=nil{return CharacterState{},err};typed,err:=DecodeCharacterEvent(EventType(e.EventType),e.Payload);if err!=nil{return CharacterState{},err};next,err:=ReduceCharacter(state,typed);if err!=nil{return CharacterState{},err};if CharacterStream(next.DiceID,next.UserID,next.CharacterID)!=stream{return CharacterState{},ErrInvalidState};return next,nil}
func ApplyModerationEnvelope(state ModerationState,e eventstore.Envelope,stream eventstore.StreamID)(ModerationState,error){if err:=validateEnvelope(state.Version,e,stream,ModerationAggregateType);err!=nil{return ModerationState{},err};typed,err:=DecodeModerationEvent(EventType(e.EventType),e.Payload);if err!=nil{return ModerationState{},err};next,err:=ReduceModeration(state,typed);if err!=nil{return ModerationState{},err};if ModerationStream(next.DiceID,next.GroupID,next.SubjectID)!=stream{return ModerationState{},ErrInvalidState};return next,nil}

func canonical(parts ...string)string{var out string;for _,p:=range parts{out+=fmt.Sprintf("%d:%s",len(p),p)};return out}
func validParts(parts ...string)bool{for _,p:=range parts{if strings.TrimSpace(p)==""||len(p)>MaxIdentityPartBytes{return false}};return len(canonical(parts...))<=255}
func PlayerStream(diceID,groupID,userID string)eventstore.StreamID{if !validParts(diceID,groupID,userID){return eventstore.StreamID{AggregateType:PlayerAggregateType}};return eventstore.StreamID{AggregateType:PlayerAggregateType,AggregateID:canonical(diceID,groupID,userID)}}
func PlayerStreamPrefix(diceID,groupID string)StreamPrefix{return streamPrefix(PlayerAggregateType,diceID,groupID)}
func GroupUserAttrsStream(diceID,groupID,userID string)eventstore.StreamID{if !validParts(diceID,groupID,userID){return eventstore.StreamID{AggregateType:GroupUserAttrsAggregateType}};return eventstore.StreamID{AggregateType:GroupUserAttrsAggregateType,AggregateID:canonical(diceID,groupID,userID)}}
func GroupUserAttrsStreamPrefix(diceID,groupID string)StreamPrefix{return streamPrefix(GroupUserAttrsAggregateType,diceID,groupID)}
func CharacterStream(diceID,userID,characterID string)eventstore.StreamID{if !validParts(diceID,userID,characterID){return eventstore.StreamID{AggregateType:CharacterAggregateType}};return eventstore.StreamID{AggregateType:CharacterAggregateType,AggregateID:canonical(diceID,userID,characterID)}}
func ModerationStream(diceID,groupID,subjectID string)eventstore.StreamID{if !validParts(diceID,groupID,subjectID){return eventstore.StreamID{AggregateType:ModerationAggregateType}};return eventstore.StreamID{AggregateType:ModerationAggregateType,AggregateID:canonical(diceID,groupID,subjectID)}}
type StreamPrefix struct{AggregateType string;Prefix string}
func streamPrefix(kind string,parts ...string)StreamPrefix{if !validParts(parts...){return StreamPrefix{AggregateType:kind}};return StreamPrefix{AggregateType:kind,Prefix:canonical(parts...)}}
