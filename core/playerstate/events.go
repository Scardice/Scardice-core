package playerstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"Scardice-core/eventstore"
)

type EventType string
const (
	EventPlayerCreated EventType = "player.created"
	EventPlayerNameChanged EventType = "player.name_changed"
	EventPlayerPrivilegeChanged EventType = "player.privilege_changed"
	EventPlayerTemplateChanged EventType = "player.template_changed"
	EventPlayerLastCommandChanged EventType = "player.last_command_changed"
	EventPlayerDeleted EventType = "player.deleted"
	EventGroupUserAttrsCreated EventType = "attrs.group_user.created"
	EventGroupUserAttrsBindingChanged EventType = "attrs.group_user.binding_changed"
	EventGroupUserAttrsSet EventType = "attrs.group_user.set"
	EventGroupUserAttrsIncremented EventType = "attrs.group_user.incremented"
	EventGroupUserAttrsDeleted EventType = "attrs.group_user.deleted"
	EventGroupUserAttrsCleared EventType = "attrs.group_user.cleared"
	EventCharacterCreated EventType = "character.created"
	EventCharacterRenamed EventType = "character.renamed"
	EventCharacterSheetReplaced EventType = "character.sheet_replaced"
	EventCharacterDeleted EventType = "character.deleted"
	EventModerationCreated EventType = "moderation.created"
	EventModerationScoreChanged EventType = "moderation.score_changed"
	EventModerationRankChanged EventType = "moderation.rank_changed"
	EventModerationDeleted EventType = "moderation.deleted"
)
const (
	PlayerCreated = EventPlayerCreated
	PlayerNameChanged = EventPlayerNameChanged
	PlayerPrivilegeChanged = EventPlayerPrivilegeChanged
	PlayerTemplateChanged = EventPlayerTemplateChanged
	PlayerLastCommandChanged = EventPlayerLastCommandChanged
	PlayerDeleted = EventPlayerDeleted
	GroupUserAttrsCreated = EventGroupUserAttrsCreated
	GroupUserAttrsBindingChanged = EventGroupUserAttrsBindingChanged
	GroupUserAttrsSet = EventGroupUserAttrsSet
	GroupUserAttrsIncremented = EventGroupUserAttrsIncremented
	GroupUserAttrsDeleted = EventGroupUserAttrsDeleted
	GroupUserAttrsCleared = EventGroupUserAttrsCleared
	CharacterCreated = EventCharacterCreated
	CharacterRenamed = EventCharacterRenamed
	CharacterSheetReplaced = EventCharacterSheetReplaced
	CharacterDeleted = EventCharacterDeleted
	ModerationCreated = EventModerationCreated
	ModerationScoreChanged = EventModerationScoreChanged
	ModerationRankChanged = EventModerationRankChanged
	ModerationDeleted = EventModerationDeleted
)

var (
	ErrInvalidEvent = errors.New("playerstate: invalid event")
	ErrUnsupportedSchema = errors.New("playerstate: unsupported event schema")
	ErrInvalidState = errors.New("playerstate: invalid state")
	ErrInvalidIdentity = errors.New("playerstate: invalid identity")
	ErrDeletedState = errors.New("playerstate: state is deleted")
	ErrRepositoryUnavailable = errors.New("playerstate: repository unavailable")
)

// Typed event interfaces are sealed by unexported methods. Event payloads carry
// only player-record facts or opaque encrypted bytes; request-local $t values
// have no event representation.
type PlayerEvent interface { EventType() EventType; playerApply(*PlayerState) error; playerValidate() error }
type GroupUserAttrsEvent interface { EventType() EventType; attrsApply(*GroupUserAttrsState) error; attrsValidate() error }
type CharacterEvent interface { EventType() EventType; characterApply(*CharacterState) error; characterValidate() error }
type ModerationEvent interface { EventType() EventType; moderationApply(*ModerationState) error; moderationValidate() error }

type PlayerCreatedV1 struct { DiceID string `json:"diceId"`; GroupID string `json:"groupId"`; UserID string `json:"userId"`; Name string `json:"name,omitempty"` }
func NewPlayerCreatedV1(diceID, groupID, userID, name string) PlayerCreatedV1 { return PlayerCreatedV1{diceID, groupID, userID, name} }
func (PlayerCreatedV1) EventType() EventType { return EventPlayerCreated }
func (e PlayerCreatedV1) playerValidate() error { return validateIdentity(e.DiceID,e.GroupID,e.UserID) }
func (e PlayerCreatedV1) playerApply(s *PlayerState) error { if s.Version != 0 || s.Deleted { return ErrInvalidState }; s.DiceID,s.GroupID,s.UserID,s.Name=e.DiceID,e.GroupID,e.UserID,e.Name; return nil }

type PlayerNameChangedV1 struct { Name string `json:"name"` }
func NewPlayerNameChangedV1(name string) PlayerNameChangedV1 { return PlayerNameChangedV1{Name:name} }
func (PlayerNameChangedV1) EventType() EventType { return EventPlayerNameChanged }
func (e PlayerNameChangedV1) playerValidate() error { return validateText(e.Name) }
func (e PlayerNameChangedV1) playerApply(s *PlayerState) error { if s.Version==0 || s.Deleted{return ErrInvalidState}; s.Name=e.Name; return nil }

type PlayerPrivilegeChangedV1 struct { Privilege int `json:"privilege"` }
func NewPlayerPrivilegeChangedV1(privilege int) PlayerPrivilegeChangedV1 { return PlayerPrivilegeChangedV1{privilege} }
func (PlayerPrivilegeChangedV1) EventType() EventType { return EventPlayerPrivilegeChanged }
func (e PlayerPrivilegeChangedV1) playerValidate() error { if e.Privilege < -30 || e.Privilege > 100{return ErrInvalidState}; return nil }
func (e PlayerPrivilegeChangedV1) playerApply(s *PlayerState) error { if s.Version==0 || s.Deleted{return ErrInvalidState}; s.Privilege=e.Privilege; return nil }

type PlayerAutoSetNameTemplateChangedV1 struct { Template string `json:"template,omitempty"` }
func NewPlayerAutoSetNameTemplateChangedV1(template string) PlayerAutoSetNameTemplateChangedV1 { return PlayerAutoSetNameTemplateChangedV1{template} }
func (PlayerAutoSetNameTemplateChangedV1) EventType() EventType { return EventPlayerTemplateChanged }
func (e PlayerAutoSetNameTemplateChangedV1) playerValidate() error { return validateOptionalText(e.Template) }
func (e PlayerAutoSetNameTemplateChangedV1) playerApply(s *PlayerState) error { if s.Version==0 || s.Deleted{return ErrInvalidState}; s.AutoSetNameTemplate=e.Template; return nil }

type PlayerLastCommandChangedV1 struct { At int64 `json:"at"` }
func NewPlayerLastCommandChangedV1(at int64) PlayerLastCommandChangedV1 { return PlayerLastCommandChangedV1{at} }
func (PlayerLastCommandChangedV1) EventType() EventType { return EventPlayerLastCommandChanged }
func (e PlayerLastCommandChangedV1) playerValidate() error { if e.At<0{return ErrInvalidState}; return nil }
func (e PlayerLastCommandChangedV1) playerApply(s *PlayerState) error { if s.Version==0 || s.Deleted{return ErrInvalidState}; s.LastCommandAt=e.At; return nil }

type PlayerDeletedV1 struct{}
func NewPlayerDeletedV1() PlayerDeletedV1 { return PlayerDeletedV1{} }
func (PlayerDeletedV1) EventType() EventType { return EventPlayerDeleted }
func (PlayerDeletedV1) playerValidate() error{return nil}
func (PlayerDeletedV1) playerApply(s *PlayerState) error { if s.Version==0{return ErrInvalidState}; s.Name=""; s.AutoSetNameTemplate=""; s.Deleted=true; return nil }

type EncryptedValue struct { Ciphertext []byte `json:"ciphertext,omitempty"`; KeyID string `json:"keyId,omitempty"` }
func NewEncryptedValue(ciphertext []byte, keyID string) EncryptedValue { return EncryptedValue{append([]byte(nil), ciphertext...), keyID} }
func (v EncryptedValue) Clone() EncryptedValue { return NewEncryptedValue(v.Ciphertext,v.KeyID) }
func (v EncryptedValue) valid() error { if len(v.Ciphertext)==0 || strings.TrimSpace(v.KeyID)=="" || len(v.KeyID)>255{return ErrInvalidState}; return nil }

type GroupUserAttrsCreatedV1 struct { DiceID string `json:"diceId"`; GroupID string `json:"groupId"`; UserID string `json:"userId"` }
func NewGroupUserAttrsCreatedV1(diceID,groupID,userID string) GroupUserAttrsCreatedV1{return GroupUserAttrsCreatedV1{diceID,groupID,userID}}
func (GroupUserAttrsCreatedV1) EventType() EventType{return EventGroupUserAttrsCreated}
func (e GroupUserAttrsCreatedV1) attrsValidate()error{return validateIdentity(e.DiceID,e.GroupID,e.UserID)}
func (e GroupUserAttrsCreatedV1) attrsApply(s *GroupUserAttrsState)error{if s.Version!=0||s.Deleted{return ErrInvalidState};s.DiceID,s.GroupID,s.UserID=e.DiceID,e.GroupID,e.UserID;return nil}

type GroupUserAttrsBindingChangedV1 struct { BindingSheetID string `json:"bindingSheetId,omitempty"` }
func NewGroupUserAttrsBindingChangedV1(id string) GroupUserAttrsBindingChangedV1{return GroupUserAttrsBindingChangedV1{id}}
func (GroupUserAttrsBindingChangedV1) EventType() EventType{return EventGroupUserAttrsBindingChanged}
func (e GroupUserAttrsBindingChangedV1) attrsValidate()error{return validateOptionalText(e.BindingSheetID)}
func (e GroupUserAttrsBindingChangedV1) attrsApply(s *GroupUserAttrsState)error{if s.Version==0||s.Deleted{return ErrInvalidState};s.BindingSheetID=e.BindingSheetID;return nil}

type GroupUserAttrsSetV1 struct { Key string `json:"key"`; Value EncryptedValue `json:"value"` }
func NewGroupUserAttrsSetV1(key string,ciphertext []byte,keyID string) GroupUserAttrsSetV1{return GroupUserAttrsSetV1{key,NewEncryptedValue(ciphertext,keyID)}}
func (GroupUserAttrsSetV1) EventType() EventType{return EventGroupUserAttrsSet}
func (e GroupUserAttrsSetV1) attrsValidate()error{if err:=validateText(e.Key);err!=nil{return err};return e.Value.valid()}
func (e GroupUserAttrsSetV1) attrsApply(s *GroupUserAttrsState)error{if s.Version==0||s.Deleted{return ErrInvalidState};if s.Values==nil{s.Values=map[string]EncryptedValue{}};s.Values[e.Key]=e.Value.Clone();s.Operations=append(s.Operations,AttributeOperation{Kind:OperationSet,Key:e.Key});return nil}

type GroupUserAttrsIncrementedV1 struct { Key string `json:"key"`; Delta int64 `json:"delta"` }
func NewGroupUserAttrsIncrementedV1(key string,delta int64) GroupUserAttrsIncrementedV1{return GroupUserAttrsIncrementedV1{key,delta}}
func (GroupUserAttrsIncrementedV1) EventType() EventType{return EventGroupUserAttrsIncremented}
func (e GroupUserAttrsIncrementedV1) attrsValidate()error{return validateText(e.Key)}
func (e GroupUserAttrsIncrementedV1) attrsApply(s *GroupUserAttrsState)error{if s.Version==0||s.Deleted{return ErrInvalidState};s.Operations=append(s.Operations,AttributeOperation{Kind:OperationIncrement,Key:e.Key,Delta:e.Delta});return nil}

type GroupUserAttrsDeletedV1 struct { Key string `json:"key"` }
func NewGroupUserAttrsDeletedV1(key string) GroupUserAttrsDeletedV1{return GroupUserAttrsDeletedV1{key}}
func (GroupUserAttrsDeletedV1) EventType() EventType{return EventGroupUserAttrsDeleted}
func (e GroupUserAttrsDeletedV1) attrsValidate()error{return validateText(e.Key)}
func (e GroupUserAttrsDeletedV1) attrsApply(s *GroupUserAttrsState)error{if s.Version==0||s.Deleted{return ErrInvalidState};delete(s.Values,e.Key);s.Operations=append(s.Operations,AttributeOperation{Kind:OperationDelete,Key:e.Key});return nil}

type GroupUserAttrsClearedV1 struct{}
func NewGroupUserAttrsClearedV1() GroupUserAttrsClearedV1{return GroupUserAttrsClearedV1{}}
func (GroupUserAttrsClearedV1) EventType() EventType{return EventGroupUserAttrsCleared}
func (GroupUserAttrsClearedV1) attrsValidate()error{return nil}
func (GroupUserAttrsClearedV1) attrsApply(s *GroupUserAttrsState)error{if s.Version==0||s.Deleted{return ErrInvalidState};s.Values=map[string]EncryptedValue{};s.Operations=append(s.Operations,AttributeOperation{Kind:OperationClear});return nil}

type CharacterCreatedV1 struct { DiceID string `json:"diceId"`; UserID string `json:"userId"`; CharacterID string `json:"characterId"`; Name string `json:"name"`; SheetType string `json:"sheetType,omitempty"` }
func NewCharacterCreatedV1(diceID,userID,id,name,sheetType string) CharacterCreatedV1{return CharacterCreatedV1{diceID,userID,id,name,sheetType}}
func (CharacterCreatedV1) EventType() EventType{return EventCharacterCreated}
func (e CharacterCreatedV1) characterValidate()error{if err:=validateIdentity(e.DiceID,e.UserID);err!=nil{return err};if err:=validateText(e.CharacterID);err!=nil{return err};return validateText(e.Name)}
func (e CharacterCreatedV1) characterApply(s *CharacterState)error{if s.Version!=0||s.Deleted{return ErrInvalidState};s.DiceID,s.UserID,s.CharacterID,s.Name,s.SheetType=e.DiceID,e.UserID,e.CharacterID,e.Name,e.SheetType;return nil}

type CharacterRenamedV1 struct { Name string `json:"name"` }
func NewCharacterRenamedV1(name string) CharacterRenamedV1{return CharacterRenamedV1{name}}
func (CharacterRenamedV1) EventType() EventType{return EventCharacterRenamed}
func (e CharacterRenamedV1) characterValidate()error{return validateText(e.Name)}
func (e CharacterRenamedV1) characterApply(s *CharacterState)error{if s.Version==0||s.Deleted{return ErrInvalidState};s.Name=e.Name;return nil}

type CharacterSheetReplacedV1 struct { Sheet EncryptedValue `json:"sheet"` }
func NewCharacterSheetReplacedV1(ciphertext []byte,keyID string) CharacterSheetReplacedV1{return CharacterSheetReplacedV1{NewEncryptedValue(ciphertext,keyID)}}
func (CharacterSheetReplacedV1) EventType() EventType{return EventCharacterSheetReplaced}
func (e CharacterSheetReplacedV1) characterValidate()error{return e.Sheet.valid()}
func (e CharacterSheetReplacedV1) characterApply(s *CharacterState)error{if s.Version==0||s.Deleted{return ErrInvalidState};s.Sheet=e.Sheet.Clone();return nil}

type CharacterDeletedV1 struct{}
func NewCharacterDeletedV1() CharacterDeletedV1{return CharacterDeletedV1{}}
func (CharacterDeletedV1) EventType() EventType{return EventCharacterDeleted}
func (CharacterDeletedV1) characterValidate()error{return nil}
func (CharacterDeletedV1) characterApply(s *CharacterState)error{if s.Version==0{return ErrInvalidState};s.Name="";s.Sheet=EncryptedValue{};s.Deleted=true;return nil}

type ModerationCreatedV1 struct { DiceID string `json:"diceId"`; GroupID string `json:"groupId"`; SubjectID string `json:"subjectId"`; Rank int `json:"rank"`; Score int64 `json:"score"` }
func NewModerationCreatedV1(diceID,groupID,subjectID string,rank int,score int64) ModerationCreatedV1{return ModerationCreatedV1{diceID,groupID,subjectID,rank,score}}
func (ModerationCreatedV1) EventType() EventType{return EventModerationCreated}
func (e ModerationCreatedV1) moderationValidate()error{if err:=validateIdentity(e.DiceID,e.GroupID);err!=nil{return err};if err:=validateText(e.SubjectID);err!=nil{return err};if e.Rank < -30 || e.Rank > 30{return ErrInvalidState};return nil}
func (e ModerationCreatedV1) moderationApply(s *ModerationState)error{if s.Version!=0||s.Deleted{return ErrInvalidState};s.DiceID,s.GroupID,s.SubjectID,s.Rank,s.Score=e.DiceID,e.GroupID,e.SubjectID,e.Rank,e.Score;return nil}

type ModerationScoreChangedV1 struct { Score int64 `json:"score"`; ReasonDigest string `json:"reasonDigest,omitempty"` }
func NewModerationScoreChangedV1(score int64,reasonDigest string) ModerationScoreChangedV1{return ModerationScoreChangedV1{score,reasonDigest}}
func (ModerationScoreChangedV1) EventType() EventType{return EventModerationScoreChanged}
func (e ModerationScoreChangedV1) moderationValidate()error{return validateOptionalText(e.ReasonDigest)}
func (e ModerationScoreChangedV1) moderationApply(s *ModerationState)error{if s.Version==0||s.Deleted{return ErrInvalidState};s.Score=e.Score;s.ReasonDigest=e.ReasonDigest;return nil}

type ModerationRankChangedV1 struct { Rank int `json:"rank"` }
func NewModerationRankChangedV1(rank int) ModerationRankChangedV1{return ModerationRankChangedV1{rank}}
func (ModerationRankChangedV1) EventType() EventType{return EventModerationRankChanged}
func (e ModerationRankChangedV1) moderationValidate()error{if e.Rank < -30 || e.Rank > 30{return ErrInvalidState};return nil}
func (e ModerationRankChangedV1) moderationApply(s *ModerationState)error{if s.Version==0||s.Deleted{return ErrInvalidState};s.Rank=e.Rank;return nil}

type ModerationDeletedV1 struct{}
func NewModerationDeletedV1() ModerationDeletedV1{return ModerationDeletedV1{}}
func (ModerationDeletedV1) EventType() EventType{return EventModerationDeleted}
func (ModerationDeletedV1) moderationValidate()error{return nil}
func (ModerationDeletedV1) moderationApply(s *ModerationState)error{if s.Version==0{return ErrInvalidState};s.Deleted=true;return nil}

func validateText(value string) error { if strings.TrimSpace(value)=="" || len(value)>eventstore.MaxEventPayloadBytes{return ErrInvalidState}; return nil }
func validateOptionalText(value string) error { if value!="" { return validateText(value) }; return nil }
func validateIdentity(parts ...string) error { for _,part:=range parts {if strings.TrimSpace(part)==""||len(part)>255{return ErrInvalidIdentity}};if len(canonical(parts...))>255{return ErrInvalidIdentity};return nil }
func marshalTyped(event any, typ EventType, validate func() error) ([]byte,error) { if event==nil{return nil,ErrInvalidEvent};if err:=validate();err!=nil{return nil,err};payload,err:=json.Marshal(event);if err!=nil{return nil,err};if len(payload)>eventstore.MaxEventPayloadBytes{return nil,&eventstore.OversizeError{Bound:"playerstate event payload",Limit:eventstore.MaxEventPayloadBytes,Actual:len(payload)}};return payload,nil }
func marshalArray(events any) ([]byte,error) { payload,err:=json.Marshal(events);if err!=nil{return nil,err};if len(payload)>eventstore.MaxEventPayloadBytes{return nil,&eventstore.OversizeError{Bound:"playerstate event payload",Limit:eventstore.MaxEventPayloadBytes,Actual:len(payload)}};return payload,nil }
func MarshalPlayerEvent(event PlayerEvent)([]byte,error){switch e:=event.(type){case PlayerCreatedV1:return marshalTyped(e,e.EventType(),e.playerValidate);case PlayerNameChangedV1:return marshalTyped(e,e.EventType(),e.playerValidate);case PlayerPrivilegeChangedV1:return marshalTyped(e,e.EventType(),e.playerValidate);case PlayerAutoSetNameTemplateChangedV1:return marshalTyped(e,e.EventType(),e.playerValidate);case PlayerLastCommandChangedV1:return marshalTyped(e,e.EventType(),e.playerValidate);case PlayerDeletedV1:return marshalTyped(e,e.EventType(),e.playerValidate);default:return nil,ErrInvalidEvent}}
func MarshalPlayerEvents(events []PlayerEvent)([]byte,error){for _,e:=range events{if _,err:=MarshalPlayerEvent(e);err!=nil{return nil,err}};return marshalArray(events)}
func MarshalGroupUserAttrsEvent(event GroupUserAttrsEvent)([]byte,error){switch e:=event.(type){case GroupUserAttrsCreatedV1:return marshalTyped(e,e.EventType(),e.attrsValidate);case GroupUserAttrsBindingChangedV1:return marshalTyped(e,e.EventType(),e.attrsValidate);case GroupUserAttrsSetV1:return marshalTyped(e,e.EventType(),e.attrsValidate);case GroupUserAttrsIncrementedV1:return marshalTyped(e,e.EventType(),e.attrsValidate);case GroupUserAttrsDeletedV1:return marshalTyped(e,e.EventType(),e.attrsValidate);case GroupUserAttrsClearedV1:return marshalTyped(e,e.EventType(),e.attrsValidate);default:return nil,ErrInvalidEvent}}
func MarshalGroupUserAttrsEvents(events []GroupUserAttrsEvent)([]byte,error){for _,e:=range events{if _,err:=MarshalGroupUserAttrsEvent(e);err!=nil{return nil,err}};return marshalArray(events)}
func MarshalCharacterEvent(event CharacterEvent)([]byte,error){switch e:=event.(type){case CharacterCreatedV1:return marshalTyped(e,e.EventType(),e.characterValidate);case CharacterRenamedV1:return marshalTyped(e,e.EventType(),e.characterValidate);case CharacterSheetReplacedV1:return marshalTyped(e,e.EventType(),e.characterValidate);case CharacterDeletedV1:return marshalTyped(e,e.EventType(),e.characterValidate);default:return nil,ErrInvalidEvent}}
func MarshalCharacterEvents(events []CharacterEvent)([]byte,error){for _,e:=range events{if _,err:=MarshalCharacterEvent(e);err!=nil{return nil,err}};return marshalArray(events)}
func MarshalModerationEvent(event ModerationEvent)([]byte,error){switch e:=event.(type){case ModerationCreatedV1:return marshalTyped(e,e.EventType(),e.moderationValidate);case ModerationScoreChangedV1:return marshalTyped(e,e.EventType(),e.moderationValidate);case ModerationRankChangedV1:return marshalTyped(e,e.EventType(),e.moderationValidate);case ModerationDeletedV1:return marshalTyped(e,e.EventType(),e.moderationValidate);default:return nil,ErrInvalidEvent}}
func MarshalModerationEvents(events []ModerationEvent)([]byte,error){for _,e:=range events{if _,err:=MarshalModerationEvent(e);err!=nil{return nil,err}};return marshalArray(events)}

func decodeObject(payload []byte, out any) error { var value any; if err:=json.Unmarshal(payload,&value);err!=nil{return ErrInvalidEvent}; if _,ok:=value.(map[string]any);!ok||containsNull(value){return ErrInvalidEvent}; decoder:=json.NewDecoder(bytes.NewReader(payload));decoder.DisallowUnknownFields();if err:=decoder.Decode(out);err!=nil{return ErrInvalidEvent};if err:=decoder.Decode(&struct{}{});err!=io.EOF{return ErrInvalidEvent};return nil }
func containsNull(value any)bool{switch v:=value.(type){case nil:return true;case map[string]any:for _,x:=range v{if containsNull(x){return true}};case []any:for _,x:=range v{if containsNull(x){return true}}};return false}
func DecodePlayerEvent(typ EventType,payload []byte)(PlayerEvent,error){switch typ{case EventPlayerCreated:var e PlayerCreatedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.playerValidate();case EventPlayerNameChanged:var e PlayerNameChangedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.playerValidate();case EventPlayerPrivilegeChanged:var e PlayerPrivilegeChangedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.playerValidate();case EventPlayerTemplateChanged:var e PlayerAutoSetNameTemplateChangedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.playerValidate();case EventPlayerLastCommandChanged:var e PlayerLastCommandChangedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.playerValidate();case EventPlayerDeleted:var e PlayerDeletedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.playerValidate();default:return nil,ErrInvalidEvent}}
func DecodeGroupUserAttrsEvent(typ EventType,payload []byte)(GroupUserAttrsEvent,error){switch typ{case EventGroupUserAttrsCreated:var e GroupUserAttrsCreatedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.attrsValidate();case EventGroupUserAttrsBindingChanged:var e GroupUserAttrsBindingChangedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.attrsValidate();case EventGroupUserAttrsSet:var e GroupUserAttrsSetV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.attrsValidate();case EventGroupUserAttrsIncremented:var e GroupUserAttrsIncrementedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.attrsValidate();case EventGroupUserAttrsDeleted:var e GroupUserAttrsDeletedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.attrsValidate();case EventGroupUserAttrsCleared:var e GroupUserAttrsClearedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.attrsValidate();default:return nil,ErrInvalidEvent}}
func DecodeCharacterEvent(typ EventType,payload []byte)(CharacterEvent,error){switch typ{case EventCharacterCreated:var e CharacterCreatedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.characterValidate();case EventCharacterRenamed:var e CharacterRenamedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.characterValidate();case EventCharacterSheetReplaced:var e CharacterSheetReplacedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.characterValidate();case EventCharacterDeleted:var e CharacterDeletedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.characterValidate();default:return nil,ErrInvalidEvent}}
func DecodeModerationEvent(typ EventType,payload []byte)(ModerationEvent,error){switch typ{case EventModerationCreated:var e ModerationCreatedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.moderationValidate();case EventModerationScoreChanged:var e ModerationScoreChangedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.moderationValidate();case EventModerationRankChanged:var e ModerationRankChangedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.moderationValidate();case EventModerationDeleted:var e ModerationDeletedV1;if err:=decodeObject(payload,&e);err!=nil{return nil,err};return e,e.moderationValidate();default:return nil,ErrInvalidEvent}}

func NewEvent(event any, metadata eventstore.Metadata)(eventstore.NewEvent,error){if metadata.EventID==""||metadata.CommandID==""||metadata.CorrelationID==""||(metadata.OccurredAt.IsZero()&&metadata.OccurredAtUnixNanoUTC==0&&!metadata.OccurredAtUnixNanoSet){return eventstore.NewEvent{},eventstore.ErrInvalidMetadata};if !metadata.OccurredAt.IsZero()&&(metadata.OccurredAtUnixNanoSet||metadata.OccurredAtUnixNanoUTC!=0)&&metadata.OccurredAt.UTC().UnixNano()!=metadata.OccurredAtUnixNanoUTC{return eventstore.NewEvent{},eventstore.ErrInvalidMetadata};var typ EventType;var payload []byte;var err error;switch e:=event.(type){case PlayerEvent:typ=e.EventType();payload,err=MarshalPlayerEvent(e);case GroupUserAttrsEvent:typ=e.EventType();payload,err=MarshalGroupUserAttrsEvent(e);case CharacterEvent:typ=e.EventType();payload,err=MarshalCharacterEvent(e);case ModerationEvent:typ=e.EventType();payload,err=MarshalModerationEvent(e);default:return eventstore.NewEvent{},ErrInvalidEvent};if err!=nil{return eventstore.NewEvent{},err};return eventstore.NewEvent{EventType:string(typ),SchemaVersion:EventSchemaVersion,Payload:payload,Metadata:metadata},nil}
func NewEventWithFactory(factory eventstore.EventFactory, event any, metadata eventstore.Metadata) (eventstore.NewEvent, error) {
	var typ EventType
	var payload []byte
	var err error
	switch value := event.(type) {
	case PlayerEvent:
		typ = value.EventType(); payload, err = MarshalPlayerEvent(value)
	case GroupUserAttrsEvent:
		typ = value.EventType(); payload, err = MarshalGroupUserAttrsEvent(value)
	case CharacterEvent:
		typ = value.EventType(); payload, err = MarshalCharacterEvent(value)
	case ModerationEvent:
		typ = value.EventType(); payload, err = MarshalModerationEvent(value)
	default:
		return eventstore.NewEvent{}, ErrInvalidEvent
	}
	if err != nil { return eventstore.NewEvent{}, err }
	return factory.NewEvent(string(typ), EventSchemaVersion, payload, metadata)
}

