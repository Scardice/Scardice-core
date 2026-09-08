package playerstate

import "errors"

type PlayerCommandKind string
const (
	CommandPlayerCreate PlayerCommandKind = "create"
	CommandPlayerName PlayerCommandKind = "name"
	CommandPlayerPrivilege PlayerCommandKind = "privilege"
	CommandPlayerTemplate PlayerCommandKind = "template"
	CommandPlayerLastCommand PlayerCommandKind = "last_command"
	CommandPlayerDelete PlayerCommandKind = "delete"
)
type PlayerCommand struct { Kind PlayerCommandKind; DiceID string; GroupID string; UserID string; Name string; Privilege int; Template string; LastCommandAt int64; ExpectedVersion uint64; ExpectedVersionSet bool }
type Decision struct { Events []PlayerEvent }
var ErrInvalidCommand = errors.New("playerstate: invalid command")
var ErrStaleVersion = errors.New("playerstate: stale expected version")
func DecidePlayer(state PlayerState, command PlayerCommand) (Decision,error) {
	if command.ExpectedVersionSet && command.ExpectedVersion != state.Version{return Decision{},ErrStaleVersion}
	kind:=command.Kind
	switch kind {
	case CommandPlayerCreate:
		if state.Version!=0{return Decision{},ErrInvalidCommand}; if err:=validateIdentity(command.DiceID,command.GroupID,command.UserID);err!=nil{return Decision{},err}; return Decision{[]PlayerEvent{NewPlayerCreatedV1(command.DiceID,command.GroupID,command.UserID,command.Name)}},nil
	case CommandPlayerName:
		return Decision{[]PlayerEvent{NewPlayerNameChangedV1(command.Name)}},nil
	case CommandPlayerPrivilege:
		return Decision{[]PlayerEvent{NewPlayerPrivilegeChangedV1(command.Privilege)}},nil
	case CommandPlayerTemplate:
		return Decision{[]PlayerEvent{NewPlayerAutoSetNameTemplateChangedV1(command.Template)}},nil
	case CommandPlayerLastCommand:
		return Decision{[]PlayerEvent{NewPlayerLastCommandChangedV1(command.LastCommandAt)}},nil
	case CommandPlayerDelete:
		return Decision{[]PlayerEvent{NewPlayerDeletedV1()}},nil
	default:return Decision{},ErrInvalidCommand
	}
}

type LocalOverlay struct{ values map[string]string }
func NewLocalOverlay() *LocalOverlay{return &LocalOverlay{values:map[string]string{}}}
func (o *LocalOverlay) Set(name,value string){if o==nil{return};if o.values==nil{o.values=map[string]string{}};if len(name)<2||name[:2]!="$t"{return};o.values[name]=value}
func (o *LocalOverlay) Get(name string)(string,bool){if o==nil||len(name)<2||name[:2]!="$t"{return "",false};v,ok:=o.values[name];return v,ok}
func (o *LocalOverlay) Snapshot()map[string]string{out:=map[string]string{};if o!=nil{for k,v:=range o.values{out[k]=v}};return out}
