package groupstate

import "errors"

type CommandKind string
const (
	CommandCreate CommandKind = "create"
	CommandActivation CommandKind = "activation"
	CommandIdentity CommandKind = "identity"
	CommandName CommandKind = "name"
	CommandExtension CommandKind = "extension"
	CommandSystem CommandKind = "system"
	CommandTemplate CommandKind = "template"
	CommandHelp CommandKind = "help"
	CommandWelcome CommandKind = "welcome"
	CommandBotList CommandKind = "bot_list"
	CommandPrivilege CommandKind = "privilege"
	CommandDelete CommandKind = "delete"
)
const (
	Create = CommandCreate
	Activation = CommandActivation
	Identity = CommandIdentity
	Name = CommandName
	Extension = CommandExtension
	System = CommandSystem
	Help = CommandHelp
	Welcome = CommandWelcome
	BotList = CommandBotList
	Privilege = CommandPrivilege
	Delete = CommandDelete
)

type Command struct {
	Kind CommandKind
	Type CommandKind
	DiceID string
	GroupID string
	GroupName string
	InviteUserID string
	EnteredAt int64
	GuildID string
	ChannelID string
	DiceIDForActivation string
	Active bool
	Exists bool
	ExtensionID string
	Enabled bool
	System string
	DiceSideNum int64
	DiceSideExpr string
	RollShaperMode string
	CocRuleIndex int

	DefaultHelpGroup string
	HelpPackages []string
	WelcomeMessage string
	UserID string
	Level int
	ExpectedVersion uint64
	ExpectedVersionSet bool
}

type Decision struct {
	Events []TypedEvent
	Replay bool
}
type GroupCommand = Command
type GroupDecision = Decision

var ErrInvalidCommand = errors.New("groupstate: invalid command")
var ErrStaleVersion = errors.New("groupstate: stale expected version")

func Decide(state State, command Command) (Decision, error) {
	kind := command.Kind; if kind == "" { kind = command.Type }
	if state.Version > 0 && command.ExpectedVersionSet && command.ExpectedVersion != state.Version { return Decision{}, ErrStaleVersion }
	if kind == CommandCreate {
		if state.Version != 0 { return Decision{}, ErrInvalidState }
		if ValidateIdentity(command.DiceID, command.GroupID) != nil { return Decision{}, ErrInvalidCommand }
		return Decision{Events: []TypedEvent{NewGroupCreatedWithInviteV1(command.DiceID, command.GroupID, command.GroupName, command.InviteUserID, command.EnteredAt)}}, nil
	}
	if state.Version == 0 || state.Deleted { return Decision{}, ErrInvalidState }
	switch kind {
	case CommandIdentity:
		return Decision{Events: []TypedEvent{NewGroupIdentityChangedV1(command.GuildID, command.ChannelID)}}, nil
	case CommandActivation:
		if command.DiceIDForActivation == "" { command.DiceIDForActivation = command.DiceID }
		return Decision{Events: []TypedEvent{NewGroupActivationChangedV1(command.DiceIDForActivation, command.Active, command.Exists)}}, nil
	case CommandName:
		return Decision{Events: []TypedEvent{NewGroupNameChangedV1(command.GroupName)}}, nil
	case CommandExtension:
		return Decision{Events: []TypedEvent{NewGroupExtensionChangedV1(command.ExtensionID, command.Enabled)}}, nil
	case CommandSystem:
		return Decision{Events: []TypedEvent{NewGroupSystemChangedV1(command.System)}}, nil
	case CommandTemplate:
		return Decision{Events: []TypedEvent{NewGroupTemplateWithCocRuleV1(command.DiceSideNum, command.DiceSideExpr, command.RollShaperMode, command.CocRuleIndex)}}, nil
	case CommandHelp:
		return Decision{Events: []TypedEvent{NewGroupHelpChangedV1(command.DefaultHelpGroup, command.HelpPackages)}}, nil
	case CommandWelcome:
		return Decision{Events: []TypedEvent{NewGroupWelcomeChangedV1(command.Active, command.WelcomeMessage)}}, nil
	case CommandBotList:
		return Decision{Events: []TypedEvent{NewGroupBotListChangedV1(command.UserID, command.Enabled)}}, nil
	case CommandPrivilege:
		return Decision{Events: []TypedEvent{NewGroupPrivilegeChangedV1(command.UserID, command.Level)}}, nil
	case CommandDelete:
		return Decision{Events: []TypedEvent{NewGroupRecordDeletedV1()}}, nil
	default:
		return Decision{}, ErrInvalidCommand
	}
}
