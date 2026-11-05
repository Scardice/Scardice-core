package groupstate

import (
	"errors"
	"slices"
)

type CommandKind string

const (
	CommandCreate            CommandKind = "create"
	CommandActivation        CommandKind = "activation"
	CommandIdentity          CommandKind = "identity"
	CommandInvitation        CommandKind = "invitation"
	CommandName              CommandKind = "name"
	CommandExtension         CommandKind = "extension"
	CommandExtensionPriority CommandKind = "extension_priority"
	CommandSystem            CommandKind = "system"
	CommandTemplate          CommandKind = "template"
	CommandHelp              CommandKind = "help"
	CommandWelcome           CommandKind = "welcome"
	CommandBotList           CommandKind = "bot_list"
	CommandPrivilege         CommandKind = "privilege"
	CommandTeam              CommandKind = "team"
	CommandDelete            CommandKind = "delete"
)

type Command struct {
	Kind                CommandKind
	DiceID              string
	GroupID             string
	GroupName           string
	InviteUserID        string
	EnteredAt           int64
	InviteUserIDSet     bool
	EnteredAtSet        bool
	GuildID             string
	ChannelID           string
	GuildIDSet          bool
	ChannelIDSet        bool
	DiceIDForActivation string
	Active              bool
	Exists              bool
	ActiveSet           bool
	ExistsSet           bool
	ExtensionID         string
	ExtensionIDs        []string
	Enabled             bool
	System              string
	DiceSideNum         int64
	DiceSideExpr        string
	RollShaperMode      string
	CocRuleIndex        int
	DiceSideNumSet      bool
	DiceSideExprSet     bool
	RollShaperModeSet   bool
	CocRuleIndexSet     bool

	DefaultHelpGroup    string
	HelpPackages        []string
	DefaultHelpGroupSet bool
	HelpPackagesSet     bool
	WelcomeEnabled      bool
	WelcomeMessage      string
	WelcomeEnabledSet   bool
	WelcomeMessageSet   bool
	UserID              string
	Level               int
	TeamName            string
	TeamMembers         []string
	TeamDelete          bool
	ExpectedVersion     uint64
	ExpectedVersionSet  bool
}

type Decision struct {
	Events []TypedEvent
	Replay bool
}

var ErrInvalidCommand = errors.New("groupstate: invalid command")
var ErrStaleVersion = errors.New("groupstate: stale expected version")

func Decide(state State, command Command) (Decision, error) {
	if command.ExpectedVersionSet && command.ExpectedVersion != state.Version {
		return Decision{}, ErrStaleVersion
	}
	kind := command.Kind
	if kind == CommandCreate {
		if ValidateIdentity(command.DiceID, command.GroupID) != nil ||
			!validOptionalScopedIdentifier(command.InviteUserID) {
			return Decision{}, ErrInvalidCommand
		}
		if state.Version != 0 {
			if !state.Deleted && state.DiceID == command.DiceID && state.GroupID == command.GroupID {
				return Decision{}, nil
			}
			return Decision{}, ErrInvalidState
		}
		return Decision{Events: []TypedEvent{NewGroupCreatedWithInviteV1(command.DiceID, command.GroupID, command.GroupName, command.InviteUserID, command.EnteredAt)}}, nil
	}
	if state.Version == 0 {
		return Decision{}, ErrInvalidState
	}
	if state.Deleted {
		if kind == CommandDelete {
			return Decision{}, nil
		}
		return Decision{}, ErrInvalidState
	}
	switch kind {
	case CommandIdentity:
		guildID, channelID := command.GuildID, command.ChannelID
		if command.GuildIDSet || command.ChannelIDSet {
			if !command.GuildIDSet {
				guildID = state.GuildID
			}
			if !command.ChannelIDSet {
				channelID = state.ChannelID
			}
		}
		if !validOptionalScopedIdentifier(guildID) || !validOptionalScopedIdentifier(channelID) {
			return Decision{}, ErrInvalidCommand
		}
		if state.GuildID == guildID && state.ChannelID == channelID {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupIdentityChangedV1(guildID, channelID)}}, nil
	case CommandInvitation:
		inviteUserID, enteredAt := command.InviteUserID, command.EnteredAt
		if command.InviteUserIDSet || command.EnteredAtSet {
			if !command.InviteUserIDSet {
				inviteUserID = state.InviteUserID
			}
			if !command.EnteredAtSet {
				enteredAt = state.EnteredAt
			}
		}
		if !validOptionalScopedIdentifier(inviteUserID) {
			return Decision{}, ErrInvalidCommand
		}
		if state.InviteUserID == inviteUserID && state.EnteredAt == enteredAt {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupInvitationChangedV1(inviteUserID, enteredAt)}}, nil
	case CommandActivation:
		if command.DiceIDForActivation == "" {
			command.DiceIDForActivation = command.DiceID
		}
		if !validScopedIdentifier(command.DiceIDForActivation) {
			return Decision{}, ErrInvalidCommand
		}
		active, exists := command.Active, command.Exists
		if command.ActiveSet || command.ExistsSet {
			if !command.ActiveSet {
				active = state.DiceIDActive[command.DiceIDForActivation]
			}
			if !command.ExistsSet {
				exists = state.DiceIDExists[command.DiceIDForActivation]
			}
		}
		if state.DiceIDActive[command.DiceIDForActivation] == active &&
			state.DiceIDExists[command.DiceIDForActivation] == exists {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupActivationChangedV1(command.DiceIDForActivation, active, exists)}}, nil
	case CommandName:
		if state.GroupName == command.GroupName {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupNameChangedV1(command.GroupName)}}, nil
	case CommandExtension:
		if !validScopedIdentifier(command.ExtensionID) {
			return Decision{}, ErrInvalidCommand
		}
		active := slices.Contains(state.ActivatedExtensions, command.ExtensionID)
		inactivated := state.InactivatedExtensions[command.ExtensionID]
		if (command.Enabled && active && !inactivated) || (!command.Enabled && !active && inactivated) {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupExtensionChangedV1(command.ExtensionID, command.Enabled)}}, nil
	case CommandExtensionPriority:
		if len(command.ExtensionIDs) == 0 {
			return Decision{}, ErrInvalidCommand
		}
		seen := make(map[string]struct{}, len(state.ActivatedExtensions))
		ordered := make([]string, 0, len(state.ActivatedExtensions))
		for _, extensionID := range command.ExtensionIDs {
			if !validScopedIdentifier(extensionID) {
				return Decision{}, ErrInvalidCommand
			}
			if _, duplicate := seen[extensionID]; duplicate ||
				!slices.Contains(state.ActivatedExtensions, extensionID) {
				return Decision{}, ErrInvalidCommand
			}
			seen[extensionID] = struct{}{}
			ordered = append(ordered, extensionID)
		}
		for _, extensionID := range state.ActivatedExtensions {
			if _, promoted := seen[extensionID]; !promoted {
				ordered = append(ordered, extensionID)
			}
		}
		if slices.Equal(state.ActivatedExtensions, ordered) {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupExtensionPriorityChangedV1(ordered)}}, nil
	case CommandSystem:
		if state.System == command.System {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupSystemChangedV1(command.System)}}, nil
	case CommandTemplate:
		num, expr := command.DiceSideNum, command.DiceSideExpr
		mode, cocRuleIndex := command.RollShaperMode, command.CocRuleIndex
		if command.DiceSideNumSet || command.DiceSideExprSet || command.RollShaperModeSet || command.CocRuleIndexSet {
			if !command.DiceSideNumSet {
				num = state.DiceSideNum
			}
			if !command.DiceSideExprSet {
				expr = state.DiceSideExpr
			}
			if !command.RollShaperModeSet {
				mode = state.RollShaperMode
			}
			if !command.CocRuleIndexSet {
				cocRuleIndex = state.CocRuleIndex
			}
		}
		if state.DiceSideNum == num && state.DiceSideExpr == expr &&
			state.RollShaperMode == mode && state.CocRuleIndex == cocRuleIndex {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupTemplateWithCocRuleV1(num, expr, mode, cocRuleIndex)}}, nil
	case CommandHelp:
		defaultGroup, packages := command.DefaultHelpGroup, command.HelpPackages
		if command.DefaultHelpGroupSet || command.HelpPackagesSet {
			if !command.DefaultHelpGroupSet {
				defaultGroup = state.DefaultHelpGroup
			}
			if !command.HelpPackagesSet {
				packages = state.HelpPackages
			}
		}
		if !validOptionalScopedIdentifier(defaultGroup) {
			return Decision{}, ErrInvalidCommand
		}
		for _, item := range packages {
			if !validOptionalScopedIdentifier(item) {
				return Decision{}, ErrInvalidCommand
			}
		}
		if state.DefaultHelpGroup == defaultGroup && slices.Equal(state.HelpPackages, packages) {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupHelpChangedV1(defaultGroup, packages)}}, nil
	case CommandWelcome:
		enabled, message := command.WelcomeEnabled, command.WelcomeMessage
		if command.WelcomeEnabledSet || command.WelcomeMessageSet {
			if !command.WelcomeEnabledSet {
				enabled = state.ShowGroupWelcome
			}
			if !command.WelcomeMessageSet {
				message = state.GroupWelcomeMessage
			}
		}
		if state.ShowGroupWelcome == enabled && state.GroupWelcomeMessage == message {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupWelcomeChangedV1(enabled, message)}}, nil
	case CommandBotList:
		if !validScopedIdentifier(command.UserID) {
			return Decision{}, ErrInvalidCommand
		}
		if state.BotList[command.UserID] == command.Enabled {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupBotListChangedV1(command.UserID, command.Enabled)}}, nil
	case CommandPrivilege:
		if !validScopedIdentifier(command.UserID) || command.Level < -30 || command.Level > 100 {
			return Decision{}, ErrInvalidCommand
		}
		if level, ok := state.Privileges[command.UserID]; ok && level == command.Level {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupPrivilegeChangedV1(command.UserID, command.Level)}}, nil
	case CommandTeam:
		if !validScopedIdentifier(command.TeamName) {
			return Decision{}, ErrInvalidCommand
		}
		for _, userID := range command.TeamMembers {
			if !validScopedIdentifier(userID) {
				return Decision{}, ErrInvalidCommand
			}
		}
		members, exists := state.PlayerGroups[command.TeamName]
		if (command.TeamDelete && !exists) ||
			(!command.TeamDelete && exists && slices.Equal(members, command.TeamMembers)) {
			return Decision{}, nil
		}
		return Decision{Events: []TypedEvent{NewGroupTeamChangedV1(command.TeamName, command.TeamMembers, command.TeamDelete)}}, nil
	case CommandDelete:
		return Decision{Events: []TypedEvent{NewGroupRecordDeletedV1()}}, nil
	default:
		return Decision{}, ErrInvalidCommand
	}
}
