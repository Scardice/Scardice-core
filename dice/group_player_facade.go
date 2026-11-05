package dice

import (
	"context"
	"errors"
	"strings"
	"sync"

	"Scardice-core/core/execution"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"

	ds "github.com/sealdice/dicescript"
)

var ErrDomainTxUnavailable = errors.New("dice: domain transaction unavailable")
var ErrGroupHandleUnavailable = errors.New("dice: group handle unavailable")
var ErrPlayerHandleUnavailable = errors.New("dice: player handle unavailable")
var ErrGroupRuntimeRevoked = errors.New("dice: group runtime revoked")

// GroupInfo is a request-local capability over one canonical group handle.
// Runtime resources are registry-owned and contain no durable group facts.
type GroupInfo struct {
	handle      *execution.GroupHandle
	runtime     *GroupRuntimeResources
	transaction *DurableCallbackTransaction

	extensionCacheMu              sync.Mutex
	activatedExtensions           []*ExtInfo
	activatedExtensionIDs         []string
	extensionCacheStateVersion    uint64
	extensionCacheRegistryVersion int64

	rollShaperCacheMu sync.Mutex
	localRollShaper   *diceRollShaper
}

func newGroupInfo(
	handle *execution.GroupHandle,
	runtime *GroupRuntimeResources,
	transaction *DurableCallbackTransaction,
) (*GroupInfo, error) {
	if handle == nil {
		return nil, ErrGroupHandleUnavailable
	}
	if runtime == nil {
		return nil, errors.New("dice: group runtime resources unavailable")
	}
	if transaction == nil {
		return nil, ErrDomainTxUnavailable
	}
	return &GroupInfo{handle: handle, runtime: runtime, transaction: transaction}, nil
}

func (g *GroupInfo) Version() uint64 {
	if g == nil || g.handle == nil {
		return 0
	}
	return g.handle.Version()
}
func (g *GroupInfo) DiceID() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.DiceID()
}
func (g *GroupInfo) GroupID() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.GroupID()
}
func (g *GroupInfo) GroupName() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.GroupName()
}
func (g *GroupInfo) InviteUserID() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.InviteUserID()
}
func (g *GroupInfo) GuildID() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.GuildID()
}
func (g *GroupInfo) ChannelID() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.ChannelID()
}
func (g *GroupInfo) Active() bool { return g != nil && g.handle != nil && g.handle.Active() }
func (g *GroupInfo) DiceIDActive(id string) bool {
	return g != nil && g.handle != nil && g.handle.DiceIDActive(id)
}
func (g *GroupInfo) DiceIDExists(id string) bool {
	return g != nil && g.handle != nil && g.handle.DiceIDExists(id)
}
func (g *GroupInfo) System() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.System()
}
func (g *GroupInfo) DiceSideNum() int64 {
	if g == nil || g.handle == nil {
		return 0
	}
	return g.handle.DiceSideNum()
}
func (g *GroupInfo) DiceSideExpr() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.DiceSideExpr()
}
func (g *GroupInfo) RollShaperMode() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.RollShaperMode()
}
func (g *GroupInfo) CocRuleIndex() int {
	if g == nil || g.handle == nil {
		return 0
	}
	return g.handle.CocRuleIndex()
}
func (g *GroupInfo) DefaultHelpGroup() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.DefaultHelpGroup()
}
func (g *GroupInfo) ShowGroupWelcome() bool {
	return g != nil && g.handle != nil && g.handle.ShowGroupWelcome()
}
func (g *GroupInfo) GroupWelcomeMessage() string {
	if g == nil || g.handle == nil {
		return ""
	}
	return g.handle.GroupWelcomeMessage()
}
func (g *GroupInfo) EnteredAt() int64 {
	if g == nil || g.handle == nil {
		return 0
	}
	return g.handle.EnteredAt()
}
func (g *GroupInfo) Deleted() bool { return g != nil && g.handle != nil && g.handle.Deleted() }
func (g *GroupInfo) ExtensionActive(id string) bool {
	return g != nil && g.handle != nil && g.handle.ExtensionActive(id)
}
func (g *GroupInfo) ExtensionInactivated(id string) bool {
	return g != nil && g.handle != nil && g.handle.ExtensionInactivated(id)
}
func (g *GroupInfo) BotExists(id string) bool {
	return g != nil && g.handle != nil && g.handle.BotExists(id)
}
func (g *GroupInfo) Privilege(id string) (int, bool) {
	if g == nil || g.handle == nil {
		return 0, false
	}
	return g.handle.Privilege(id)
}
func (g *GroupInfo) ActivatedExtensionIDs() []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.ActivatedExtensionIDs()
}
func (g *GroupInfo) InactivatedExtensionIDs() []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.InactivatedExtensionIDs()
}
func (g *GroupInfo) HelpPackageIDs() []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.HelpPackageIDs()
}
func (g *GroupInfo) ActiveDiceIDs() []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.ActiveDiceIDs()
}
func (g *GroupInfo) ExistingDiceIDs() []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.ExistingDiceIDs()
}
func (g *GroupInfo) BotIDs() []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.BotIDs()
}
func (g *GroupInfo) TeamNames() []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.TeamNames()
}
func (g *GroupInfo) TeamMembers(name string) []string {
	if g == nil || g.handle == nil {
		return nil
	}
	return g.handle.TeamMembers(name)
}

func (g *GroupInfo) requireRuntimeAuthority() error {
	if g == nil || g.handle == nil {
		return ErrGroupHandleUnavailable
	}
	if g.runtime == nil || g.runtime.revoked.Load() {
		return ErrGroupRuntimeRevoked
	}
	return nil
}

func (g *GroupInfo) decide(command groupstate.Command) error {
	if err := g.requireRuntimeAuthority(); err != nil {
		return err
	}
	return g.handle.Decide(command)
}
func (g *GroupInfo) create(diceID, groupID, groupName, inviteUserID string, enteredAt int64) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandCreate, DiceID: diceID, GroupID: groupID,
		GroupName: groupName, InviteUserID: inviteUserID, EnteredAt: enteredAt,
	})
}

func (g *GroupInfo) SetActivation(diceID string, active, exists bool) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandActivation, DiceIDForActivation: diceID,
		Active: active, Exists: exists,
	})
}
func (g *GroupInfo) SetDiceActive(diceID string, active bool) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandActivation, DiceIDForActivation: diceID,
		Active: active, ActiveSet: true,
	})
}
func (g *GroupInfo) SetDiceExists(diceID string, exists bool) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandActivation, DiceIDForActivation: diceID,
		Exists: exists, ExistsSet: true,
	})
}
func (g *GroupInfo) SetIdentity(guildID, channelID string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandIdentity, GuildID: guildID, ChannelID: channelID})
}
func (g *GroupInfo) SetGuildID(value string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandIdentity, GuildID: value, GuildIDSet: true})
}
func (g *GroupInfo) SetChannelID(value string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandIdentity, ChannelID: value, ChannelIDSet: true})
}
func (g *GroupInfo) SetGroupName(name string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandName, GroupName: name})
}
func (g *GroupInfo) SetInvitation(inviteUserID string, enteredAt int64) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandInvitation, InviteUserID: inviteUserID, EnteredAt: enteredAt})
}
func (g *GroupInfo) SetInviteUserID(value string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandInvitation, InviteUserID: value, InviteUserIDSet: true})
}
func (g *GroupInfo) SetEnteredAt(value int64) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandInvitation, EnteredAt: value, EnteredAtSet: true})
}
func (g *GroupInfo) SetExtension(id string, enabled bool) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandExtension, ExtensionID: id, Enabled: enabled})
}
func (g *GroupInfo) promoteExtensions(extensionIDs []string) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandExtensionPriority, ExtensionIDs: extensionIDs,
	})
}
func (g *GroupInfo) SetSystem(system string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandSystem, System: system})
}
func (g *GroupInfo) SetDiceSideNum(value int64) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandTemplate, DiceSideNum: value, DiceSideNumSet: true})
}
func (g *GroupInfo) SetDiceSideExpr(value string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandTemplate, DiceSideExpr: value, DiceSideExprSet: true})
}
func (g *GroupInfo) SetRollShaperMode(value string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandTemplate, RollShaperMode: value, RollShaperModeSet: true})
}
func (g *GroupInfo) SetCocRuleIndex(value int) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandTemplate, CocRuleIndex: value, CocRuleIndexSet: true})
}
func (g *GroupInfo) SetHelp(defaultGroup string, packages []string) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandHelp, DefaultHelpGroup: defaultGroup,
		HelpPackages: packages,
	})
}
func (g *GroupInfo) SetDefaultHelpGroup(value string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandHelp, DefaultHelpGroup: value, DefaultHelpGroupSet: true})
}
func (g *GroupInfo) SetHelpPackageIDs(value []string) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandHelp, HelpPackages: value, HelpPackagesSet: true,
	})
}
func (g *GroupInfo) SetWelcome(enabled bool, message string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandWelcome, WelcomeEnabled: enabled, WelcomeMessage: message})
}
func (g *GroupInfo) SetShowGroupWelcome(value bool) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandWelcome, WelcomeEnabled: value, WelcomeEnabledSet: true})
}
func (g *GroupInfo) SetGroupWelcomeMessage(value string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandWelcome, WelcomeMessage: value, WelcomeMessageSet: true})
}
func (g *GroupInfo) SetBot(userID string, enabled bool) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandBotList, UserID: userID, Enabled: enabled})
}
func (g *GroupInfo) SetPrivilege(userID string, level int) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandPrivilege, UserID: userID, Level: level})
}
func (g *GroupInfo) SetTeam(name string, members []string) error {
	return g.decide(groupstate.Command{
		Kind: groupstate.CommandTeam, TeamName: name,
		TeamMembers: members,
	})
}
func (g *GroupInfo) DeleteTeam(name string) error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandTeam, TeamName: name, TeamDelete: true})
}
func (g *GroupInfo) Delete() error {
	return g.decide(groupstate.Command{Kind: groupstate.CommandDelete})
}

func (g *GroupInfo) RecentDiceSendTime() int64 {
	if g == nil || g.requireRuntimeAuthority() != nil {
		return 0
	}
	return g.runtime.recentDiceSendTime.Load()
}
func (g *GroupInfo) SetRecentDiceSendTime(value int64) {
	if g != nil && g.requireRuntimeAuthority() == nil {
		g.runtime.recentDiceSendTime.Store(value)
	}
}

// CheckCustomReplyCooldown atomically checks and, when allowed, advances the
// process-local custom-reply clock shared by every facade for this group.
func (g *GroupInfo) CheckCustomReplyCooldown(now, interval float64) bool {
	if g == nil || g.runtime == nil || g.runtime.revoked.Load() {
		return true
	}
	g.runtime.customReplyMu.Lock()
	defer g.runtime.customReplyMu.Unlock()
	if now-g.runtime.lastCustomReplyTime < interval {
		return true
	}
	g.runtime.lastCustomReplyTime = now
	return false
}

type GroupLogState struct {
	ID          uint64
	Name        string
	On          bool
	BaselineSeq int64
}

func (g *GroupInfo) GetLogState() (GroupLogState, error) {
	if err := g.requireRuntimeAuthority(); err != nil {
		return GroupLogState{}, err
	}
	if g.transaction == nil {
		return GroupLogState{}, ErrDomainTxUnavailable
	}
	readCtx := g.transaction.executionContext
	if readCtx == nil {
		readCtx = context.Background()
	}
	state, err := g.transaction.ReadStoryLogState(readCtx, g.DiceID(), g.GroupID())
	if err != nil {
		return GroupLogState{}, err
	}
	return GroupLogState{
		ID: state.SessionID, Name: state.Name, On: state.On, BaselineSeq: state.BaselineSeq,
	}, nil
}

func (g *GroupInfo) logSequenceRuntime() *groupLogRuntime {
	if g == nil || g.requireRuntimeAuthority() != nil {
		return nil
	}
	return g.runtime.logSequence
}

func (g *GroupInfo) noteLogSelfSent() {
	state := g.logSequenceRuntime()
	if state == nil {
		return
	}
	state.mu.Lock()
	state.selfSent++
	state.mu.Unlock()
}

func (g *GroupInfo) IsActive(ctx *MsgContext) bool {
	if g == nil || g.requireRuntimeAuthority() != nil {
		return false
	}
	if strings.HasPrefix(g.GroupID(), "UI-Group:") {
		return true
	}
	return g.Active() && ctx != nil && ctx.EndPoint != nil && g.DiceIDActive(ctx.EndPoint.UserID)
}

func (g *GroupInfo) GetCharTemplate(dice *Dice) *GameSystemTemplate {
	if g == nil || dice == nil {
		return nil
	}
	if system := g.System(); system != "" {
		if value, _ := dice.GameSystemMap.Load(system); value != nil {
			return value
		}
		template := &GameSystemTemplate{GameSystemTemplateV2: &GameSystemTemplateV2{Name: system, FullName: "空白模板"}}
		template.Init()
		return template
	}
	for _, system := range []string{"coc7", "dnd5e"} {
		if g.ExtensionActive(system) {
			value, _ := dice.GameSystemMap.Load(system)
			return value
		}
	}
	template := &GameSystemTemplate{GameSystemTemplateV2: &GameSystemTemplateV2{Name: "default", FullName: "空白模板"}}
	template.Init()
	return template
}

// GroupPlayerInfo is a request-local capability over one canonical player
// handle. Temporary variables are local to this facade; limiter state is
// registry-owned and survives facade reconstruction.
type GroupPlayerInfo struct {
	handle  *execution.PlayerHandle
	runtime *PlayerRuntimeResources
	inGroup bool
	temp    *ds.ValueMap

	// Detached identities exist only for local formatting contexts which have
	// no durable execution root. They never authorize durable commands.
	localDiceID  string
	localGroupID string
	localUserID  string
	localName    string
}

func newGroupPlayerInfo(handle *execution.PlayerHandle, runtime *PlayerRuntimeResources) (*GroupPlayerInfo, error) {
	if handle == nil {
		return nil, ErrPlayerHandleUnavailable
	}
	if runtime == nil {
		return nil, errors.New("dice: player runtime resources unavailable")
	}
	return &GroupPlayerInfo{handle: handle, runtime: runtime, inGroup: true, temp: &ds.ValueMap{}}, nil
}

func newDetachedGroupPlayerInfo(diceID, groupID, userID, name string) *GroupPlayerInfo {
	return &GroupPlayerInfo{
		runtime:      &PlayerRuntimeResources{},
		inGroup:      groupID != "",
		temp:         &ds.ValueMap{},
		localDiceID:  diceID,
		localGroupID: groupID,
		localUserID:  userID,
		localName:    name,
	}
}
func (p *GroupPlayerInfo) Version() uint64 {
	if p == nil || p.handle == nil {
		return 0
	}
	return p.handle.Version()
}
func (p *GroupPlayerInfo) DiceID() string {
	if p == nil {
		return ""
	}
	if p.handle == nil {
		return p.localDiceID
	}
	return p.handle.DiceID()
}
func (p *GroupPlayerInfo) GroupID() string {
	if p == nil {
		return ""
	}
	if p.handle == nil {
		return p.localGroupID
	}
	return p.handle.GroupID()
}
func (p *GroupPlayerInfo) UserID() string {
	if p == nil {
		return ""
	}
	if p.handle == nil {
		return p.localUserID
	}
	return p.handle.UserID()
}
func (p *GroupPlayerInfo) Name() string {
	if p == nil {
		return ""
	}
	if p.handle == nil {
		return p.localName
	}
	return p.handle.Name()
}
func (p *GroupPlayerInfo) Privilege() int {
	if p == nil || p.handle == nil {
		return 0
	}
	return p.handle.Privilege()
}
func (p *GroupPlayerInfo) AutoSetNameTemplate() string {
	if p == nil || p.handle == nil {
		return ""
	}
	return p.handle.AutoSetNameTemplate()
}
func (p *GroupPlayerInfo) LastCommandAt() int64 {
	if p == nil || p.handle == nil {
		return 0
	}
	return p.handle.LastCommandAt()
}
func (p *GroupPlayerInfo) DiceSideNum() int64 {
	if p == nil || p.handle == nil {
		return 0
	}
	return p.handle.DiceSideNum()
}
func (p *GroupPlayerInfo) Deleted() bool { return p != nil && p.handle != nil && p.handle.Deleted() }
func (p *GroupPlayerInfo) InGroup() bool { return p != nil && p.inGroup }
func (p *GroupPlayerInfo) SetInGroup(value bool) {
	if p != nil {
		p.inGroup = value
	}
}
func (p *GroupPlayerInfo) tempValues() *ds.ValueMap {
	if p == nil {
		return nil
	}
	if p.temp == nil {
		p.temp = &ds.ValueMap{}
	}
	return p.temp
}
func (p *GroupPlayerInfo) requireRuntimeAuthority() error {
	if p == nil || p.handle == nil {
		return ErrPlayerHandleUnavailable
	}
	if p.runtime == nil || p.runtime.revoked.Load() {
		return ErrGroupRuntimeRevoked
	}
	return nil
}
func (p *GroupPlayerInfo) decide(command playerstate.PlayerCommand) error {
	if err := p.requireRuntimeAuthority(); err != nil {
		return err
	}
	return p.handle.Decide(command)
}
func (p *GroupPlayerInfo) create(diceID, groupID, userID, name string) error {
	return p.decide(playerstate.PlayerCommand{
		Kind: playerstate.CommandPlayerCreate, DiceID: diceID,
		GroupID: groupID, UserID: userID, Name: name,
	})
}
func (p *GroupPlayerInfo) SetName(value string) error {
	return p.decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerName, Name: value})
}
func (p *GroupPlayerInfo) SetPrivilege(value int) error {
	return p.decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerPrivilege, Privilege: value})
}
func (p *GroupPlayerInfo) SetAutoSetNameTemplate(value string) error {
	return p.decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerTemplate, Template: value})
}
func (p *GroupPlayerInfo) SetLastCommandAt(value int64) error {
	return p.decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerLastCommand, LastCommandAt: value})
}
func (p *GroupPlayerInfo) SetDiceSideNum(value int64) error {
	return p.decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerDiceSide, DiceSideNum: value})
}
func (p *GroupPlayerInfo) Delete() error {
	return p.decide(playerstate.PlayerCommand{Kind: playerstate.CommandPlayerDelete})
}
