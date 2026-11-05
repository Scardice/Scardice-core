package dice

import (
	"context"
	"errors"
	"sync"

	"Scardice-core/core/execution"
)

type invocationFacadeRegistry struct {
	mu      sync.Mutex
	groups  map[groupRuntimeKey]*GroupInfo
	players map[playerRuntimeKey]*GroupPlayerInfo
}

func newInvocationFacadeRegistry() *invocationFacadeRegistry {
	return &invocationFacadeRegistry{
		groups:  make(map[groupRuntimeKey]*GroupInfo),
		players: make(map[playerRuntimeKey]*GroupPlayerInfo),
	}
}

func (s *IMSession) runtimeResources() *GroupPlayerRuntimeRegistry {
	if s == nil {
		return nil
	}
	s.runtimeRegistryMu.Lock()
	defer s.runtimeRegistryMu.Unlock()
	if s.runtimeRegistry == nil {
		s.runtimeRegistry = NewGroupPlayerRuntimeRegistry()
	}
	return s.runtimeRegistry
}

// InvalidateGroupRuntime revokes live process resources for a purged group.
// Subsequent callbacks receive fresh resources if the group is recreated.
func (s *IMSession) InvalidateGroupRuntime(groupID string) {
	if s == nil || s.Parent == nil || groupID == "" {
		return
	}
	s.runtimeResources().DeleteGroup(s.Parent.BaseConfig.Name, groupID)
}
func (s *IMSession) GroupRecentDiceSendTime(groupID string) int64 {
	if s == nil || s.Parent == nil || groupID == "" {
		return 0
	}
	resources := s.runtimeResources().LookupGroup(s.Parent.BaseConfig.Name, groupID)
	if resources == nil || resources.revoked.Load() {
		return 0
	}
	return resources.recentDiceSendTime.Load()
}

func (ctx *MsgContext) facadeResources() *invocationFacadeRegistry {
	if ctx == nil {
		return nil
	}
	ctx.facadeRegistryMu.Lock()
	defer ctx.facadeRegistryMu.Unlock()
	if ctx.facadeRegistry == nil {
		ctx.facadeRegistry = newInvocationFacadeRegistry()
	}
	return ctx.facadeRegistry
}
func (ctx *MsgContext) domainContext() context.Context {
	if ctx != nil {
		if ctx.callbackTransaction != nil && ctx.callbackTransaction.executionContext != nil {
			return ctx.callbackTransaction.executionContext
		}
		if ctx.executionContext != nil {
			return ctx.executionContext
		}
	}
	return context.Background()
}

func (ctx *MsgContext) groupFacade(diceID, groupID string, handle *execution.GroupHandle) (*GroupInfo, error) {
	facades := ctx.facadeResources()
	runtimes := ctx.Session.runtimeResources()
	if facades == nil || runtimes == nil {
		return nil, errors.New("dice: group facade registry unavailable")
	}
	key := groupRuntimeKey{diceID: diceID, groupID: groupID}
	facades.mu.Lock()
	defer facades.mu.Unlock()
	if group := facades.groups[key]; group != nil {
		return group, nil
	}
	group, err := newGroupInfo(handle, runtimes.Group(diceID, groupID), ctx.callbackTransaction)
	if err != nil {
		return nil, err
	}
	facades.groups[key] = group
	return group, nil
}

func (ctx *MsgContext) playerFacade(diceID, groupID, userID string, handle *execution.PlayerHandle) (*GroupPlayerInfo, error) {
	facades := ctx.facadeResources()
	runtimes := ctx.Session.runtimeResources()
	if facades == nil || runtimes == nil {
		return nil, errors.New("dice: player facade registry unavailable")
	}
	key := playerRuntimeKey{diceID: diceID, groupID: groupID, userID: userID}
	facades.mu.Lock()
	defer facades.mu.Unlock()
	if player := facades.players[key]; player != nil {
		return player, nil
	}
	player, err := newGroupPlayerInfo(handle, runtimes.Player(diceID, groupID, userID))
	if err != nil {
		return nil, err
	}
	facades.players[key] = player
	return player, nil
}

func (ctx *MsgContext) ResolveGroup(callCtx context.Context, groupID string) (*GroupInfo, error) {
	if ctx == nil || ctx.Dice == nil || ctx.Session == nil || ctx.callbackTransaction == nil {
		return nil, ErrDomainTxUnavailable
	}
	domain := ctx.callbackTransaction.Domain()
	if domain == nil {
		return nil, ErrDomainTxUnavailable
	}
	diceID := ctx.Dice.BaseConfig.Name
	if diceID == "" || groupID == "" {
		return nil, errors.New("dice: invalid group facade identity")
	}
	handle, err := domain.Group(callCtx, diceID, groupID)
	if err != nil {
		return nil, err
	}
	return ctx.groupFacade(diceID, groupID, handle)
}

func (ctx *MsgContext) ResolvePlayer(callCtx context.Context, groupID, userID string) (*GroupPlayerInfo, error) {
	if ctx == nil || ctx.Dice == nil || ctx.Session == nil || ctx.callbackTransaction == nil {
		return nil, ErrDomainTxUnavailable
	}
	domain := ctx.callbackTransaction.Domain()
	if domain == nil {
		return nil, ErrDomainTxUnavailable
	}
	diceID := ctx.Dice.BaseConfig.Name
	if diceID == "" || groupID == "" || userID == "" {
		return nil, errors.New("dice: invalid player facade identity")
	}
	handle, err := domain.Player(callCtx, diceID, groupID, userID)
	if err != nil {
		return nil, err
	}
	return ctx.playerFacade(diceID, groupID, userID, handle)
}

// ResolveExistingDomainConversation binds an adapter event to existing
// canonical group/player facts without creating either aggregate.
func (ctx *MsgContext) ResolveExistingDomainConversation(groupID, userID string) error {
	if ctx == nil || ctx.Dice == nil || ctx.Session == nil || ctx.callbackTransaction == nil {
		return ErrDomainTxUnavailable
	}
	ctx.Group, ctx.Player = nil, nil
	domain := ctx.callbackTransaction.Domain()
	if domain == nil {
		return ErrDomainTxUnavailable
	}
	diceID := ctx.Dice.BaseConfig.Name
	if diceID == "" || groupID == "" {
		return errors.New("dice: invalid existing conversation identity")
	}
	groupHandle, err := domain.Group(ctx.domainContext(), diceID, groupID)
	if err != nil {
		return err
	}
	if groupHandle.Version() == 0 || groupHandle.Deleted() {
		return nil
	}
	group, err := ctx.groupFacade(diceID, groupID, groupHandle)
	if err != nil {
		return err
	}
	ctx.Group = group
	if userID == "" {
		return nil
	}
	playerHandle, err := domain.Player(ctx.domainContext(), diceID, groupID, userID)
	if err != nil {
		return err
	}
	if playerHandle.Version() == 0 || playerHandle.Deleted() {
		return nil
	}
	player, err := ctx.playerFacade(diceID, groupID, userID, playerHandle)
	if err != nil {
		return err
	}
	ctx.Player = player
	return nil
}

// NewDomainMsgContext builds a command context over an explicit root
// transaction. It never creates an ambient or fallback transaction.
func NewDomainMsgContext(
	transaction *DurableCallbackTransaction,
	d *Dice,
	session *IMSession,
	endpoint *EndPointInfo,
	message *Message,
) (*MsgContext, error) {
	if transaction == nil || d == nil || session == nil || endpoint == nil || message == nil {
		return nil, ErrDomainTxUnavailable
	}
	ctx := &MsgContext{
		Dice: d, Session: session, EndPoint: endpoint,
		MessageType: message.MessageType, IsPrivate: message.MessageType == "private",
		callbackTransaction: transaction, executionContext: context.Background(),
	}
	group, player, err := GetPlayerInfoBySender(ctx, message)
	if err != nil {
		return nil, err
	}
	ctx.Group, ctx.Player = group, player
	ctx.IsCurGroupBotOn = message.MessageType == "group" && group.IsActive(ctx)
	return ctx, nil
}
