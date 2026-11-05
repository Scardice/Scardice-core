package dice

import (
	"Scardice-core/adapterapi"
	"Scardice-core/message"
)

type PlatformAdapter interface {
	QuitGroup(ctx *MsgContext, ID string)

	SendToPerson(ctx *MsgContext, userID string, text string, flag string)
	SendToGroup(ctx *MsgContext, groupID string, text string, flag string)
	SetGroupCardName(ctx *MsgContext, name string)

	SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string)
	SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string)

	// EffectSucceeded requires synchronous provider acceptance, not recipient delivery. Fire-and-forget adapters return EffectAmbiguous; unsupported adapters return EffectUnsupported.
	SendFileToPerson(ctx *MsgContext, userID string, path string, flag string) adapterapi.EffectResult
	SendFileToGroup(ctx *MsgContext, groupID string, path string, flag string) adapterapi.EffectResult

	MemberBan(groupID string, userID string, duration int64)
	MemberKick(groupID string, userID string)

	GetGroupInfoAsync(groupID string)

	// DeleteFriend 删除好友，目前只有 QQ 平台下的 gocq 和 walleq 实现有这个方法
	// DeleteFriend(ctx *MsgContext, id string)

	// EditMessage replace the content of the message with msgID with message.
	// Context is retrieved from ctx.
	EditMessage(ctx *MsgContext, msgID, message string)
	// RecallMessage recalls the message with msgID. Context is retrieved from ctx.
	RecallMessage(ctx *MsgContext, msgID string)
}

// notifyDirectMessageSend runs the legacy direct-send hook exactly once. Group
// sends resolve their destination through the current durable root so extension
// selection never falls back to the removed process-wide group map.
func notifyDirectMessageSend(ctx *MsgContext, msg *Message, flag string) error {
	if ctx == nil || ctx.Dice == nil || ctx.callbackTransaction == nil {
		return ErrDomainTxUnavailable
	}
	if msg == nil {
		return adapterapi.ErrInvalidContract
	}
	if msg.MessageType != "group" {
		for _, extension := range ctx.Dice.ExtList {
			if extension != nil && extension.HasOnMessageSend() {
				extension.CallOnMessageSend(ctx.Dice, ctx, msg, flag)
			}
		}
		return nil
	}
	if msg.GroupID == "" {
		return adapterapi.ErrInvalidContract
	}
	group := ctx.Group
	if group == nil || group.GroupID() != msg.GroupID {
		var err error
		group, err = ctx.ResolveGroup(ctx.domainContext(), msg.GroupID)
		if err != nil {
			return err
		}
	}
	if group.Version() == 0 || group.Deleted() {
		return nil
	}
	for _, extension := range group.GetActivatedExtList(ctx.Dice) {
		extension.CallOnMessageSend(ctx.Dice, ctx, msg, flag)
	}
	return nil
}

// 实现检查
var (
	_ PlatformAdapter = (*PlatformAdapterGocq)(nil)
	_ PlatformAdapter = (*PlatformAdapterHTTP)(nil)
	_ PlatformAdapter = (*PlatformAdapterOfficialQQ)(nil)
	_ PlatformAdapter = (*PlatformAdapterWalleQ)(nil)
	_ PlatformAdapter = (*PlatformAdapterSatori)(nil)
	_ PlatformAdapter = (*PlatformAdapterMilky)(nil)

	// _ PlatformAdapter = (*PlatformAdapterLagrangeGo)(nil)
)
