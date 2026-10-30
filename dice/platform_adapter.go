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
