package dice

import (
	"fmt"

	"Scardice-core/dice/events"
)

func RegisterBuiltinExtCore(dice *Dice) {
	theExt := &ExtInfo{
		Name:        "core",
		Version:     "1.0.0",
		Brief:       "核心逻辑模块，该扩展即使被关闭也会依然生效",
		Author:      "Scardice-Team",
		AutoActive:  true, // 是否自动开启
		Official:    true,
		GetDescText: GetExtensionDesc,
		OnGroupLeave: func(ctx *MsgContext, event *events.GroupLeaveEvent) {
			if event.UserID == ctx.EndPoint.UserID {
				if event.OperatorID == ctx.EndPoint.UserID {
					return
				}

				opUID := event.OperatorID
				groupName := ctx.Dice.Parent.TryGetGroupName(event.GroupID)
				userName := ctx.Dice.Parent.TryGetUserName(opUID)
				if opUID == "" {
					txt := fmt.Sprintf("退出群组<%s>(%s)，但操作者ID为空，停止继续处理", groupName, event.GroupID)
					dice.Logger.Info(txt)
					ctx.Notice(txt, NoticeTypeGroup)
					return
				}

				skip := false
				skipReason := ""
				ban := ctx.Dice.Config().BanList
				banInfo, ok, err := ban.GetByIDForContext(ctx, opUID)
				if err != nil {
					ctx.setExecutionError(err)
					dice.Logger.Errorf("读取踢群操作者名单状态失败: %v", err)
					return
				}
				if ok && banInfo.Rank == BanRankTrusted {
					skip = true
					skipReason = "信任用户"
				}
				if ctx.Dice.IsMaster(opUID) {
					skip = true
					skipReason = "Master"
				}

				var extra string
				if skip {
					extra = fmt.Sprintf("\n取消处罚，原因为%s", skipReason)
				} else if err = ban.AddScoreByGroupKickedForContext(opUID, event.GroupID, ctx); err != nil {
					ctx.setExecutionError(err)
					dice.Logger.Errorf("记录踢群处罚失败: %v", err)
					return
				}

				txt := fmt.Sprintf("被踢出群: 在群组<%s>(%s)中被踢出，操作者:<%s>(%s)%s", groupName, event.GroupID, userName, event.OperatorID, extra)
				dice.Logger.Info(txt)
				ctx.Notice(txt, NoticeTypeGroup)
			}
		},
	}

	theExt.CmdMap = map[string]*CmdItemInfo{
		"team": cmdTeam,
	}

	dice.RegisterExtension(theExt)
}
