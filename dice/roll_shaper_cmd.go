package dice

import (
	"fmt"
	"strings"
)

func canManageDiceRollShaper(ctx *MsgContext) bool {
	if ctx == nil {
		return false
	}
	return ctx.IsPrivate || ctx.PrivilegeLevel >= 50
}

func formatDiceRollShaperMode(mode DiceRollShaperMode) string {
	switch mode {
	case DiceRollShaperModeBalanced:
		return "Balanced / Shuffle Bag"
	case DiceRollShaperModeSoft:
		return "Soft / Beta(1.35,1.35)"
	case DiceRollShaperModeStable:
		return "Stable / Beta(2,2)"
	case DiceRollShaperModeSafeTail:
		return "Safe Tail"
	default:
		return "Raw / Uniform"
	}
}

func formatDiceRollShaperHelpText() string {
	return strings.Join([]string{
		"骰点整形模式：",
		".rollshape // 查看当前生效范围和模式",
		".rollshape get // 查看当前生效范围和模式",
		".rollshape set <模式> // 设置模式；群聊需管理员，私聊由发送者本人设置",
		".rollshape off // 恢复 Raw / Uniform",
		"可用模式：",
		"raw // 保持均匀随机",
		"balanced // 每轮均匀覆盖所有面；超过 1048576 面时使用 Raw",
		"soft // 轻度向中间结果集中",
		"stable // 明显向中间结果集中",
		"safe-tail // 两端结果概率减半；没有中间区间时使用 Raw",
	}, "\n")
}

func formatDiceRollShaperStatusText(ctx *MsgContext) string {
	if ctx == nil || ctx.Group == nil {
		return "骰点整形模式不可用：当前消息没有可用的设置范围"
	}
	mode := ctx.Group.getDiceRollShaperMode()
	return fmt.Sprintf("生效范围：%s\n骰点整形模式：%s", ctx.Group.GroupID, formatDiceRollShaperMode(mode))
}

func solveDiceRollShaper(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
	if cmdArgs.IsArgEqual(1, "help") {
		return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
	}

	subCommand := strings.ToLower(strings.TrimSpace(cmdArgs.GetArgN(1)))
	if subCommand == "" || subCommand == "get" {
		ReplyToSender(ctx, msg, formatDiceRollShaperStatusText(ctx))
		return CmdExecuteResult{Matched: true, Solved: true}
	}
	if subCommand != "set" && subCommand != "off" {
		ReplyToSender(ctx, msg, formatDiceRollShaperHelpText())
		return CmdExecuteResult{Matched: true, Solved: true}
	}
	if !canManageDiceRollShaper(ctx) {
		ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限"))
		return CmdExecuteResult{Matched: true, Solved: true}
	}
	if ctx == nil || ctx.Group == nil {
		ReplyToSender(ctx, msg, "骰点整形模式不可用：当前消息没有可用的设置范围")
		return CmdExecuteResult{Matched: true, Solved: true}
	}

	rawMode := "raw"
	if subCommand == "set" {
		rawMode = cmdArgs.GetArgN(2)
		if rawMode == "" {
			ReplyToSender(ctx, msg, formatDiceRollShaperHelpText())
			return CmdExecuteResult{Matched: true, Solved: true}
		}
	}
	mode, ok := parseDiceRollShaperMode(rawMode)
	if !ok {
		ReplyToSender(ctx, msg, fmt.Sprintf("不支持的骰点整形模式：%s\n%s", rawMode, formatDiceRollShaperHelpText()))
		return CmdExecuteResult{Matched: true, Solved: true}
	}
	ctx.Group.setDiceRollShaperMode(string(mode))
	ctx.Group.MarkDirty(ctx.Dice)
	ReplyToSender(ctx, msg, fmt.Sprintf("已设置骰点整形模式：%s\n生效范围：%s", formatDiceRollShaperMode(mode), ctx.Group.GroupID))
	return CmdExecuteResult{Matched: true, Solved: true}
}
