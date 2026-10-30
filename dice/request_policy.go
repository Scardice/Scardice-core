package dice

import (
	"regexp"
	"strings"
)

var onebotFriendRequestAnswerPattern = regexp.MustCompile(`\n回答:([^\n]+)`)
var onebotFriendRequestExpectedItemPattern = regexp.MustCompile(`\s+`)

func normalizeOnebotFriendRequestComment(comment string) string {
	comment = strings.TrimSpace(comment)
	comment = strings.ReplaceAll(comment, "\u00a0", " ")
	comment = strings.ReplaceAll(comment, "\r\n", "\n")
	comment = strings.ReplaceAll(comment, `\r\n`, "\n")
	comment = strings.ReplaceAll(comment, `\n`, "\n")
	return comment
}

func formatOnebotFriendRequestCommentForLog(comment string) string {
	comment = strings.ReplaceAll(comment, `\`, `\\`)
	comment = strings.ReplaceAll(comment, `"`, `\"`)
	return `"` + comment + `"`
}

func checkMultiFriendAddVerify(comment string, toMatch string) bool {
	if toMatch == "" {
		return true
	}

	matches := onebotFriendRequestAnswerPattern.FindAllStringSubmatch(comment, -1)
	answers := make([]string, 0, len(matches))
	for _, match := range matches {
		answer := strings.TrimSpace(strings.ReplaceAll(match[1], "\u00a0", " "))
		answers = append(answers, answer)
	}

	expectedItems := onebotFriendRequestExpectedItemPattern.Split(toMatch, -1)
	if len(expectedItems) != len(answers) {
		return false
	}

	for i, item := range expectedItems {
		expected := strings.TrimSpace(strings.ReplaceAll(item, "\u00a0", " "))
		if expected != answers[i] {
			return false
		}
	}

	return true
}

type BlackListCheckResult struct {
	Passed      bool
	FailureType string           // "user_banned", "group_banned", "trust_mode", "refuse_invite"
	Reason      string           // 具体原因
	BanInfo     *BanListInfoItem // 详细的封禁信息，用于后续逻辑
}

// checkBlackList 检查用户或群组是否通过黑名单检查
// 参数:
//   - userId: 用户ID或群组ID
//   - checkType: 检查类型，"user"或"group"
//   - ctx: 消息上下文
//
// 返回值:
//   - BlackListCheckResult: 包含检查结果和详细信息
func checkBlackList(id string, checkType string, inviterID string, ctx *MsgContext) BlackListCheckResult {
	result := BlackListCheckResult{
		Passed: true,
	}

	if id == "" {
		return result
	}

	banInfo, ok := ctx.Dice.Config.BanList.GetByID(id)
	if !ok || banInfo == nil {
		if checkType != "group" {
			return result
		}
		if ctx.Dice.Config.RefuseGroupInvite {
			result.Passed = false
			result.FailureType = "refuse_invite"
			result.Reason = "拒绝拉群邀请"
			return result
		}
		if inviterID != "" {
			isMaster := ctx.Dice.IsMaster(inviterID)
			if ctx.Dice.Config.TrustOnlyMode && !isMaster {
				result.Passed = false
				result.FailureType = "trust_mode"
				result.Reason = "只允许信任的人拉群"
				return result
			}
		}
		return result
	}

	result.BanInfo = banInfo

	switch checkType {
	case "user":
		// 检查用户是否被ban且配置了拒绝邀请
		if banInfo.Rank == BanRankBanned && ctx.Dice.Config.BanList.BanBehaviorRefuseInvite {
			result.Passed = false
			result.FailureType = "user_banned"
			result.Reason = "邀请人在黑名单上"
		}
	case "group":
		// 检查群组是否被ban
		if banInfo.Rank == BanRankBanned {
			result.Passed = false
			result.FailureType = "group_banned"
			result.Reason = "群组在黑名单上"
			return result
		}

		// 信任模式检查
		isMaster := inviterID != "" && ctx.Dice.IsMaster(inviterID)
		if ctx.Dice.Config.TrustOnlyMode && banInfo.Rank != BanRankTrusted && !isMaster {
			result.Passed = false
			result.FailureType = "trust_mode"
			result.Reason = "只允许信任的人拉群"
			return result
		}

		// 拒绝所有群邀请的配置检查
		if ctx.Dice.Config.RefuseGroupInvite {
			result.Passed = false
			result.FailureType = "refuse_invite"
			result.Reason = "拒绝拉群邀请"
		}
	}

	return result
}

func checkPassBlackListGroup(inviterID string, groupID string, ctx *MsgContext) (bool, string) {
	userResult := checkBlackList(inviterID, "user", "", ctx)
	if !userResult.Passed {
		return false, userResult.Reason
	}
	groupResult := checkBlackList(groupID, "group", inviterID, ctx)
	if !groupResult.Passed {
		return false, groupResult.Reason
	}
	return true, ""
}
