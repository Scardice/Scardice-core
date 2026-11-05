package dice

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/golang-module/carbon"
	"github.com/juliangruber/go-intersect"
	cp "github.com/otiai10/copy"
	ds "github.com/sealdice/dicescript"

	"Scardice-core/core/groupstate"

	"Scardice-core/dice/docengine"
)

type dismissConfirmState struct {
	Code      string
	ExpiresAt int64
}

var dismissConfirmCodes SyncMap[string, *dismissConfirmState]
var dismissConfirmLastCleanup atomic.Int64

const dismissConfirmTTL = 10 * time.Minute
const dismissConfirmCleanupInterval = 30 * time.Minute

const (
	errGetGroupMemberInfoNil       = "get_group_member_info returned nil"
	errGetGroupMemberInfoEmptyRole = "empty role from get_group_member_info"
)

func getDismissConfirmKeyForGroup(ctx *MsgContext, operatorID string, targetGroupID string) string {
	return fmt.Sprintf("%s:%s:%s", ctx.EndPoint.ID, targetGroupID, operatorID)
}

func cleanupExpiredDismissConfirmCodes() {
	now := time.Now()
	last := dismissConfirmLastCleanup.Load()
	if last != 0 && now.Unix()-last < int64(dismissConfirmCleanupInterval/time.Second) {
		return
	}
	dismissConfirmLastCleanup.Store(now.Unix())
	dismissConfirmCodes.Range(func(key string, state *dismissConfirmState) bool {
		if state == nil || now.Unix() > state.ExpiresAt {
			dismissConfirmCodes.Delete(key)
		}
		return true
	})
}

func generateFourDigitCode() (string, error) {
	n, err := crand.Int(crand.Reader, big.NewInt(9000))
	if err != nil {
		return "", fmt.Errorf("generate confirmation code: %w", err)
	}
	return strconv.FormatInt(n.Int64()+1000, 10), nil
}

func storeDismissConfirmCode(key string, code string) {
	cleanupExpiredDismissConfirmCodes()
	dismissConfirmCodes.Store(key, &dismissConfirmState{Code: code, ExpiresAt: time.Now().Add(dismissConfirmTTL).Unix()})
}

func loadDismissConfirmCode(key string) (string, bool) {
	state, ok := dismissConfirmCodes.Load(key)
	if !ok || state == nil {
		return "", false
	}
	if time.Now().Unix() > state.ExpiresAt {
		dismissConfirmCodes.Delete(key)
		return "", false
	}
	return state.Code, true
}

func getOnebotBotQQID(ctx *MsgContext) (int64, bool) {
	if ctx == nil || ctx.EndPoint == nil {
		return 0, false
	}

	if userID := strings.TrimSpace(ctx.EndPoint.UserID); userID != "" {
		if botID := ExtractQQEmitterUserID(userID); botID > 0 {
			return botID, true
		}
	}
	return 0, false
}

func normalizeQQGroupRole(role string) string {
	norm := strings.ToLower(strings.TrimSpace(role))

	switch norm {
	case "owner", "creator", "群主":
		return "owner"
	case "admin", "administrator", "管理员":
		return "admin"
	case "member", "membernormal", "成员":
		return "member"
	default:
		return norm
	}
}

func parseQQGroupRole(role string) (string, bool) {
	normalized := normalizeQQGroupRole(role)
	if normalized == "" {
		return "", false
	}
	return normalized, true
}

func checkBotGroupRole(ctx *MsgContext, groupID string) (string, bool) {
	if ctx == nil || ctx.EndPoint == nil {
		return "context invalid", false
	}
	const bypassCache = true

	// Adapters that still own a provider connection answer for themselves; an
	// endpoint run by the supervisor has no adapter and is asked through the
	// provider query port.
	if ctx.EndPoint.Adapter != nil {
		if resolver, ok := ctx.EndPoint.Adapter.(botGroupRoleResolver); ok {
			role, err := resolver.botGroupRole(ctx, groupID, bypassCache)
			if err != nil {
				return err.Error(), false
			}
			return normalizedBotRole(role)
		}
	}
	if ctx.Dice == nil || ctx.Dice.ProviderQuery == nil {
		return "adapter does not support group role check", false
	}
	role, err := queryBotGroupRole(ctx, groupID, bypassCache)
	if err != nil {
		return err.Error(), false
	}
	return normalizedBotRole(role)
}

func normalizedBotRole(role string) (string, bool) {
	normalized, ok := parseQQGroupRole(role)
	if !ok {
		return errGetGroupMemberInfoEmptyRole, false
	}
	return normalized, true
}

func shouldDismissRequireOwnerConfirm(ctx *MsgContext, groupID string) (bool, bool, string) {
	detail, ok := checkBotGroupRole(ctx, groupID)
	if !ok {
		return false, false, detail
	}
	return detail == "owner", true, detail
}

func normalizeDismissTargetGroupID(ctx *MsgContext, rawGroupID string) string {
	groupID := strings.TrimSpace(rawGroupID)
	if groupID == "" {
		return ""
	}
	if strings.Contains(groupID, ":") {
		return groupID
	}
	return FormatDiceID(ctx, groupID, true)
}

func isDismissConfirmCode(text string) bool {
	if len(text) != 4 {
		return false
	}
	for _, ch := range text {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func resolveGroupQuitTarget(ctx *MsgContext, groupID string) (*GroupInfo, error) {
	if ctx == nil || ctx.callbackTransaction == nil || ctx.Dice == nil || ctx.EndPoint == nil {
		return nil, ErrDurableStateUnavailable
	}
	group, err := ctx.ResolveGroup(ctx.domainContext(), groupID)
	if err != nil {
		return nil, err
	}
	if group.Version() == 0 || group.Deleted() {
		return nil, fmt.Errorf("群组 %s 不存在", groupID)
	}
	return group, nil
}

func (d *Dice) executeDismissOperation(ctx *MsgContext, msg *Message, targetGroupID string) CmdExecuteResult {
	targetGroup, membershipErr := resolveGroupQuitTarget(ctx, targetGroupID)
	if membershipErr != nil {
		ctx.setExecutionError(membershipErr)
		d.Logger.Errorf("退群状态准备失败: group=%s error=%v", targetGroupID, membershipErr)
		ReplyToSender(ctx, msg, fmt.Sprintf("退群请求提交失败：%v", membershipErr))
		return CmdExecuteResult{Matched: true, Solved: true}
	}
	ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子退群预告"))

	userName := ctx.Dice.Parent.TryGetUserName(msg.Sender.UserID)
	groupName := targetGroupID
	if targetGroup.GroupName() != "" {
		groupName = targetGroup.GroupName()
	} else if name := ctx.Dice.Parent.TryGetGroupName(targetGroupID); name != "" {
		groupName = name
	}
	txt := fmt.Sprintf("指令退群: 于群组<%s>(%s)中告别，操作者:<%s>(%s)",
		groupName, targetGroupID, userName, msg.Sender.UserID)
	d.Logger.Info(txt)
	ctx.Notice(txt, NoticeTypeGroup)

	if ctx.Dice.OutboundBridge == nil && ctx.EndPoint != nil && ctx.EndPoint.Adapter != nil && !isPureOnebotEndpoint(ctx.EndPoint) {
		time.Sleep(3 * time.Second)
	}
	if err := QuitGroup(ctx, targetGroupID); err != nil {
		ctx.setExecutionError(err)
		d.Logger.Errorf("退群请求提交失败: group=%s error=%v", targetGroupID, err)
		ReplyToSender(ctx, msg, fmt.Sprintf("退群请求提交失败：%v", err))
		return CmdExecuteResult{Matched: true, Solved: true}
	}
	if err := targetGroup.SetActivation(ctx.EndPoint.UserID, false, false); err != nil {
		ctx.setExecutionError(err)
		d.Logger.Errorf("退群状态写入失败: group=%s error=%v", targetGroupID, err)
		ReplyToSender(ctx, msg, fmt.Sprintf("退群请求提交失败：%v", err))
		return CmdExecuteResult{Matched: true, Solved: true}
	}

	return CmdExecuteResult{Matched: true, Solved: true}
}

func (d *Dice) executeDismissWithConfirm(ctx *MsgContext, msg *Message, targetGroupID string, inputCode string, hasExtraArgs bool, confirmCommand string) CmdExecuteResult {
	processDismissConfirmation := func(roleDetail string, issueLogTpl string, issueReplyTpl string, successLogTpl string) CmdExecuteResult {
		confirmKey := getDismissConfirmKeyForGroup(ctx, msg.Sender.UserID, targetGroupID)
		if inputCode == "" || hasExtraArgs {
			confirmCode, err := generateFourDigitCode()
			if err != nil {
				ctx.setExecutionError(err)
				d.Logger.Errorf("生成退群确认码失败: %v", err)
				ReplyToSender(ctx, msg, "无法生成安全确认码，请稍后重试")
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			confirmCmdWithCode := fmt.Sprintf("%s %s", confirmCommand, confirmCode)
			storeDismissConfirmCode(confirmKey, confirmCode)
			d.Logger.Infof(issueLogTpl, targetGroupID, msg.Sender.UserID, ctx.EndPoint.UserID, roleDetail)
			ReplyToSender(ctx, msg, fmt.Sprintf(issueReplyTpl, confirmCmdWithCode))
			return CmdExecuteResult{Matched: true, Solved: true}
		}

		confirmCode, ok := loadDismissConfirmCode(confirmKey)
		if !ok || inputCode != confirmCode {
			d.Logger.Warnf("指令退群确认失败: 群组<%s>中，操作者<%s>提供的确认码无效，本次不执行退群。", targetGroupID, msg.Sender.UserID)
			ReplyToSender(ctx, msg, fmt.Sprintf("退群确认码无效，请重新输入 `%s` 获取新的确认码。", confirmCommand))
			return CmdExecuteResult{Matched: true, Solved: true}
		}

		d.Logger.Infof(successLogTpl, targetGroupID, msg.Sender.UserID, ctx.EndPoint.UserID, roleDetail)
		dismissConfirmCodes.Delete(confirmKey)
		return d.executeDismissOperation(ctx, msg, targetGroupID)
	}

	if needConfirm, checked, detail := shouldDismissRequireOwnerConfirm(ctx, targetGroupID); checked {
		if needConfirm {
			return processDismissConfirmation(
				detail,
				"指令退群需二次确认: 群组<%s>中，操作者<%s>请求让骰子账号<%s>退出；当前检测到该账号身份为%s，已发出确认码。",
				"当前骰子账号在本群是群主，继续 `%s` 将会直接解散群聊。\n请在当前群内重新输入上面的完整命令进行二次确认。",
				"指令退群二次确认通过: 群组<%s>中，操作者<%s>确认让骰子账号<%s>退出；因该账号为%s，这将导致群聊被解散。",
			)
		}
	} else if ctx.EndPoint.ProtocolType == "onebot" || ctx.EndPoint.Platform == "QQ" {
		return processDismissConfirmation(
			detail,
			"指令退群进入安全确认: 群组<%s>中，操作者<%s>请求让骰子账号<%s>退出；但当前无法确认该账号群内身份(%s)，为避免误解散群聊，已改为二次确认。",
			"当前无法确认骰子账号在本群的身份，为避免误解散群聊，已启用安全确认。\n如确认仍要退出，请在当前群内重新输入 `%s`。",
			"指令退群安全确认通过: 群组<%s>中，操作者<%s>确认让骰子账号<%s>退出；此前未能确认该账号群内身份(%s)。",
		)
	}

	if inputCode != "" || hasExtraArgs {
		return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
	}

	return d.executeDismissOperation(ctx, msg, targetGroupID)
}

/** 这几条指令不能移除 */
func (d *Dice) registerCoreCommands() {
	helpForBlack := ".ban add user <帐号> [<原因>] //添加个人\n" +
		".ban add group <群号> [<原因>] //添加群组\n" +
		".ban add <统一ID>\n" +
		".ban rm user <帐号> //解黑/移出信任\n" +
		".ban rm group <群号>\n" +
		".ban rm <统一ID> //同上\n" +
		".ban list // 展示列表\n" +
		".ban list ban/warn/trust //只显示被禁用/被警告/信任用户\n" +
		".ban trust <统一ID> //添加信任\n" +
		".ban query <统一ID> //查看指定用户拉黑情况\n" +
		".ban help //查看帮助\n" +
		"// 统一ID示例: QQ:12345、QQ-Group:12345"
	cmdBlack := &CmdItemInfo{
		Name:      "ban",
		ShortHelp: helpForBlack,
		Help:      "黑名单指令:\n" + helpForBlack,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			cmdArgs.ChopPrefixToArgsWith("add", "rm", "del", "list", "show", "find", "trust")
			if ctx.PrivilegeLevel < 100 {
				ReplyToSender(ctx, msg, "你不具备Master权限")
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			ban := d.Config().BanList
			fail := func(prefix string, err error) {
				ctx.setExecutionError(err)
				ReplyToSender(ctx, msg, fmt.Sprintf("%s：%v", prefix, err))
			}

			getID := func() string {
				if cmdArgs.IsArgEqual(2, "user") || cmdArgs.IsArgEqual(2, "group") {
					id := cmdArgs.GetArgN(3)
					if id == "" {
						return ""
					}

					isGroup := cmdArgs.IsArgEqual(2, "group")
					return FormatDiceID(ctx, id, isGroup)
				}

				arg := cmdArgs.GetArgN(2)
				if !strings.Contains(arg, ":") {
					return ""
				}
				return arg
			}

			var val = cmdArgs.GetArgN(1)
			var uid string
			switch strings.ToLower(val) {
			case "add":
				uid = getID()
				if uid == "" {
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				}
				reason := cmdArgs.GetArgN(4)
				if reason == "" {
					reason = "骰主指令"
				}
				settings, err := ban.settingsForContext(ctx)
				if err != nil {
					fail("读取黑名单设置失败", err)
					break
				}
				if _, err := ban.AddScoreBaseWithError(uid, settings.ThresholdBan, "骰主指令", reason, ctx); err != nil {
					fail("加入黑名单失败", err)
					break
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("已将用户/群组 %s 加入黑名单，原因: %s", uid, reason))
			case "rm", "del":
				uid = getID()
				if uid == "" {
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				}

				item, ok, err := ban.GetByIDForContext(ctx, uid)
				if err != nil {
					fail("读取名单失败", err)
					break
				}
				if !ok || (item.Rank != BanRankBanned && item.Rank != BanRankTrusted && item.Rank != BanRankWarn) {
					ReplyToSender(ctx, msg, "找不到用户/群组")
					break
				}

				if err = ban.SetRankByIDForContext(ctx, d, uid, BanRankNormal, item.Name, "", ""); err != nil {
					fail("移出名单失败", err)
					break
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("已将用户/群组 %s 移出%s列表", uid, BanRankText[item.Rank]))
			case "trust":
				uid = cmdArgs.GetArgN(2)
				if !strings.Contains(uid, ":") {
					// 如果不是这种格式，那么放弃
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				}

				if err := ban.SetTrustByIDForContext(ctx, uid, "骰主指令", "骰主指令"); err != nil {
					fail("加入信任列表失败", err)
					break
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("已将用户/群组 %s 加入信任列表", uid))
			case "list", "show":
				// ban/warn/trust
				var extra string
				var text strings.Builder
				extra = cmdArgs.GetArgN(2)
				items, err := ban.SnapshotForContext(ctx)
				if err != nil {
					fail("读取名单失败", err)
					break
				}
				for _, v := range items {
					if v.Rank == BanRankNormal {
						continue
					}
					match := (extra == "trust" && v.Rank == BanRankTrusted) ||
						(extra == "ban" && v.Rank == BanRankBanned) ||
						(extra == "warn" && v.Rank == BanRankWarn)
					if extra == "" || match {
						text.WriteString(v.toText(d))
						text.WriteByte('\n')
					}
				}
				if text.Len() == 0 {
					text.WriteString("<无内容>")
				}
				ReplyToSender(ctx, msg, "当前名单:\n"+text.String())
			case "query":
				var targetID = cmdArgs.GetArgN(2)
				if targetID == "" {
					ReplyToSender(ctx, msg, "未指定要查询的对象！")
					break
				}

				v, exists, err := ban.GetByIDForContext(ctx, targetID)
				if err != nil {
					fail("读取名单失败", err)
					break
				}
				if !exists {
					ReplyToSender(ctx, msg, fmt.Sprintf("所查询的<%s>情况：正常(0)", targetID))
					break
				}

				var text strings.Builder
				fmt.Fprintf(&text, "所查询的<%s>情况：", targetID)
				switch v.Rank {
				case BanRankBanned:
					text.WriteString("禁止(-30)")
				case BanRankWarn:
					text.WriteString("警告(-10)")
				case BanRankTrusted:
					text.WriteString("信任(30)")
				default:
					text.WriteString("正常(0)")
				}
				for i, reason := range v.Reasons {
					fmt.Fprintf(
						&text,
						"\n%s在「%s」，原因：%s",
						carbon.CreateFromTimestamp(v.Times[i]).ToDateTimeString(),
						v.Places[i],
						reason,
					)
				}
				ReplyToSender(ctx, msg, text.String())
			default:
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["black"] = cmdBlack
	d.CmdMap["ban"] = cmdBlack

	helpForFind := ".find/查询 <关键字> // 查找文档。关键字可以多个，用空格分割\n" +
		".find #<分组> <关键字> // 查找指定分组下的文档。关键字可以多个，用空格分割\n" +
		".find <数字ID> // 显示该ID的词条\n" +
		".find --rand // 显示随机词条\n" +
		".find <关键字> --num=10 // 需要更多结果\n" +
		".find config --group // 查看当前默认搜索分组\n" +
		".find config --group=<分组> // 设置当前默认搜索分组\n" +
		".find config --groupclr // 清空当前默认搜索分组"
	cmdFind := &CmdItemInfo{
		Name:      "find",
		ShortHelp: helpForFind,
		Help:      "查询指令，通常使用全文搜索(x86版)或快速查询(arm, 移动版):\n" + helpForFind,
		// 写不下了
		// + "\n注: 默认搭载的《怪物之锤查询》来自蜜瓜包、October整理\n默认搭载的COC《魔法大典》来自魔骨，NULL，Dr.Amber整理\n默认搭载的DND系列文档来自DicePP项目"
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			if cmdArgs.IsArgEqual(1, "help") {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}

			if d.Parent.IsHelpDocLoading() {
				ReplyToSender(ctx, msg, "帮助文档正在重新装载，请稍后...")
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			var commandReply string
			var showHelp bool
			err := d.Parent.WithHelpDocManagerRead(func(help *HelpManager) error {
				if help == nil {
					return errors.New("help manager is unavailable")
				}

				if _config := cmdArgs.GetArgN(1); _config == "config" {
					oldDefault := ctx.Group.DefaultHelpGroup()
					if cmdArgs.GetKwarg("groupclr") != nil {
						if err := ctx.Group.SetDefaultHelpGroup(""); err != nil {
							return err
						}
						if oldDefault != "" {
							commandReply = "已清空默认搜索分组，原分组为" + oldDefault
						} else {
							commandReply = "未指定默认搜索分组"
						}
					} else if _defaultGroup := cmdArgs.GetKwarg("group"); _defaultGroup != nil {
						defaultGroup := _defaultGroup.Value
						if defaultGroup == "" {
							// 为查看默认分组
							if oldDefault != "" {
								commandReply = "当前默认搜索分组为" + oldDefault
							} else {
								commandReply = "未指定默认搜索分组"
							}
						} else {
							// 为设置默认分组
							// 修复别名查询问题：在设置默认分组时，需要将别名转换为原名
							// 这样确保存储的始终是原名，避免后续查询时出现别名无法识别的问题
							realGroup := defaultGroup
							if _g, ok := help.GroupAliases[defaultGroup]; ok {
								// 如果输入的是别名，转换为对应的原名
								realGroup = _g
							}
							// 使用转换后的原名设置默认分组
							if err := ctx.Group.SetDefaultHelpGroup(realGroup); err != nil {
								return err
							}
							if oldDefault != "" {
								commandReply = fmt.Sprintf("默认搜索分组由%s切换到%s", oldDefault, defaultGroup)
							} else {
								commandReply = "指定默认搜索分组为" + defaultGroup
							}
						}
					} else {
						commandReply = "设置选项有误"
						return nil
					}
					return nil
				}

				var (
					useGroupSearch bool
					group          string
					text           = cmdArgs.CleanArgs
				)
				if rawGroup := cmdArgs.GetArgN(1); strings.HasPrefix(rawGroup, "#") {
					useGroupSearch = true
					fakeGroup := strings.TrimPrefix(rawGroup, "#")
					text = strings.TrimPrefix(text, rawGroup+" ")

					// 转换 group 别名
					if _g, ok := help.GroupAliases[fakeGroup]; ok {
						group = _g
					} else {
						group = fakeGroup
					}
				}
				var groupStr string
				if group != "" {
					groupStr = "[搜索分组" + group + "]"
				}

				var id string
				if cmdArgs.GetKwarg("rand") != nil || cmdArgs.GetKwarg("随机") != nil {
					// FIXME: byd WHAT IS THAT
					if count := int(help.CurID); count > 0 {
						id = strconv.Itoa(ctx.RandIntn(count) + 1)
					}
				}

				if id == "" {
					var _id string
					if useGroupSearch {
						_id = cmdArgs.GetArgN(2)
					} else {
						_id = cmdArgs.GetArgN(1)
					}
					if _id != "" {
						_, err2 := strconv.ParseInt(_id, 10, 64)
						if err2 == nil {
							id = _id
						}
					}
				}

				if id != "" {
					text, err := help.GetItemByNumericIDString(id)
					if err == nil {
						// Copied from 支援换行符 By Fripine #963
						text.Content = ctx.TranslateSplit(text.Content)
						content := help.GetContent(text, 0)
						commandReply = fmt.Sprintf("词条: %s:%s\n%s", text.PackageName, text.Title, content)
					} else {
						commandReply = "未发现对应ID的词条"
					}
					return nil
				}

				{ // 判断是否关键字缺失
					var val string
					if useGroupSearch {
						val = cmdArgs.GetArgN(2)
					} else {
						val = cmdArgs.GetArgN(1)
					}
					if val == "" {
						showHelp = true
						return nil
					}
				}

				numLimit := 4
				numParam := cmdArgs.GetKwarg("num")
				if numParam != nil {
					_num, err := strconv.ParseInt(numParam.Value, 10, 64)
					if err == nil {
						numLimit = int(_num)
					}
				}

				page := 1
				pageParam := cmdArgs.GetKwarg("page")
				if pageParam != nil {
					if _page, err := strconv.ParseInt(pageParam.Value, 10, 64); err == nil {
						page = int(_page)
					}
				}

				if numLimit <= 0 {
					numLimit = 1
				} else if numLimit > 10 {
					numLimit = 10
				}
				if page <= 0 {
					page = 1
				}
				if group == "" {
					// 未指定搜索分组时，取当前群指定的分组
					group = ctx.Group.DefaultHelpGroup()
				}
				// 进行结果搜索
				search, total, pgStart, pgEnd, err := help.Search(ctx, text, false, numLimit, page, group)
				if err != nil {
					ctx.setExecutionError(err)
					commandReply = groupStr + "搜索故障: " + err.Error()
					//nolint:nilerr // The callback root carries the error while the command preserves its failure reply.
					return nil
				}
				if len(search.Hits) == 0 {
					if total == 0 {
						commandReply = groupStr + "未找到搜索结果"
					} else {
						commandReply = fmt.Sprintf("%s找到%d条结果, 但在当前页码并无结果", groupStr, total)
					}
					return nil
				}

				// 准备接下来读取这里面的Fields
				bestRaw := search.Hits[0].Fields
				best := &docengine.HelpTextItem{
					Group:       fmt.Sprintf("%v", bestRaw["group"]),
					From:        fmt.Sprintf("%v", bestRaw["from"]),
					Title:       fmt.Sprintf("%v", bestRaw["title"]),
					Content:     fmt.Sprintf("%v", bestRaw["content"]),
					PackageName: fmt.Sprintf("%v", bestRaw["package"]),
					// 这俩是什么东西？！
					// KeyWords:   "",
					// RelatedExt: nil,
				}
				var others strings.Builder

				for _, i := range search.Hits {
					t := &docengine.HelpTextItem{
						Group:       fmt.Sprintf("%v", i.Fields["group"]),
						Title:       fmt.Sprintf("%v", i.Fields["title"]),
						PackageName: fmt.Sprintf("%v", i.Fields["package"]),
					}
					if t.Group != "" && t.Group != HelpBuiltinGroup {
						fmt.Fprintf(&others, "[%s][%s]【%s:%s】 匹配度%.2f\n", i.ID, t.Group, t.PackageName, t.Title, i.Score)
					} else {
						fmt.Fprintf(&others, "[%s]【%s:%s】 匹配度%.2f\n", i.ID, t.PackageName, t.Title, i.Score)
					}
				}

				showBest := shouldShowBestHelpResult(search.Hits, text != "" && best.Title == text, help.GetShowBestRelativeGap())

				var bestResult string
				if showBest {
					// Copied from 支援换行符 By Fripine #963
					best.Content = ctx.TranslateSplit(best.Content)
					content := help.GetContent(best, 0)
					bestResult = fmt.Sprintf("最优先结果%s:\n词条: %s:%s\n%s\n\n", groupStr, best.PackageName, best.Title, content)
				}

				prefix := help.GetPrefixText()
				rplCurPage := fmt.Sprintf("本页结果:\n%s\n", others.String())
				rplDetailHint := "使用\".find <序号>\"可查看明细，如.find 123\n"
				// pgStart是下标闭左边界, 加1以获得序号; pgEnd是下标开右边界, 无需调整就是最后一条的序号
				rplPageNum := fmt.Sprintf("共%d条结果, 当前显示第%d页(第%d条 到 第%d条)\n", total, page, pgStart+1, pgEnd)
				rplPageHint := "使用\".find <词条> --page=<页码> 查看更多结果\n"
				commandReply = prefix + groupStr + bestResult + rplCurPage + rplDetailHint + rplPageNum + rplPageHint
				return nil
			})
			if err != nil {
				ctx.setExecutionError(err)
				ReplyToSender(ctx, msg, "搜索故障: "+err.Error())
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if commandReply != "" {
				ReplyToSender(ctx, msg, commandReply)
			}
			return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: showHelp}
		},
	}
	d.CmdMap["查询"] = cmdFind
	d.CmdMap["査詢"] = cmdFind
	d.CmdMap["find"] = cmdFind

	helpForHelp := ".help // 查看本帮助\n" +
		".help 指令 // 查看某指令信息\n" +
		".help 骰点 // 查看骰主配置的骰点教程\n" +
		".help 房规 // 查看骰主配置的房规\n" +
		".help 特色功能 // 查看骰主配置的额外功能教程\n" +
		".help 扩展模块 // 查看扩展信息，如.help coc7\n" +
		".help 关键字 // 查看任意帮助，同.find\n" +
		".help reload // 重新加载帮助文档，需要Master权限"
	cmdHelp := &CmdItemInfo{
		Name:      "help",
		ShortHelp: helpForHelp,
		Help:      "帮助指令，用于查看指令帮助和helpdoc中录入的信息:\n" + helpForHelp,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			arg := cmdArgs.GetArgN(1)
			if arg == "" {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子帮助文本"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			if strings.EqualFold(arg, "reload") {
				if ctx.PrivilegeLevel < 100 {
					ReplyToSender(ctx, msg, "你不具备Master权限")
				} else {
					dm := d.Parent
					if dm.JustForTest {
						ReplyToSender(ctx, msg, "此指令在展示模式下不可用")
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					if !dm.IsHelpReloading.Load() {
						if err := dm.ReloadHelp(); err != nil {
							ctx.setExecutionError(err)
							ReplyToSender(ctx, msg, "帮助文档重载失败: "+err.Error())
						} else {
							ReplyToSender(ctx, msg, "帮助文档已经重新装载")
						}
					} else {
						ReplyToSender(ctx, msg, "帮助文档正在重新装载，请稍后...")
					}
				}
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "help") {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			if cmdArgs.IsArgEqual(1, "骰点") {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子帮助文本_骰点"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "房规") {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子帮助文本_房规"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "骰主", "骰主信息") {
				masterMsg := DiceFormatTmpl(ctx, "核心:骰子帮助文本_骰主")
				ReplyToSender(ctx, msg, masterMsg)
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "协议", "使用协议") {
				masterMsg := DiceFormatTmpl(ctx, "核心:骰子帮助文本_协议")
				ReplyToSender(ctx, msg, masterMsg)
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "娱乐") {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子帮助文本_娱乐"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "特色功能") {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子帮助文本_特色功能"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "其他", "其它") {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子帮助文本_其他"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			if d.Parent.IsHelpDocLoading() {
				ReplyToSender(ctx, msg, "帮助文档正在重新装载，请稍后...")
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			var helpReply string
			err := d.Parent.WithHelpDocManagerRead(func(help *HelpManager) error {
				if help == nil {
					return errors.New("help manager is unavailable")
				}
				search, _, _, _, err := help.Search(ctx, cmdArgs.CleanArgs, true, 1, 1, "")
				if err != nil {
					ctx.setExecutionError(err)
					helpReply = "搜索故障: " + err.Error()
					//nolint:nilerr // The callback root carries the error while the command preserves its failure reply.
					return nil
				}
				if len(search.Hits) == 0 {
					helpReply = "未找到搜索结果"
					return nil
				}
				a := &docengine.HelpTextItem{
					Group: fmt.Sprintf("%v", search.Hits[0].Fields["group"]),
					From:  fmt.Sprintf("%v", search.Hits[0].Fields["from"]),
					Title: fmt.Sprintf("%v", search.Hits[0].Fields["title"]),
					// Edited. Original change from 支援换行符 By Fripine #963
					Content:     ctx.TranslateSplit(fmt.Sprintf("%v", search.Hits[0].Fields["content"])),
					PackageName: fmt.Sprintf("%v", search.Hits[0].Fields["package"]),
					// 这俩是什么东西？！
					KeyWords:   "",
					RelatedExt: nil,
				}
				content := help.GetContent(a, 0)
				helpReply = fmt.Sprintf("%s:%s\n%s", a.PackageName, a.Title, content)
				return nil
			})
			if err != nil {
				ctx.setExecutionError(err)
				helpReply = "搜索故障: " + err.Error()
			}
			ReplyToSender(ctx, msg, helpReply)
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["help"] = cmdHelp

	cmdBot := &CmdItemInfo{
		Name:      "bot",
		ShortHelp: ".bot on/off/about/bye/quit // 开启、关闭、查看信息、退群",
		Help:      "骰子管理:\n.bot on/off/about/bye[exit,quit] // 开启、关闭、查看信息、退群",
		Raw:       true,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			inGroup := msg.MessageType == "group"

			if inGroup {
				// 不响应裸指令选项
				if len(cmdArgs.At) < 1 && ctx.Dice.Config().IgnoreUnaddressedBotCmd {
					return CmdExecuteResult{Matched: false, Solved: false}
				}
				// 不响应at其他人
				if cmdArgs.SomeoneBeMentionedButNotMe {
					return CmdExecuteResult{Matched: false, Solved: false}
				}
			}

			if len(cmdArgs.Args) > 0 && !cmdArgs.IsArgEqual(1, "about") { //nolint:nestif
				if cmdArgs.SomeoneBeMentionedButNotMe {
					return CmdExecuteResult{Matched: false, Solved: false}
				}

				cmdArgs.ChopPrefixToArgsWith("on", "off")

				if cmdArgs.IsArgEqual(1, "on", "off") {
					matchNumber := func() (bool, bool) {
						txt := cmdArgs.GetArgN(2)
						if len(txt) >= 4 {
							if strings.HasSuffix(ctx.EndPoint.UserID, txt) {
								return true, txt != ""
							}
						}
						return false, txt != ""
					}

					isMe, exists := matchNumber()
					if exists && !isMe {
						return CmdExecuteResult{Matched: false, Solved: false}
					}
				}

				if cmdArgs.IsArgEqual(1, "on") {
					if msg.Platform != "QQ-CH" && !ctx.Dice.Config().BotExtFreeSwitch && ctx.PrivilegeLevel < 40 {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限_非master/管理/邀请者"))
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					if ctx.IsPrivate {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					group, err := SetBotOnAtGroup(ctx, msg.GroupID)
					if err != nil {
						ctx.setExecutionError(err)
						ReplyToSender(ctx, msg, fmt.Sprintf("开启失败：%v", err))
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					ctx.Group = group
					ctx.IsCurGroupBotOn = true

					text := DiceFormatTmpl(ctx, "核心:骰子开启")
					if state, stateErr := ctx.ReadGroupLogState(); stateErr == nil && state.On {
						text += "\n请特别注意: 日志记录处于开启状态"
					}
					ReplyToSender(ctx, msg, text)

					return CmdExecuteResult{Matched: true, Solved: true}
				} else if cmdArgs.IsArgEqual(1, "off") {
					if msg.Platform != "QQ-CH" && !ctx.Dice.Config().BotExtFreeSwitch && ctx.PrivilegeLevel < 40 {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限_非master/管理/邀请者"))
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					if ctx.IsPrivate {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					if err := SetBotOffAtGroup(ctx, ctx.Group.GroupID()); err != nil {
						ctx.setExecutionError(err)
						ReplyToSender(ctx, msg, fmt.Sprintf("关闭失败：%v", err))
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子关闭"))
					return CmdExecuteResult{Matched: true, Solved: true}
				} else if cmdArgs.IsArgEqual(1, "bye", "exit", "quit") {
					if ctx.IsPrivate {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					if ctx.PrivilegeLevel < 40 {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限_非master/管理"))
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					if !cmdArgs.AmIBeMentioned && !ctx.Dice.Config().BotExitWithoutAt {
						// 裸指令，如果当前群内开启，予以提示
						if ctx.IsCurGroupBotOn {
							ReplyToSender(ctx, msg, "[退群指令] 请@我使用这个命令，以进行确认")
						}
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					targetGroupID := msg.GroupID
					inputCode := ""
					hasExtraArgs := false
					confirmCommand := ".bot bye"

					arg2 := strings.TrimSpace(cmdArgs.GetArgN(2))
					arg3 := strings.TrimSpace(cmdArgs.GetArgN(3))
					arg4 := strings.TrimSpace(cmdArgs.GetArgN(4))
					if arg2 != "" {
						confirmKey := getDismissConfirmKeyForGroup(ctx, msg.Sender.UserID, msg.GroupID)
						if arg3 == "" && isDismissConfirmCode(arg2) {
							if confirmCode, ok := loadDismissConfirmCode(confirmKey); ok && confirmCode == arg2 {
								inputCode = arg2
							} else {
								targetGroupID = normalizeDismissTargetGroupID(ctx, arg2)
								confirmCommand = ".bot bye " + arg2
							}
						} else {
							targetGroupID = normalizeDismissTargetGroupID(ctx, arg2)
							inputCode = arg3
							hasExtraArgs = arg4 != ""
							confirmCommand = ".bot bye " + arg2
						}
					}

					if targetGroupID == "" {
						return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
					}

					return d.executeDismissWithConfirm(ctx, msg, targetGroupID, inputCode, hasExtraArgs, confirmCommand)
				} else if cmdArgs.IsArgEqual(1, "save") {
					// 当前执行统一提交，回复只会在提交成功后投递。

					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰子保存设置"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}

			if cmdArgs.SomeoneBeMentionedButNotMe {
				return CmdExecuteResult{Matched: false, Solved: false}
			}

			activeCount := 0
			serveCount := 0
			projected, projectionErr := groupstate.ListProjected(ctx.domainContext(), d.DurableStore, d.BaseConfig.Name)
			if projectionErr != nil {
				ctx.setExecutionError(projectionErr)
				ReplyToSender(ctx, msg, fmt.Sprintf("读取群组状态失败：%v", projectionErr))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			for _, group := range projected {
				if group.GroupID != "" && !group.Deleted &&
					!strings.HasPrefix(group.GroupID, "PG-") &&
					group.DiceIDExists[ctx.EndPoint.UserID] {
					serveCount++
					if group.DiceIDActive[ctx.EndPoint.UserID] {
						activeCount++
					}
				}
			}

			var groupWorkInfo, activeText string
			if inGroup {
				activeText = "关闭"
				if ctx.Group.IsActive(ctx) {
					activeText = "开启"
				}
				groupWorkInfo = "\n群内工作状态: " + activeText
			}

			VarSetValueInt64(ctx, "$t供职群数", int64(serveCount))
			VarSetValueInt64(ctx, "$t启用群数", int64(activeCount))
			VarSetValueStr(ctx, "$t群内工作状态", groupWorkInfo)
			VarSetValueStr(ctx, "$t群内工作状态_仅状态", activeText)
			text := DiceFormatTmpl(ctx, "核心:骰子状态文本")

			ReplyToSender(ctx, msg, text)

			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["bot"] = cmdBot

	helpForDismiss := ".dismiss // 退出当前群，主用于QQ，支持机器人的平台可以直接移出成员"
	cmdDismiss := &CmdItemInfo{
		Name:              "dismiss",
		ShortHelp:         helpForDismiss,
		Help:              "退群(映射到bot bye):\n" + helpForDismiss,
		Raw:               true,
		DisabledInPrivate: true,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			if ctx.IsPrivate {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.SomeoneBeMentionedButNotMe {
				// 如果是别人被at，置之不理
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if !cmdArgs.AmIBeMentioned && !ctx.Dice.Config().BotExitWithoutAt {
				// 裸指令，如果当前群内开启，予以提示
				if ctx.IsCurGroupBotOn {
					ReplyToSender(ctx, msg, "[退群指令] 请@我使用这个命令，以进行确认")
				}
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			return d.executeDismissWithConfirm(ctx, msg, msg.GroupID, cmdArgs.GetArgN(1), cmdArgs.GetArgN(2) != "", ".dismiss")
		},
	}
	d.CmdMap["dismiss"] = cmdDismiss

	readIDList := func(ctx *MsgContext, _ *Message, cmdArgs *CmdArgs) []string {
		var uidLst []string
		for _, i := range cmdArgs.At {
			if i.UserID == ctx.EndPoint.UserID {
				// 不许添加自己
				continue
			}
			uidLst = append(uidLst, i.UserID)
		}

		if len(cmdArgs.Args) > 1 {
			for _, i := range cmdArgs.Args[1:] {
				if i == "me" {
					uidLst = append(uidLst, ctx.Player.UserID())
					continue
				}
				uid := FormatDiceIDQQ(i)
				uidLst = append(uidLst, uid)
			}
		}
		return uidLst
	}

	botListHelp := ".botlist add @A @B @C // 标记群内其他机器人，以免发生误触和无限对话\n" +
		".botlist add @A @B --s  // 同上，不过骰子不会做出回复\n" +
		".botlist del @A @B @C // 去除机器人标记\n" +
		".botlist list/show // 查看当前列表"
	cmdBotList := &CmdItemInfo{
		Name:      "botlist",
		ShortHelp: botListHelp,
		Help:      "机器人列表:\n" + botListHelp,
		Raw:       true,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			if ctx.IsPrivate {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			cmdArgs.ChopPrefixToArgsWith("add", "rm", "del", "show", "list")

			checkSlience := func() bool {
				return (!cmdArgs.AmIBeMentionedFirst) || cmdArgs.GetKwarg("s") != nil ||
					cmdArgs.GetKwarg("slience") != nil
			}

			reply := ""
			showHelp := false

			subCmd := cmdArgs.GetArgN(1)
			switch subCmd {
			case "add":
				allCount := 0
				existsCount := 0
				newCount := 0
				for _, uid := range readIDList(ctx, msg, cmdArgs) {
					allCount++
					if ctx.Group.BotExists(uid) {
						existsCount++
						continue
					}
					if err := ctx.Group.SetBot(uid, true); err != nil {
						ctx.setExecutionError(err)
						ReplyToSender(ctx, msg, fmt.Sprintf("机器人列表写入失败：%v", err))
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					newCount++
				}

				reply = fmt.Sprintf(
					"新增标记了%d/%d个帐号，这些账号将被视为机器人。\n因此他们被人@，或主动发出指令时，余烬将不会回复。\n另外对于botlist add/rm，如果群里有多个余烬，只有第一个被@的会回复，其余的执行指令但不回应",
					newCount, allCount,
				)
			case "del", "rm":
				allCount := 0
				existsCount := 0
				for _, uid := range readIDList(ctx, msg, cmdArgs) {
					allCount++
					if !ctx.Group.BotExists(uid) {
						continue
					}
					existsCount++
					if err := ctx.Group.SetBot(uid, false); err != nil {
						ctx.setExecutionError(err)
						ReplyToSender(ctx, msg, fmt.Sprintf("机器人列表写入失败：%v", err))
						return CmdExecuteResult{Matched: true, Solved: true}
					}
				}

				reply = fmt.Sprintf(
					"删除标记了%d/%d个帐号，这些账号将不再被视为机器人。\n余烬将继续回应他们的命令",
					existsCount, allCount,
				)
			case "list", "show":
				if cmdArgs.SomeoneBeMentionedButNotMe {
					break
				}

				var text strings.Builder
				for _, id := range ctx.Group.BotIDs() {
					text.WriteString("- ")
					text.WriteString(id)
					text.WriteByte('\n')
				}
				if text.Len() == 0 {
					text.WriteString("无")
				}
				reply = fmt.Sprintf("群内其他机器人列表:\n%s", text.String())
			default:
				showHelp = !cmdArgs.SomeoneBeMentionedButNotMe
			}

			// NOTE(Xiangze-Li): 不可使用 ctx.IsCurGroupBotOn, 因其将被 at 也视为开启
			if ctx.Group.IsActive(ctx) {
				if len(reply) > 0 {
					if !checkSlience() {
						ReplyToSender(ctx, msg, reply)
					} else {
						d.Logger.Infof("botlist 静默执行: " + reply)
					}
				}
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: showHelp}
			}
			if len(reply) > 0 {
				d.Logger.Infof("botlist 静默执行: " + reply)
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["botlist"] = cmdBotList

	var (
		reloginFlag     bool
		reloginLastTime int64
		updateCode      = "0000"
	)

	var masterListHelp = `.master add @A @B // 将别人标记为骰主
.master del @A @B @C // 去除骰主标记
.master list // 查看当前骰主列表
.master reboot // 重新启动(需要二次确认)
.master checkupdate // 检查更新(需要二次确认)
.master relogin // 30s后重新登录，有机会清掉风控(仅master可用)
.master backup // 做一次备份
.master reload deck/js/helpdoc // 重新加载牌堆/js/帮助文档
.master quitgroup <群组ID> [<理由>] // 从指定群组中退出，必须在同一平台使用
.master jsclear <插件ID> // 清除指定插件的存储，随后重载JS环境`

	cmdMaster := &CmdItemInfo{
		Name:          "master",
		ShortHelp:     masterListHelp,
		Help:          "骰主指令:\n" + masterListHelp,
		AllowDelegate: true,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			var subCmd string

			cmdArgs.ChopPrefixToArgsWith(
				"unlock", "rm", "del", "add", "checkupdate", "reboot", "backup", "reload",
			)
			ctx.DelegateText = ""
			subCmd = cmdArgs.GetArgN(1)

			if subCmd != "add" && subCmd != "del" && subCmd != "rm" {
				// 如果不是add/del/rm，那么就不需要代骰
				// 补充，在组内才这样，私聊不需要at
				if ctx.MessageType == "group" && (!cmdArgs.AmIBeMentionedFirst && len(cmdArgs.At) > 0) {
					return CmdExecuteResult{Matched: false, Solved: false}
				}
			}

			pRequired := 100

			// 单独处理解锁指令
			if subCmd == "unlock" {
				// NOTE(lyjjl): master unlock 已禁用，避免绕过 master 列表的权限检查。
				ReplyToSender(ctx, msg, "该指令已禁用")
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			if ctx.PrivilegeLevel < pRequired {
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限"))
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			switch subCmd {
			case "add":
				for _, arg := range cmdArgs.Args[1:] {
					if arg == "me" {
						ReplyToSender(ctx, msg, "该指令已禁用")
						return CmdExecuteResult{Matched: true, Solved: true}
					}
				}
				var count int
				for _, uid := range readIDList(ctx, msg, cmdArgs) {
					if uid == ctx.EndPoint.UserID {
						continue
					}
					changed, err := ctx.Dice.SetDiceMasterForContext(ctx, uid, true)
					if err != nil {
						ctx.setExecutionError(err)
						ReplyToSender(ctx, msg, "新增Master失败："+err.Error())
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					if changed {
						count++
					}
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("余烬将新增%d位master", count))
			case "del", "rm":
				var count int
				for _, uid := range readIDList(ctx, msg, cmdArgs) {
					changed, err := ctx.Dice.SetDiceMasterForContext(ctx, uid, false)
					if err != nil {
						ctx.setExecutionError(err)
						ReplyToSender(ctx, msg, "移除Master失败："+err.Error())
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					if changed {
						count++
					}
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("余烬移除了%d名master", count))
			case "relogin":
				var kw *Kwarg

				if kw = cmdArgs.GetKwarg("cancel"); kw != nil {
					if reloginFlag {
						reloginFlag = false
						ReplyToSender(ctx, msg, "已取消重登录")
					} else {
						ReplyToSender(ctx, msg, "错误: 不存在能够取消的重新登录行为")
					}
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				endpointID := ctx.EndPoint.ID
				doRelogin := func(reply func(text string)) {
					reloginLastTime = time.Now().Unix()
					reply("开始执行重新登录")
					reloginFlag = false
					time.Sleep(1 * time.Second)
					if err := d.ReloginEndpoint(context.Background(), endpointID); err != nil {
						d.Logger.Errorf("重新登录 endpoint 失败: %v", err)
					}
				}

				if time.Now().Unix()-reloginLastTime < 5*60 {
					ReplyToSender(
						ctx,
						msg,
						fmt.Sprintf(
							"执行过不久，指令将在%d秒后可以使用",
							5*60-(time.Now().Unix()-reloginLastTime),
						),
					)
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				if kw = cmdArgs.GetKwarg("now"); kw != nil {
					doRelogin(func(text string) { ReplyToSender(ctx, msg, text) })
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				reloginFlag = true
				ReplyToSender(ctx, msg, "将在30s后重新登录，期间可以输入.master relogin --cancel解除\n若遭遇风控，可能会没有任何输出。静等或输入.master relogin --now立即执行\n此指令每5分钟只能执行一次，可能解除风控，也可能使骰子失联。后果自负")

				// The delayed run happens after this command returned and released its
				// context, so its report goes through a detached reply.
				reply := ctx.detachReply(msg)
				go func() {
					time.Sleep(30 * time.Second)
					if reloginFlag {
						doRelogin(reply)
					}
				}()
			case "backup":
				ReplyToSender(ctx, msg, "开始备份数据")

				_, err := ctx.Dice.Parent.Backup(ctx.Dice.Parent.AutoBackupSelection, false)
				if err == nil {
					ReplyToSender(ctx, msg, "备份成功！请到UI界面(综合设置-备份)处下载备份，或在骰子backup目录下读取")
				} else {
					ctx.setExecutionError(err)
					d.Logger.Error("骰子备份:", err)
					ReplyToSender(ctx, msg, "备份失败！错误已写入日志。可能是磁盘已满所致，建议立即进行处理！")
				}
			case "checkupdate":
				var dm = ctx.Dice.Parent
				if dm.JustForTest {
					ReplyToSender(ctx, msg, "此指令在展示模式下不可用")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				if runtime.GOOS == "android" {
					ReplyToSender(ctx, msg, "检测到手机版，手机版余烬不支持指令更新，请手动下载新版本安装包")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				if dm.ContainerMode {
					ReplyToSender(ctx, msg, "容器模式下禁止指令更新，请手动拉取最新镜像")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				code := cmdArgs.GetArgN(2)
				if code == "" {
					var text string
					dm.AppVersionOnline = nil
					dm.UpdateCheckRequestChan <- 1

					// 等待获取新版本，最多10s
					for range 5 {
						time.Sleep(2 * time.Second)
						if dm.AppVersionOnline != nil {
							break
						}
					}

					if dm.AppVersionOnline != nil {
						text = fmt.Sprintf("当前本地版本为: %s\n当前线上版本为: %s", VERSION.String(), dm.AppVersionOnline.VersionLatestDetail)
						if dm.AppVersionCode != dm.AppVersionOnline.VersionLatestCode {
							generatedCode, err := generateFourDigitCode()
							if err != nil {
								ctx.setExecutionError(err)
								updateCode = "0000"
								text += "\n无法生成安全确认码，请稍后重试"
							} else {
								updateCode = generatedCode
								text += fmt.Sprintf("\n如需升级，请输入.master checkupdate %s 确认进行升级\n升级将花费约2分钟，升级失败可能导致进程关闭，建议在接触服务器情况下操作。\n当前进程启动时间: %s", updateCode, time.Unix(dm.AppBootTime, 0).Format("2006-01-02 15:04:05"))
							}
						}
					} else {
						text = fmt.Sprintf("当前本地版本为: %s\n当前线上版本为: %s", VERSION.String(), "未知")
					}
					ReplyToSender(ctx, msg, text)
					break
				}

				if code != updateCode || updateCode == "0000" {
					ReplyToSender(ctx, msg, "无效的升级指令码")
					break
				}

				ReplyToSender(ctx, msg, "开始下载新版本，完成后将自动进行一次备份")
				// The download finishes long after this command returned and released
				// its context, so the goroutine keeps only stable references and
				// reports through a detached reply.
				reply := ctx.detachReply(msg)
				upgradeWindowID := msg.Sender.UserID
				if !ctx.IsPrivate {
					upgradeWindowID = ctx.Group.GroupID()
				}
				upgradeEndpointID := ctx.EndPoint.ID
				if err := d.SetUpgradeTargetForContext(ctx, upgradeWindowID, upgradeEndpointID); err != nil {
					ctx.setExecutionError(err)
					ReplyToSender(ctx, msg, fmt.Sprintf("保存升级回复目标失败：%v", err))
					break
				}
				go func() {
					ret := <-dm.UpdateDownloadedChan

					bakFn, _ := dm.Backup(BackupSelectionAll, false)
					tmpPath := path.Join(os.TempDir(), bakFn)
					_ = os.MkdirAll(tmpPath, 0755)
					d.Logger.Infof("将备份文件复制到此路径: %s", tmpPath)
					_ = cp.Copy(path.Join(BackupDir, bakFn), tmpPath)

					if ret == "" {
						reply("准备开始升级，服务即将离线")
					} else {
						reply("升级失败，原因: " + ret)
					}
				}()
				dm.UpdateRequestChan <- d
			case "reboot":
				var dm = ctx.Dice.Parent
				if dm.JustForTest {
					ReplyToSender(ctx, msg, "此指令在展示模式下不可用")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				code := cmdArgs.GetArgN(2)
				if code == "" {
					generatedCode, err := generateFourDigitCode()
					if err != nil {
						ctx.setExecutionError(err)
						updateCode = "0000"
						ReplyToSender(ctx, msg, "无法生成安全确认码，请稍后重试")
						break
					}
					updateCode = generatedCode
					text := fmt.Sprintf("进程重启:\n如需重启，请输入.master reboot %s 确认进行重启\n升级将花费约2分钟，失败可能导致进程关闭，建议在接触服务器情况下操作。\n当前进程启动时间: %s", updateCode, time.Unix(dm.AppBootTime, 0).Format("2006-01-02 15:04:05"))
					ReplyToSender(ctx, msg, text)
					break
				}

				if code == updateCode && updateCode != "0000" {
					ReplyToSender(ctx, msg, "3秒后开始重启")
					time.Sleep(3 * time.Second)
					dm.RebootRequestChan <- 1
				} else {
					ReplyToSender(ctx, msg, "无效的重启指令码")
				}
			case "list":
				var textBuilder strings.Builder
				masters, err := ctx.Dice.DiceMasterIDsForContext(ctx)
				if err != nil {
					ctx.setExecutionError(err)
					ReplyToSender(ctx, msg, "读取Master列表失败："+err.Error())
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				for _, i := range masters {
					// uid := FormatDiceIdQQ(i)
					textBuilder.WriteString("- ")
					textBuilder.WriteString(i)
					textBuilder.WriteString("\n")
				}
				text := textBuilder.String()
				if text == "" {
					text = "无"
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("Master列表:\n%s", text))
			case "reload":
				dice := ctx.Dice
				switch cmdArgs.GetArgN(2) {
				case "deck":
					DeckReload(dice)
					ReplyToSender(ctx, msg, "牌堆已重载")
				case "js":
					dice.JsReload()
					ReplyToSender(ctx, msg, "js已重载")
				case "help", "helpdoc":
					dm := dice.Parent
					if !dm.IsHelpReloading.Load() {
						if err := dm.ReloadHelp(); err != nil {
							ctx.setExecutionError(err)
							ReplyToSender(ctx, msg, "帮助文档重载失败: "+err.Error())
						} else {
							ReplyToSender(ctx, msg, "帮助文档已重载")
						}
					} else {
						ReplyToSender(ctx, msg, "帮助文档正在重新装载")
					}
				}
			case "quitgroup":
				gid := cmdArgs.GetArgN(2)
				if gid == "" {
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				}

				n := strings.Split(gid, ":")
				platform := strings.Split(n[0], "-")[0]

				gp, err := ctx.ResolveGroup(ctx.domainContext(), gid)
				if err != nil {
					ctx.setExecutionError(err)
					ReplyToSender(ctx, msg, fmt.Sprintf("读取群组%s失败：%v", gid, err))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				if gp.Version() == 0 || gp.Deleted() || len(n[0]) < 2 {
					ReplyToSender(ctx, msg, fmt.Sprintf("群组列表中没有找到%s", gid))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				if msg.Platform != platform {
					ReplyToSender(ctx, msg, fmt.Sprintf("目标群组不在当前平台，请前往%s完成操作", platform))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				// 既然是骰主自己操作，就不通知了
				// 除非有多骰主……
				ReplyToSender(ctx, msg, fmt.Sprintf("收到指令，将在5秒后退出群组%s", gp.GroupID()))

				txt := "注意，收到骰主指令，5秒后将从该群组退出。"
				wherefore := cmdArgs.GetArgN(3)
				if wherefore != "" {
					txt += fmt.Sprintf("原因: %s", wherefore)
				}

				mctx := ctx.ShallowCopy()
				mctx.MessageType = "group"
				mctx.Group = nil
				mctx.Player = nil
				mctx.IsPrivate = false
				if err := SubmitDurableGroupQuit(ctx.domainContext(), mctx, gp.GroupID(), txt); err != nil {
					ctx.setExecutionError(err)
					d.Logger.Errorf("骰主退群请求提交失败: group=%s error=%v", gp.GroupID(), err)
					ReplyToSender(ctx, msg, fmt.Sprintf("退群请求提交失败：%v", err))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				return CmdExecuteResult{Matched: true, Solved: true}
			case "jsclear":
				extName := cmdArgs.GetArgN(2)
				if extName == "" {
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				}

				ext := ctx.Dice.ExtFind(extName, false)
				if ext == nil {
					ReplyToSender(ctx, msg, "没有找到插件"+extName)
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				if !ext.IsJsExt {
					ReplyToSender(ctx, msg, fmt.Sprintf("%s是内置模块，为了骰子的正常运行，暂不支持清除", extName))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				err := ClearExtStorage(ctx.Dice, ext, extName)
				if err != nil {
					ctx.setExecutionError(err)
					ctx.Dice.Logger.Errorf("jsclear: %v", err)
					ReplyToSender(ctx, msg, "清除数据失败，请查看日志")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				d.JsReload()
				ReplyToSender(ctx, msg, fmt.Sprintf("已经清除%s数据，重新加载JS插件", extName))
				return CmdExecuteResult{Matched: true, Solved: true}
			default:
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["master"] = cmdMaster

	helpRoll := ".r <表达式> [<原因>] // 骰点指令\n.rh <表达式> <原因> // 暗骰"
	cmdRoll := &CmdItemInfo{
		EnableExecuteTimesParse: true,
		Name:                    "roll",
		ShortHelp:               helpRoll,
		Help:                    "骰点:\n" + helpRoll,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			var text string
			var diceResultExists bool
			var detail string

			if cmdArgs.IsArgEqual(1, "help") {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}

			ctx.SystemTemplate = ctx.Group.GetCharTemplate(ctx.Dice)
			if ctx.Dice.Config().CommandCompatibleMode {
				if (cmdArgs.Command == "rd" || cmdArgs.Command == "rhd" || cmdArgs.Command == "rdh") && len(cmdArgs.Args) >= 1 {
					if m, _ := regexp.MatchString(`^\d|优势|劣势|\+|-`, cmdArgs.CleanArgs); m {
						if cmdArgs.IsSpaceBeforeArgs {
							cmdArgs.CleanArgs = "d " + cmdArgs.CleanArgs
						} else {
							cmdArgs.CleanArgs = "d" + cmdArgs.CleanArgs
						}
					}
				}
			}

			var r *VMResultV2m
			var commandInfoItems []any

			rollOne := func() *CmdExecuteResult {
				forWhat := ""
				var matched string

				var diceResultX *ds.VMValue
				if len(cmdArgs.Args) >= 1 { //nolint:nestif
					var err error
					r, detail, err = DiceExprEvalBase(ctx, cmdArgs.CleanArgs, RollExtraFlags{
						DefaultDiceSideNum: getDefaultDicePoints(ctx),
						DisableBlock:       true,
						V2Only:             true,
					})

					if r != nil && !r.IsCalculated() {
						forWhat = cmdArgs.CleanArgs

						defExpr := "d"
						if ctx.diceExprOverwrite != "" {
							defExpr = ctx.diceExprOverwrite
						}
						r, detail, err = DiceExprEvalBase(ctx, defExpr, RollExtraFlags{
							DefaultDiceSideNum: getDefaultDicePoints(ctx),
							DisableBlock:       true,
						})
					}

					if r != nil {
						diceResultX = r.VMValue
						diceResultExists = true
					}

					if err == nil {
						matched = r.GetMatched()
						if forWhat == "" {
							forWhat = r.GetRestInput()
						}
					} else {
						errs := err.Error()
						if strings.HasPrefix(errs, "E1:") || strings.HasPrefix(errs, "E5:") || strings.HasPrefix(errs, "E6:") || strings.HasPrefix(errs, "E7:") || strings.HasPrefix(errs, "E8:") {
							ReplyToSender(ctx, msg, errs)
							return &CmdExecuteResult{Matched: true, Solved: true}
						}
						forWhat = cmdArgs.CleanArgs
					}
				}

				forWhat = LimitCommandReasonText(forWhat)
				VarSetValueStr(ctx, "$t原因", forWhat)
				if forWhat != "" {
					forWhatText := DiceFormatTmpl(ctx, "核心:骰点_原因")
					VarSetValueStr(ctx, "$t原因句子", forWhatText)
				} else {
					VarSetValueStr(ctx, "$t原因句子", "")
				}

				if diceResultExists { //nolint:nestif
					detailWrap := ""
					if detail != "" {
						detailWrap = "=" + detail
						re := regexp.MustCompile(`\[((\d+)d\d+)\=(\d+)\]`)
						match := re.FindStringSubmatch(detail)
						if len(match) > 0 {
							num := match[2]
							if num == "1" && (match[1] == matched || match[1] == "1"+matched) {
								detailWrap = ""
							}
						}
					}

					// 指令信息标记
					item := map[string]interface{}{
						"expr":   matched,
						"reason": forWhat,
					}

					if diceResultX != nil {
						switch diceResultX.TypeId {
						case ds.VMTypeInt:
							item["result"] = diceResultX.MustReadInt()
						case ds.VMTypeFloat:
							item["result"] = diceResultX.MustReadFloat()
						default:
							item["result"] = diceResultX.ToRepr()
						}
					}

					if forWhat == "" {
						delete(item, "reason")
					}
					commandInfoItems = append(commandInfoItems, item)

					VarSetValueStr(ctx, "$t表达式文本", matched)
					VarSetValueStr(ctx, "$t计算过程", detailWrap)
					// VarSetValueInt64(ctx, "$t计算结果", diceResult)
					VarSetValue(ctx, "$t计算结果", diceResultX)
				} else {
					var val int64
					var detail string
					dicePoints := getDefaultDicePoints(ctx)
					if ctx.diceExprOverwrite != "" {
						r, detail, _ = DiceExprEvalBase(ctx, cmdArgs.CleanArgs, RollExtraFlags{
							DefaultDiceSideNum: dicePoints,
							DisableBlock:       true,
						})
						if r != nil && r.TypeId == ds.VMTypeInt {
							valX, _ := r.ReadInt()
							val = int64(valX)
						}
					} else {
						r, _, _ = DiceExprEvalBase(ctx, "d", RollExtraFlags{
							DefaultDiceSideNum: dicePoints,
							DisableBlock:       true,
						})
						if r != nil && r.TypeId == ds.VMTypeInt {
							valX, _ := r.ReadInt()
							val = int64(valX)
						}
					}

					// 指令信息标记
					item := map[string]any{
						"expr":       fmt.Sprintf("D%d", dicePoints),
						"reason":     forWhat,
						"dicePoints": dicePoints,
						"result":     val,
					}
					if forWhat == "" {
						delete(item, "reason")
					}
					commandInfoItems = append(commandInfoItems, item)

					VarSetValueStr(ctx, "$t表达式文本", fmt.Sprintf("D%d", dicePoints))
					VarSetValueStr(ctx, "$t计算过程", detail)
					VarSetValueInt64(ctx, "$t计算结果", val)
				}
				return nil
			}

			if cmdArgs.SpecialExecuteTimes > 1 {
				VarSetValueInt64(ctx, "$t次数", int64(cmdArgs.SpecialExecuteTimes))
				if cmdArgs.SpecialExecuteTimes > int(ctx.Dice.Config().MaxExecuteTime) {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:骰点_轮数过多警告"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				var texts []string
				for range cmdArgs.SpecialExecuteTimes {
					ret := rollOne()
					if ret != nil {
						return *ret
					}
					texts = append(texts, DiceFormatTmpl(ctx, "核心:骰点_单项结果文本"))
				}
				VarSetValueStr(ctx, "$t结果文本", strings.Join(texts, "\n"))
				text = DiceFormatTmpl(ctx, "核心:骰点_多轮")
			} else {
				ret := rollOne()
				if ret != nil {
					return *ret
				}
				VarSetValueStr(ctx, "$t结果文本", DiceFormatTmpl(ctx, "核心:骰点_单项结果文本"))
				text = DiceFormatTmpl(ctx, "核心:骰点")
			}

			isHide := strings.Contains(cmdArgs.Command, "h")

			// 指令信息
			commandInfo := map[string]any{
				"cmd":    "roll",
				"pcName": ctx.Player.Name(),
				"items":  commandInfoItems,
			}
			if isHide {
				commandInfo["hide"] = isHide
			}
			ctx.CommandInfo = commandInfo

			if kw := cmdArgs.GetKwarg("asm"); r != nil && kw != nil {
				if ctx.PrivilegeLevel >= 40 {
					asm := r.GetAsmText()
					text += "\n" + asm
				}
			}

			if kw := cmdArgs.GetKwarg("ci"); kw != nil {
				info, err := json.Marshal(ctx.CommandInfo)
				if err == nil {
					text += "\n" + string(info)
				} else {
					text += "\n" + "指令信息无法序列化"
				}
			}

			if isHide {
				if msg.Platform == "QQ-CH" {
					ReplyToSender(ctx, msg, "QQ频道内尚不支持暗骰")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				if ctx.Group != nil {
					if ctx.IsPrivate {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_私聊不可用"))
					} else {
						ctx.CommandHideFlag = ctx.Group.GroupID()
						prefix := DiceFormatTmpl(ctx, "核心:暗骰_私聊_前缀")
						ReplyGroup(ctx, msg, DiceFormatTmpl(ctx, "核心:暗骰_群内"))
						ReplyPerson(ctx, msg, prefix+text)
					}
				} else {
					ReplyToSender(ctx, msg, text)
				}
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			ReplyToSender(ctx, msg, text)
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}

	helpRollX := ".rx <表达式> <原因> // 骰点指令\n.rxh <表达式> <原因> // 暗骰"
	cmdRollX := &CmdItemInfo{
		Name:          "roll",
		ShortHelp:     helpRoll,
		Help:          "骰点(和r相同，但支持代骰):\n" + helpRollX,
		AllowDelegate: true,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			mctx := GetCtxProxyFirst(ctx, cmdArgs)
			return cmdRoll.Solve(mctx, msg, cmdArgs)
		},
	}

	d.CmdMap["r"] = cmdRoll
	d.CmdMap["rd"] = cmdRoll
	d.CmdMap["roll"] = cmdRoll
	d.CmdMap["rh"] = cmdRoll
	d.CmdMap["rhd"] = cmdRoll
	d.CmdMap["rdh"] = cmdRoll
	d.CmdMap["rx"] = cmdRollX
	d.CmdMap["rxh"] = cmdRollX
	d.CmdMap["rhx"] = cmdRollX

	helpExt := ".ext // 查看扩展列表"
	cmdExt := &CmdItemInfo{
		Name:      "ext",
		ShortHelp: helpExt,
		Help:      "群扩展模块管理:\n" + helpExt,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			if cmdArgs.IsArgEqual(1, "help") {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			fail := func(action string, err error) CmdExecuteResult {
				ctx.setExecutionError(err)
				ReplyToSender(ctx, msg, fmt.Sprintf("%s失败：%v", action, err))
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			showList := func() {
				var text strings.Builder
				text.WriteString("检测到以下扩展(名称-版本-作者)：\n")
				for index, i := range ctx.Dice.ExtList {
					state := "关"
					for _, j := range ctx.Group.GetActivatedExtList(ctx.Dice) {
						if i.Name == j.Name {
							state = "开"
							break
						}
					}
					var officialMark string
					if i.Official {
						officialMark = "[官方]"
					}
					author := i.Author
					if author == "" {
						author = "<未注明>"
					}
					aliases := ""
					if len(i.Aliases) > 0 {
						aliases = "(" + strings.Join(i.Aliases, ",") + ")"
					}
					fmt.Fprintf(&text, "%d. [%s]%s%s %s - %s - %s\n", index+1, state, officialMark, i.Name, aliases, i.Version, author)
				}
				text.WriteString("使用命令: .ext <扩展名> on/off 可以在当前群开启或关闭某扩展。\n")
				text.WriteString("使用命令: .ext all on/off 可以在当前群开启或关闭全部扩展。\n")
				text.WriteString("命令: .ext <扩展名> 可以查看扩展介绍及帮助")
				ReplyToSender(ctx, msg, text.String())
			}

			if len(cmdArgs.Args) == 0 {
				showList()
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			var last int
			if len(cmdArgs.Args) >= 2 {
				last = len(cmdArgs.Args)
			}

			//nolint:nestif
			if cmdArgs.IsArgEqual(1, "list") {
				showList()
			} else if cmdArgs.IsArgEqual(last, "on") {
				if !ctx.Dice.Config().BotExtFreeSwitch && ctx.PrivilegeLevel < 40 {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限_非master/管理/邀请者"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				checkConflict := func(ext *ExtInfo) []string {
					var actived []string
					for _, i := range ctx.Group.GetActivatedExtList(ctx.Dice) {
						actived = append(actived, i.Name)
					}

					if ext.ConflictWith != nil {
						var ret []string
						for _, i := range intersect.Simple(actived, ext.ConflictWith) {
							ret = append(ret, i.(string))
						}
						return ret
					}
					return []string{}
				}

				var extNames []string
				var conflictsAll []string

				// 判断是否是 .ext all on
				if cmdArgs.IsArgEqual(1, "all") {
					for _, ext := range ctx.Dice.ExtList {
						isActive := false
						for _, activated := range ctx.Group.GetActivatedExtList(ctx.Dice) {
							if ext.Name == activated.Name {
								isActive = true
								break
							}
						}
						if !isActive {
							extNames = append(extNames, ext.Name)
							conflictsAll = append(conflictsAll, checkConflict(ext)...)
							if err := ctx.Group.ExtActive(ext); err != nil {
								return fail("开启扩展", err)
							}
						}
					}

					if len(extNames) == 0 {
						ReplyToSender(ctx, msg, "所有扩展已经处于开启状态，无需再次开启。")
					} else {
						text := fmt.Sprintf("已开启所有未激活的扩展: %s", strings.Join(extNames, ", "))
						if len(conflictsAll) > 0 {
							text += "\n检测到可能冲突的扩展，建议关闭: " + strings.Join(conflictsAll, ",")
							text += "\n对于扩展中存在的同名指令，则越晚开启的扩展，优先级越高。"
						}
						ReplyToSender(ctx, msg, text)
					}
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				var companionExtNames []string

				// 记录激活前已有的扩展
				beforeActivate := make(map[string]bool)
				for _, ext := range ctx.Group.GetActivatedExtList(ctx.Dice) {
					beforeActivate[ext.Name] = true
				}

				userActivatedNames := make(map[string]bool)

				// 排除最后一个参数 "on"
				for index := range len(cmdArgs.Args) - 1 {
					extName := strings.ToLower(cmdArgs.Args[index])
					if i := d.ExtFind(extName, false); i != nil {
						extNames = append(extNames, i.Name)
						userActivatedNames[i.Name] = true
						conflictsAll = append(conflictsAll, checkConflict(i)...)
						if err := ctx.Group.ExtActive(i); err != nil {
							return fail("开启扩展", err)
						}
					}
				}

				// 循环结束后统一检查新激活的伴随扩展
				for _, ext := range ctx.Group.GetActivatedExtList(ctx.Dice) {
					if !beforeActivate[ext.Name] && !userActivatedNames[ext.Name] {
						companionExtNames = append(companionExtNames, ext.Name)
					}
				}

				if len(extNames) == 0 {
					ReplyToSender(ctx, msg, "输入的扩展类别名无效")
				} else {
					text := fmt.Sprintf("打开扩展 %s", strings.Join(extNames, ","))
					if len(companionExtNames) > 0 {
						text += fmt.Sprintf("\n自动启用伴随扩展: %s", strings.Join(companionExtNames, ", "))
					}
					if len(conflictsAll) > 0 {
						text += "\n检测到可能冲突的扩展，建议关闭: " + strings.Join(conflictsAll, ",")
						text += "\n对于扩展中存在的同名指令，则越晚开启的扩展，优先级越高。"
					}
					ReplyToSender(ctx, msg, text)
				}
			} else if cmdArgs.IsArgEqual(last, "off") {
				if !ctx.Dice.Config().BotExtFreeSwitch && ctx.PrivilegeLevel < 40 {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限_非master/管理/邀请者"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				// 判断是否是 .ext all off
				if cmdArgs.IsArgEqual(1, "all") {
					before := ctx.Group.GetActivatedExtList(ctx.Dice)
					if len(before) == 0 {
						ReplyToSender(ctx, msg, "当前群没有开启任何扩展。")
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					beforeNames := make([]string, 0, len(before))
					for _, ext := range before {
						if ext != nil {
							beforeNames = append(beforeNames, ext.Name)
						}
					}

					for _, name := range beforeNames {
						if _, err := ctx.Group.ExtInactiveByName(name); err != nil {
							return fail("关闭扩展", err)
						}
					}

					after := ctx.Group.GetActivatedExtList(ctx.Dice)
					if len(after) == 0 {
						ReplyToSender(ctx, msg, fmt.Sprintf("已关闭全部扩展: %s", strings.Join(beforeNames, ", ")))
						return CmdExecuteResult{Matched: true, Solved: true}
					}

					afterSet := make(map[string]struct{}, len(after))
					for _, ext := range after {
						if ext != nil {
							afterSet[ext.Name] = struct{}{}
						}
					}

					var closed []string
					for _, name := range beforeNames {
						if _, stillOn := afterSet[name]; !stillOn {
							closed = append(closed, name)
						}
					}

					var stillOn []string
					for _, ext := range after {
						if ext != nil {
							stillOn = append(stillOn, ext.Name)
						}
					}

					ReplyToSender(ctx, msg, fmt.Sprintf("已尝试关闭全部扩展。\n已关闭: %s\n仍处于开启状态: %s", strings.Join(closed, ", "), strings.Join(stillOn, ", ")))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				var closed []string
				var companionClosed []string
				var notfound []string
				companionClosedSet := make(map[string]struct{})

				// 记录关闭前的扩展列表
				beforeDeactivate := make(map[string]bool)
				for _, ext := range ctx.Group.GetActivatedExtList(ctx.Dice) {
					beforeDeactivate[ext.Name] = true
				}
				directlyClosed := make(map[string]struct{})

				// 排除最后一个参数 "off"
				for index := range len(cmdArgs.Args) - 1 {
					extName := cmdArgs.Args[index]
					extName = d.ExtAliasToName(extName)

					ei, err := ctx.Group.ExtInactiveByName(extName)
					if err != nil {
						return fail("关闭扩展", err)
					}
					if ei != nil {
						closed = append(closed, ei.Name)
						directlyClosed[ei.Name] = struct{}{}
					} else {
						notfound = append(notfound, extName)
					}
				}

				// 检查被连带关闭的伴随扩展：差集 = 关闭前 - 关闭后 - 主动关闭
				afterDeactivate := make(map[string]bool)
				for _, ext := range ctx.Group.GetActivatedExtList(ctx.Dice) {
					afterDeactivate[ext.Name] = true
				}
				for closedExtName := range beforeDeactivate {
					if afterDeactivate[closedExtName] {
						continue
					}
					if _, manuallyClosed := directlyClosed[closedExtName]; manuallyClosed {
						continue
					}
					if _, alreadyAdded := companionClosedSet[closedExtName]; alreadyAdded {
						continue
					}
					companionClosedSet[closedExtName] = struct{}{}
					companionClosed = append(companionClosed, closedExtName)
				}

				var text string

				if len(closed) > 0 {
					text += fmt.Sprintf("关闭扩展: %s", strings.Join(closed, ","))
					if len(companionClosed) > 0 {
						text += fmt.Sprintf("\n自动关闭伴随扩展: %s", strings.Join(companionClosed, ", "))
					}
				} else {
					text += fmt.Sprintf(" 已关闭或未找到: %s", strings.Join(notfound, ","))
				}
				ReplyToSender(ctx, msg, text)
				return CmdExecuteResult{Matched: true, Solved: true}
			} else {
				extName := cmdArgs.Args[0]
				if i := d.ExtFind(extName, false); i != nil {
					text := fmt.Sprintf("> [%s] 版本%s 作者%s\n", i.Name, i.Version, i.Author)
					i.callWithJsCheck(d, func() {
						ReplyToSender(ctx, msg, text+i.GetDescText(i))
					}, jsCallbackDispatch{kind: jsCallbackCommand, message: ctx})
					return CmdExecuteResult{Matched: true, Solved: true}
				}
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["ext"] = cmdExt

	helpNN := ".nn // 查看当前角色名\n" +
		".nn <角色名> // 改为指定角色名，若有卡片不会连带修改\n" +
		".nn clr // 重置回群名片"
	cmdNN := &CmdItemInfo{
		Name:      "nn",
		ShortHelp: helpNN,
		Help:      "角色名设置:\n" + helpNN,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			fail := func(prefix string, err error) CmdExecuteResult {
				ctx.setExecutionError(err)
				ReplyToSender(ctx, msg, fmt.Sprintf("%s：%v", prefix, err))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			updatePlayerGroupCard := func() error {
				template := ctx.Player.AutoSetNameTemplate()
				if template == "" {
					return nil
				}
				_, err := SetPlayerGroupCardByTemplate(ctx, template)
				return err
			}
			val := strings.ToLower(cmdArgs.GetArgN(1))
			switch val {
			case "":
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:昵称_当前"))
			case "help":
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			case "clr", "reset":
				oldName := ctx.Player.Name()
				VarSetValueStr(ctx, "$t旧昵称", fmt.Sprintf("<%s>", oldName))
				VarSetValueStr(ctx, "$t旧昵称_RAW", oldName)
				if err := ctx.Player.SetName(msg.Sender.Nickname); err != nil {
					return fail("重置昵称失败", err)
				}
				VarSetValueStr(ctx, "$t玩家", fmt.Sprintf("<%s>", ctx.Player.Name()))
				VarSetValueStr(ctx, "$t玩家_RAW", ctx.Player.Name())
				if err := updatePlayerGroupCard(); err != nil {
					return fail("更新群名片失败", err)
				}
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:昵称_重置"))
			default:
				oldName := ctx.Player.Name()
				VarSetValueStr(ctx, "$t旧昵称", fmt.Sprintf("<%s>", oldName))
				VarSetValueStr(ctx, "$t旧昵称_RAW", oldName)
				if err := ctx.Player.SetName(cmdArgs.Args[0]); err != nil {
					return fail("修改昵称失败", err)
				}
				VarSetValueStr(ctx, "$t玩家", fmt.Sprintf("<%s>", ctx.Player.Name()))
				VarSetValueStr(ctx, "$t玩家_RAW", ctx.Player.Name())
				if err := updatePlayerGroupCard(); err != nil {
					return fail("更新群名片失败", err)
				}
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:昵称_改名"))
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["nn"] = cmdNN

	d.CmdMap["userid"] = &CmdItemInfo{
		Name:      "userid",
		ShortHelp: ".userid // 查看当前帐号和群组ID",
		Help:      "查看ID:\n.userid // 查看当前帐号和群组ID",
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			if cmdArgs.IsArgEqual(1, "help") {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			text := fmt.Sprintf("个人账号ID为 %s", ctx.Player.UserID())
			if !ctx.IsPrivate {
				text += fmt.Sprintf("\n当前群组ID为 %s", ctx.Group.GroupID())
			}

			ReplyToSender(ctx, msg, text)
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}

	randalgoHelp := formatDiceRandomModeHelpText()
	d.CmdMap["randalgo"] = &CmdItemInfo{
		Name:      "randalgo",
		ShortHelp: ".randalgo // 查看当前随机算法与规范\n.randalgo get [面数] // 对全部随机源各掷一次并显示单次耗时\n.randalgo set <模式> // 设置随机模式，仅Master可用",
		Help:      randalgoHelp,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			if cmdArgs.IsArgEqual(1, "help") {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			if cmdArgs.IsArgEqual(1, "get") {
				points := int64(100)
				if rawPoints := cmdArgs.GetArgN(2); rawPoints != "" {
					parsedPoints, err := strconv.ParseInt(rawPoints, 10, 64)
					if err != nil || parsedPoints <= 0 {
						ReplyToSender(ctx, msg, formatDiceRandomModeGetInvalidPointsText(rawPoints))
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					points = parsedPoints
				}

				ReplyToSender(ctx, msg, globalRandSource.ReportGetText(points))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			if cmdArgs.IsArgEqual(1, "set") {
				if ctx.PrivilegeLevel < 100 {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:提示_无权限"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				rawMode := cmdArgs.GetArgN(2)
				if rawMode == "" {
					ReplyToSender(ctx, msg, formatDiceRandomModeSetMissingModeText())
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				mode, ok := parseDiceRandomModeStrict(rawMode)
				if !ok {
					ReplyToSender(ctx, msg, formatDiceRandomModeSetInvalidModeText(rawMode))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				manager := ctx.Dice.Parent
				if manager == nil {
					ctx.setExecutionError(errors.New("DiceManager 未初始化"))
					ReplyToSender(ctx, msg, "随机模式配置不可用：DiceManager 未初始化")
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				effectiveMode, err := manager.SetDiceRandomModeForContext(ctx, mode)
				if err != nil {
					ctx.setExecutionError(err)
					if effectiveMode != "" && effectiveMode != mode {
						ReplyToSender(ctx, msg, fmt.Sprintf("随机模式 %s 当前不可用，仍使用 %s: %v", mode, effectiveMode, err))
					} else {
						ReplyToSender(ctx, msg, formatDiceRandomModeSetUnavailableText(mode, err))
					}
					return CmdExecuteResult{Matched: true, Solved: true}
				}

				ReplyToSender(ctx, msg, formatDiceRandomModeSetSuccessText(mode))
				return CmdExecuteResult{Matched: true, Solved: true}
			}

			mode := DiceRandomModePCG
			if ctx.Dice.Parent != nil {
				mode = ctx.Dice.Parent.GetDiceRandomMode()
			}
			ReplyToSender(ctx, msg, globalRandSource.ReportStatusText(mode))
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["rollshape"] = &CmdItemInfo{
		Name:      "rollshape",
		ShortHelp: ".rollshape // 查看当前生效范围和模式\n.rollshape set <模式> // 设置模式；群聊需管理员，私聊由发送者本人设置\n.rollshape off // 恢复 Raw / Uniform",
		Help:      formatDiceRollShaperHelpText(),
		Solve:     solveDiceRollShaper,
	}

	helpSet := ".set info// 查看当前面数设置\n" +
		".set dnd/coc // 设置群内骰子面数为20/100，并自动开启对应扩展 \n" +
		".set <面数> // 设置群内骰子面数\n" +
		".set clr // 清除群内骰子面数设置"
	cmdSet := &CmdItemInfo{
		Name:      "set",
		ShortHelp: helpSet,
		Help:      "设定骰子面数:\n" + helpSet,
		HelpFunc: func(isShort bool) string {
			text := ".set info // 查看当前面数设置\n"
			text += ".set <面数> // 设置群内骰子面数\n"
			text += ".set dnd // 设置群内骰子面数为20，并自动开启对应扩展\n"
			d.GameSystemMap.Range(func(key string, tmpl *GameSystemTemplate) bool {
				textHelp := fmt.Sprintf("设置群内骰子面数为%d，并自动开启对应扩展", tmpl.SetConfig.DiceSides)
				text += fmt.Sprintf(".set %s // %s\n", strings.Join(tmpl.SetConfig.Keys, "/"), textHelp)
				return true
			})
			text += `.set clr // 清除群内骰子面数设置`
			if isShort {
				return text
			}
			return "设定骰子面数:\n" + text
		},
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			fail := func(prefix string, err error) CmdExecuteResult {
				ctx.setExecutionError(err)
				ReplyToSender(ctx, msg, fmt.Sprintf("%s：%v", prefix, err))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			isSetGroup := cmdArgs.GetKwarg("my") == nil
			arg1 := cmdArgs.GetArgN(1)
			if arg1 == "" {
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}

			modSwitch := false
			tipText := "\n提示:"
			var switchErr error
			ctx.Dice.GameSystemMap.Range(func(key string, tmpl *GameSystemTemplate) bool {
				isMatch := false
				for _, candidate := range tmpl.SetConfig.Keys {
					if strings.EqualFold(arg1, candidate) {
						isMatch = true
						break
					}
				}
				if !isMatch {
					return true
				}

				modSwitch = true
				if switchErr = ctx.Group.SetSystem(key); switchErr != nil {
					return false
				}
				if switchErr = ctx.Group.SetDiceSideNum(tmpl.SetConfig.DiceSides); switchErr != nil {
					return false
				}

				enableTip := tmpl.SetConfig.EnableTip
				if enableTip == "" {
					extNames := append([]string(nil), tmpl.Commands.Set.RelatedExt...)
					enableTip = fmt.Sprintf("已切换至 %s(%s) 规则，默认骰子面数 %s，自动启用关联扩展: %s", tmpl.FullName, tmpl.Name, tmpl.Commands.Set.DiceSideExpr, strings.Join(extNames, ", "))
				}
				tipText += enableTip
				cmdArgs.Args[0] = strconv.FormatInt(tmpl.SetConfig.DiceSides, 10)

				for _, name := range tmpl.SetConfig.RelatedExt {
					if extension := ctx.Dice.ExtFind(name, false); extension != nil {
						if switchErr = ctx.Group.ExtActive(extension); switchErr != nil {
							return false
						}
					}
				}
				return false
			})
			if switchErr != nil {
				return fail("切换规则失败", switchErr)
			}

			num, err := strconv.ParseInt(cmdArgs.Args[0], 10, 64)
			if num < 0 {
				num = 0
			}
			if err == nil {
				if isSetGroup {
					if !modSwitch {
						if err = ctx.Group.SetDiceSideNum(num); err != nil {
							return fail("设置群组骰子面数失败", err)
						}
						switch num {
						case 20:
							tipText += "20面骰。如果要进行DND游戏，建议执行.set dnd以确保开启dnd5e指令"
						case 100:
							tipText += "100面骰。如果要进行COC游戏，建议执行.set coc以确保开启coc7指令"
						}
					}
					if tipText == "\n提示:" {
						tipText = ""
					}
					VarSetValueInt64(ctx, "$t群组骰子面数", ctx.Group.DiceSideNum())
					VarSetValueInt64(ctx, "$t当前骰子面数", getDefaultDicePoints(ctx))
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:设定默认群组骰子面数")+tipText)
				} else {
					if err = ctx.Player.SetDiceSideNum(num); err != nil {
						return fail("设置个人骰子面数失败", err)
					}
					VarSetValueInt64(ctx, "$t个人骰子面数", ctx.Player.DiceSideNum())
					VarSetValueInt64(ctx, "$t当前骰子面数", getDefaultDicePoints(ctx))
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:设定默认骰子面数"))
				}
			} else {
				switch arg1 {
				case "clr":
					if isSetGroup {
						if err = ctx.Group.SetDiceSideNum(0); err != nil {
							return fail("清除群组骰子面数失败", err)
						}
					} else if err = ctx.Player.SetDiceSideNum(0); err != nil {
						return fail("清除个人骰子面数失败", err)
					}
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:设定默认骰子面数_重置"))
				case "help":
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				case "info":
					ReplyToSender(ctx, msg, DiceFormat(ctx, `个人骰子面数: {$t个人骰子面数}\n`+
						`群组骰子面数: {$t群组骰子面数}\n当前骰子面数: {$t当前骰子面数}`))
				default:
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:设定默认骰子面数_错误"))
				}
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["set"] = cmdSet

	helpCh := ".pc new <角色名> // 新建角色并绑卡\n" +
		".pc tag [<角色名> | <角色序号>] // 当前群绑卡/解除绑卡(不填角色名)\n" +
		".pc untagAll [<角色名> | <角色序号>] // 全部群解绑(不填即当前卡)\n" +
		".pc list // 列出当前角色和序号\n" +
		".pc rename <新角色名> // 将当前绑定角色改名\n" +
		".pc rename <角色名|序号> <新角色名> // 将指定角色改名 \n" +
		// ".ch group // 列出各群当前绑卡\n" +
		".pc save [<角色名>] // [不绑卡]保存角色，角色名可省略\n" +
		".pc load (<角色名> | <角色序号>) // [不绑卡]加载角色\n" +
		".pc del/rm (<角色名> | <角色序号>) // 删除角色 角色序号可用pc list查询\n" +
		"> 注: 余烬各群数据独立(多张空白卡)，单群游戏不需要存角色。"

	cmdChar := &CmdItemInfo{
		Name:      "pc",
		ShortHelp: helpCh,
		Help:      "角色管理:\n" + helpCh,
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			cmdArgs.ChopPrefixToArgsWith("list", "lst", "load", "save", "del", "rm", "new", "tag", "untagAll", "rename")
			val1 := cmdArgs.GetArgN(1)
			am := d.AttrsManager
			userID := ctx.Player.UserID()
			groupID := ctx.Group.GroupID()

			fail := func(prefix string, err error) CmdExecuteResult {
				ctx.setExecutionError(err)
				ReplyToSender(ctx, msg, fmt.Sprintf("%s: %v", prefix, err))
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			copyValues := func(source, target *AttributesItem) error {
				snapshot := make(map[string]*ds.VMValue)
				source.Range(func(key string, value *ds.VMValue) bool {
					snapshot[key] = value
					return true
				})
				return target.MutateValues(func(values *ds.ValueMap) {
					values.Clear()
					for key, value := range snapshot {
						values.Store(key, value)
					}
				})
			}
			updatePlayerGroupCard := func() error {
				template := ctx.Player.AutoSetNameTemplate()
				if template == "" {
					return nil
				}
				_, err := SetPlayerGroupCardByTemplate(ctx, template)
				return err
			}
			getNicknameRaw := func(usePlayerName bool, tryIndex bool) (string, error) {
				name := cmdArgs.CleanArgsChopRest
				if tryIndex {
					index, err := strconv.ParseInt(name, 10, 64)
					if err == nil && index > 0 {
						items, listErr := am.GetCharacterListForCtx(ctx, userID)
						if listErr != nil {
							return "", listErr
						}
						if index <= int64(len(items)) {
							return items[index-1].Name, nil
						}
					}
				}
				if usePlayerName && name == "" {
					name = ctx.Player.Name()
				}
				name = strings.ReplaceAll(name, "\n", "")
				name = strings.ReplaceAll(name, "\r", "")
				if len(name) > 90 {
					name = name[:90]
				}
				return name, nil
			}
			resolveCharacterID := func(name string) (string, error) {
				index, err := strconv.ParseInt(name, 10, 64)
				if err == nil && index > 0 {
					items, listErr := am.GetCharacterListForCtx(ctx, userID)
					if listErr != nil {
						return "", listErr
					}
					if index <= int64(len(items)) {
						return items[index-1].Id, nil
					}
				}
				return am.CharIdGetByNameForCtx(ctx, userID, name)
			}
			getBindingID := func() (string, error) {
				return am.CharGetBindingIdForCtx(ctx, groupID, userID)
			}
			setCurPlayerName := func(name string) error {
				return ctx.Player.SetName(name)
			}

			switch val1 {
			case "list", "lst":
				list, err := am.GetCharacterListForCtx(ctx, userID)
				if err != nil {
					return fail("读取角色列表失败", err)
				}
				bindingID, err := getBindingID()
				if err != nil {
					return fail("读取当前绑定失败", err)
				}

				var newChars []string
				for idx, item := range list {
					prefix := "[×]"
					if item.BindingGroupsNum > 0 {
						prefix = "[★]"
					}
					if bindingID == item.Id {
						prefix = "[√]"
					}
					suffix := ""
					if item.SheetType != "" {
						suffix = fmt.Sprintf(" #%s", item.SheetType)
					}
					newChars = append(newChars, fmt.Sprintf("%2d %s %s%s", idx+1, prefix, item.Name, suffix))
				}

				if len(list) == 0 {
					ReplyToSender(ctx, msg, fmt.Sprintf("<%s>当前还没有角色列表", ctx.Player.Name()))
				} else {
					ReplyToSender(ctx, msg, fmt.Sprintf("<%s>的角色列表为:\n%s\n[√]已绑 [×]未绑 [★]其他群绑定", ctx.Player.Name(), strings.Join(newChars, "\n")))
				}
				return CmdExecuteResult{Matched: true, Solved: true}

			case "new":
				name, err := getNicknameRaw(true, false)
				if err != nil {
					return fail("读取角色名失败", err)
				}
				VarSetValueStr(ctx, "$t角色名", name)
				exists, err := am.CharCheckExistsForCtx(ctx, userID, name)
				if err != nil {
					return fail("检查角色失败", err)
				}
				if !exists {
					item, createErr := am.CharNewForCtx(ctx, userID, name, ctx.Group.System())
					if createErr != nil {
						return fail("新建角色失败", createErr)
					}
					if err = am.CharBindForCtx(ctx, item.Id, groupID, userID); err != nil {
						return fail("绑定角色失败", err)
					}
					if err = setCurPlayerName(name); err != nil {
						return fail("更新当前角色名失败", err)
					}
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_新建"))
				} else {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_新建_已存在"))
				}
				if err = updatePlayerGroupCard(); err != nil {
					return fail("更新群名片失败", err)
				}
				return CmdExecuteResult{Matched: true, Solved: true}

			case "rename":
				var charID string
				a := cmdArgs.GetArgN(2)
				b := cmdArgs.GetArgN(3)
				var err error
				if b == "" {
					b = a
					charID, err = getBindingID()
				} else {
					charID, err = resolveCharacterID(a)
				}
				if err != nil {
					return fail("读取角色失败", err)
				}
				if a != "" && b != "" {
					if charID == "" {
						ReplyToSender(ctx, msg, "未找到此角色")
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					exists, existsErr := am.CharCheckExistsForCtx(ctx, userID, b)
					if existsErr != nil {
						return fail("检查角色名失败", existsErr)
					}
					if exists {
						ReplyToSender(ctx, msg, "此角色名已存在")
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					attrs, loadErr := am.LoadByIdForCtx(ctx, charID)
					if loadErr != nil {
						return fail("读取角色失败", loadErr)
					}
					if err = attrs.SetName(b); err != nil {
						return fail("角色改名失败", err)
					}
					bindingID, bindingErr := getBindingID()
					if bindingErr != nil {
						return fail("读取当前绑定失败", bindingErr)
					}
					if charID == bindingID {
						if err = setCurPlayerName(b); err != nil {
							return fail("更新当前角色名失败", err)
						}
					}
					ReplyToSender(ctx, msg, "操作完成")
					return CmdExecuteResult{Matched: true, Solved: true}
				}

			case "tag":
				name, err := getNicknameRaw(false, true)
				if err != nil {
					return fail("读取角色名失败", err)
				}
				VarSetValueStr(ctx, "$t角色名", name)
				if name != "" {
					charID, lookupErr := am.CharIdGetByNameForCtx(ctx, userID, name)
					if lookupErr != nil {
						return fail("读取角色失败", lookupErr)
					}
					if charID == "" {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_绑定_失败"))
					} else {
						if err = am.CharBindForCtx(ctx, charID, groupID, userID); err != nil {
							return fail("绑定角色失败", err)
						}
						if err = setCurPlayerName(name); err != nil {
							return fail("更新当前角色名失败", err)
						}
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_绑定_成功"))
					}
				} else {
					charID, bindingErr := getBindingID()
					if bindingErr != nil {
						return fail("读取当前绑定失败", bindingErr)
					}
					if charID == "" {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_绑定_并未绑定"))
					} else {
						attrs, loadErr := am.LoadByIdForCtx(ctx, charID)
						if loadErr != nil {
							return fail("读取角色失败", loadErr)
						}
						name = attrs.Name()
						if err = am.CharBindForCtx(ctx, "", groupID, userID); err != nil {
							return fail("解除绑定失败", err)
						}
						if err = setCurPlayerName(name); err != nil {
							return fail("更新当前角色名失败", err)
						}
						VarSetValueStr(ctx, "$t角色名", name)
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_绑定_解除"))
					}
				}
				if err = updatePlayerGroupCard(); err != nil {
					return fail("更新群名片失败", err)
				}
				return CmdExecuteResult{Matched: true, Solved: true}

			case "load":
				name, err := getNicknameRaw(false, true)
				if err != nil {
					return fail("读取角色名失败", err)
				}
				VarSetValueStr(ctx, "$t角色名", name)
				charID, err := am.CharIdGetByNameForCtx(ctx, userID, name)
				if err != nil {
					return fail("读取角色失败", err)
				}
				if charID == "" {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_角色不存在"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				source, err := am.LoadByIdForCtx(ctx, charID)
				if err != nil {
					return fail("读取角色失败", err)
				}
				sourceName, sourceSheet := source.Name(), source.SheetType()
				current, err := d.AttrsManager.LoadByCtx(ctx)
				if err != nil {
					return fail("读取当前角色卡失败", err)
				}
				if err = copyValues(source, current); err != nil {
					return fail("加载角色数据失败", err)
				}
				if err = current.SetName(sourceName); err != nil {
					return fail("加载角色名失败", err)
				}
				if err = current.SetSheetType(sourceSheet); err != nil {
					return fail("加载角色卡类型失败", err)
				}
				if err = setCurPlayerName(name); err != nil {
					return fail("更新当前角色名失败", err)
				}
				if err = updatePlayerGroupCard(); err != nil {
					return fail("更新群名片失败", err)
				}
				VarSetValueStr(ctx, "$t玩家", fmt.Sprintf("<%s>", ctx.Player.Name()))
				ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_加载成功"))
				return CmdExecuteResult{Matched: true, Solved: true}

			case "save":
				name, err := getNicknameRaw(true, true)
				if err != nil {
					return fail("读取角色名失败", err)
				}
				exists, err := am.CharCheckExistsForCtx(ctx, userID, name)
				if err != nil {
					return fail("检查角色失败", err)
				}
				current, err := am.LoadByCtx(ctx)
				if err != nil {
					return fail("读取当前角色卡失败", err)
				}
				if !exists {
					newItem, createErr := am.CharNewForCtx(ctx, userID, name, ctx.Group.System())
					if createErr != nil {
						return fail("新建角色失败", createErr)
					}
					target, loadErr := am.LoadByIdForCtx(ctx, newItem.Id)
					if loadErr != nil {
						return fail("读取新角色失败", loadErr)
					}
					if err = copyValues(current, target); err != nil {
						return fail("储存角色失败", err)
					}
					if err = target.SetName(name); err != nil {
						return fail("储存角色名失败", err)
					}
					if err = target.SetSheetType(ctx.Group.System()); err != nil {
						return fail("储存角色卡类型失败", err)
					}
					VarSetValueStr(ctx, "$t角色名", name)
					VarSetValueStr(ctx, "$t新角色名", fmt.Sprintf("<%s>", name))
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_储存成功"))
				} else {
					VarSetValueStr(ctx, "$t角色名", name)
					charID, lookupErr := am.CharIdGetByNameForCtx(ctx, userID, name)
					if lookupErr != nil {
						return fail("读取角色失败", lookupErr)
					}
					if charID == "" {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_角色不存在"))
						return CmdExecuteResult{Matched: true, Solved: true}
					}
					bindingGroups, bindingErr := am.CharGetBindingGroupIDListForCtx(ctx, charID)
					if bindingErr != nil {
						return fail("读取角色绑定失败", bindingErr)
					}
					if len(bindingGroups) == 0 {
						target, loadErr := am.LoadByIdForCtx(ctx, charID)
						if loadErr != nil {
							return fail("读取角色失败", loadErr)
						}
						if err = copyValues(current, target); err != nil {
							return fail("储存角色失败", err)
						}
						if err = target.SetName(name); err != nil {
							return fail("储存角色名失败", err)
						}
						if err = target.SetSheetType(ctx.Group.System()); err != nil {
							return fail("储存角色卡类型失败", err)
						}
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_储存成功"))
					} else {
						ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_储存失败_已绑定"))
					}
				}
				return CmdExecuteResult{Matched: true, Solved: true}

			case "untagAll":
				name, err := getNicknameRaw(false, true)
				if err != nil {
					return fail("读取角色名失败", err)
				}
				var charID string
				if name == "" {
					charID, err = getBindingID()
				} else {
					charID, err = am.CharIdGetByNameForCtx(ctx, userID, name)
				}
				if err != nil {
					return fail("读取角色失败", err)
				}
				var groups []string
				if charID != "" {
					groups, err = am.CharUnbindAllForCtx(ctx, charID)
					if err != nil {
						return fail("解除全部绑定失败", err)
					}
				}
				for _, boundGroupID := range groups {
					if boundGroupID == groupID {
						if err = setCurPlayerName(msg.Sender.Nickname); err != nil {
							return fail("重置当前角色名失败", err)
						}
						if err = updatePlayerGroupCard(); err != nil {
							return fail("更新群名片失败", err)
						}
					}
				}
				if len(groups) > 0 {
					ReplyToSender(ctx, msg, "绑定已全部解除:\n"+strings.Join(groups, "\n"))
				} else {
					ReplyToSender(ctx, msg, "这张卡片并未绑定到任何群")
				}
				return CmdExecuteResult{Matched: true, Solved: true}

			case "del", "rm":
				name, err := getNicknameRaw(false, true)
				if err != nil {
					return fail("读取角色名失败", err)
				}
				if name == "" {
					return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
				}
				VarSetValueStr(ctx, "$t角色名", name)
				charID, err := am.CharIdGetByNameForCtx(ctx, userID, name)
				if err != nil {
					return fail("读取角色失败", err)
				}
				if charID == "" {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_角色不存在"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				groups, err := am.CharGetBindingGroupIDListForCtx(ctx, charID)
				if err != nil {
					return fail("读取角色绑定失败", err)
				}
				if len(groups) > 0 {
					ReplyToSender(ctx, msg, DiceFormatTmpl(ctx, "核心:角色管理_删除失败_已绑定"))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				bindingCharID, err := getBindingID()
				if err != nil {
					return fail("读取当前绑定失败", err)
				}
				if err = am.CharDeleteForCtx(ctx, charID); err != nil {
					return fail("角色删除失败", err)
				}
				VarSetValueStr(ctx, "$t角色名", name)
				VarSetValueStr(ctx, "$t新角色名", fmt.Sprintf("<%s>", name))
				text := DiceFormatTmpl(ctx, "核心:角色管理_删除成功")
				if bindingCharID == charID {
					VarSetValueStr(ctx, "$t新角色名", fmt.Sprintf("<%s>", msg.Sender.Nickname))
					text += "\n" + DiceFormatTmpl(ctx, "核心:角色管理_删除成功_当前卡")
					if err = setCurPlayerName(msg.Sender.Nickname); err != nil {
						return fail("重置当前角色名失败", err)
					}
				}
				ReplyToSender(ctx, msg, text)
				return CmdExecuteResult{Matched: true, Solved: true}
			}
			return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
		},
	}

	d.CmdMap["角色"] = cmdChar
	d.CmdMap["ch"] = cmdChar
	d.CmdMap["char"] = cmdChar
	d.CmdMap["character"] = cmdChar
	d.CmdMap["pc"] = cmdChar

	cmdReply := &CmdItemInfo{
		Name:      "reply",
		ShortHelp: ".reply on/off",
		Help:      "打开或关闭自定义回复:\n.reply on/off",
		Solve: func(ctx *MsgContext, msg *Message, cmdArgs *CmdArgs) CmdExecuteResult {
			val := cmdArgs.GetArgN(1)
			switch val {
			case "on":
				onText := "开"
				if ctx.Group.ExtGetActive("reply") == nil {
					onText = "关"
				}
				extReply := ctx.Dice.ExtFind("reply", false)
				if err := ctx.Group.ExtActive(extReply); err != nil {
					ctx.setExecutionError(err)
					ReplyToSender(ctx, msg, fmt.Sprintf("开启自定义回复失败：%v", err))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("已在当前群开启自定义回复(%s➯开)。\n此指令等价于.ext reply on", onText))
			case "off":
				onText := "开"
				if ctx.Group.ExtGetActive("reply") == nil {
					onText = "关"
				}
				if _, err := ctx.Group.ExtInactiveByName("reply"); err != nil {
					ctx.setExecutionError(err)
					ReplyToSender(ctx, msg, fmt.Sprintf("关闭自定义回复失败：%v", err))
					return CmdExecuteResult{Matched: true, Solved: true}
				}
				ReplyToSender(ctx, msg, fmt.Sprintf("已在当前群关闭自定义回复(%s➯关)。\n此指令等价于.ext reply off", onText))
			default:
				return CmdExecuteResult{Matched: true, Solved: true, ShowHelp: true}
			}
			return CmdExecuteResult{Matched: true, Solved: true}
		},
	}
	d.CmdMap["reply"] = cmdReply
}

func getDefaultDicePoints(ctx *MsgContext) int64 {
	diceSides := int64(0)
	if ctx.Player != nil {
		diceSides = ctx.Player.DiceSideNum()
	}
	if diceSides == 0 && ctx.Group != nil {
		diceSides = ctx.Group.DiceSideNum()
	}
	if diceSides <= 0 {
		diceSides = 100
	}
	return diceSides
}

func setRuleByName(ctx *MsgContext, name string) error {
	if name == "" {
		return nil
	}
	var applyErr error
	ctx.Dice.GameSystemMap.Range(func(key string, tmpl *GameSystemTemplate) bool {
		isMatch := false
		for _, candidate := range tmpl.SetConfig.Keys {
			if strings.EqualFold(name, candidate) {
				isMatch = true
				break
			}
		}
		if !isMatch {
			return true
		}
		if applyErr = ctx.Group.SetSystem(key); applyErr != nil {
			return false
		}
		if applyErr = ctx.Group.SetDiceSideNum(tmpl.SetConfig.DiceSides); applyErr != nil {
			return false
		}
		for _, extensionName := range tmpl.SetConfig.RelatedExt {
			extension := ctx.Dice.ExtFind(extensionName, false)
			if extension != nil {
				if applyErr = ctx.Group.ExtActive(extension); applyErr != nil {
					return false
				}
			}
		}
		return false
	})
	return applyErr
}
