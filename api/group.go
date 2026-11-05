package api

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"Scardice-core/core/groupstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/core/privacypurge"
	"Scardice-core/dice"
	"Scardice-core/eventstore"
)

const (
	groupLocalDataScopeGroupRecord = "group_record"
	groupLocalDataScopePlayers     = "players"
	groupLocalDataScopeAttrs       = "attrs"
	groupLocalDataScopeLogs        = "logs"
)

var groupLocalDataScopeOrder = []string{
	groupLocalDataScopeGroupRecord,
	groupLocalDataScopePlayers,
	groupLocalDataScopeAttrs,
	groupLocalDataScopeLogs,
}

type groupLocalDataDeleteRequest struct {
	GroupID        string   `json:"groupId"     yaml:"groupId"`
	Scopes         []string `json:"scopes"      yaml:"scopes"`
	AllowActive    bool     `json:"allowActive" yaml:"allowActive"`
	DryRun         bool     `json:"dryRun"      yaml:"dryRun"`
	ConfirmDigest  string   `json:"confirmDigest,omitempty" yaml:"confirmDigest,omitempty"`
	ConfirmVersion uint64   `json:"confirmVersion,omitempty" yaml:"confirmVersion,omitempty"`
}

type groupLocalDataDeleteDeleted struct {
	GroupRecord       bool  `json:"groupRecord"`
	GroupInfoRows     int64 `json:"groupInfoRows"`
	PlayerRows        int64 `json:"playerRows"`
	GroupAttrRows     int64 `json:"groupAttrRows"`
	GroupUserAttrRows int64 `json:"groupUserAttrRows"`
	LogSessions       int64 `json:"logSessions"`
	LogStates         int64 `json:"logStates"`
	LogEntries        int64 `json:"logEntries"`
	LogIntents        int64 `json:"logIntents"`
	LogImports        int64 `json:"logImports"`
	InboxRows         int64 `json:"inboxRows"`
	OutboxRows        int64 `json:"outboxRows"`
	SecretRows        int64 `json:"secretRows"`
	ProjectionRows    int64 `json:"projectionRows"`
}

type groupLocalDataDeleteResult struct {
	GroupID         string                      `json:"groupId"`
	Scopes          []string                    `json:"scopes"`
	DryRun          bool                        `json:"dryRun"`
	ExistedInMemory bool                        `json:"existedInMemory"`
	ActiveDiceIDs   []string                    `json:"activeDiceIds"`
	ExistingDiceIDs []string                    `json:"existingDiceIds"`
	Deleted         groupLocalDataDeleteDeleted `json:"deleted"`
	Counts          eventstore.PrivacyCounts    `json:"counts"`
	Completed       bool                        `json:"completed"`
	Status          string                      `json:"status,omitempty"`
	Confirmation    map[string]interface{}      `json:"confirmation,omitempty"`
	UncoveredData   []string                    `json:"uncoveredData,omitempty"`
}

func normalizeGroupLocalDataDeleteScopes(scopes []string) ([]string, error) {
	requested := map[string]bool{}
	if len(scopes) == 0 {
		requested[groupLocalDataScopeGroupRecord] = true
	} else {
		for _, rawScope := range scopes {
			scope := strings.TrimSpace(rawScope)
			switch scope {
			case groupLocalDataScopeGroupRecord, groupLocalDataScopePlayers, groupLocalDataScopeAttrs, groupLocalDataScopeLogs:
				requested[scope] = true
			case "":
				return nil, errors.New("scope 不能为空")
			default:
				return nil, fmt.Errorf("未知 scope: %s", scope)
			}
		}
	}

	result := make([]string, 0, len(requested))
	for _, scope := range groupLocalDataScopeOrder {
		if requested[scope] {
			result = append(result, scope)
		}
	}
	return result, nil
}

func groupLocalDataTrueDiceIDs(items map[string]bool) []string {
	result := []string{}
	for diceID, exists := range items {
		if exists {
			result = append(result, diceID)
		}
	}
	sort.Strings(result)
	return result
}

func groupLocalDataDiceIDs(group groupstate.State) ([]string, []string) {
	return groupLocalDataTrueDiceIDs(group.DiceIDActive), groupLocalDataTrueDiceIDs(group.DiceIDExists)
}

type groupListItem struct {
	Active              bool                `json:"active"`
	ActivatedExtList    []*dice.ExtInfo     `json:"activatedExtList"`
	InactivatedExtSet   dice.StringSet      `json:"inactivatedExtSet"`
	GroupID             string              `json:"groupId"`
	GuildID             string              `json:"guildId"`
	ChannelID           string              `json:"channelId"`
	GroupName           string              `json:"groupName"`
	DiceIDActiveMap     map[string]bool     `json:"diceIdActiveMap"`
	DiceIDExistsMap     map[string]bool     `json:"diceIdExistsMap"`
	BotList             map[string]bool     `json:"botList"`
	DiceSideNum         int64               `json:"diceSideNum"`
	DiceSideExpr        string              `json:"diceSideExpr"`
	System              string              `json:"system"`
	RollShaperMode      string              `json:"rollShaperMode"`
	HelpPackages        []string            `json:"helpPackages"`
	CocRuleIndex        int                 `json:"cocRuleIndex"`
	LogCurName          string              `json:"logCurName"`
	LogOn               bool                `json:"logOn"`
	RecentDiceSendTime  int64               `json:"recentDiceSendTime"`
	ShowGroupWelcome    bool                `json:"showGroupWelcome"`
	GroupWelcomeMessage string              `json:"groupWelcomeMessage"`
	EnteredTime         int64               `json:"enteredTime"`
	InviteUserID        string              `json:"inviteUserId"`
	TmpPlayerNum        int64               `json:"tmpPlayerNum"`
	TmpExtList          []string            `json:"tmpExtList"`
	DefaultHelpGroup    string              `json:"defaultHelpGroup"`
	PlayerGroups        map[string][]string `json:"playerGroups"`
	ExtAppliedVersion   int64               `json:"extAppliedVersion"`
}

func groupList(c echo.Context) error {
	projected, err := groupstate.ListProjected(c.Request().Context(), myDice.DurableStore, myDice.BaseConfig.Name)
	if err != nil {
		return &echo.HTTPError{Code: http.StatusServiceUnavailable, Message: "group projections are unavailable", Internal: err}
	}
	items := make([]groupListItem, 0, len(projected))
	groupIDs := make([]string, 0, len(projected))
	for _, group := range projected {
		if group.Deleted || strings.HasPrefix(group.GroupID, "PG-") || len(group.DiceIDExists) == 0 {
			continue
		}
		var extensions []*dice.ExtInfo
		if len(group.ActivatedExtensions) != 0 {
			extensions = make([]*dice.ExtInfo, 0, len(group.ActivatedExtensions))
		}
		for _, name := range group.ActivatedExtensions {
			extension := myDice.ExtFind(name, false)
			if extension == nil {
				extension = &dice.ExtInfo{Name: name}
			}
			extensions = append(extensions, extension)
		}
		inactivated := make(dice.StringSet, len(group.InactivatedExtensions))
		for name, disabled := range group.InactivatedExtensions {
			if disabled {
				inactivated[name] = struct{}{}
			}
		}
		logState, logErr := dice.ReadCommittedGroupLogState(c.Request().Context(), myDice, group.GroupID)
		if logErr != nil {
			return &echo.HTTPError{Code: http.StatusServiceUnavailable, Message: "group log state is unavailable", Internal: logErr}
		}
		items = append(items, groupListItem{
			Active: group.Active, ActivatedExtList: extensions, InactivatedExtSet: inactivated,
			GroupID: group.GroupID, GuildID: group.GuildID, ChannelID: group.ChannelID, GroupName: group.GroupName,
			DiceIDActiveMap: group.DiceIDActive, DiceIDExistsMap: group.DiceIDExists, BotList: group.BotList,
			DiceSideNum: group.DiceSideNum, DiceSideExpr: group.DiceSideExpr, System: group.System,
			RollShaperMode: group.RollShaperMode, HelpPackages: group.HelpPackages, CocRuleIndex: group.CocRuleIndex,
			LogCurName: logState.Name, LogOn: logState.On, RecentDiceSendTime: myDice.ImSession.GroupRecentDiceSendTime(group.GroupID),
			ShowGroupWelcome: group.ShowGroupWelcome, GroupWelcomeMessage: group.GroupWelcomeMessage,
			EnteredTime: group.EnteredAt, InviteUserID: group.InviteUserID,
			TmpExtList: append([]string(nil), group.ActivatedExtensions...), DefaultHelpGroup: group.DefaultHelpGroup,
			PlayerGroups: group.PlayerGroups,
		})
		groupIDs = append(groupIDs, group.GroupID)
	}
	counts, err := playerstate.CountProjectedGroupProfiles(c.Request().Context(), myDice.DurableStore, groupIDs)
	if err != nil {
		return &echo.HTTPError{Code: http.StatusServiceUnavailable, Message: "group player profile counts are unavailable", Internal: err}
	}
	for index := range items {
		items[index].TmpPlayerNum = counts[items[index].GroupID]
	}
	return c.JSON(http.StatusOK, map[string]interface{}{"items": items})
}

func groupSetOne(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}

	v := struct {
		Active  bool   `json:"active"  yaml:"active"`
		GroupID string `json:"groupId" yaml:"groupId"`
		DiceID  string `json:"diceId"  yaml:"diceId"`
	}{}
	err := c.Bind(&v)
	if err != nil {
		return c.String(430, "")
	}
	if err := myDice.RecordGroupActivation(
		c.Request().Context(), v.GroupID, []string{v.DiceID}, v.Active,
	); err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	return c.String(http.StatusOK, "")
}

func groupLocalDataDelete(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	v := groupLocalDataDeleteRequest{}
	if err := c.Bind(&v); err != nil {
		return Error(&c, "请求格式错误", Response{})
	}

	v.GroupID = strings.TrimSpace(v.GroupID)
	if v.GroupID == "" {
		return Error(&c, "groupId 不能为空", Response{})
	}

	scopes, err := normalizeGroupLocalDataDeleteScopes(v.Scopes)
	if err != nil {
		return Error(&c, err.Error(), Response{
			"supportedScopes": groupLocalDataScopeOrder,
		})
	}

	group, readErr := groupstate.ReadProjected(c.Request().Context(), myDice.DurableStore, myDice.BaseConfig.Name, v.GroupID)
	if readErr != nil && !errors.Is(readErr, eventstore.ErrNotFound) {
		return Error(&c, "读取群组状态失败", Response{})
	}
	activeDiceIDs, existingDiceIDs := groupLocalDataDiceIDs(group)
	data := groupLocalDataDeleteResult{
		GroupID: v.GroupID, Scopes: scopes, DryRun: v.DryRun,
		ExistedInMemory: group.Version != 0 && !group.Deleted,
		ActiveDiceIDs:   activeDiceIDs, ExistingDiceIDs: existingDiceIDs,
	}

	if len(activeDiceIDs) > 0 && !v.AllowActive {
		return Error(&c, "群组当前仍有启用中的骰号，删除本地数据需要 allowActive=true", Response{
			"data": data,
		})
	}

	if dm.JustForTest {
		return Success(&c, Response{
			"testMode": true,
			"data":     data,
		})
	}

	durable := privacyPurgeService()
	if durable == nil {
		if !v.DryRun {
			return Error(&c, "持久化隐私删除服务不可用，已拒绝执行", Response{"data": data})
		}
		return Success(&c, Response{"data": data, "uncoveredData": []string{"eventstore 未配置"}})
	}
	diceIDs := make([]string, 0, len(dm.Dice))
	for _, runtime := range dm.Dice {
		if runtime == nil || runtime.BaseConfig.Name == "" || slices.Contains(diceIDs, runtime.BaseConfig.Name) {
			continue
		}
		diceIDs = append(diceIDs, runtime.BaseConfig.Name)
	}
	confirmation, decodeErr := hex.DecodeString(strings.TrimSpace(v.ConfirmDigest))
	if decodeErr != nil {
		confirmation = nil
	}
	purgeReq := privacypurge.Request{GroupID: v.GroupID, DiceIDs: diceIDs, Scopes: scopes, ActiveDiceIDs: activeDiceIDs, AllowActive: v.AllowActive, DryRun: v.DryRun, ConfirmationDigest: confirmation, ConfirmationVersion: v.ConfirmVersion}
	var purgeResult privacypurge.Result
	if v.DryRun {
		purgeResult, err = durable.DryRun(c.Request().Context(), purgeReq)
	} else {
		purgeResult, err = durable.Confirm(c.Request().Context(), purgeReq)
	}
	data.Status = purgeResult.Status
	data.Counts, data.Completed = purgeResult.Counts, purgeResult.Completed
	data.Confirmation = map[string]interface{}{"digest": hex.EncodeToString(purgeResult.ConfirmationDigest), "version": purgeResult.ConfirmationVersion}
	data.UncoveredData = append([]string(nil), purgeResult.Uncovered...)
	data.Deleted.GroupRecord = purgeResult.Deleted.GroupRecord > 0
	data.Deleted.PlayerRows = purgeResult.Deleted.Players
	data.Deleted.GroupAttrRows = purgeResult.Deleted.Attrs
	data.Deleted.LogSessions = purgeResult.Deleted.LogSessions
	data.Deleted.LogStates = purgeResult.Deleted.LogStates
	data.Deleted.LogEntries = purgeResult.Deleted.LogEntries
	data.Deleted.LogIntents = purgeResult.Deleted.LogIntents
	data.Deleted.LogImports = purgeResult.Deleted.LogImports
	data.Deleted.InboxRows = purgeResult.Deleted.Inbox
	data.Deleted.OutboxRows = purgeResult.Deleted.Outbox
	data.Deleted.SecretRows = purgeResult.Deleted.Secrets
	data.Deleted.ProjectionRows = purgeResult.Deleted.Projections
	if err != nil {
		return Error(&c, err.Error(), Response{"data": data})
	}
	return Success(&c, Response{"data": data})
}

func nextGroupQuitCommandIdentity(d *dice.Dice) (int64, string) {
	requestID := uuid.NewString()
	digest := sha256.Sum256([]byte(requestID))
	commandID := int64(binary.BigEndian.Uint64(digest[:8]) & ((1 << 63) - 1))
	if commandID == 0 {
		commandID = 1
	}
	return commandID, d.DomainExecutionIdentity("api/group-quit", requestID)
}

func groupQuit(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return c.JSON(200, map[string]interface{}{
			"testMode": true,
		})
	}
	v := struct {
		GroupID   string `json:"groupId"   yaml:"groupId"`
		DiceID    string `json:"diceId"    yaml:"diceId"`
		Silence   bool   `json:"silence"   yaml:"silence"`
		ExtraText string `json:"extraText" yaml:"extraText"`
	}{}
	if err := c.Bind(&v); err != nil {
		return Error(&c, "请求格式错误", Response{})
	}

	group, err := groupstate.ReadProjected(c.Request().Context(), myDice.DurableStore, myDice.BaseConfig.Name, v.GroupID)
	if err != nil {
		return Error(&c, "读取群组状态失败: "+err.Error(), Response{})
	}
	if group.Version == 0 || group.Deleted {
		return Error(&c, "群组不存在", Response{})
	}
	request, err := json.Marshal(v)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	for _, endpoint := range myDice.ImSession.EndPointsReadOnly() {
		if endpoint == nil || endpoint.UserID != v.DiceID {
			continue
		}
		logText := fmt.Sprintf("Master后台操作退群: 于群组<%s>(%s)中告别", group.GroupName, group.GroupID)
		myDice.Logger.Info(logText)
		commandID, currentCommand := nextGroupQuitCommandIdentity(myDice)
		runErr := myDice.WithDomainExecution(c.Request().Context(), currentCommand, request, func(transaction *dice.DurableCallbackTransaction) error {
			message := &dice.Message{MessageType: "group", GroupID: v.GroupID, Sender: dice.SenderBase{UserID: endpoint.UserID}}
			messageContext, contextErr := dice.NewDomainMsgContext(transaction, myDice, myDice.ImSession, endpoint, message)
			if contextErr != nil {
				return contextErr
			}
			messageContext.CommandID = commandID
			messageContext.CurrentCommand = currentCommand
			farewell := ""
			if !v.Silence {
				farewell = dice.DiceFormatTmpl(messageContext, "核心:提示_手动退群前缀")
				if v.ExtraText != "" {
					farewell += "\n骰主留言: " + v.ExtraText
				}
			}
			if myDice.OutboundBridge != nil {
				if submitErr := dice.SubmitDurableGroupQuit(c.Request().Context(), messageContext, v.GroupID, farewell); submitErr != nil {
					return submitErr
				}
			} else {
				legacyQuit := endpoint.Adapter != nil &&
					(endpoint.Platform != "QQ" || endpoint.ProtocolType != string(dice.PureOnebotAdapterKey))
				if farewell != "" {
					dice.ReplyGroup(messageContext, &dice.Message{GroupID: v.GroupID}, farewell)
				}
				if legacyQuit && farewell != "" {
					timer := time.NewTimer(6 * time.Second)
					select {
					case <-c.Request().Context().Done():
						timer.Stop()
						return c.Request().Context().Err()
					case <-timer.C:
					}
				}
				if quitErr := dice.QuitGroup(messageContext, v.GroupID); quitErr != nil {
					return quitErr
				}
				if activationErr := messageContext.Group.SetActivation(v.DiceID, false, false); activationErr != nil {
					return activationErr
				}
			}
			messageContext.Notice(logText, dice.NoticeTypeGroup)
			return transaction.Domain().Err()
		})
		if runErr != nil {
			return Error(&c, runErr.Error(), Response{})
		}
		return c.String(http.StatusOK, "")
	}
	return Error(&c, "未找到对应骰号", Response{})
}
