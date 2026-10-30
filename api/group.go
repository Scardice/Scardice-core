package api

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"Scardice-core/core/playerstate"
	"Scardice-core/core/privacypurge"
	"Scardice-core/dice"
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
	OperationID    string   `json:"operationId,omitempty" yaml:"operationId,omitempty"`
	Resume         bool     `json:"resume,omitempty" yaml:"resume,omitempty"`
	Phase          string   `json:"phase,omitempty" yaml:"phase,omitempty"`
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
}

type groupLocalDataDeleteResult struct {
	GroupID         string                      `json:"groupId"`
	Scopes          []string                    `json:"scopes"`
	DryRun          bool                        `json:"dryRun"`
	ExistedInMemory bool                        `json:"existedInMemory"`
	ActiveDiceIDs   []string                    `json:"activeDiceIds"`
	ExistingDiceIDs []string                    `json:"existingDiceIds"`
	Deleted         groupLocalDataDeleteDeleted `json:"deleted"`
	Operation       string                      `json:"operation,omitempty"`
	Status          string                      `json:"status,omitempty"`
	Phase           string                      `json:"phase,omitempty"`
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

func groupLocalDataTrueDiceIDs(items *dice.SyncMap[string, bool]) []string {
	result := []string{}
	if items == nil {
		return result
	}
	items.Range(func(diceID string, exists bool) bool {
		if exists {
			result = append(result, diceID)
		}
		return true
	})
	sort.Strings(result)
	return result
}

func groupLocalDataDiceIDs(group *dice.GroupInfo) ([]string, []string) {
	if group == nil {
		return []string{}, []string{}
	}
	activeDiceIDs := groupLocalDataTrueDiceIDs(group.DiceIDActiveMap)
	existingDiceIDs := groupLocalDataTrueDiceIDs(group.DiceIDExistsMap)
	return activeDiceIDs, existingDiceIDs
}

func groupList(c echo.Context) error {
	var items []*dice.GroupInfo
	var groupIDs []string
	// Pinenutn: Range模板 ServiceAtNew重构代码
	myDice.ImSession.ServiceAtNew.Range(func(groupID string, item *dice.GroupInfo) bool {
		// Pinenutn: ServiceAtNew重构
		item.GroupID = groupID
		if !strings.HasPrefix(item.GroupID, "PG-") {
			if item != nil {
				var exts []string
				// 使用 Raw 版本避免触发全量初始化
				for _, i := range item.GetActivatedExtListRaw() {
					if i != nil {
						exts = append(exts, i.Name)
					}
				}
				item.TmpExtList = exts

				if item.DiceIDExistsMap.Len() > 0 {
					items = append(items, item)
					groupIDs = append(groupIDs, item.GroupID)
				}
			}
		}
		return true
	})

	counts, err := playerstate.CountProjectedGroupProfiles(c.Request().Context(), myDice.DurableStore, groupIDs)
	if err != nil {
		return &echo.HTTPError{
			Code: http.StatusServiceUnavailable, Message: "group player profile counts are unavailable", Internal: err,
		}
	}
	for _, item := range items {
		item.TmpPlayerNum = counts[item.GroupID]
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"items": items,
	})
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
	endpoints := make([]*dice.EndPointInfo, 0, 1)
	diceIDs := make([]string, 0, 1)
	for _, ep := range myDice.ImSession.EndPointsReadOnly() {
		if ep != nil && endpointServesGroup(ep, v.GroupID) {
			endpoints = append(endpoints, ep)
			diceIDs = append(diceIDs, ep.UserID)
		}
	}
	if err := myDice.RecordGroupActivation(c.Request().Context(), v.GroupID, diceIDs, v.Active); err != nil {
		return c.String(http.StatusInternalServerError, err.Error())
	}
	if _, loaded := myDice.ImSession.ServiceAtNew.Load(v.GroupID); !loaded {
		return c.String(http.StatusOK, "")
	}
	for _, ep := range endpoints {
		ctx := &dice.MsgContext{Dice: myDice, EndPoint: ep, Session: myDice.ImSession}
		if v.Active {
			dice.SetBotOnAtGroup(ctx, v.GroupID)
		} else {
			dice.SetBotOffAtGroup(ctx, v.GroupID)
		}
	}
	return c.String(http.StatusOK, "")
}

// endpointServesGroup reports whether an account of the endpoint's platform
// could be in the group, such as QQ for "QQ-Group:1" or "PG-QQ:2".
func endpointServesGroup(ep *dice.EndPointInfo, groupID string) bool {
	id := strings.TrimPrefix(groupID, "PG-")
	return ep.Platform != "" && (strings.HasPrefix(id, ep.Platform+"-") || strings.HasPrefix(id, ep.Platform+":"))
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

	group, existedInMemory := myDice.ImSession.ServiceAtNew.Load(v.GroupID)
	activeDiceIDs, existingDiceIDs := groupLocalDataDiceIDs(group)
	data := groupLocalDataDeleteResult{
		GroupID:         v.GroupID,
		Scopes:          scopes,
		DryRun:          v.DryRun,
		ExistedInMemory: existedInMemory,
		ActiveDiceIDs:   activeDiceIDs,
		ExistingDiceIDs: existingDiceIDs,
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
	diceIDs := append([]string(nil), existingDiceIDs...)
	for _, id := range activeDiceIDs {
		found := false
		for _, current := range diceIDs {
			if current == id {
				found = true
				break
			}
		}
		if !found {
			diceIDs = append(diceIDs, id)
		}
	}
	confirmation, decodeErr := hex.DecodeString(strings.TrimSpace(v.ConfirmDigest))
	if decodeErr != nil {
		confirmation = nil
	}
	purgeReq := privacypurge.Request{GroupID: v.GroupID, DiceIDs: diceIDs, Scopes: scopes, ActiveDiceIDs: activeDiceIDs, AllowActive: v.AllowActive, DryRun: v.DryRun, ConfirmationDigest: confirmation, ConfirmationVersion: v.ConfirmVersion, OperationID: v.OperationID, Resume: v.Resume}
	var purgeResult privacypurge.Result
	if v.DryRun {
		purgeResult, err = durable.DryRun(c.Request().Context(), purgeReq)
	} else {
		purgeResult, err = durable.Confirm(c.Request().Context(), purgeReq)
	}
	data.Operation, data.Status, data.Phase = purgeResult.OperationID, purgeResult.Status, purgeResult.Phase
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
	if err != nil {
		return Error(&c, err.Error(), Response{"data": data})
	}
	return Success(&c, Response{"data": data})
}

func nextGroupQuitCommandIdentity() (int64, string) {
	requestID := uuid.NewString()
	digest := sha256.Sum256([]byte(requestID))
	commandID := int64(binary.BigEndian.Uint64(digest[:8]) & ((1 << 63) - 1))
	if commandID == 0 {
		commandID = 1
	}
	return commandID, "api/group-quit:" + requestID
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

	// 不太好弄，主要会出现多个帐号在群的情况
	group, exists := myDice.ImSession.ServiceAtNew.Load(v.GroupID)
	if !exists {
		return Error(&c, "群组不存在", Response{})
	}

	for _, ep := range myDice.ImSession.EndPointsReadOnly() {
		if ep.UserID != v.DiceID {
			continue
		}
		// 就是这个
		logText := fmt.Sprintf("Master后台操作退群: 于群组<%s>(%s)中告别", group.GroupName, group.GroupID)
		myDice.Logger.Info(logText)

		commandID, currentCommand := nextGroupQuitCommandIdentity()
		ctx := &dice.MsgContext{
			Dice: myDice, EndPoint: ep, Session: myDice.ImSession,
			CommandID: commandID, CurrentCommand: currentCommand,
		}

		farewell := ""
		if !v.Silence {
			farewell = dice.DiceFormatTmpl(ctx, "核心:提示_手动退群前缀")
			if v.ExtraText != "" {
				farewell += "\n骰主留言: " + v.ExtraText
			}
		}

		if myDice.OutboundBridge != nil {
			if err := dice.SubmitDurableGroupQuit(c.Request().Context(), ctx, v.GroupID, farewell); err != nil {
				return Error(&c, err.Error(), Response{})
			}
		} else {
			legacyQuit := ep.Adapter != nil &&
				(ep.Platform != "QQ" || ep.ProtocolType != string(dice.PureOnebotAdapterKey))
			if farewell != "" {
				dice.ReplyGroup(ctx, &dice.Message{GroupID: v.GroupID}, farewell)
			}
			if legacyQuit && farewell != "" {
				timer := time.NewTimer(6 * time.Second)
				select {
				case <-c.Request().Context().Done():
					timer.Stop()
					return Error(&c, c.Request().Context().Err().Error(), Response{})
				case <-timer.C:
				}
			}
			if err := dice.QuitGroup(ctx, v.GroupID); err != nil {
				return Error(&c, err.Error(), Response{})
			}
		}

		group.DiceIDExistsMap.Delete(v.DiceID)
		group.MarkDirty(myDice)
		ctx.Notice(logText, dice.NoticeTypeGroup)
		return c.String(http.StatusOK, "")
	}
	return Error(&c, "未找到对应骰号", Response{})
}
