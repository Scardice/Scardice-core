package api

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
	"Scardice-core/dice/service"
)

const (
	groupLocalDataScopeGroupRecord = "group_record"
	groupLocalDataScopePlayers     = "players"
	groupLocalDataScopeAttrs       = "attrs"
)

var groupLocalDataScopeOrder = []string{
	groupLocalDataScopeGroupRecord,
	groupLocalDataScopePlayers,
	groupLocalDataScopeAttrs,
}

type groupLocalDataDeleteRequest struct {
	GroupID     string   `json:"groupId"     yaml:"groupId"`
	Scopes      []string `json:"scopes"      yaml:"scopes"`
	AllowActive bool     `json:"allowActive" yaml:"allowActive"`
	DryRun      bool     `json:"dryRun"      yaml:"dryRun"`
}

type groupLocalDataDeleteDeleted struct {
	GroupRecord       bool  `json:"groupRecord"`
	GroupInfoRows     int64 `json:"groupInfoRows"`
	PlayerRows        int64 `json:"playerRows"`
	GroupAttrRows     int64 `json:"groupAttrRows"`
	GroupUserAttrRows int64 `json:"groupUserAttrRows"`
}

type groupLocalDataDeleteResult struct {
	GroupID         string                      `json:"groupId"`
	Scopes          []string                    `json:"scopes"`
	DryRun          bool                        `json:"dryRun"`
	ExistedInMemory bool                        `json:"existedInMemory"`
	ActiveDiceIDs   []string                    `json:"activeDiceIds"`
	ExistingDiceIDs []string                    `json:"existingDiceIds"`
	Deleted         groupLocalDataDeleteDeleted `json:"deleted"`
}

func normalizeGroupLocalDataDeleteScopes(scopes []string) ([]string, error) {
	requested := map[string]bool{}
	if len(scopes) == 0 {
		requested[groupLocalDataScopeGroupRecord] = true
	} else {
		for _, rawScope := range scopes {
			scope := strings.TrimSpace(rawScope)
			switch scope {
			case groupLocalDataScopeGroupRecord, groupLocalDataScopePlayers, groupLocalDataScopeAttrs:
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

func groupLocalDataScopeSelected(scopes []string, scope string) bool {
	for _, item := range scopes {
		if item == scope {
			return true
		}
	}
	return false
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
	// Pinenutn: Range模板 ServiceAtNew重构代码
	myDice.ImSession.ServiceAtNew.Range(func(groupID string, item *dice.GroupInfo) bool {
		// Pinenutn: ServiceAtNew重构
		item.GroupID = groupID
		if !strings.HasPrefix(item.GroupID, "PG-") {
			if item != nil {
				var exts []string
				item.TmpPlayerNum, _ = service.GroupPlayerNumGet(myDice.DBOperator, item.GroupID)
				// 使用 Raw 版本避免触发全量初始化
				for _, i := range item.GetActivatedExtListRaw() {
					if i != nil {
						exts = append(exts, i.Name)
					}
				}
				item.TmpExtList = exts

				if item.DiceIDExistsMap.Len() > 0 {
					items = append(items, item)
				}
			}
		}
		return true
	})

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

	if err == nil {
		_, exists := myDice.ImSession.ServiceAtNew.Load(v.GroupID)
		if exists {
			for _, ep := range myDice.ImSession.EndPoints {
				// if ep.UserId == v.DiceId {
				ctx := &dice.MsgContext{Dice: myDice, EndPoint: ep, Session: myDice.ImSession}
				if v.Active {
					dice.SetBotOnAtGroup(ctx, v.GroupID)
				} else {
					dice.SetBotOffAtGroup(ctx, v.GroupID)
				}
				//}
			}
		}
		return c.String(http.StatusOK, "")
	}
	return c.String(430, "")
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

	if v.DryRun {
		return Success(&c, Response{
			"data": data,
		})
	}

	if groupLocalDataScopeSelected(scopes, groupLocalDataScopeGroupRecord) {
		if myDice.DirtyGroups != nil {
			myDice.DirtyGroups.Delete(v.GroupID)
		}
		myDice.ImSession.ServiceAtNew.Delete(v.GroupID)
		if dm != nil {
			dm.GroupNameCache.Delete(v.GroupID)
		}

		rows, err := service.GroupInfoDelete(myDice.DBOperator, v.GroupID)
		if err != nil {
			return Error(&c, fmt.Sprintf("删除群组本地记录失败: %v", err), Response{
				"data": data,
			})
		}
		data.Deleted.GroupInfoRows = rows
		data.Deleted.GroupRecord = existedInMemory || rows > 0
	}

	if groupLocalDataScopeSelected(scopes, groupLocalDataScopePlayers) {
		if group != nil {
			group.Players = new(dice.SyncMap[string, *dice.GroupPlayerInfo])
		}
		rows, err := service.GroupPlayerInfoDeleteByGroup(myDice.DBOperator, v.GroupID)
		if err != nil {
			return Error(&c, fmt.Sprintf("删除群组玩家本地记录失败: %v", err), Response{
				"data": data,
			})
		}
		data.Deleted.PlayerRows = rows
	}

	if groupLocalDataScopeSelected(scopes, groupLocalDataScopeAttrs) {
		groupAttrRows, groupUserAttrRows, err := service.AttrsDeleteByGroupScope(myDice.DBOperator, v.GroupID)
		if err != nil {
			return Error(&c, fmt.Sprintf("删除群组属性本地记录失败: %v", err), Response{
				"data": data,
			})
		}
		if myDice.AttrsManager != nil {
			myDice.AttrsManager.DeleteCachedGroupData(v.GroupID, true, true)
		}
		data.Deleted.GroupAttrRows = groupAttrRows
		data.Deleted.GroupUserAttrRows = groupUserAttrRows
	}

	return Success(&c, Response{
		"data": data,
	})
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
	err := c.Bind(&v)
	if err != nil {
		return c.String(430, "")
	}

	// 不太好弄，主要会出现多个帐号在群的情况
	group, exists := myDice.ImSession.ServiceAtNew.Load(v.GroupID)
	if !exists {
		return c.String(430, "")
	}

	for _, ep := range myDice.ImSession.EndPoints {
		if ep.UserID != v.DiceID {
			continue
		}
		// 就是这个
		_txt := fmt.Sprintf("Master后台操作退群: 于群组<%s>(%s)中告别", group.GroupName, group.GroupID)
		myDice.Logger.Info(_txt)

		ctx := &dice.MsgContext{Dice: myDice, EndPoint: ep, Session: myDice.ImSession}
		ctx.Notice(_txt)
		// dice.SetBotOffAtGroup(ctx, group.GroupId)

		if !v.Silence {
			txtPost := dice.DiceFormatTmpl(ctx, "核心:提示_手动退群前缀")
			if v.ExtraText != "" {
				txtPost += "\n骰主留言: " + v.ExtraText
			}
			dice.ReplyGroup(ctx, &dice.Message{GroupID: v.GroupID}, txtPost)
		}

		group.DiceIDExistsMap.Delete(v.DiceID)
		time.Sleep(6 * time.Second)
		group.MarkDirty(myDice)

		ep.Adapter.QuitGroup(ctx, v.GroupID)
		return c.String(http.StatusOK, "")
	}
	return c.String(430, "")
}
