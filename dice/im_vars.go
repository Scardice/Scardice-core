package dice

// 用户变量相关

import (
	"fmt"
	"math/rand"
	"strconv"
	"strings"
	"time"

	ds "github.com/sealdice/dicescript"
)

func aliasMapForCtx(ctx *MsgContext) map[string][]string {
	if ctx != nil && ctx.SystemTemplate != nil {
		return ctx.SystemTemplate.Alias
	}
	return nil
}

func VarSetValueStr(ctx *MsgContext, s string, v string) {
	VarSetValue(ctx, s, ds.NewStrVal(v))
}

func VarSetValueInt64(ctx *MsgContext, s string, v int64) {
	VarSetValue(ctx, s, ds.NewIntVal(ds.IntType(v)))
}

func VarSetValueComputed(ctx *MsgContext, s string, v string) {
	VarSetValue(ctx, s, ds.NewComputedVal(v))
}

func _VarSetValueV1(ctx *MsgContext, s string, v *VMValue) {
	VarSetValue(ctx, s, v.ConvertToV2())
}

func VarSetValue(ctx *MsgContext, s string, v *ds.VMValue) {
	if err := ctx.checkExecution(); err != nil {
		panic(err)
	}
	ctx.CreateVmIfNotExists()
	am := ctx.Dice.AttrsManager
	name := GetValueNameByAlias(s, aliasMapForCtx(ctx))
	vClone := v.Clone()

	// Temporary values belong to this invocation's VM.
	if strings.HasPrefix(s, "$t") {
		ctx.vm.StoreNameLocal(s, vClone)
		return
	}
	if ctx.IsCompatibilityTest {
		key := name
		if strings.HasPrefix(s, "$g") {
			key = s
		}
		ctx.vm.StoreNameLocal(key, vClone)
		return
	}

	// 个人变量
	if strings.HasPrefix(s, "$m") {
		if ctx.Session != nil && ctx.Player != nil {
			playerAttrs, err := am.LoadByIdForCtx(ctx, ctx.Player.UserID())
			if err != nil {
				ctx.setExecutionError(err)
				return
			}
			if err = playerAttrs.Store(name, vClone); err != nil {
				ctx.setExecutionError(err)
			}
		}
		return
	}

	// 群变量
	if ctx.Group != nil && strings.HasPrefix(s, "$g") {
		groupAttrs, err := am.LoadByIdForCtx(ctx, ctx.Group.GroupID())
		if err != nil {
			ctx.setExecutionError(err)
			return
		}
		if err = groupAttrs.Store(s, vClone); err != nil {
			ctx.setExecutionError(err)
		}
		return
	}

	// 个人属性
	if ctx.Session != nil && ctx.Player != nil {
		curAttrs, err := am.LoadByCtx(ctx)
		if err != nil {
			ctx.setExecutionError(err)
			return
		}
		if err = curAttrs.Store(name, vClone); err != nil {
			ctx.setExecutionError(err)
		}
	}
}

func VarDelValue(ctx *MsgContext, s string) {
	if err := ctx.checkExecution(); err != nil {
		panic(err)
	}
	am := ctx.Dice.AttrsManager
	name := GetValueNameByAlias(s, aliasMapForCtx(ctx))

	// Temporary values never fall through to persistent attributes.
	if strings.HasPrefix(s, "$t") {
		if ctx.vm != nil {
			ctx.vm.Attrs.Delete(s)
		}
		if ctx.Player != nil {
			if values := ctx.Player.tempValues(); values != nil {
				values.Delete(s)
			}
		}
		return
	}
	if ctx.IsCompatibilityTest {
		if ctx.vm != nil {
			key := name
			if strings.HasPrefix(s, "$g") {
				key = s
			}
			ctx.vm.Attrs.Delete(key)
		}
		return
	}

	// 个人变量
	if strings.HasPrefix(s, "$m") {
		if ctx.Session != nil && ctx.Player != nil {
			playerAttrs, err := am.LoadByIdForCtx(ctx, ctx.Player.UserID())
			if err != nil {
				ctx.setExecutionError(err)
				return
			}
			if err = playerAttrs.Delete(name); err != nil {
				ctx.setExecutionError(err)
			}
			return
		}
	}

	// 群变量
	if ctx.Group != nil && strings.HasPrefix(s, "$g") {
		groupAttrs, err := am.LoadByIdForCtx(ctx, ctx.Group.GroupID())
		if err != nil {
			ctx.setExecutionError(err)
			return
		}
		if err = groupAttrs.Delete(s); err != nil {
			ctx.setExecutionError(err)
		}
		return
	}

	curAttrs, err := am.LoadByCtx(ctx)
	if err != nil {
		ctx.setExecutionError(err)
		return
	}
	if err = curAttrs.Delete(name); err != nil {
		ctx.setExecutionError(err)
	}
}

func VarGetValueInt64(ctx *MsgContext, s string) (int64, bool) {
	v, exists := VarGetValue(ctx, s)
	if exists && v.TypeId == ds.VMTypeInt {
		return int64(v.MustReadInt()), true
	}
	return 0, false
}

func VarGetValueStr(ctx *MsgContext, s string) (string, bool) {
	v, exists := _VarGetValueV1(ctx, s)
	if exists && v.TypeID == VMTypeString {
		return v.Value.(string), true
	}
	return "", false
}

func VarGetValueComputed(ctx *MsgContext, s string) (string, bool) {
	v, exists := VarGetValue(ctx, s)
	if exists && v.TypeId == ds.VMTypeComputedValue {
		return v.Value.(*ds.ComputedData).Expr, true
	}
	return "", false
}

func VarGetValue(ctx *MsgContext, s string) (*ds.VMValue, bool) {
	name := GetValueNameByAlias(s, aliasMapForCtx(ctx))
	am := ctx.Dice.AttrsManager

	// 临时变量
	if strings.HasPrefix(s, "$t") {
		if ctx.vm != nil {
			v, ok := ctx.vm.Attrs.Load(s)
			if ok {
				return v, ok
			}
		}
		// 跟入群致辞闪退的一个bug有关：临时值表必须按请求初始化。
		if values := ctx.Player.tempValues(); values != nil {
			if v, ok := values.Load(s); ok {
				return v, ok
			}
		}
		return nil, false
	}
	if ctx.IsCompatibilityTest {
		if ctx.vm == nil {
			return nil, false
		}
		key := name
		if strings.HasPrefix(s, "$g") {
			key = s
		}
		return ctx.vm.Attrs.Load(key)
	}

	// 个人全局变量
	if strings.HasPrefix(s, "$m") {
		if ctx.Session != nil && ctx.Player != nil {
			playerAttrs, err := am.LoadByIdForCtx(ctx, ctx.Player.UserID())
			if err != nil {
				ctx.setExecutionError(err)
				return nil, false
			}
			return playerAttrs.LoadX(name)
		}
	}

	// 群变量
	if ctx.Group != nil && strings.HasPrefix(s, "$g") {
		groupAttrs, err := am.LoadByIdForCtx(ctx, ctx.Group.GroupID())
		if err != nil {
			ctx.setExecutionError(err)
			return nil, false
		}
		return groupAttrs.LoadX(s)
	}

	// 个人群变量
	if ctx.Player != nil {
		curAttrs, err := am.LoadByCtx(ctx)
		if err != nil {
			ctx.setExecutionError(err)
			return nil, false
		}
		return curAttrs.LoadX(name)
	}

	return nil, false
}

func _VarGetValueV1(ctx *MsgContext, s string) (*VMValue, bool) {
	if v, ok := VarGetValue(ctx, s); ok {
		return dsValueToRollVMv1(v), ok
	}
	return nil, false
}

func (i *GroupPlayerInfo) GetValueNameByAlias(s string, alias map[string][]string) string {
	name := s

	for k, v := range alias {
		if strings.EqualFold(s, k) {
			name = k // 防止一手大小写不一致
			break    // 名字本身就是确定值，不用修改
		}
		for _, i := range v {
			if strings.EqualFold(s, i) {
				name = k
				break
			}
		}
	}

	return name
}

func GetValueNameByAlias(s string, alias map[string][]string) string {
	name := s

	for k, v := range alias {
		if strings.EqualFold(s, k) {
			name = k
			break
		}
		for _, i := range v {
			if strings.EqualFold(s, i) {
				name = k
				break
			}
		}
	}

	return name
}

func SetTempVars(ctx *MsgContext, qqNickname string) {
	// 设置临时变量
	if ctx.Player != nil {
		pcName := ctx.Player.Name()
		pcName = strings.ReplaceAll(pcName, "\n", "")
		pcName = strings.ReplaceAll(pcName, "\r", "")
		pcName = strings.ReplaceAll(pcName, `\n`, "")
		pcName = strings.ReplaceAll(pcName, `\r`, "")
		pcName = strings.ReplaceAll(pcName, `\f`, "")

		VarSetValueStr(ctx, "$t玩家", fmt.Sprintf("<%s>", pcName))
		if ctx.Dice != nil && !ctx.Dice.Config().PlayerNameWrapEnable {
			VarSetValueStr(ctx, "$t玩家", pcName)
		}
		VarSetValueStr(ctx, "$t玩家_RAW", pcName)
		VarSetValueStr(ctx, "$tQQ昵称", fmt.Sprintf("<%s>", qqNickname))
		VarSetValueStr(ctx, "$t帐号昵称", fmt.Sprintf("<%s>", qqNickname))
		VarSetValueStr(ctx, "$t账号昵称", fmt.Sprintf("<%s>", qqNickname))
		playerID := ctx.Player.UserID()
		VarSetValueStr(ctx, "$t帐号ID", playerID)
		VarSetValueStr(ctx, "$t账号ID", playerID)
		VarSetValueInt64(ctx, "$t个人骰子面数", ctx.Player.DiceSideNum())
		VarSetValueStr(ctx, "$tQQ", playerID)
		VarSetValueStr(ctx, "$t骰子帐号", ctx.EndPoint.UserID)
		VarSetValueStr(ctx, "$t骰子账号", ctx.EndPoint.UserID)
		VarSetValueStr(ctx, "$t骰子昵称", ctx.EndPoint.Nickname)
		VarSetValueStr(ctx, "$t帐号ID_RAW", UserIDExtract(playerID))
		VarSetValueStr(ctx, "$t账号ID_RAW", UserIDExtract(playerID))

		if ctx.EndPoint.ProtocolType != "official" {
			VarSetValueStr(ctx, "$t平台", ctx.EndPoint.Platform)
		} else {
			VarSetValueStr(ctx, "$t平台", "QQ-official")
		}

		rpSeed := (time.Now().Unix() + (8 * 60 * 60)) / (24 * 60 * 60)
		rpSeed += int64(fingerprint(ctx.EndPoint.UserID))
		rpSeed += int64(fingerprint(playerID))
		randItem := rand.NewSource(rpSeed)
		rp := randItem.Int63()%100 + 1
		VarSetValueInt64(ctx, "$t人品", rp)

		now := time.Now()
		t, _ := strconv.ParseInt(now.Format("20060102"), 10, 64)
		VarSetValueInt64(ctx, "$tDate", t)
		wd := int64(now.Weekday())
		if wd == 0 {
			wd = 7
		}
		VarSetValueInt64(ctx, "$tWeekday", wd)

		t, _ = strconv.ParseInt(now.Format("2006"), 10, 64)
		VarSetValueInt64(ctx, "$tYear", t)
		t, _ = strconv.ParseInt(now.Format("01"), 10, 64)
		VarSetValueInt64(ctx, "$tMonth", t)
		t, _ = strconv.ParseInt(now.Format("02"), 10, 64)
		VarSetValueInt64(ctx, "$tDay", t)
		t, _ = strconv.ParseInt(now.Format("15"), 10, 64)
		VarSetValueInt64(ctx, "$tHour", t)
		t, _ = strconv.ParseInt(now.Format("04"), 10, 64)
		VarSetValueInt64(ctx, "$tMinute", t)
		t, _ = strconv.ParseInt(now.Format("05"), 10, 64)
		VarSetValueInt64(ctx, "$tSecond", t)
		VarSetValueInt64(ctx, "$tTimestamp", now.Unix())
	}

	if ctx.Group != nil {
		groupID := ctx.Group.GroupID()
		if ctx.MessageType == "group" {
			VarSetValueStr(ctx, "$t群号", groupID)
			VarSetValueStr(ctx, "$t群名", ctx.Group.GroupName())
			VarSetValueStr(ctx, "$t群号_RAW", UserIDExtract(groupID))
		}
		VarSetValueInt64(ctx, "$t群组骰子面数", ctx.Group.DiceSideNum())
		VarSetValueInt64(ctx, "$t当前骰子面数", getDefaultDicePoints(ctx))
		system := ctx.Group.System()
		if system == "" {
			if err := ctx.Group.SetSystem("coc7"); err != nil {
				ctx.setExecutionError(err)
				return
			}
			system = "coc7"
		}
		VarSetValueStr(ctx, "$t游戏模式", system)
		VarSetValueStr(ctx, "$t规则模板", system)
		VarSetValueStr(ctx, "$tSystem", system)
		logState, err := ctx.Group.GetLogState()
		if err != nil {
			ctx.setExecutionError(err)
			return
		}
		VarSetValueStr(ctx, "$t当前记录", logState.Name)
		VarSetValueInt64(ctx, "$t权限等级", int64(ctx.PrivilegeLevel))

		var isLogOn int64
		if logState.On {
			isLogOn = 1
		}
		VarSetValueInt64(ctx, "$t日志开启", isLogOn)
	}

	if ctx.MessageType == "group" {
		VarSetValueStr(ctx, "$t消息类型", "group")
	} else {
		VarSetValueStr(ctx, "$t消息类型", "private")
	}
}
