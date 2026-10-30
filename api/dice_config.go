package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/labstack/echo/v4"
	"golang.org/x/time/rate"

	"Scardice-core/dice"
	"Scardice-core/utils"
)

type DiceConfigInfo struct {
	dice.Config

	CommandPrefix       []string `form:"commandPrefix"       json:"commandPrefix"`
	DiceMasters         []string `form:"diceMasters"         json:"diceMasters"`
	UIPassword          string   `form:"uiPassword"          json:"uiPassword"`
	LogPageItemLimit    int64    `json:"logPageItemLimit"`
	DefaultCocRuleIndex string   `json:"defaultCocRuleIndex"` // 默认coc index
	MaxExecuteTime      string   `json:"maxExecuteTime"`      // 最大骰点次数
	MaxCocCardGen       string   `json:"maxCocCardGen"`       // 最大coc制卡数
	ServerAddress       string   `form:"serveAddress"        json:"serveAddress"`
	TrayTooltip         string   `json:"trayTooltip"`
	HelpDocEngineType   int      `json:"helpDocEngineType"`
	DiceRandomMode      string   `json:"diceRandomMode"`
}

func DiceConfig(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	configView := myDice.Config
	commandPrefix := append([]string(nil), myDice.CommandPrefix...)
	diceMasters := append([]string(nil), myDice.DiceMasters...)
	var projectedConfigState struct {
		mailPasswordRef string
	}
	extDefaultSettings := make([]*dice.ExtDefaultSettingItem, 0, len(configView.ExtDefaultSettings))
	runtimeExtensionDefaults := configView.ExtDefaultSettings
	if myDice.DurableStoreAttached() {
		view, _, state, err := myDice.DurableLegacyConfigView(context.Background())
		if err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
		}
		configView = view
		commandPrefix = append([]string(nil), state.Outer.CommandPrefix...)
		diceMasters = append([]string(nil), state.Outer.DiceMasters...)
		projectedConfigState.mailPasswordRef = state.Mail.MailPasswordRef
		extensionState, err := myDice.DurableExtensionState(context.Background())
		if err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
		}
		durableExtensionSettings := make(map[string]struct{}, len(extensionState.DefaultCommands))
		for _, extensionID := range extensionState.ExtensionOrder {
			defaults, ok := extensionState.DefaultCommands[extensionID]
			if !ok {
				continue
			}
			disabled := make(map[string]bool, len(defaults.DisabledCommands))
			for command := range defaults.DisabledCommands {
				disabled[command] = true
			}
			extension := myDice.ExtFind(extensionID, false)
			extDefaultSettings = append(extDefaultSettings, &dice.ExtDefaultSettingItem{
				Name:            extensionID,
				AutoActive:      defaults.AutoActive,
				DisabledCommand: disabled,
				ExtItem:         extension,
				Loaded:          extension != nil,
			})
			durableExtensionSettings[extensionID] = struct{}{}
		}
		for _, item := range runtimeExtensionDefaults {
			if item == nil || !item.Loaded {
				continue
			}
			if _, ok := durableExtensionSettings[item.Name]; ok {
				continue
			}
			extDefaultSettings = append(extDefaultSettings, item)
		}
	} else {
		for _, item := range configView.ExtDefaultSettings {
			if item.Loaded {
				extDefaultSettings = append(extDefaultSettings, item)
			}
		}
	}

	password := ""
	if myDice.Parent.UIPasswordHash != "" {
		password = "------"
	}

	limit := configView.UILogLimit
	if limit == 0 {
		limit = 100
	}
	myDice.UnlockCodeUpdate(false)

	cocRule := strconv.FormatInt(configView.DefaultCocRuleIndex, 10)
	if configView.DefaultCocRuleIndex == 11 {
		cocRule = "dg"
	}

	maxExec := strconv.FormatInt(configView.MaxExecuteTime, 10)
	maxCard := strconv.FormatInt(configView.MaxCocCardGen, 10)

	emailPasswordMasked := ""
	if projectedConfigState.mailPasswordRef != "" || configView.MailPassword != "" {
		emailPasswordMasked = "******"
	}

	info := DiceConfigInfo{
		Config:              configView,
		CommandPrefix:       commandPrefix,
		DiceMasters:         diceMasters,
		UIPassword:          password,
		LogPageItemLimit:    limit,
		DefaultCocRuleIndex: cocRule,
		ServerAddress:       myDice.Parent.ServeAddress,
		TrayTooltip:         myDice.Parent.GetTrayTooltip(),
		HelpDocEngineType:   myDice.Parent.HelpDocEngineType,
		DiceRandomMode:      string(myDice.Parent.GetDiceRandomMode()),
		MaxExecuteTime:      maxExec,
		MaxCocCardGen:       maxCard,
	}
	info.ExtDefaultSettings = extDefaultSettings
	info.DefaultCocRuleIndex = cocRule
	info.MailPassword = emailPasswordMasked
	info.QuitInactiveThresholdDays = info.QuitInactiveThreshold.Hours() / 24

	return c.JSON(http.StatusOK, info)
}

func DiceConfigSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	jsonMap := make(map[string]interface{})
	err := json.NewDecoder(c.Request().Body).Decode(&jsonMap)

	stringConvert := func(val interface{}) []string {
		var lst []string
		for _, i := range val.([]interface{}) {
			t := i.(string)
			if t != "" {
				lst = append(lst, t)
			}
		}
		return lst
	}

	if err != nil {
		myDice.Logger.Error("DiceConfigSet", err)
		return c.JSON(http.StatusOK, nil)
	}

	durableAttached := myDice.DurableStoreAttached()
	persistDiceConfig := false
	if durableAttached {
		for key := range jsonMap {
			switch key {
			case "serveAddress", "trayTooltip", "uiPassword", "extDefaultSettings":
				continue
			default:
				persistDiceConfig = true
			}
		}
	}

	_, hasExtensionDefaults := jsonMap["extDefaultSettings"]
	lockConfigUpdate := !durableAttached || persistDiceConfig || hasExtensionDefaults
	if lockConfigUpdate {
		myDice.LockConfigUpdate()
		defer myDice.UnlockConfigUpdate()
	}
	var stagedConfig dice.Config
	config := &myDice.Config
	if durableAttached {
		config = &stagedConfig
		if lockConfigUpdate {
			stagedConfig = myDice.Config
		}
	}
	var commandPrefix, diceMasters []string
	if lockConfigUpdate {
		commandPrefix = append([]string(nil), myDice.CommandPrefix...)
		diceMasters = append([]string(nil), myDice.DiceMasters...)
	}
	var durableManagerUpdate dice.DurableManagerConfigPatch
	var durableExtensionDefaults []dice.DurableExtensionDefault
	var pendingExtensionSettings []*dice.ExtDefaultSettingItem
	persistExtensionDefaults := false
	var pendingLogLimit *int
	resetInactiveCron := false
	if durableAttached {
		if value, ok := jsonMap["mailPassword"]; ok {
			password, ok := value.(string)
			if !ok {
				return c.JSON(http.StatusBadRequest, Response{"result": false, "err": "邮箱密码必须是 secret reference"})
			}
			password = strings.TrimSpace(password)
			if password != "" && !strings.HasPrefix(password, "vault:") && !strings.HasPrefix(password, "sha256:") {
				return c.JSON(http.StatusBadRequest, Response{"result": false, "err": "邮箱密码必须是 vault: 或 sha256: 引用"})
			}
		}
	}

	trayTooltip := ""
	trayTooltipModified := false
	if val, ok := jsonMap["trayTooltip"]; ok {
		value, ok := val.(string)
		if !ok {
			return c.JSON(http.StatusBadRequest, Response{
				"result": false,
				"err":    "托盘提示文本必须是字符串",
			})
		}
		value = strings.TrimSpace(value)
		if utf8.RuneCountInString(value) > dice.MaxTrayTooltipPrefixLength {
			return c.JSON(http.StatusBadRequest, Response{
				"result": false,
				"err":    "托盘提示文本前缀不能超过" + strconv.Itoa(dice.MaxTrayTooltipPrefixLength) + "个字符",
			})
		}
		trayTooltip = value
		trayTooltipModified = true
	}

	if val, ok := jsonMap["commandPrefix"]; ok {
		value := stringConvert(val)
		commandPrefix = value
		if !durableAttached {
			myDice.CommandPrefix = value
		}
	}

	if val, ok := jsonMap["diceMasters"]; ok {
		data := stringConvert(val)
		var masters []string
		// 自动修复部分不正确的格式
		for _, i := range data {
			i = strings.ReplaceAll(i, "qq：", "QQ:")
			i = strings.ReplaceAll(i, "QQ：", "QQ:")

			if _, errConv := strconv.Atoi(i); errConv == nil {
				i = "QQ:" + i
			}

			masters = append(masters, i)
		}
		diceMasters = masters
		if !durableAttached {
			myDice.DiceMasters = masters
		}
	}

	if val, ok := jsonMap["noticeIds"]; ok {
		rawTargets := stringConvert(val)
		config.NoticeIDs = make([]string, 0, len(rawTargets))
		for _, rawTarget := range rawTargets {
			if target := dice.ParseNoticeTarget(rawTarget); target.ID != "" {
				config.NoticeIDs = append(config.NoticeIDs, target.String())
			}
		}
	}

	if val, ok := jsonMap["defaultCocRuleIndex"]; ok { //nolint:nestif
		valStr, ok := val.(string)
		if ok {
			valStr = strings.TrimSpace(valStr)
			if strings.EqualFold(valStr, "dg") {
				config.DefaultCocRuleIndex = 11
			} else {
				config.DefaultCocRuleIndex, err = strconv.ParseInt(valStr, 10, 64)
				if err == nil {
					if config.DefaultCocRuleIndex > 5 || config.DefaultCocRuleIndex < 0 {
						config.DefaultCocRuleIndex = dice.DefaultConfig.DefaultCocRuleIndex
					}
				}
			}
		}
	}

	if val, ok := jsonMap["maxExecuteTime"]; ok {
		valStr, ok := val.(string)
		if ok {
			valStr = strings.TrimSpace(valStr)
			var valInt int64
			valInt, err = strconv.ParseInt(valStr, 10, 64)
			if err == nil && valInt > 0 {
				config.MaxExecuteTime = valInt
			} /* else {
				Should return some error?
			} */
		}
	}

	if val, ok := jsonMap["maxCocCardGen"]; ok {
		valStr, ok := val.(string)
		if ok {
			valStr = strings.TrimSpace(valStr)
			var valInt int64
			valInt, err = strconv.ParseInt(valStr, 10, 64)
			if err == nil && valInt > 0 {
				config.MaxCocCardGen = valInt
			} /* else {
				Should return some error?
			} */
		}
	}

	if val, ok := jsonMap["cocCardMergeForward"]; ok {
		if b, ok2 := val.(bool); ok2 {
			config.CocCardMergeForward = b
		}
	}

	if val, ok := jsonMap["personalBurst"]; ok {
		valStr, ok := val.(float64)
		if ok {
			customBurst := int64(valStr)
			if customBurst >= 1 {
				config.PersonalBurst = customBurst
			}
		}
	}

	if val, ok := jsonMap["personalReplenishRate"]; ok {
		valStr, ok := val.(string)
		if ok {
			valStr = strings.TrimSpace(valStr)
			newRate, errParse := utils.ParseRate(valStr)
			if errParse == nil && newRate != rate.Limit(0) {
				config.PersonalReplenishRate = newRate
				config.PersonalReplenishRateStr = valStr
			}
		}
	}

	if val, ok := jsonMap["groupBurst"]; ok {
		valStr, ok := val.(float64)
		if ok {
			customBurst := int64(valStr)
			if customBurst >= 1 {
				config.GroupBurst = customBurst
			}
		}
	}

	if val, ok := jsonMap["groupReplenishRate"]; ok {
		valStr, ok := val.(string)
		if ok {
			valStr = strings.TrimSpace(valStr)
			newRate, errParse := utils.ParseRate(valStr)
			if errParse == nil && newRate != rate.Limit(0) {
				config.GroupReplenishRate = newRate
				config.GroupReplenishRateStr = valStr
			}
		}
	}

	if val, ok := jsonMap["spamSameCommandWindowSec"]; ok {
		valNum, ok2 := val.(float64)
		if ok2 {
			window := int64(valNum)
			if window >= 1 {
				config.SpamSameCommandWindowSec = window
			}
		}
	}

	if val, ok := jsonMap["spamRecoveryMultiplierMax"]; ok {
		valNum, ok2 := val.(float64)
		if ok2 {
			maxMul := int64(valNum)
			if maxMul >= 1 {
				config.SpamRecoveryMultiplierMax = maxMul
			}
		}
	}

	if val, ok := jsonMap["onlyLogCommandInGroup"]; ok {
		config.OnlyLogCommandInGroup = val.(bool)
	}

	if val, ok := jsonMap["onlyLogCommandInPrivate"]; ok {
		config.OnlyLogCommandInPrivate = val.(bool)
	}

	if val, ok := jsonMap["refuseGroupInvite"]; ok {
		config.RefuseGroupInvite = val.(bool)
	}

	if val, ok := jsonMap["workInQQChannel"]; ok {
		config.WorkInQQChannel = val.(bool)
	}

	if val, ok := jsonMap["diceRandomMode"]; ok {
		v, ok := val.(string)
		if !ok {
			return c.JSON(http.StatusBadRequest, Response{
				"result": false,
				"err":    "随机模式必须是字符串",
			})
		}
		mode, ok := dice.ParseDiceRandomMode(v)
		if !ok {
			return c.JSON(http.StatusBadRequest, Response{
				"result": false,
				"err":    fmt.Sprintf("不支持的随机模式: %s", v),
			})
		}
		if myDice.Parent == nil {
			return c.JSON(http.StatusInternalServerError, Response{
				"result": false,
				"err":    "DiceManager 未初始化",
			})
		}
		if durableAttached {
			if effectiveMode, err := myDice.Parent.ValidateDiceRandomMode(mode); err != nil {
				return c.JSON(http.StatusBadRequest, Response{
					"result": false,
					"err":    fmt.Sprintf("随机模式 %s 当前不可用，当前生效模式为 %s: %v", mode, effectiveMode, err),
				})
			}
			modeValue := string(mode)
			durableManagerUpdate.DiceRandomMode = &modeValue
			config.DiceRandomMode = modeValue
		} else if effectiveMode, err := myDice.Parent.SetDiceRandomMode(mode); err != nil {
			return c.JSON(http.StatusBadRequest, Response{
				"result": false,
				"err":    fmt.Sprintf("随机模式 %s 当前不可用，当前生效模式为 %s: %v", mode, effectiveMode, err),
			})
		}
	}

	if val, ok := jsonMap["QQChannelLogMessage"]; ok {
		config.QQChannelLogMessage = val.(bool)
	}

	if val, ok := jsonMap["QQChannelAutoOn"]; ok {
		config.QQChannelAutoOn = val.(bool)
	}

	if val, ok := jsonMap["botExtFreeSwitch"]; ok {
		config.BotExtFreeSwitch = val.(bool)
	}
	if val, ok := jsonMap["botExitWithoutAt"]; ok {
		config.BotExitWithoutAt = val.(bool)
	}
	if val, ok := jsonMap["rateLimitEnabled"]; ok {
		config.RateLimitEnabled = val.(bool)
	}
	if val, ok := jsonMap["trustOnlyMode"]; ok {
		config.TrustOnlyMode = val.(bool)
	}

	aliveNoticeMod := false
	if val, ok := jsonMap["aliveNoticeEnable"]; ok {
		config.AliveNoticeEnable = val.(bool)
		aliveNoticeMod = true
	}

	if val, ok := jsonMap["aliveNoticeValue"]; ok {
		config.AliveNoticeValue = val.(string)
		aliveNoticeMod = true
	}
	if aliveNoticeMod && !durableAttached {
		myDice.ApplyAliveNotice()
	}

	if val, ok := jsonMap["UILogLimit"]; ok {
		val, err := strconv.ParseInt(val.(string), 10, 64)
		if err == nil && val >= 0 {
			limit := int(val)
			if durableAttached {
				pendingLogLimit = &limit
			} else {
				myDice.LogWriter.SetLogLimit(limit)
			}
		}
	}

	if val, ok := jsonMap["messageDelayRangeStart"]; ok {
		f, err := strconv.ParseFloat(val.(string), 64)
		if err == nil {
			if f < 0 {
				f = 0
			}
			if config.MessageDelayRangeEnd < f {
				config.MessageDelayRangeEnd = f
			}
			config.MessageDelayRangeStart = f
		}
	}

	if val, ok := jsonMap["messageDelayRangeEnd"]; ok {
		f, err := strconv.ParseFloat(val.(string), 64)
		if err == nil {
			if f < 0 {
				f = 0
			}

			if f >= config.MessageDelayRangeStart {
				config.MessageDelayRangeEnd = f
			}
		}
	}

	if val, ok := jsonMap["friendAddComment"]; ok {
		config.FriendAddComment = strings.TrimSpace(val.(string))
	}

	if val, ok := jsonMap["uiPassword"]; ok {
		if !dm.JustForTest {
			passwordHash := val.(string)
			if durableAttached {
				durableManagerUpdate.UIPasswordHash = &passwordHash
			} else {
				myDice.Parent.UIPasswordHash = passwordHash
				// 清空所有现有的访问令牌，强制重新登录
				myDice.Parent.AccessTokens = dice.SyncMap[string, bool]{}
			}
		}
	}

	if val, ok := jsonMap["extDefaultSettings"]; ok {
		if durableAttached {
			if _, ok := val.([]interface{}); !ok {
				return c.JSON(http.StatusBadRequest, Response{"result": false, "err": "扩展默认设置必须是数组"})
			}
		}
		data, err := json.Marshal(val)
		if err != nil {
			if durableAttached {
				return c.JSON(http.StatusBadRequest, Response{"result": false, "err": "扩展默认设置格式无效"})
			}
		} else {
			var items []*dice.ExtDefaultSettingItem
			err := json.Unmarshal(data, &items)
			if err != nil && durableAttached {
				return c.JSON(http.StatusBadRequest, Response{"result": false, "err": "扩展默认设置格式无效"})
			}
			if err == nil {
				if durableAttached {
					for _, item := range items {
						if item == nil {
							return c.JSON(http.StatusBadRequest, Response{"result": false, "err": "扩展默认设置项不能为空"})
						}
					}
					pendingExtensionSettings = items
					persistExtensionDefaults = true
					for _, item := range items {
						disabledCommands := make([]string, 0, len(item.DisabledCommand))
						for command, isDisabled := range item.DisabledCommand {
							if isDisabled {
								disabledCommands = append(disabledCommands, command)
							}
						}
						durableExtensionDefaults = append(durableExtensionDefaults, dice.DurableExtensionDefault{
							ExtensionID: item.Name, AutoActive: item.AutoActive, DisabledCommands: disabledCommands,
						})
					}
				} else {
					config.ExtDefaultSettings = items
					myDice.ApplyExtDefaultSettings()
				}
			}
		}
	}

	if val, ok := jsonMap["serveAddress"]; ok {
		if !dm.JustForTest {
			address := val.(string)
			if durableAttached {
				durableManagerUpdate.ServeAddress = &address
			} else {
				myDice.Parent.ServeAddress = address
			}
		}
	}
	if trayTooltipModified {
		if durableAttached {
			durableManagerUpdate.TrayTooltip = &trayTooltip
		} else {
			myDice.Parent.SetTrayTooltip(trayTooltip)
		}
	}

	// if val, ok := jsonMap["customBotExtraText"]; ok {
	// 	myDice.CustomBotExtraText = val.(string)
	// }

	// if val, ok := jsonMap["customDrawKeysText"]; ok {
	// 	myDice.CustomDrawKeysText = val.(string)
	// }

	// if val, ok := jsonMap["customDrawKeysTextEnable"]; ok {
	// 	myDice.CustomDrawKeysTextEnable = val.(bool)
	// }

	if val, ok := jsonMap["logSizeNoticeEnable"]; ok {
		config.LogSizeNoticeEnable = val.(bool)
	}

	if val, ok := jsonMap["logSizeNoticeCount"]; ok {
		count, ok := val.(float64)
		if ok {
			config.LogSizeNoticeCount = int(count)
		}
		if !ok {
			if v, ok := val.(string); ok {
				v2, _ := strconv.ParseInt(v, 10, 64)
				config.LogSizeNoticeCount = int(v2)
			}
		}
		if config.LogSizeNoticeCount == 0 {
			// 不能为零
			config.LogSizeNoticeCount = dice.DefaultConfig.LogSizeNoticeCount
		}
	}

	if val, ok := jsonMap["customReplyConfigEnable"]; ok {
		config.CustomReplyConfigEnable = val.(bool)
	}

	if val, ok := jsonMap["textCmdTrustOnly"]; ok {
		config.TextCmdTrustOnly = val.(bool)
	}

	if val, ok := jsonMap["ignoreUnaddressedBotCmd"]; ok {
		config.IgnoreUnaddressedBotCmd = val.(bool)
	}

	if val, ok := jsonMap["QQEnablePoke"]; ok {
		config.QQEnablePoke = val.(bool)
	}

	if val, ok := jsonMap["playerNameWrapEnable"]; ok {
		config.PlayerNameWrapEnable = val.(bool)
	}

	if val, ok := jsonMap["mailEnable"]; ok {
		config.MailEnable = val.(bool)
	}
	if val, ok := jsonMap["mailFrom"]; ok {
		config.MailFrom = val.(string)
	}
	if val, ok := jsonMap["mailPassword"]; ok {
		config.MailPassword = val.(string)
	}
	if val, ok := jsonMap["mailSmtp"]; ok {
		config.MailSMTP = val.(string)
	}

	if val, ok := jsonMap["quitInactiveThreshold"]; ok {
		set := false
		switch v := val.(type) {
		case string:
			if vv, err := strconv.ParseFloat(v, 64); err == nil {
				config.QuitInactiveThreshold = time.Duration(float64(24*time.Hour) * vv)
				set = true
			}
		case float64:
			config.QuitInactiveThreshold = time.Duration(float64(24*time.Hour) * v)
			set = true
		case int64:
			config.QuitInactiveThreshold = 24 * time.Hour * time.Duration(v)
			set = true
		default:
			// ignore
		}
		if set {
			if durableAttached {
				resetInactiveCron = true
			} else {
				myDice.ResetQuitInactiveCron()
			}
		}
	}

	if val, ok := jsonMap["quitInactiveNoticeSummaryMode"]; ok {
		if v, ok := val.(bool); ok {
			config.QuitInactiveNoticeSummaryMode = v
		}
	}

	if val, ok := jsonMap["quitInactiveBatchSize"]; ok {
		if v, ok := val.(float64); ok {
			if vv := int64(v); vv > 0 {
				config.QuitInactiveBatchSize = vv
			}
		}
	}

	if val, ok := jsonMap["quitInactiveBatchWait"]; ok {
		if v, ok := val.(float64); ok {
			if vv := int64(v); vv > 0 {
				config.QuitInactiveBatchWait = vv
			}
		}
	}

	if durableAttached {
		var mailPasswordRef *string
		if value, ok := jsonMap["mailPassword"]; ok {
			ref := strings.TrimSpace(value.(string))
			mailPasswordRef = &ref
		}
		if err := myDice.DurableCommitConfigRequest(context.Background(), dice.DurableConfigRequest{
			Config:                   *config,
			CommandPrefix:            commandPrefix,
			DiceMasters:              diceMasters,
			MailPasswordRef:          mailPasswordRef,
			PersistDiceConfig:        persistDiceConfig,
			Manager:                  &durableManagerUpdate,
			ExtensionDefaults:        durableExtensionDefaults,
			PersistExtensionDefaults: persistExtensionDefaults,
		}); err != nil {
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		}
		if persistDiceConfig {
			myDice.Config = *config
			myDice.CommandPrefix = commandPrefix
			myDice.DiceMasters = diceMasters
			myDice.Config.MailPassword = ""
			if aliveNoticeMod {
				myDice.ApplyAliveNotice()
			}
			if pendingLogLimit != nil {
				myDice.LogWriter.SetLogLimit(*pendingLogLimit)
			}
			if resetInactiveCron {
				myDice.ResetQuitInactiveCron()
			}
		}
		if persistExtensionDefaults {
			myDice.Config.ExtDefaultSettings = pendingExtensionSettings
			myDice.ApplyExtDefaultSettings()
		}
		myDice.MarkModified()
		return c.JSON(http.StatusOK, nil)
	}
	myDice.MarkModified()
	myDice.Parent.Save()
	return c.JSON(http.StatusOK, nil)
}

func DiceMailTest(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}

	err := myDice.SendMail("", dice.MailTest, dice.NoticeTypeSystem)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	return Success(&c, Response{})
}

func vmVersionSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if dm.JustForTest {
		return Error(&c, "展示模式不支持该操作", Response{"testMode": true})
	}

	var req []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}

	err := c.Bind(&req)
	if err != nil {
		return Error(&c, err.Error(), nil)
	}
	if len(req) == 0 {
		return Error(&c, "缺少设置vm版本的参数", Response{})
	}

	var failTypes []string
	for _, data := range req {
		if data.Type == "" || data.Value == "" {
			failTypes = append(failTypes, data.Type)
			continue
		}
		switch data.Type {
		case dice.VMVersionReply:
			(&myDice.Config).VMVersionForReply = data.Value
		case dice.VMVersionDeck:
			(&myDice.Config).VMVersionForDeck = data.Value
		case dice.VMVersionCustomText:
			(&myDice.Config).VMVersionForCustomText = data.Value
		case dice.VmVersionMsg:
			(&myDice.Config).VMVersionForMsg = data.Value
		default:
			failTypes = append(failTypes, data.Type)
		}
	}
	myDice.MarkModified()
	myDice.Save(false)

	return Success(&c, Response{
		"failTypes": failTypes,
	})
}
