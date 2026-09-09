package api

import (
	"context"
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"

	"Scardice-core/dice"
)

func shouldReloadDangerousAPIState(jsEnabled bool, runtimeSealInstExposed bool, desiredExposeDangerousSealInst bool) bool {
	return jsEnabled && runtimeSealInstExposed != desiredExposeDangerousSealInst
}

func DiceAdvancedConfigGet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if myDice.DurableStoreAttached() {
		advancedConfig, err := myDice.DurableLegacyAdvancedView(context.Background())
		if err != nil {
			return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
		}
		return c.JSON(http.StatusOK, advancedConfig)
	}
	return c.JSON(http.StatusOK, myDice.AdvancedConfig)
}

func DiceAdvancedConfigSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	prevAdvancedConfig := myDice.AdvancedConfig
	advancedConfig := prevAdvancedConfig
	durableAttached := myDice.DurableStoreAttached()
	err := c.Bind(&advancedConfig)
	if err != nil {
		return Error(&c, err.Error(), nil)
	}
	if advancedConfig.CustomReplyCooldown <= 0 {
		advancedConfig.CustomReplyCooldown = dice.DefaultCustomReplyCooldown
	}

	var tokenRef *string
	if durableAttached && advancedConfig.StoryLogBackendToken != prevAdvancedConfig.StoryLogBackendToken {
		ref := strings.TrimSpace(advancedConfig.StoryLogBackendToken)
		if ref != "" && !strings.HasPrefix(ref, "vault:") && !strings.HasPrefix(ref, "sha256:") {
			return Error(&c, "高级设置 token 必须是 vault: 或 sha256: 引用", nil)
		}
		tokenRef = &ref
	}

	if durableAttached {
		if err := myDice.DurableCommitAdvancedSnapshot(context.Background(), advancedConfig, tokenRef); err != nil {
			myDice.AdvancedConfig = prevAdvancedConfig
			return echo.NewHTTPError(http.StatusConflict, err.Error())
		}
		advancedConfig.StoryLogBackendToken = ""
	}
	myDice.AdvancedConfig = advancedConfig

	// 统一标记为修改
	myDice.MarkModified()
	if !durableAttached {
		myDice.Parent.Save()
	}

	reloadTriggered := false
	if shouldReloadDangerousAPIState(myDice.Config.JsEnable, myDice.JsSealInstExposed, advancedConfig.ExposeDangerousSealInst) {
		myDice.JsReloadLock.Lock()
		myDice.JsReload()
		myDice.JsReloadLock.Unlock()
		reloadTriggered = true
	}

	return c.JSON(http.StatusOK, map[string]any{
		"result":            true,
		"jsReloadTriggered": reloadTriggered,
	})
}
