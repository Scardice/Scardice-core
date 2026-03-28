package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func shouldReloadDangerousAPIState(jsEnabled bool, runtimeSealInstExposed bool, desiredExposeDangerousSealInst bool) bool {
	return jsEnabled && runtimeSealInstExposed != desiredExposeDangerousSealInst
}

func DiceAdvancedConfigGet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	return c.JSON(http.StatusOK, myDice.AdvancedConfig)
}

func DiceAdvancedConfigSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	prevAdvancedConfig := myDice.AdvancedConfig
	advancedConfig := prevAdvancedConfig
	err := c.Bind(&advancedConfig)
	if err != nil {
		return Error(&c, err.Error(), nil)
	}
	if advancedConfig.CustomReplyCooldown <= 0 {
		advancedConfig.CustomReplyCooldown = dice.DefaultCustomReplyCooldown
	}

	myDice.AdvancedConfig = advancedConfig

	// 统一标记为修改
	myDice.MarkModified()
	myDice.Parent.Save()

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
