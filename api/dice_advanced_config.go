package api

import (
	"context"
	"net/http"
	"strings"

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

	var advancedConfig dice.AdvancedConfig
	reloadNeeded := false
	updateErr := func() error {
		myDice.LockConfigUpdate()
		defer myDice.UnlockConfigUpdate()

		prevAdvancedConfig := myDice.AdvancedConfig
		advancedConfig = prevAdvancedConfig
		durableAttached := myDice.DurableStoreAttached()
		if err := c.Bind(&advancedConfig); err != nil {
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

		myDice.MarkModified()
		if !durableAttached {
			myDice.Parent.Save()
		}
		reloadNeeded = shouldReloadDangerousAPIState(myDice.Config.JsEnable, myDice.JsSealInstExposed, advancedConfig.ExposeDangerousSealInst)
		return nil
	}()
	if updateErr != nil {
		return updateErr
	}

	reloadTriggered := false
	if reloadNeeded {
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
