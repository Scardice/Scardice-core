package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

func DiceAdvancedConfigGet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	return c.JSON(http.StatusOK, myDice.AdvancedConfig())
}

func DiceAdvancedConfigSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	previous := myDice.AdvancedConfig()
	advancedConfig := previous
	if err := c.Bind(&advancedConfig); err != nil {
		return Error(&c, err.Error(), nil)
	}
	if advancedConfig.CustomReplyCooldown <= 0 {
		advancedConfig.CustomReplyCooldown = dice.DefaultCustomReplyCooldown
	}
	if advancedConfig.ExposeDangerousSealInst {
		return c.JSON(http.StatusBadRequest, Response{
			"result": false,
			"code":   "dangerous_seal_inst_unsupported",
			"err":    dice.ErrDangerousSealInstUnsupported.Error(),
		})
	}
	var tokenRef *string
	if advancedConfig.StoryLogBackendToken != previous.StoryLogBackendToken {
		ref := strings.TrimSpace(advancedConfig.StoryLogBackendToken)
		if ref != "" && !strings.HasPrefix(ref, "vault:") && !strings.HasPrefix(ref, "sha256:") {
			return Error(&c, "高级设置 token 必须是 vault: 或 sha256: 引用", nil)
		}
		tokenRef = &ref
	}
	if err := myDice.DurableCommitAdvancedSnapshot(c.Request().Context(), advancedConfig, tokenRef); err != nil {
		var applyErr *dice.ConfigRuntimeApplyError
		if errors.As(err, &applyErr) {
			return c.JSON(http.StatusInternalServerError, Response{
				"result": false,
				"code":   "config_committed_runtime_apply_failed",
				"err":    err.Error(),
			})
		}
		return echo.NewHTTPError(http.StatusConflict, err.Error())
	}
	return c.JSON(http.StatusOK, map[string]any{
		"result":            true,
		"jsReloadTriggered": false,
	})
}
