package api

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// logGapFillStatusGet 返回自动补全的只读运行时状态。
func logGapFillStatusGet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if myDice == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "core not ready"})
	}
	return c.JSON(http.StatusOK, myDice.LogGapFillStatusSnapshot())
}
