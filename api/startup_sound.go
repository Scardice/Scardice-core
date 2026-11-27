package api

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"Scardice-core/bootsound"
)

type StartupSoundStatusResponse struct {
	Enabled   bool             `json:"enabled"`
	Available bool             `json:"available"`
	Player    string           `json:"player"`
	Status    bootsound.Status `json:"status"`
}

// StartupSoundStatus 返回 UI 音频开关、播放路径可用性和最近一次播放结果。
func StartupSoundStatus(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	available, player := bootsound.Availability()
	return c.JSON(http.StatusOK, StartupSoundStatusResponse{
		Enabled:   myDice.Config.StartupSoundEnable,
		Available: available,
		Player:    player,
		Status:    bootsound.StatusSnapshot(),
	})
}
