package api

import (
	"net/http"
	"sort"
	"time"

	"Scardice-core/dice"

	"github.com/labstack/echo/v4"
)

func dicePublicInfo(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"endpoints": myDice.ImSession.EndPointsReadOnly(),
		"config":    myDice.Config().PublicDiceConfig})
}
func dicePublicSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	v := struct {
		Config   dice.PublicDiceConfig    `json:"config"`
		Selected []map[string]interface{} `json:"selected"`
	}{}
	err := c.Bind(&v)
	if err != nil {
		return Error(&c, err.Error(), Response{})
	}
	selected := make(map[string]struct{}, len(v.Selected))
	for _, item := range v.Selected {
		if id, ok := item["id"].(string); ok && id != "" {
			selected[id] = struct{}{}
		}
	}
	endpointIDs := make([]string, 0, len(selected))
	for id := range selected {
		endpointIDs = append(endpointIDs, id)
	}
	sort.Strings(endpointIDs)
	if err = myDice.DurableMutateConfig(c.Request().Context(), "public-dice", v, func(config *dice.Config) error {
		config.PublicDiceConfig = v.Config
		config.EndpointIDs = append([]string(nil), endpointIDs...)
		return nil
	}); err != nil {
		return Error(&c, err.Error(), Response{"code": "config_update_failed"})
	}
	//nolint:staticcheck // keep explicit gate on PublicDiceConfig to avoid semantic ambiguity
	if myDice.Config().PublicDiceConfig.Enable {
		if myDice.PublicDiceInfoRegister() {
			myDice.PublicDiceEndpointRefresh()
		}
	}
	myDice.PublicDiceSetupTick()
	myDice.LastUpdatedTime = time.Now().Unix()
	return Success(&c, Response{})
}
