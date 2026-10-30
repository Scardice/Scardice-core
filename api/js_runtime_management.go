package api

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"Scardice-core/dice"
)

type jsRuntimeManagementResponse struct {
	Runtimes        []dice.JSRuntimeStatus        `json:"runtimes"`
	DiscoveryError  string                        `json:"discoveryError"`
	DefaultRuntime  string                        `json:"defaultRuntime"`
	ExtensionRoutes map[string]string             `json:"extensionRoutes"`
	PendingChanges  []dice.JSRuntimePendingChange `json:"pendingChanges"`
}

func jsRuntimeManagementGet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if myDice == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"err": "Dice runtime is unavailable"})
	}
	defaultRuntime, routes := myDice.JSRuntimeConfig()
	pending, err := myDice.JSRuntimePendingChanges()
	if err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"err": err.Error()})
	}
	return c.JSON(http.StatusOK, jsRuntimeManagementResponse{
		Runtimes:        myDice.JSRuntimeStatuses(),
		DiscoveryError:  myDice.JSRuntimeDiscoveryError(),
		DefaultRuntime:  defaultRuntime,
		ExtensionRoutes: routes,
		PendingChanges:  pending,
	})
}

func jsRuntimeConfigSet(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if myDice == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"result": false, "err": "Dice runtime is unavailable"})
	}
	var request struct {
		DefaultRuntime  string            `json:"defaultRuntime"`
		ExtensionRoutes map[string]string `json:"extensionRoutes"`
	}
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]any{"result": false, "err": err.Error()})
	}
	if err := myDice.SetJSRuntimeConfig(c.Request().Context(), request.DefaultRuntime, request.ExtensionRoutes); err != nil {
		status := http.StatusServiceUnavailable
		if errors.Is(err, dice.ErrInvalidJSRuntimeConfig) {
			status = http.StatusBadRequest
		}
		return c.JSON(status, map[string]any{"result": false, "err": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]any{"result": true})
}

func jsRuntimeInstall(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if myDice == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"result": false, "err": "Dice runtime is unavailable"})
	}
	change, err := myDice.StageJSRuntimeArchive(c.Request().Body)
	if err != nil {
		return c.JSON(jsRuntimePackageHTTPStatus(err), map[string]any{"result": false, "err": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]any{"result": true, "pendingChange": change})
}

func jsRuntimeUninstall(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}
	if myDice == nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]any{"result": false, "err": "Dice runtime is unavailable"})
	}
	var request struct {
		ID string `json:"id"`
	}
	if err := c.Bind(&request); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]any{"result": false, "err": err.Error()})
	}
	change, err := myDice.StageJSRuntimeUninstall(request.ID)
	if err != nil {
		return c.JSON(jsRuntimePackageHTTPStatus(err), map[string]any{"result": false, "err": err.Error()})
	}
	return c.JSON(http.StatusOK, map[string]any{"result": true, "pendingChange": change})
}

func jsRuntimePackageHTTPStatus(err error) int {
	switch {
	case errors.Is(err, dice.ErrInvalidJSRuntimeArchive):
		return http.StatusBadRequest
	case errors.Is(err, dice.ErrJSRuntimeArchiveTooLarge):
		return http.StatusRequestEntityTooLarge
	case errors.Is(err, dice.ErrJSRuntimePackageExists), errors.Is(err, dice.ErrJSRuntimePackagePending), errors.Is(err, dice.ErrJSRuntimeInUse):
		return http.StatusConflict
	case errors.Is(err, dice.ErrJSRuntimeNotManaged):
		return http.StatusNotFound
	case errors.Is(err, dice.ErrJSRuntimeStoreUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}
