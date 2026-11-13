package api

import (
	"net/http"
	"net/http/pprof"

	"github.com/labstack/echo/v4"
)

func pprofAuthMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if !doAuth(c) {
			return c.JSON(http.StatusForbidden, nil)
		}
		return next(c)
	}
}

func bindPProfAPIs(e *echo.Echo, prefix string) {
	group := e.Group(prefix+"/debug/pprof", pprofAuthMiddleware)

	group.GET("", echo.WrapHandler(http.HandlerFunc(pprof.Index)))
	group.GET("/", echo.WrapHandler(http.HandlerFunc(pprof.Index)))
	group.GET("/cmdline", echo.WrapHandler(http.HandlerFunc(pprof.Cmdline)))
	group.GET("/profile", echo.WrapHandler(http.HandlerFunc(pprof.Profile)))
	group.GET("/symbol", echo.WrapHandler(http.HandlerFunc(pprof.Symbol)))
	group.GET("/trace", echo.WrapHandler(http.HandlerFunc(pprof.Trace)))
	group.GET("/allocs", echo.WrapHandler(pprof.Handler("allocs")))
	group.GET("/block", echo.WrapHandler(pprof.Handler("block")))
	group.GET("/goroutine", echo.WrapHandler(pprof.Handler("goroutine")))
	group.GET("/heap", echo.WrapHandler(pprof.Handler("heap")))
	group.GET("/mutex", echo.WrapHandler(pprof.Handler("mutex")))
	group.GET("/threadcreate", echo.WrapHandler(pprof.Handler("threadcreate")))
}
