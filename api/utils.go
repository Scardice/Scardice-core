package api

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

const filePreviewContentSecurityPolicy = "sandbox; default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline'"

type Response map[string]interface{}

func Success(c *echo.Context, res Response) error {
	res["result"] = true
	return (*c).JSON(http.StatusOK, res)
}

func Error(c *echo.Context, errMsg string, res Response) error {
	res["result"] = false
	res["err"] = errMsg
	return (*c).JSON(http.StatusOK, res)
}

func Int64ToBytes(i int64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(i))
	return buf
}

func doAuth(c echo.Context) bool {
	if testWebUIAuthBypassEnabled() {
		if WebUIOriginRateLimitBypassEnabled() {
			return true
		}
		if c == nil || c.Request() == nil {
			return false
		}
		return sameOriginOrNoOrigin(c.Request())
	}
	token := c.Request().Header.Get("token") //nolint:canonicalheader // private header
	if token == "" {
		token = c.QueryParam("token")
	}
	return myDice.Parent.AccessTokens.Exists(token)
}

func GetHexData(c echo.Context, method string, name string) (value []byte, finished bool) {
	var err error
	var strValue string
	// var exists bool

	switch method {
	case "GET":
		strValue = c.Param(name)
	case "POST":
		strValue = c.FormValue(name)
	}

	// if !exists {
	// 	c.String(http.StatusNotAcceptable, "")
	// 	return nil, true
	// }

	value, err = hex.DecodeString(strValue)
	if err != nil {
		_ = c.String(http.StatusBadRequest, "")
		return nil, true
	}

	return value, false
}

func getGithubAvatar(c echo.Context) error {
	// 因为不明原因阻塞，会导致显示离线，先注释掉了
	uid := c.Param("uid")
	return c.Redirect(http.StatusFound, fmt.Sprintf("https://avatars.githubusercontent.com/%s?s=200", uid))

	// uid := c.Param("uid")
	// req := request.Client{
	// 	URL:    fmt.Sprintf("https://avatars.githubusercontent.com/%s?s=200", uid),
	// 	Method: "GET",
	// }

	// resp := req.Send()
	// if resp.OK() {
	// 	// 设置缓存时间为3天
	// 	c.Response().Header().Set("Cache-Control", "max-age=259200")

	// 	return c.Blob(http.StatusOK, resp.ContentType(), resp.Bytes())
	// }
	// return c.JSON(http.StatusNotFound, "")
}
