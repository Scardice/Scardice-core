package logger

import (
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// redactURIToken 把访问日志里的 token 查询参数替换为 ***。
// 前端 EventSource 无法自定义请求头，只能在 URL 带 token；访问日志和
// 反向代理日志不应因此记录管理员凭证。
func redactURIToken(uri string) string {
	q := strings.IndexByte(uri, '?')
	if q < 0 {
		return uri
	}
	prefix, query := uri[:q], uri[q+1:]
	parts := strings.Split(query, "&")
	changed := false
	for i, part := range parts {
		key, _, _ := strings.Cut(part, "=")
		if key == "token" {
			parts[i] = "token=***"
			changed = true
		}
	}
	if !changed {
		return uri
	}
	return prefix + "?" + strings.Join(parts, "&")
}

func EchoLogMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			log := zap.S().Named(LogKeyWeb)
			req := c.Request()
			res := c.Response()
			start := time.Now()

			var err error
			if err = next(c); err != nil {
				c.Error(err)
			}
			stop := time.Now()

			id := req.Header.Get(echo.HeaderXRequestID)
			if id == "" {
				id = res.Header().Get(echo.HeaderXRequestID)
			}
			reqSize := req.Header.Get(echo.HeaderContentLength)
			if reqSize == "" {
				reqSize = "0"
			}

			// 特殊情况下，需要输出DEBUG日志
			log.Debugf("%s %s [%v] %s %-7s %s %3d %s %s %13v %s %s",
				id,
				c.RealIP(),
				stop.Format(time.RFC3339),
				req.Host,
				req.Method,
				redactURIToken(req.RequestURI),
				res.Status,
				reqSize,
				strconv.FormatInt(res.Size, 10),
				stop.Sub(start).String(),
				req.Referer(),
				req.UserAgent(),
			)
			return err
		}
	}
}
