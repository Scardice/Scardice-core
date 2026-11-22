package api

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"

	"Scardice-core/logger"
)

type logHistoryResponse struct {
	Items         []*logger.LogItem `json:"items"`
	HasMore       bool              `json:"hasMore"`
	NextBeforeSeq int64             `json:"nextBeforeSeq"`
}

// logHistory 读取主页日志的历史记录，按 seq 从新到旧翻页。
// 参数：beforeSeq、limit、levels、startTs、endTs、q。
func logHistory(c echo.Context) error {
	if !doAuth(c) {
		return c.JSON(http.StatusForbidden, nil)
	}

	beforeSeq := int64(math.MaxInt64)
	if raw := strings.TrimSpace(c.QueryParam("beforeSeq")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "beforeSeq 参数无效"})
		}
		beforeSeq = value
	}

	limit := uiHistoryDefaultLimit
	if raw := strings.TrimSpace(c.QueryParam("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value <= 0 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "limit 参数无效"})
		}
		limit = value
	}
	if limit > uiHistoryMaxLimit {
		limit = uiHistoryMaxLimit
	}

	levels := make(map[string]struct{})
	for _, level := range strings.Split(c.QueryParam("levels"), ",") {
		level = strings.ToLower(strings.TrimSpace(level))
		switch level {
		case "debug", "info", "warn", "error":
			levels[level] = struct{}{}
		}
	}

	startTS, err := parseLogHistoryTimestamp(c.QueryParam("startTs"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "startTs 参数无效"})
	}
	endTS, err := parseLogHistoryTimestamp(c.QueryParam("endTs"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "endTs 参数无效"})
	}

	keyword := strings.TrimSpace(c.QueryParam("q"))
	if runes := []rune(keyword); len(runes) > uiHistoryKeywordMaxRunes {
		keyword = string(runes[:uiHistoryKeywordMaxRunes])
	}

	if myDice.LogWriter == nil {
		return c.JSON(http.StatusOK, logHistoryResponse{})
	}

	items, hasMore, err := myDice.LogWriter.ReadHistory(logger.HistoryQuery{
		BeforeSeq: beforeSeq,
		Limit:     limit,
		Levels:    levels,
		StartTS:   startTS,
		EndTS:     endTS,
		Keyword:   keyword,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, nil)
	}

	nextBeforeSeq := int64(0)
	if len(items) > 0 {
		nextBeforeSeq = items[0].Seq
	}
	return c.JSON(http.StatusOK, logHistoryResponse{
		Items:         items,
		HasMore:       hasMore,
		NextBeforeSeq: nextBeforeSeq,
	})
}

const (
	uiHistoryDefaultLimit    = 100
	uiHistoryMaxLimit        = 500
	uiHistoryKeywordMaxRunes = 100
)

func parseLogHistoryTimestamp(raw string) (float64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value < 0 {
		return 0, errors.New("时间戳参数无效")
	}
	return value, nil
}
