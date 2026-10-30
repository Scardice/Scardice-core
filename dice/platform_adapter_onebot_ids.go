package dice

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func FormatOnebotDiceIDQQ(diceQQ string) string {
	return fmt.Sprintf("QQ:%s", diceQQ)
}

func FormatOnebotDiceIDQQGroup(diceQQ string) string {
	return fmt.Sprintf("QQ-Group:%s", diceQQ)
}

func canonicalOnebotUserID(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "QQ:") {
		return raw
	}
	return FormatOnebotDiceIDQQ(raw)
}

func canonicalOnebotGroupID(raw string) string {
	if raw == "" {
		return ""
	}
	if strings.HasPrefix(raw, "QQ-Group:") {
		return raw
	}
	return FormatOnebotDiceIDQQGroup(raw)
}

func parseOnebotMessageID(msgID string) (int64, error) {
	msgID = strings.TrimSpace(msgID)
	if msgID == "" {
		return 0, errors.New("empty message id")
	}
	id, err := strconv.ParseInt(msgID, 10, 64)
	if err != nil || id == 0 {
		return 0, errors.New("invalid message id")
	}
	return id, nil
}

func ExtractQQEmitterUserID(id string) int64 {
	id = canonicalOnebotUserID(id)
	if strings.HasPrefix(id, "QQ:") {
		atoi, _ := strconv.ParseInt(id[len("QQ:"):], 10, 64)
		return atoi
	}
	return 0
}

func ExtractQQEmitterGroupID(id string) int64 {
	id = canonicalOnebotGroupID(id)
	if strings.HasPrefix(id, "QQ-Group:") {
		atoi, _ := strconv.ParseInt(id[len("QQ-Group:"):], 10, 64)
		return atoi
	}
	return 0
}

func onebotAuthorizationMatches(configuredToken, headerValue string) bool {
	if configuredToken == "" {
		return headerValue == ""
	}

	if configuredToken == headerValue {
		return true
	}

	configuredWithoutBearer := strings.TrimPrefix(configuredToken, "Bearer ")
	headerWithoutBearer := strings.TrimPrefix(headerValue, "Bearer ")
	return configuredWithoutBearer == headerWithoutBearer
}
