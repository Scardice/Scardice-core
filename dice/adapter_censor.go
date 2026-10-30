package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/dice/censor"
	"Scardice-core/message"
)

var (
	errAdapterCensorBlocked     = errors.New("adapter content rejected by censor")
	errAdapterCensorUnavailable = errors.New("adapter censor unavailable")
)

func (d *Dice) checkAdapterOutboundCensor(ctx *MsgContext, raw string) error {
	if !d.Config.EnableCensor || d.Config.CensorMode != OnlyOutputReply {
		return nil
	}
	return d.checkAdapterProtocolCensor(ctx, raw)
}

func (d *Dice) checkAdapterInboundCensor(ctx *MsgContext, event adapterapi.AdapterEvent) error {
	if !d.Config.EnableCensor {
		return nil
	}
	switch d.Config.CensorMode {
	case AllInput:
	case OnlyInputCommand:
		if event.Type != "message" || ctx == nil || ctx.CommandID == 0 {
			return nil
		}
	default:
		return nil
	}
	// 核心消息链已经拦截的输入沿用同一个结果，避免透传再次交付或重复记账。
	if ctx != nil && ctx.Censored {
		return errAdapterCensorBlocked
	}
	return d.checkAdapterProtocolCensor(ctx, event.RawJSON)
}

func (d *Dice) checkAdapterProtocolCensor(ctx *MsgContext, raw string) error {
	manager := d.CensorManager
	if manager == nil || manager.Censor == nil || manager.IsLoading {
		return errAdapterCensorUnavailable
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	body, err := readAdapterCensorJSON(decoder)
	if err != nil {
		return err
	}
	matcher := adapterCensorMatcher{engine: manager.Censor, result: censor.CheckResult{HighestLevel: censor.Ignore}}
	if err := matcher.visit(body, false); err != nil {
		return err
	}
	if matcher.result.HighestLevel <= censor.Ignore {
		return nil
	}

	// 责任身份来自宿主会话；请求中的 user_id/group_id 是协议目标。
	if ctx != nil && !ctx.adapterEventUnattributed && ctx.Dice == d && ctx.Session != nil && ctx.EndPoint != nil && ctx.Player != nil && ctx.Player.UserID != "" {
		msg := &Message{
			MessageType: ctx.MessageType,
			Message:     "adapter protocol content",
			Sender:      SenderBase{UserID: ctx.Player.UserID, Nickname: ctx.Player.Name},
		}
		canHandle := ctx.MessageType == "private"
		if ctx.MessageType == "group" && ctx.Group != nil && ctx.Session.ServiceAtNew != nil {
			msg.GroupID = ctx.Group.GroupID
			group, exists := ctx.Session.ServiceAtNew.Load(msg.GroupID)
			canHandle = exists && group != nil
		}
		if canHandle {
			result := manager.recordCensorCheck(ctx, msg, matcher.result, d.Config.CensorThresholds, true)
			handlerCtx := ctx
			if ctx.callbackTransaction != nil {
				handlerCtx = ctx.ShallowCopy()
				handlerCtx.callbackTransaction = nil
			}
			// 处置采用独立提交，先于插件错误完成；通知内容使用命中词。
			d.applyCensorResult(handlerCtx, msg, strings.Join(result.CurSensitiveWords, "\n"), "", result)
		}
	}
	if ctx != nil {
		ctx.Censored = true
	}
	return errAdapterCensorBlocked
}

type adapterCensorMatcher struct {
	engine *censor.Censor
	result censor.CheckResult
}

func (m *adapterCensorMatcher) text(text string) {
	if text == "" {
		return
	}
	result := m.engine.Check(text)
	if result.HighestLevel > censor.Ignore {
		m.result.HighestLevel = censor.HigherLevel(m.result.HighestLevel, result.HighestLevel)
		if m.result.SensitiveWords == nil {
			m.result.SensitiveWords = result.SensitiveWords
		} else {
			for word, level := range result.SensitiveWords {
				m.result.SensitiveWords[word] = level
			}
		}
	}
}

func readAdapterCensorJSON(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: adapter censor JSON", adapterapi.ErrInvalidContract)
	}
	switch token {
	case json.Delim('{'):
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, fmt.Errorf("%w: adapter censor JSON field", adapterapi.ErrInvalidContract)
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, fmt.Errorf("%w: adapter censor JSON field", adapterapi.ErrInvalidContract)
			}
			if _, exists := object[key]; exists {
				return nil, fmt.Errorf("%w: adapter censor requires unique JSON fields", adapterapi.ErrInvalidContract)
			}
			child, err := readAdapterCensorJSON(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = child
		}
		if _, err := decoder.Token(); err != nil {
			return nil, fmt.Errorf("%w: adapter censor JSON object", adapterapi.ErrInvalidContract)
		}
		return object, nil
	case json.Delim('['):
		var array []any
		for decoder.More() {
			child, err := readAdapterCensorJSON(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, child)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, fmt.Errorf("%w: adapter censor JSON array", adapterapi.ErrInvalidContract)
		}
		return array, nil
	default:
		return token, nil
	}
}

func (m *adapterCensorMatcher) cardJSON(raw string) error {
	if !json.Valid([]byte(raw)) {
		return fmt.Errorf("%w: adapter censor card JSON", adapterapi.ErrInvalidContract)
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	body, err := readAdapterCensorJSON(decoder)
	if err != nil {
		return err
	}
	return m.visit(body, false)
}

func (m *adapterCensorMatcher) cqText(text string) error {
	if !strings.Contains(text, "[CQ:") {
		return nil
	}
	var parseErr error
	visible := cqCodeRe.ReplaceAllStringFunc(text, func(code string) string {
		kind, args, _ := strings.Cut(code[4:len(code)-1], ",")
		for arg := range strings.SplitSeq(args, ",") {
			key, value, ok := strings.Cut(arg, "=")
			if !ok {
				continue
			}
			value = message.UnescapeCQParam(value)
			m.text(value)
			if kind == "json" && key == "data" && parseErr == nil {
				parseErr = m.cardJSON(value)
			}
		}
		return ""
	})
	m.text(visible)
	return parseErr
}

func (m *adapterCensorMatcher) visit(value any, messageValue bool) error {
	switch value := value.(type) {
	case string:
		m.text(value)
		if messageValue {
			return m.cqText(value)
		}
	case map[string]any:
		for key, child := range value {
			isMessage := key == "message" || key == "messages" || key == "raw_message" || key == "content"
			if err := m.visit(child, isMessage); err != nil {
				return err
			}
		}
		if messageValue && value["type"] == "json" {
			if data, ok := value["data"].(map[string]any); ok {
				if raw, ok := data["data"].(string); ok {
					return m.cardJSON(raw)
				}
			}
		}
	case []any:
		var first string
		var joined strings.Builder
		for _, child := range value {
			if err := m.visit(child, messageValue); err != nil {
				return err
			}
			if !messageValue {
				continue
			}
			segment, ok := child.(map[string]any)
			if !ok || segment["type"] != "text" {
				continue
			}
			data, ok := segment["data"].(map[string]any)
			if !ok {
				continue
			}
			text, _ := data["text"].(string)
			if text == "" {
				continue
			}
			if first == "" {
				first = text
				continue
			}
			if joined.Len() == 0 {
				joined.WriteString(first)
			}
			joined.WriteString(text)
		}
		if joined.Len() > 0 {
			m.text(joined.String())
		}
	}
	return nil
}
