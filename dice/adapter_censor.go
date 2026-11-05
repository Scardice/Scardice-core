package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/dice/censor"
	"Scardice-core/eventstore"
	"Scardice-core/message"
)

var (
	errAdapterCensorBlocked     = errors.New("adapter content rejected by censor")
	errAdapterCensorUnavailable = errors.New("adapter censor unavailable")
)

func (d *Dice) checkAdapterOutboundCensor(ctx *MsgContext, raw string) error {
	config := d.Config()
	if !config.EnableCensor || config.CensorMode != OnlyOutputReply {
		return nil
	}
	return d.checkAdapterProtocolCensor(ctx, raw)
}

func (d *Dice) checkAdapterInboundCensor(ctx *MsgContext, event adapterapi.AdapterEvent) error {
	config := d.Config()
	if !config.EnableCensor {
		return nil
	}
	switch config.CensorMode {
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
	if err = matcher.visit(body, false); err != nil {
		return err
	}
	if matcher.result.HighestLevel <= censor.Ignore {
		return nil
	}

	// The protocol payload's user/group fields are targets, never the
	// responsible identity. Enforcement is attributed only to a proven
	// conversational context and commits in an independent root so rejecting
	// the invoking plugin callback cannot roll it back.
	if ctx != nil && !ctx.adapterEventUnattributed && ctx.Dice == d && ctx.Session != nil && ctx.EndPoint != nil && ctx.Player != nil {
		playerID := ctx.Player.UserID()
		groupID := ""
		if ctx.MessageType == "group" && ctx.Group != nil && ctx.Group.Version() != 0 {
			groupID = ctx.Group.GroupID()
		}
		if playerID != "" && (ctx.MessageType == "private" || groupID != "") {
			if enforcementErr := d.enforceAdapterProtocolCensor(ctx, raw, playerID, groupID, matcher.result, manager); enforcementErr != nil && d.Logger != nil {
				d.Logger.Errorf("适配器敏感词独立处置失败: %v", enforcementErr)
			}
		}
	}
	if ctx != nil {
		ctx.Censored = true
	}
	return errAdapterCensorBlocked
}

func (d *Dice) enforceAdapterProtocolCensor(
	source *MsgContext,
	raw, playerID, groupID string,
	result censor.CheckResult,
	manager *CensorManager,
) error {
	if source == nil || source.Session == nil || source.EndPoint == nil || source.Player == nil {
		return errors.New("adapter censor enforcement context is unavailable")
	}
	session := source.Session
	endpoint := source.EndPoint
	messageType := source.MessageType
	commandID := source.CommandID
	currentCommand := source.CurrentCommand
	privilegeLevel := source.PrivilegeLevel
	alreadyCensored := source.Censored
	playerName := source.Player.Name()
	invocationID, err := (eventstore.UUIDGenerator{}).NewID()
	if err != nil {
		return err
	}
	request, err := json.Marshal(struct {
		InvocationID string `json:"invocationId"`
		EndpointID   string `json:"endpointId"`
		MessageType  string `json:"messageType"`
		PlayerID     string `json:"playerId"`
		GroupID      string `json:"groupId,omitempty"`
		Raw          string `json:"raw"`
	}{
		InvocationID: invocationID,
		EndpointID:   endpoint.ID,
		MessageType:  messageType,
		PlayerID:     playerID,
		GroupID:      groupID,
		Raw:          raw,
	})
	if err != nil {
		return err
	}
	identity := d.DomainExecutionIdentity("adapter-censor", invocationID)
	return d.WithDomainExecution(context.Background(), identity, request, func(transaction *DurableCallbackTransaction) error {
		enforcement := &MsgContext{
			Dice:                d,
			Session:             session,
			EndPoint:            endpoint,
			MessageType:         messageType,
			IsPrivate:           messageType == "private",
			CommandID:           commandID,
			CurrentCommand:      currentCommand,
			PrivilegeLevel:      privilegeLevel,
			Censored:            alreadyCensored,
			callbackTransaction: transaction,
			callbackMetadata:    transaction.metadata,
			executionContext:    transaction.executionContext,
		}
		defer enforcement.releaseExecutionState()

		conversationID := groupID
		if enforcement.IsPrivate {
			conversationID = "PG-" + playerID
		}
		if err := enforcement.ResolveExistingDomainConversation(conversationID, playerID); err != nil {
			return err
		}
		msg := &Message{
			MessageType: messageType,
			Message:     "adapter protocol content",
			GroupID:     groupID,
			Sender:      SenderBase{UserID: playerID, Nickname: playerName},
		}
		checkResult := manager.recordCensorCheck(
			enforcement,
			msg,
			result,
			d.Config().CensorThresholds,
			true,
		)
		d.applyCensorResult(
			enforcement,
			msg,
			strings.Join(checkResult.CurSensitiveWords, "\n"),
			"",
			checkResult,
		)
		if err := enforcement.getExecutionError(); err != nil {
			return err
		}
		return transaction.Domain().Err()
	})
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
