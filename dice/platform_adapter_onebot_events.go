package dice

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"Scardice-core/adapterapi"
)

// onebotInboundEnvelope is the subset of a OneBot v11 event the runtime reads
// to classify it. Identifier fields stay raw because providers send them as
// either numbers or strings.
type onebotInboundEnvelope struct {
	PostType    string          `json:"post_type"`
	MessageType string          `json:"message_type"`
	NoticeType  string          `json:"notice_type"`
	RequestType string          `json:"request_type"`
	SubType     string          `json:"sub_type"`
	Time        int64           `json:"time"`
	SelfID      json.RawMessage `json:"self_id"`
	UserID      json.RawMessage `json:"user_id"`
	GroupID     json.RawMessage `json:"group_id"`
	GuildID     json.RawMessage `json:"guild_id"`
	ChannelID   json.RawMessage `json:"channel_id"`
	MessageID   json.RawMessage `json:"message_id"`
	MessageSeq  json.RawMessage `json:"message_seq"`
	OperatorID  json.RawMessage `json:"operator_id"`
	TargetID    json.RawMessage `json:"target_id"`
	Duration    json.RawMessage `json:"duration"`
	Flag        json.RawMessage `json:"flag"`
	Comment     string          `json:"comment"`
	Message     json.RawMessage `json:"message"`
	Sender      struct {
		Role     string `json:"role"`
		Nickname string `json:"nickname"`
		Card     string `json:"card"`
	} `json:"sender"`
}

func onebotEventRejected(detail string) error {
	return fmt.Errorf("%w: %s", ErrOnebotUnsupportedInboundEvent, detail)
}

// onebotEventPrincipal reads an optional account id. OneBot uses 0 for "no
// operator", which is reported as absent rather than as account "QQ:0".
func onebotEventPrincipal(raw json.RawMessage, field string) (adapterapi.PrincipalID, error) {
	id, ok := onebotInboundID(raw)
	if !ok || id == "0" {
		return "", nil
	}
	principal, err := adapterapi.NewPrincipalID("QQ:" + id)
	if err != nil {
		return "", onebotEventRejected("invalid " + field)
	}
	return principal, nil
}

// fillOnebotEvent translates a provider notice or request into the typed
// Notice/Request vocabulary. The boolean reports whether a typed Core handler
// should run. A false result is not itself a drop decision: handleProtocolInbound
// may retain the original protocol event for the adapter-event hook.
func (r *onebotRuntime) fillOnebotEvent(m *adapterapi.InboundMessage, e *onebotInboundEnvelope) (bool, error) {
	self, err := onebotEventPrincipal(e.SelfID, "self_id")
	if err != nil {
		return false, err
	}
	user, err := onebotEventPrincipal(e.UserID, "user_id")
	if err != nil {
		return false, err
	}
	operator, err := onebotEventPrincipal(e.OperatorID, "operator_id")
	if err != nil {
		return false, err
	}
	target, err := onebotEventPrincipal(e.TargetID, "target_id")
	if err != nil {
		return false, err
	}
	group, hasGroup := onebotInboundID(e.GroupID)
	timeKey := strconv.FormatInt(e.Time, 10)

	inGroup := func() error {
		if !hasGroup {
			return onebotEventRejected("missing group_id")
		}
		conversation, err := adapterapi.NewConversationID("QQ-Group:" + group)
		if err != nil {
			return onebotEventRejected("invalid group_id")
		}
		m.ConversationKind, m.Conversation = adapterapi.ConversationKindGroup, conversation
		return nil
	}
	withUser := func(conversation adapterapi.PrincipalID) error {
		id, err := adapterapi.NewConversationID(string(conversation))
		if err != nil {
			return onebotEventRejected("invalid user_id")
		}
		m.ConversationKind, m.Conversation = adapterapi.ConversationKindDirect, id
		return nil
	}
	identify := func(parts ...string) error {
		id, err := adapterapi.NewProviderEventID("onebot-" + strings.Join(parts, "-"))
		if err != nil {
			return onebotEventRejected("event identity is invalid")
		}
		m.ProviderEventID = id
		return nil
	}
	// actor is the principal whose action the event reports: the operator when
	// there is one, otherwise the affected user.
	actor := func() adapterapi.PrincipalID {
		if operator != "" {
			return operator
		}
		return user
	}
	finish := func(event adapterapi.InboundEventKind, sender, subject adapterapi.PrincipalID) {
		m.Event, m.Sender, m.Subject, m.Operator = event, sender, subject, operator
	}

	switch e.PostType {
	case "notice":
		m.Kind = adapterapi.InboundKindNotice
		switch e.NoticeType {
		case "group_increase":
			if user == "" || self == "" {
				return false, onebotEventRejected("incomplete group_increase identity")
			}
			if err := inGroup(); err != nil {
				return false, err
			}
			if err := identify("group-increase", group, string(user), timeKey); err != nil {
				return false, err
			}
			if user == self {
				sender := user
				if operator != "" && operator != self {
					sender = operator
				}
				finish(adapterapi.InboundEventSelfJoined, sender, user)
			} else {
				finish(adapterapi.InboundEventMemberJoined, user, user)
			}
		case "group_decrease":
			if user == "" || self == "" {
				return false, onebotEventRejected("incomplete group_decrease identity")
			}
			var event adapterapi.InboundEventKind
			switch e.SubType {
			case "kick_me":
				event = adapterapi.InboundEventSelfRemoved
			case "leave", "disband":
				if user != self {
					return false, nil
				}
				event = adapterapi.InboundEventSelfLeft
			default:
				return false, nil
			}
			if err := inGroup(); err != nil {
				return false, err
			}
			if err := identify("group-decrease", group, string(user), timeKey); err != nil {
				return false, err
			}
			finish(event, actor(), user)
		case "group_dismiss":
			// LLBot reports a disbanded room as its own notice; user_id is the owner.
			if user == "" || self == "" {
				return false, onebotEventRejected("incomplete group_dismiss identity")
			}
			if err := inGroup(); err != nil {
				return false, err
			}
			if err := identify("group-dismiss", group, timeKey); err != nil {
				return false, err
			}
			operator = user
			finish(adapterapi.InboundEventSelfLeft, user, self)
		case "group_ban":
			if self == "" {
				return false, onebotEventRejected("incomplete group_ban identity")
			}
			// An absent or zero user_id mutes the whole group, which is not about the bot.
			if e.SubType != "ban" || user == "" || user != self {
				return false, nil
			}
			seconds, known := onebotInboundInt(e.Duration)
			if known && seconds == 0 {
				// A zero-length ban lifts a mute rather than starting one.
				return false, nil
			}
			if err := inGroup(); err != nil {
				return false, err
			}
			if err := identify("group-ban", group, string(user), timeKey); err != nil {
				return false, err
			}
			switch {
			case seconds < 0:
				m.DurationSeconds = math.MaxUint32 // permanent
			case seconds > 0:
				m.DurationSeconds = uint32(min(seconds, math.MaxUint32))
			}
			finish(adapterapi.InboundEventSelfMuted, actor(), user)
		case "friend_add":
			if user == "" {
				return false, onebotEventRejected("missing user_id")
			}
			if err := withUser(user); err != nil {
				return false, err
			}
			if err := identify("friend-add", string(user), timeKey); err != nil {
				return false, err
			}
			finish(adapterapi.InboundEventFriendAdded, user, user)
		case "notify":
			if e.SubType != "poke" {
				return false, onebotEventRejected(fmt.Sprintf("notify sub_type %q", e.SubType))
			}
			if user == "" || target == "" {
				return false, onebotEventRejected("incomplete poke identity")
			}
			if hasGroup {
				if err := inGroup(); err != nil {
					return false, err
				}
			} else if err := withUser(user); err != nil {
				return false, err
			}
			if err := identify("poke", string(m.Conversation), string(user), string(target), timeKey); err != nil {
				return false, err
			}
			finish(adapterapi.InboundEventPoke, user, target)
		default:
			return false, onebotEventRejected(fmt.Sprintf("notice_type %q", e.NoticeType))
		}
	case "request":
		m.Kind = adapterapi.InboundKindRequest
		flag, hasFlag := onebotInboundID(e.Flag)
		switch e.RequestType {
		case "friend":
			if user == "" || !hasFlag {
				return false, onebotEventRejected("incomplete friend request identity")
			}
			if err := withUser(user); err != nil {
				return false, err
			}
			if err := identify("friend-request", flag); err != nil {
				return false, err
			}
			finish(adapterapi.InboundEventFriendRequest, user, "")
			m.Text, m.RequestID, m.RequestPolicy = e.Comment, flag, r.config.FriendRequestPolicy
		case "group":
			if e.SubType != "invite" {
				return false, nil
			}
			if user == "" || !hasFlag {
				return false, onebotEventRejected("incomplete group invite identity")
			}
			if err := inGroup(); err != nil {
				return false, err
			}
			if err := identify("group-invite", flag); err != nil {
				return false, err
			}
			finish(adapterapi.InboundEventGroupInvite, user, "")
			m.RequestID = flag
		default:
			return false, onebotEventRejected(fmt.Sprintf("request_type %q", e.RequestType))
		}
	default:
		return false, onebotEventRejected(fmt.Sprintf("post_type %q", e.PostType))
	}
	return true, nil
}
