package dice

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
)

var _ adapterapi.QueryRuntime = (*onebotRuntime)(nil)

// defaultOnebotLookupBudget bounds all provider lookups made on behalf of one
// inbound event. The worker handles events one at a time, so a slow or silent
// provider must delay an event by at most this much and then deliver it
// without names.
const defaultOnebotLookupBudget = 3 * time.Second

var errOnebotLookupUnavailable = errors.New("onebot: provider lookup unavailable")

// onebotDisplayName makes provider-supplied display text safe for the inbound
// contract, which rejects invalid UTF-8 and oversized fields for the whole
// message. Names are display text: an unusable one is shortened or dropped, it
// never rejects the event.
func onebotDisplayName(name string) string {
	name = strings.TrimSpace(strings.ToValidUTF8(name, ""))
	if len(name) <= adapterapi.MaxInboundFieldBytes {
		return name
	}
	cut := adapterapi.MaxInboundFieldBytes
	for cut > 0 && !utf8.RuneStart(name[cut]) {
		cut--
	}
	return strings.TrimSpace(name[:cut])
}

func (r *onebotRuntime) lookupProvider() onebotOutboundEmitter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.outbound != nil {
		return r.outbound
	}
	if r.emitter != nil {
		return r.emitter
	}
	return nil
}

// onebotLookupData returns the data object of an acknowledged provider answer.
// A failed, incomplete or malformed answer is reported as not usable so a
// caller never treats it as an empty success.
func onebotLookupData(raw []byte, into any) bool {
	var envelope struct {
		Status  string          `json:"status"`
		Retcode *int            `json:"retcode"`
		Data    json.RawMessage `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || !strings.EqualFold(envelope.Status, "ok") ||
		envelope.Retcode == nil || *envelope.Retcode != 0 || len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return false
	}
	return json.Unmarshal(envelope.Data, into) == nil
}

func (r *onebotRuntime) lookupGroupName(ctx context.Context, outbound onebotOutboundEmitter, groupID int64) string {
	raw, err := outbound.Raw(ctx, emitter.ACTION_GET_GROUP_INFO, emitterTypes.GetGroupInfoReq{GroupId: groupID})
	var data struct {
		GroupName string `json:"group_name"`
	}
	if err != nil || !onebotLookupData(raw, &data) {
		return ""
	}
	return onebotDisplayName(data.GroupName)
}

// lookupMemberName prefers the group card, as the legacy handlers did.
func (r *onebotRuntime) lookupMemberName(ctx context.Context, outbound onebotOutboundEmitter, groupID, userID int64) string {
	raw, err := outbound.Raw(ctx, emitter.ACTION_GET_GROUP_MEMBER_INFO, emitterTypes.GetGroupMemberInfoReq{GroupId: groupID, UserId: userID})
	var data struct {
		Nickname string `json:"nickname"`
		Card     string `json:"card"`
	}
	if err != nil || !onebotLookupData(raw, &data) {
		return ""
	}
	if card := onebotDisplayName(data.Card); card != "" {
		return card
	}
	return onebotDisplayName(data.Nickname)
}

func (r *onebotRuntime) lookupStrangerName(ctx context.Context, outbound onebotOutboundEmitter, userID int64) string {
	raw, err := outbound.Raw(ctx, emitter.ACTION_GET_STRANGER_INFO, emitterTypes.GetStrangerInfo{UserId: userID})
	var data struct {
		Nickname string `json:"nickname"`
	}
	if err != nil || !onebotLookupData(raw, &data) {
		return ""
	}
	return onebotDisplayName(data.Nickname)
}

// enrichOnebotEvent names the people and the group a notice or request is
// about, so Core can show and remember them without any provider IO of its
// own. It is best effort and bounded: a failed lookup leaves the name empty and
// the event is delivered regardless. Events about the bot leaving a room are
// not enriched, because the provider can no longer answer for that room and
// Core already knows its name.
func (r *onebotRuntime) enrichOnebotEvent(ctx context.Context, message *adapterapi.InboundMessage) {
	if message.Kind != adapterapi.InboundKindNotice && message.Kind != adapterapi.InboundKindRequest {
		return
	}
	if message.Event == adapterapi.InboundEventSelfLeft || message.Event == adapterapi.InboundEventSelfRemoved {
		return
	}
	outbound := r.lookupProvider()
	if outbound == nil {
		return
	}
	budget := r.lookupBudget
	if budget <= 0 {
		budget = defaultOnebotLookupBudget
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	var groupID int64
	if message.ConversationKind == adapterapi.ConversationKindGroup {
		groupID = ExtractQQEmitterGroupID(string(message.Conversation))
	}
	if groupID > 0 {
		message.ConversationName = r.lookupGroupName(ctx, outbound, groupID)
	}
	// A requester is not yet in the group they invite the bot to, so a group
	// member lookup would be asked about someone who is not a member.
	member := groupID > 0 && message.Kind == adapterapi.InboundKindNotice
	if message.Sender != "" {
		if senderID := ExtractQQEmitterUserID(string(message.Sender)); senderID > 0 {
			if member {
				message.SenderName = r.lookupMemberName(ctx, outbound, groupID, senderID)
			} else {
				message.SenderName = r.lookupStrangerName(ctx, outbound, senderID)
			}
		}
	}
	if message.Subject != "" && message.Subject == message.Sender {
		message.SubjectName = message.SenderName
	}
}

// Query answers read-only lookups for Core. Unlike an outbound effect it is
// neither persisted nor retried: the caller's context bounds the wait and any
// failure is reported as an error, never as a guessed answer.
func (r *onebotRuntime) Query(ctx context.Context, request adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
	if err := request.Validate(); err != nil {
		return adapterapi.QueryResult{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	switch request.Kind {
	case adapterapi.QueryKindInvalid:
		return adapterapi.QueryResult{}, adapterapi.ErrInvalidContract
	case adapterapi.QueryKindMemberRole:
		return r.queryMemberRole(ctx, request)
	case adapterapi.QueryKindGroupHistory:
		return r.queryGroupHistory(ctx, request)
	}
	return adapterapi.QueryResult{}, adapterapi.ErrUnsupportedAction
}

func (r *onebotRuntime) queryMemberRole(ctx context.Context, request adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
	groupID := ExtractQQEmitterGroupID(string(request.Group))
	userID := ExtractQQEmitterUserID(string(request.Member))
	if !strings.HasPrefix(string(request.Group), "QQ-Group:") || !strings.HasPrefix(string(request.Member), "QQ:") || groupID <= 0 || userID <= 0 {
		return adapterapi.QueryResult{}, adapterapi.ErrInvalidContract
	}
	outbound := r.lookupProvider()
	if outbound == nil {
		return adapterapi.QueryResult{}, errOnebotLookupUnavailable
	}
	raw, err := outbound.Raw(ctx, emitter.ACTION_GET_GROUP_MEMBER_INFO, emitterTypes.GetGroupMemberInfoReq{GroupId: groupID, UserId: userID, NoCache: request.Fresh})
	if err != nil {
		return adapterapi.QueryResult{}, err
	}
	var data struct {
		Role string `json:"role"`
	}
	if !onebotLookupData(raw, &data) {
		return adapterapi.QueryResult{}, errOnebotLookupUnavailable
	}
	role := normalizeGroupSenderRole(data.Role)
	if role == "" {
		return adapterapi.QueryResult{}, errOnebotLookupUnavailable
	}
	return adapterapi.QueryResult{Role: role}, nil
}
