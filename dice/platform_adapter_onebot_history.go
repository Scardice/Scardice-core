package dice

import (
	"context"
	"encoding/json"
	"slices"
	"strings"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
)

// onebotHistoryPageSize is how many messages one get_group_msg_history call
// asks for. Providers accept far more (LLBot answered 2000), but a modest page
// keeps one slow call from holding the whole query.
const onebotHistoryPageSize = 200

// queryGroupHistory reads the messages a group received strictly between
// AfterSequence and BeforeSequence.
//
// get_group_msg_history treats message_seq as the END of the page it returns:
// the page holds the messages ending at that sequence, oldest first, and an
// anchor that does not exist yields nothing. So the window is read backwards,
// starting from BeforeSequence (the message the caller has just received, which
// exists) and anchoring each further page at the oldest message of the previous
// one. Anchoring on messages that exist is what keeps this correct when recalled
// messages leave holes in the numbering.
func (r *onebotRuntime) queryGroupHistory(ctx context.Context, request adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
	groupID := ExtractQQEmitterGroupID(string(request.Group))
	if !strings.HasPrefix(string(request.Group), "QQ-Group:") || groupID <= 0 {
		return adapterapi.QueryResult{}, adapterapi.ErrInvalidContract
	}
	outbound := r.lookupProvider()
	if outbound == nil {
		return adapterapi.QueryResult{}, errOnebotLookupUnavailable
	}

	var newestFirst []adapterapi.InboundMessage
	anchor := request.BeforeSequence
	for page := 0; page < onebotHistoryMaxPages(request.Limit) && len(newestFirst) < request.Limit; page++ {
		count := min(onebotHistoryPageSize, request.Limit-len(newestFirst)+1)
		raw, err := outbound.Raw(ctx, emitter.ACTION_GET_GROUP_MSG_HISTORY, emitterTypes.GetGroupMsgHistoryReq{GroupID: groupID, MessageSeq: anchor, Count: count})
		if err != nil {
			return adapterapi.QueryResult{}, err
		}
		var data struct {
			Messages []json.RawMessage `json:"messages"`
		}
		if !onebotLookupData(raw, &data) {
			return adapterapi.QueryResult{}, errOnebotLookupUnavailable
		}

		oldest := anchor
		for _, item := range slices.Backward(data.Messages) {
			var envelope onebotInboundEnvelope
			if json.Unmarshal(item, &envelope) != nil {
				continue
			}
			sequence, ok := onebotInboundSequence(envelope.MessageSeq)
			if !ok || sequence > anchor {
				continue
			}
			oldest = min(oldest, sequence)
			if sequence <= request.AfterSequence || sequence >= request.BeforeSequence || sequence == anchor && page > 0 {
				continue
			}
			// An entry that cannot be placed is left out; the rest of the page still counts.
			if message, err := onebotHistoryInbound(item, request.Group); err == nil {
				newestFirst = append(newestFirst, message)
			}
		}
		if oldest <= request.AfterSequence || oldest >= anchor {
			break
		}
		anchor = oldest
	}

	slices.Reverse(newestFirst)
	return adapterapi.QueryResult{History: newestFirst}, nil
}

// onebotHistoryMaxPages bounds the pages one query may read: enough for limit
// messages plus slack for pages that the window's edges cut short.
func onebotHistoryMaxPages(limit int) int {
	return limit/(onebotHistoryPageSize-1) + 3
}
