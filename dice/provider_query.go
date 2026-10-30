package dice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"Scardice-core/adapterapi"
)

// ProviderQueryPort is the narrow seam through which Core asks a running
// endpoint a read-only question. The endpoint supervisor implements it and
// owns generation fencing; Core never reaches a runtime directly.
type ProviderQueryPort interface {
	Query(ctx context.Context, request adapterapi.QueryRequest) (adapterapi.QueryResult, error)
}

// providerQueryTimeout bounds one lookup made while a command is running. A
// provider that does not answer in time is reported as unknown, never guessed.
var providerQueryTimeout = 5 * time.Second

var errBotAccountUnknown = errors.New("cannot resolve bot qq id")

// queryBotGroupRole asks the provider for the bot's own role in groupID. fresh
// bypasses the provider's cache so destructive decisions use a current answer.
func queryBotGroupRole(ctx *MsgContext, groupID string, fresh bool) (string, error) {
	botID, ok := getOnebotBotQQID(ctx)
	if !ok {
		return "", errBotAccountUnknown
	}
	request := adapterapi.QueryRequest{
		EndpointID: adapterapi.EndpointID(ctx.EndPoint.ID),
		Kind:       adapterapi.QueryKindMemberRole,
		Group:      adapterapi.ConversationID(canonicalOnebotGroupID(groupID)),
		Member:     adapterapi.PrincipalID(FormatOnebotDiceIDQQ(strconv.FormatInt(botID, 10))),
		Fresh:      fresh,
	}
	parent := context.Background()
	if ctx.callbackTransaction != nil && ctx.callbackTransaction.executionContext != nil {
		parent = ctx.callbackTransaction.executionContext
	}
	queryCtx, cancel := context.WithTimeout(parent, providerQueryTimeout)
	defer cancel()
	result, err := ctx.Dice.ProviderQuery.Query(queryCtx, request)
	if err != nil {
		return "", fmt.Errorf("get_group_member_info failed: %w", err)
	}
	return result.Role, nil
}
