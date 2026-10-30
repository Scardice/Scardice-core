package adapterapi

import (
	"context"
	"fmt"
)

// MaxHistoryQueryMessages bounds how many messages one history query may ask
// for or return. Core never needs more at once, and a runtime pages through the
// provider in smaller steps to stay under it.
const MaxHistoryQueryMessages = 1000

// QueryKind is the closed vocabulary of read-only provider lookups Core may
// ask a running endpoint for. A query never changes provider state, so unlike
// an outbound effect it is not persisted or retried: the caller waits for the
// answer under its own deadline and treats a failure as "unknown".
type QueryKind uint8

const (
	QueryKindInvalid QueryKind = iota
	// QueryKindMemberRole asks for Member's role in Group.
	QueryKindMemberRole
	// QueryKindGroupHistory asks for the messages Group received strictly
	// between AfterSequence and BeforeSequence, oldest first, at most Limit of
	// them. BeforeSequence is a message the caller has already received, which
	// a provider can anchor on. When more than Limit exist the newest are
	// returned.
	QueryKindGroupHistory
)

// Valid reports whether kind is a known query.
func (kind QueryKind) Valid() bool {
	return kind > QueryKindInvalid && kind <= QueryKindGroupHistory
}

// QueryRequest addresses one running endpoint generation. A zero Generation
// means the currently active one; the supervisor fences a stale value.
type QueryRequest struct {
	EndpointID EndpointID
	Generation uint64
	Kind       QueryKind
	Group      ConversationID
	Member     PrincipalID
	// Fresh bypasses any provider-side cache so a decision such as dismissing a
	// group is not made on a stale answer.
	Fresh bool
	// AfterSequence, BeforeSequence and Limit bound a QueryKindGroupHistory
	// window: provider sequence numbers strictly between the first two, at most
	// Limit messages. They are zero for every other kind.
	AfterSequence  int64
	BeforeSequence int64
	Limit          int
}

// Validate checks identity and closed-enum bounds before a query reaches a runtime.
func (request QueryRequest) Validate() error {
	if !request.EndpointID.Valid() || !request.Kind.Valid() {
		return fmt.Errorf("%w: query endpoint or kind", ErrInvalidContract)
	}
	hasWindow := request.AfterSequence != 0 || request.BeforeSequence != 0 || request.Limit != 0
	switch request.Kind {
	case QueryKindInvalid:
		return fmt.Errorf("%w: query endpoint or kind", ErrInvalidContract)
	case QueryKindMemberRole:
		if request.Group == "" || !validOptionalIdentifier(string(request.Group)) ||
			request.Member == "" || !validOptionalIdentifier(string(request.Member)) {
			return fmt.Errorf("%w: member role query needs a group and a member", ErrInvalidContract)
		}
		if hasWindow {
			return fmt.Errorf("%w: member role query carries a history window", ErrInvalidContract)
		}
	case QueryKindGroupHistory:
		if request.Group == "" || !validOptionalIdentifier(string(request.Group)) || request.Member != "" {
			return fmt.Errorf("%w: history query needs a group and no member", ErrInvalidContract)
		}
		if request.AfterSequence < 0 || request.BeforeSequence-request.AfterSequence < 2 ||
			request.Limit < 1 || request.Limit > MaxHistoryQueryMessages {
			return fmt.Errorf("%w: history window", ErrInvalidContract)
		}
	}
	return nil
}

// QueryResult carries the answer to one QueryRequest.
type QueryResult struct {
	// Role is "owner", "admin" or "member" for QueryKindMemberRole.
	Role string
	// History holds the messages found for QueryKindGroupHistory, oldest first.
	// They are shaped exactly like live deliveries of the same messages, so the
	// same message is the same fact whichever way it arrived.
	History []InboundMessage
}

// Validate checks that the answer fits the request that was asked.
func (result QueryResult) Validate(request QueryRequest) error {
	switch request.Kind {
	case QueryKindInvalid:
		return fmt.Errorf("%w: query answer for an unknown kind", ErrInvalidContract)
	case QueryKindMemberRole:
		if len(result.History) != 0 {
			return fmt.Errorf("%w: member role answer carries history", ErrInvalidContract)
		}
		switch result.Role {
		case "owner", "admin", "member":
			return nil
		}
		return fmt.Errorf("%w: member role answer", ErrInvalidContract)
	case QueryKindGroupHistory:
		return result.validateHistory(request)
	}
	return fmt.Errorf("%w: query answer for an unknown kind", ErrInvalidContract)
}

func (result QueryResult) validateHistory(request QueryRequest) error {
	if result.Role != "" || len(result.History) > request.Limit {
		return fmt.Errorf("%w: history answer shape", ErrInvalidContract)
	}
	previous := request.AfterSequence
	for _, message := range result.History {
		if err := message.Validate(); err != nil {
			return err
		}
		if message.Kind != InboundKindMessage || message.ConversationKind != ConversationKindGroup ||
			message.Conversation != request.Group || message.History != InboundHistoryNone {
			return fmt.Errorf("%w: history answer holds something other than the asked group's live-shaped messages", ErrInvalidContract)
		}
		if message.Sequence <= previous || message.Sequence >= request.BeforeSequence {
			return fmt.Errorf("%w: history answer outside the window or out of order", ErrInvalidContract)
		}
		previous = message.Sequence
	}
	return nil
}

// QueryRuntime is optional, like ActionRuntime, so runtimes adopt it
// incrementally. An unsupported kind returns ErrUnsupportedAction.
type QueryRuntime interface {
	Query(ctx context.Context, request QueryRequest) (QueryResult, error)
}
