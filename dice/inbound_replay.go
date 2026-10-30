package dice

import (
	"context"
	"errors"

	"Scardice-core/adapterapi"
	"Scardice-core/core/messageflow"
	"Scardice-core/eventstore"
)

// InboundReplayPort is the seam through which Core hands messages it recovered
// from a provider's history back to ingress, and learns what became of them.
// The endpoint supervisor submits them under the active generation's fence and
// the event store answers for the inbox rows; Core builds neither.
type InboundReplayPort interface {
	SubmitInbound(ctx context.Context, endpointID adapterapi.EndpointID, message adapterapi.InboundMessage) (adapterapi.IngressReceipt, error)
	// InboxStatuses reports each row's status by inbox ID; a purged row has no entry.
	InboxStatuses(ctx context.Context, inboxIDs []string) (map[string]string, error)
}

func isRetryableInboundError(err error) bool {
	return errors.Is(err, messageflow.ErrIngressBackpressure) ||
		errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, eventstore.ErrReadinessQuarantined) ||
		errors.Is(err, eventstore.ErrKeySourceUnavailable) ||
		errors.Is(err, eventstore.ErrEncryptionUnavailable) ||
		errors.Is(err, eventstore.ErrParticipantFailure)
}
