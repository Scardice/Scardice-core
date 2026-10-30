package messageflow

import (
	"context"
	"errors"
	"testing"

	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

func TestCallbackReleasesHostFenceOnEveryHostOutcome(t *testing.T) {
	hostErr := errors.New("host failure")
	commitErr := eventstore.ErrParticipantFailure
	for _, test := range []struct {
		name      string
		hostErr   error
		commitErr error
	}{
		{name: "success"},
		{name: "host failure", hostErr: hostErr},
		{name: "commit failure", commitErr: commitErr},
	} {
		t.Run(test.name, func(t *testing.T) {
			inbox := newCallbackTestInbox()
			released := false
			store := &callbackTestStore{commitErr: test.commitErr, onCommit: func() {
				if released {
					t.Fatal("host fence released before durable commit")
				}
			}}
			host := &callbackTestHost{inbox: inbox, fn: func(context.Context, CallbackRequest, *playerstate.LocalOverlay, *MutationCollector) (CallbackResult, error) {
				return CallbackResult{Release: func() { released = true }}, test.hostErr
			}}
			service := newCallbackTestService(t, inbox, store, host, callbackTestCodec{})
			_, err := service.ProcessOne(context.Background())
			if test.hostErr == nil && test.commitErr == nil && err != nil {
				t.Fatalf("ProcessOne: %v", err)
			}
			if !released {
				t.Fatal("host fence was not released")
			}
		})
	}
}
