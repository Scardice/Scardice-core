//go:build cgo

package native

import (
	"errors"
	"testing"

	jsservices "Scardice-core/utils/jsengine/services"
)

func TestNativeLoopRejectsServiceEventsAfterClose(t *testing.T) {
	loop := &nativeLoop{}
	loop.closed.Store(true)
	err := loop.enqueueServiceEvent(nativeServiceEvent{
		kind:     jsservices.EventData,
		request:  1,
		response: jsservices.Response{String: "late"},
	})
	if !errors.Is(err, ErrNativeClosed) {
		t.Fatalf("enqueueServiceEvent() error = %v, want ErrNativeClosed", err)
	}
}
