package dice

import (
	"context"
	"errors"
	"testing"

	"github.com/sealdice/botgo/dto"
)

func TestOfficialQQWebsocketLifecycle_rejectsZeroShards(t *testing.T) {
	ws := &dto.WebsocketAP{Shards: 0}

	err := validateOfficialQQWebsocketAP(ws)

	if !errors.Is(err, ErrOfficialQQZeroShards) {
		t.Fatalf("validateOfficialQQWebsocketAP() error = %v", err)
	}
	if ws.Shards != 0 {
		t.Fatalf("zero shards mutated to %d", ws.Shards)
	}
}

func TestOfficialQQWebsocketLifecycle_retriesReconnectInOrder(t *testing.T) {
	var attempts int

	err := runOfficialQQSession(t.Context(), func(context.Context) error {
		attempts++
		if attempts == 1 {
			return ErrOfficialQQReconnect
		}
		return nil
	})

	if err != nil {
		t.Fatalf("runOfficialQQSession() error = %v", err)
	}
	if attempts != 2 {
		t.Fatalf("session attempts = %d, want 2", attempts)
	}
}
