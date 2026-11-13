package dice

import (
	"context"
	"errors"
	"testing"
)

func TestOfficialQQTransientFailureKeepsEndpointEnabled(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	ctx, cancel := context.WithCancel(context.Background())
	pa := &PlatformAdapterOfficialQQ{EndPoint: ep, Ctx: ctx, CancelFunc: cancel}

	if ret := pa.failConnectTransient(ctx); ret != 1 {
		t.Fatalf("failConnectTransient = %d, want 1", ret)
	}
	if !ep.Enable || ep.State != StateConnecting {
		t.Fatalf("transient failure should keep endpoint retryable: enable=%v state=%d", ep.Enable, ep.State)
	}
	if pa.Ctx != nil {
		t.Fatal("session context should be cleared for the next retry")
	}
}

func TestOfficialQQPermanentFailureDisablesEndpoint(t *testing.T) {
	ep := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{Enable: true, State: StateConnecting}}
	ctx, cancel := context.WithCancel(context.Background())
	pa := &PlatformAdapterOfficialQQ{EndPoint: ep, Ctx: ctx, CancelFunc: cancel}

	if ret := pa.failConnect(ctx); ret != 1 {
		t.Fatalf("failConnect = %d, want 1", ret)
	}
	if ep.Enable || ep.State != StateConnectionFailed {
		t.Fatalf("permanent failure should disable endpoint: enable=%v state=%d", ep.Enable, ep.State)
	}
}

func TestOfficialQQConnectAuthErrorClassification(t *testing.T) {
	authErrors := []string{
		"retrieve token http status 401, traceID x",
		"403 forbidden",
		"invalid app secret",
	}
	for _, msg := range authErrors {
		if !isOfficialQQConnectAuthError(errors.New(msg)) {
			t.Errorf("%q should be classified as auth error", msg)
		}
	}
	transient := []string{
		"dial tcp: i/o timeout",
		"retrieve token http status 502",
		"EOF",
	}
	for _, msg := range transient {
		if isOfficialQQConnectAuthError(errors.New(msg)) {
			t.Errorf("%q should not be classified as auth error", msg)
		}
	}
}
