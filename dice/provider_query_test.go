package dice

import (
	"context"
	"errors"
	"testing"
	"time"

	"Scardice-core/adapterapi"
)

type fakeProviderQuery struct {
	role  string
	err   error
	block bool
	calls []adapterapi.QueryRequest
}

func (f *fakeProviderQuery) Query(ctx context.Context, request adapterapi.QueryRequest) (adapterapi.QueryResult, error) {
	f.calls = append(f.calls, request)
	if f.block {
		<-ctx.Done()
		return adapterapi.QueryResult{}, ctx.Err()
	}
	if f.err != nil {
		return adapterapi.QueryResult{}, f.err
	}
	return adapterapi.QueryResult{Role: f.role}, nil
}

func pureOnebotRoleContext(port ProviderQueryPort) *MsgContext {
	d := &Dice{ProviderQuery: port}
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{ID: "endpoint-1", Platform: "QQ", ProtocolType: "pureonebot", UserID: "QQ:3003"}}
	return &MsgContext{Dice: d, EndPoint: endpoint}
}

func TestPureOnebotBotRoleIsQueriedFromTheProviderWithoutTrustingTheCache(t *testing.T) {
	for role, wantOwner := range map[string]bool{"owner": true, "admin": false, "member": false} {
		port := &fakeProviderQuery{role: role}
		ctx := pureOnebotRoleContext(port)
		detail, ok := checkBotGroupRole(ctx, "QQ-Group:2002")
		if !ok || detail != role {
			t.Fatalf("role %q -> %q, %v", role, detail, ok)
		}
		if len(port.calls) != 1 {
			t.Fatalf("queries = %d, want one", len(port.calls))
		}
		got := port.calls[0]
		if got.EndpointID != "endpoint-1" || got.Kind != adapterapi.QueryKindMemberRole || got.Group != "QQ-Group:2002" || got.Member != "QQ:3003" || !got.Fresh {
			t.Fatalf("query = %#v; a dismiss decision must ask for the bot itself, uncached", got)
		}
		needConfirm, checked, _ := shouldDismissRequireOwnerConfirm(pureOnebotRoleContext(&fakeProviderQuery{role: role}), "QQ-Group:2002")
		if !checked || needConfirm != wantOwner {
			t.Fatalf("role %q: needConfirm=%v checked=%v, want %v/true", role, needConfirm, checked, wantOwner)
		}
	}
}

func TestPureOnebotBotRoleFailsClosedInsteadOfGuessing(t *testing.T) {
	ctx := pureOnebotRoleContext(&fakeProviderQuery{err: errors.New("provider says no")})
	if detail, ok := checkBotGroupRole(ctx, "QQ-Group:2002"); ok || detail == "" {
		t.Fatalf("a failed query produced %q, %v", detail, ok)
	}
	if _, checked, _ := shouldDismissRequireOwnerConfirm(ctx, "QQ-Group:2002"); checked {
		t.Fatal("a failed query was treated as a checked role")
	}

	if detail, ok := checkBotGroupRole(pureOnebotRoleContext(nil), "QQ-Group:2002"); ok || detail != "adapter does not support group role check" {
		t.Fatalf("without a query port: %q, %v", detail, ok)
	}

	noAccount := pureOnebotRoleContext(&fakeProviderQuery{role: "owner"})
	noAccount.EndPoint.UserID = ""
	if detail, ok := checkBotGroupRole(noAccount, "QQ-Group:2002"); ok {
		t.Fatalf("an endpoint without a known account answered %q", detail)
	}
}

func TestPureOnebotBotRoleQueryIsBoundedByATimeout(t *testing.T) {
	previous := providerQueryTimeout
	providerQueryTimeout = 60 * time.Millisecond
	defer func() { providerQueryTimeout = previous }()

	ctx := pureOnebotRoleContext(&fakeProviderQuery{block: true})
	started := time.Now()
	detail, ok := checkBotGroupRole(ctx, "QQ-Group:2002")
	if ok || detail == "" {
		t.Fatalf("a silent provider produced %q, %v", detail, ok)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the role check waited %s on a silent provider", elapsed)
	}
}
