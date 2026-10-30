package sealhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
	"time"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
)

type fetchTestScope struct{ context.Context }

func (s fetchTestScope) ExecutionContext() context.Context { return s.Context }

func TestFetchInvocationCancellationReachesHTTPServer(t *testing.T) {
	requests := make(chan context.Context, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		requests <- request.Context()
		select {
		case <-request.Context().Done():
		case <-release:
		}
	}))
	defer server.Close()
	defer close(release)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	loop := eventloop.NewEventLoop(eventloop.EnableConsole(false))
	loop.Start()
	defer loop.Terminate()
	lifecycle := NewFetchLifecycle()
	defer lifecycle.Close()
	invocation, cancel := context.WithCancel(context.Background())
	defer cancel()
	var runErr error
	runOnLoopSync(t, loop, func(vm *goja.Runtime) {
		runErr = EnableFetchWithPolicyAndLifecycleAndContext(vm, loop, proxy, nil, lifecycle, AsyncContextHooks{
			CurrentContext: func() any { return fetchTestScope{invocation} },
		})
		if runErr != nil {
			return
		}
		if runErr = vm.Set("requestURL", server.URL); runErr == nil {
			_, runErr = vm.RunString(`fetch(requestURL).catch(() => {});`)
		}
	})
	if runErr != nil {
		t.Fatal(runErr)
	}
	var upstream context.Context
	select {
	case upstream = <-requests:
	case <-time.After(2 * time.Second):
		t.Fatal("fetch never reached the HTTP server")
	}
	cancel()
	select {
	case <-upstream.Done():
	case <-time.After(time.Second):
		t.Fatal("invocation ended but the upstream HTTP request remained active")
	}
}
