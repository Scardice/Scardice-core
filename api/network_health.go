package api

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"golang.org/x/sync/singleflight"
)

const checkTimeout time.Duration = 5 * time.Second

type networkHealthTarget struct {
	Target     string        `json:"target"`
	Ok         bool          `json:"ok"`
	Duration   time.Duration `json:"duration"`
	StatusCode int           `json:"statusCode"`
}

type networkHealthTargetSpec struct {
	target string
	url    string
}

var networkHealthTargetSpecs = [...]networkHealthTargetSpec{
	{target: "qq", url: "https://api.sgroup.qq.com/users/@me"},
	{target: "kook", url: "https://www.kookapp.cn/api/v3/channel/view"},
	{target: "discord", url: "https://discord.com/api/v10/gateway"},
	// The invalid fixed token is only a probe marker; getMe returns API JSON, unlike the website redirect.
	{target: "telegram", url: "https://api.telegram.org/bot000000000:INVALID_NETWORK_HEALTH_PROBE/getMe"},
	{target: "dingtalk", url: "https://api.dingtalk.com/v1.0/gateway/connections/open"},
	{target: "slack", url: "https://slack.com/api/api.test"},
}

type networkHealthProbeResult struct {
	Ok         bool
	Duration   time.Duration
	StatusCode int
}

type networkHealthResult struct {
	Total     int
	Ok        []string
	Targets   []networkHealthTarget
	Timestamp int64
}

type networkHealthChecker struct {
	group singleflight.Group
	run   func() networkHealthResult
}

var networkHealthChecks = networkHealthChecker{run: runNetworkHealthCheck}

func (checker *networkHealthChecker) check(ctx context.Context) (networkHealthResult, error) {
	result := checker.group.DoChan("network-health", func() (any, error) {
		return checker.run(), nil
	})

	select {
	case <-ctx.Done():
		return networkHealthResult{}, ctx.Err()
	case call := <-result:
		if call.Err != nil {
			return networkHealthResult{}, call.Err
		}
		return call.Val.(networkHealthResult), nil
	}
}

func networkHealthHTTPClient(transport http.RoundTripper) *http.Client {
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func checkHTTPConnectivity(client *http.Client, endpoint string) networkHealthProbeResult {
	var probe networkHealthProbeResult
	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
		start := time.Now()
		myDice.Logger.Debugf("check http connectivity, url=%s", endpoint)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			cancel()
			myDice.Logger.Debugf("url can't be connected, error: %s", err)
			return networkHealthProbeResult{Duration: time.Since(start)}
		}
		resp, err := client.Do(req) //nolint:gosec
		probe.Duration = time.Since(start)
		if err == nil {
			_ = resp.Body.Close()
			cancel()
			probe.Ok = true
			probe.StatusCode = resp.StatusCode
			return probe
		}
		cancel()
		myDice.Logger.Debugf("url can't be connected, error: %s", err)
	}
	return probe
}

func runNetworkHealthCheck() networkHealthResult {
	return runNetworkHealthCheckWithClient(networkHealthHTTPClient(http.DefaultTransport))
}

func runNetworkHealthCheckWithClient(client *http.Client) networkHealthResult {
	targets := make([]networkHealthTarget, len(networkHealthTargetSpecs))
	var wg sync.WaitGroup
	for index, target := range networkHealthTargetSpecs {
		wg.Add(1)
		go func(index int, target networkHealthTargetSpec) {
			defer wg.Done()
			probe := checkHTTPConnectivity(client, target.url)
			targets[index] = networkHealthTarget{
				Target:     target.target,
				Ok:         probe.Ok,
				Duration:   probe.Duration,
				StatusCode: probe.StatusCode,
			}
		}(index, target)
	}
	wg.Wait()

	ok := make([]string, 0, len(targets))
	for _, target := range targets {
		if target.Ok {
			ok = append(ok, target.Target)
		}
	}

	return networkHealthResult{
		Total:     len(networkHealthTargetSpecs),
		Ok:        ok,
		Targets:   targets,
		Timestamp: time.Now().Unix(),
	}
}

func (checker *networkHealthChecker) handle(c echo.Context) error {
	result, err := checker.check(c.Request().Context())
	if err != nil {
		return err
	}

	if result.Ok == nil {
		result.Ok = []string{}
	}
	return Success(&c, Response{
		"total":     result.Total,
		"ok":        result.Ok,
		"targets":   result.Targets,
		"timestamp": result.Timestamp,
	})
}

func checkNetworkHealth(c echo.Context) error {
	return networkHealthChecks.handle(c)
}
