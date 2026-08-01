package api

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/samber/lo"
	"golang.org/x/sync/singleflight"

	"Scardice-core/dice"
)

const (
	checkTimes                 = 3
	checkTimeout time.Duration = 5 * time.Second
)

type networkHealthTarget struct {
	Target   string        `json:"target"`
	Ok       bool          `json:"ok"`
	Duration time.Duration `json:"duration"`
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

func checkHTTPConnectivity(url string) (bool, time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), checkTimeout)
	defer cancel()

	type rs struct {
		ok       bool
		duration time.Duration
	}
	rsChan := make(chan rs, checkTimes)
	once := func(url string) {
		myDice.Logger.Debugf("check http connectivity, url=%s", url)
		start := time.Now()
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := http.DefaultClient.Do(req) //nolint:gosec
		duration := time.Since(start)
		if err == nil {
			_ = resp.Body.Close()
			rsChan <- rs{true, duration}
		} else {
			myDice.Logger.Debugf("url can't be connected, error: %s", err)
			rsChan <- rs{false, duration}
		}
	}

	var wg sync.WaitGroup
	for range checkTimes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			once(url)
		}()
	}
	wg.Wait()
	close(rsChan)

	ok := true
	var (
		totalDuration int64
		count         int64
		duration      int64
	)
	for res := range rsChan {
		ok = ok && res.ok
		if res.ok {
			count++
			totalDuration += int64(res.duration)
		}
	}
	if count != 0 {
		duration = totalDuration / count
	}
	return ok, time.Duration(duration)
}

func runNetworkHealthCheck() networkHealthResult {
	total := 5 // baidu, seal, sign, google, github
	var wg sync.WaitGroup
	rsChan := make(chan networkHealthTarget, total)

	checkUrls := func(target string, urls []string) {
		for _, url := range urls {
			ok, duration := checkHTTPConnectivity(url)
			if ok {
				rsChan <- networkHealthTarget{
					Target:   target,
					Ok:       true,
					Duration: duration,
				}
				return
			}
		}
		rsChan <- networkHealthTarget{
			Target:   target,
			Ok:       false,
			Duration: 0,
		}
	}

	signGroups, err := dice.LagrangeGetSignInfo(myDice)
	if err == nil && len(signGroups) > 0 {
		signServers := signGroups[len(signGroups)-1].Servers // 取下发列表中 version 最新的签名服务器组，即最后一条
		urls := lo.Map(signServers, func(signServerInfo *dice.SignServerInfo, _ int) string {
			ping, _ := url.JoinPath(signServerInfo.Url, "/ping")
			return ping
		})
		wg.Add(1)
		go func() {
			defer wg.Done()
			checkUrls("sign", urls)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		checkUrls("baidu", []string{"https://baidu.com"})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		checkUrls("seal", dice.BackendUrls)
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		checkUrls("google", []string{"https://google.com"})
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		checkUrls("github", []string{"https://github.com"})
	}()

	wg.Wait()
	close(rsChan)

	var ok []string
	var targets []networkHealthTarget
	for target := range rsChan {
		targets = append(targets, target)
		if target.Ok {
			ok = append(ok, target.Target)
		}
	}

	return networkHealthResult{
		Total:     total,
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

	return Success(&c, Response{
		"total":     result.Total,
		"ok":        result.Ok, // 被 targets 代替，可废弃，但先为接口兼容保留
		"targets":   result.Targets,
		"timestamp": result.Timestamp,
	})
}

func checkNetworkHealth(c echo.Context) error {
	return networkHealthChecks.handle(c)
}
