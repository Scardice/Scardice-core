package dice

import (
	"net/url"
	"strings"
	"time"

	"github.com/monaco-io/request"
)

func _tryGetBackendBase(url string) string {
	c := request.Client{
		URL:     url,
		Method:  "GET",
		Timeout: 10 * time.Second,
	}
	resp := c.Send()
	if resp.Code() == 200 {
		return resp.String()
	}
	return ""
}

var BackendUrls = []string{
	"http://api.weizaima.com",
	"http://dice.weizaima.com",
	"http://api.sealdice.com",
}

func normalizeBackendURL(raw string) (string, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", false
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", false
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", false
	}
	if u.Host == "" {
		return "", false
	}
	return strings.TrimRight(s, "/"), true
}

func TryGetBackendURL() {
	exists := map[string]struct{}{}
	for _, v := range BackendUrls {
		if normalized, ok := normalizeBackendURL(v); ok {
			exists[normalized] = struct{}{}
		}
	}

	ret := _tryGetBackendBase("http://sealdice.com/list.txt")
	if ret == "" {
		ret = _tryGetBackendBase("http://test1.sealdice.com/list.txt")
	}
	if ret != "" {
		splits := strings.Split(ret, "\n")
		for _, s := range splits {
			normalized, ok := normalizeBackendURL(s)
			if !ok {
				continue
			}
			if _, ok = exists[normalized]; ok {
				continue
			}
			exists[normalized] = struct{}{}
			BackendUrls = append(BackendUrls, normalized)
		}
	}
}
