package logger

import "testing"

func TestRedactURIToken(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"/sd-api/log/stream?token=abc123", "/sd-api/log/stream?token=***"},
		{"/sd-api/log/stream?token=abc123&x=1", "/sd-api/log/stream?token=***&x=1"},
		{"/sd-api/log/stream?x=1&token=abc123&y=2", "/sd-api/log/stream?x=1&token=***&y=2"},
		{"/sd-api/log/stream?token", "/sd-api/log/stream?token=***"},
		{"/sd-api/log/stream?tokens=abc", "/sd-api/log/stream?tokens=abc"},
		{"/sd-api/log/stream", "/sd-api/log/stream"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := redactURIToken(tc.in); got != tc.want {
			t.Errorf("redactURIToken(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}
