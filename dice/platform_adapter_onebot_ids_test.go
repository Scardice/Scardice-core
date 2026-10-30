package dice

import (
	"strconv"
	"testing"
)

func TestParseOnebotMessageIDAcceptsSignedNonzeroValues(t *testing.T) {
	for _, value := range []int64{1, -1, 123456789, -123456789} {
		parsed, err := parseOnebotMessageID(strconv.FormatInt(value, 10))
		if err != nil || parsed != value {
			t.Fatalf("parse %d = %d, %v", value, parsed, err)
		}
	}
	for _, rejected := range []string{"0", "", "  ", "abc", "1.5"} {
		if _, err := parseOnebotMessageID(rejected); err == nil {
			t.Fatalf("message ID %q must be rejected", rejected)
		}
	}
}

func TestOnebotAuthorizationMatchesTreatsTheBearerSchemeAsOptional(t *testing.T) {
	tests := []struct {
		configured, header string
		want               bool
	}{
		{"", "", true},
		{"", "token", false},
		{"token", "token", true},
		{"token", "Bearer token", true},
		{"Bearer token", "token", true},
		{"Bearer token", "Bearer token", true},
		{"token", "other", false},
		{"token", "", false},
	}
	for _, tt := range tests {
		if got := onebotAuthorizationMatches(tt.configured, tt.header); got != tt.want {
			t.Errorf("onebotAuthorizationMatches(%q, %q) = %v, want %v", tt.configured, tt.header, got, tt.want)
		}
	}
}
