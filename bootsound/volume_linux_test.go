//go:build linux

package bootsound

import (
	"math"
	"testing"
)

func TestParseWpctlVolume(t *testing.T) {
	cases := []struct {
		text  string
		amp   float64
		muted bool
		ok    bool
	}{
		{"Volume: 0.80\n", math.Pow(0.8, 3), false, true},
		{"Volume: 0.80 [MUTED]\n", math.Pow(0.8, 3), true, true},
		{"Volume: 1.00\n", 1, false, true},
		{"Volume: 0.00 [MUTED]\n", 0, true, true},
		{"unexpected output\n", 0, false, false},
	}
	for _, tc := range cases {
		amp, muted, ok := parseWpctlVolume(tc.text)
		if ok != tc.ok || muted != tc.muted || math.Abs(amp-tc.amp) > 1e-9 {
			t.Errorf("parseWpctlVolume(%q)=(%v,%v,%v), want (%v,%v,%v)", tc.text, amp, muted, ok, tc.amp, tc.muted, tc.ok)
		}
	}
}

func TestParsePactlVolume(t *testing.T) {
	cases := []struct {
		text string
		amp  float64
		ok   bool
	}{
		{"Volume: front-left: 52429 /  80% / -5.81 dB,   front-right: 52429 /  80% / -5.81 dB", math.Pow(0.8, 3), true},
		{"Volume: front-left: 65536 / 100% / 0.00 dB", 1, true},
		{"Volume: front-left: 0 /   0% / -inf dB", 0, true},
		{"no percentage here", 0, false},
	}
	for _, tc := range cases {
		amp, ok := parsePactlVolume(tc.text)
		if ok != tc.ok || math.Abs(amp-tc.amp) > 1e-9 {
			t.Errorf("parsePactlVolume(%q)=(%v,%v), want (%v,%v)", tc.text, amp, ok, tc.amp, tc.ok)
		}
	}
}

func TestParsePactlMuted(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"Mute: no\n", false},
		{"Mute: yes\n", true},
		{"Mute: YES\n", true},
		{"", false},
		{"unexpected output\n", false},
	}
	for _, tc := range cases {
		if got := parsePactlMuted(tc.text); got != tc.want {
			t.Errorf("parsePactlMuted(%q)=%v, want %v", tc.text, got, tc.want)
		}
	}
}
