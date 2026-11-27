package api

import (
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/dice"
)

func TestDirSizeAbs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("12345"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.txt"), []byte("1234567"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := dirSizeAbs(dir); got != 12 {
		t.Fatalf("dirSizeAbs = %d, want 12", got)
	}
}

func TestCollectOverviewEndpointsSort(t *testing.T) {
	d := &dice.Dice{
		ImSession: &dice.IMSession{
			EndPoints: []*dice.EndPointInfo{
				{EndPointInfoBase: dice.EndPointInfoBase{Nickname: "disconnected", State: dice.StateDisconnected}},
				{EndPointInfoBase: dice.EndPointInfoBase{Nickname: "connected-b", State: dice.StateConnected}},
				{EndPointInfoBase: dice.EndPointInfoBase{Nickname: "connected-a", State: dice.StateConnected}},
			},
		},
	}

	items := collectOverviewEndpoints(d)
	if len(items) != 3 {
		t.Fatalf("len = %d, want 3", len(items))
	}
	if items[0].Nickname != "connected-a" || items[1].Nickname != "connected-b" {
		t.Fatalf("connected endpoints not sorted first: %+v", items)
	}
	if items[2].Nickname != "disconnected" {
		t.Fatalf("disconnected endpoint should be last: %+v", items)
	}
}

func TestRound2(t *testing.T) {
	cases := map[float64]float64{
		0:       0,
		-1:      0,
		1.234:   1.23,
		1.236:   1.24,
		99.999:  100,
		150.55:  150.6,
		1234.56: 1234.56,
	}
	for input, want := range cases {
		if got := round2(input); got != want {
			t.Fatalf("round2(%v) = %v, want %v", input, got, want)
		}
	}
}
