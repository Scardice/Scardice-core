package dice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSanitizeKookGatewayURLStripsToken(t *testing.T) {
	cases := map[string]string{
		"wss://api.kookapp.cn/v3/gateway?token=secret&compress=0": "wss://api.kookapp.cn/v3/gateway",
		"wss://api.kookapp.cn/v3/gateway":                         "wss://api.kookapp.cn/v3/gateway",
		"":                                                        "",
	}
	for in, want := range cases {
		if got := sanitizeKookGatewayURL(in); got != want {
			t.Fatalf("sanitizeKookGatewayURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteKookResumeFileNoSync(t *testing.T) {
	path := filepath.Join(t.TempDir(), "kook_resume.json")
	payload := []byte(`{"session_id":"sess-1","sn":7}`)
	if err := writeKookResumeFileNoSync(path, payload); err != nil {
		t.Fatalf("writeKookResumeFileNoSync(): %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(): %v", err)
	}
	if string(data) != string(payload) {
		t.Fatalf("file content = %q, want %q", data, payload)
	}
	if strings.Contains(string(data), "token") {
		t.Fatalf("resume file must not contain credentials: %q", data)
	}
}
