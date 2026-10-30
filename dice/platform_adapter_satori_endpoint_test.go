package dice

import "testing"

func TestSatoriEndpointsBuildVersionedHTTPAndWebSocketURLs(t *testing.T) {
	wsURL, httpURL, err := satoriEndpoints("v1", "localhost", 5500)
	if err != nil {
		t.Fatalf("build Satori endpoints: %v", err)
	}
	if got, want := wsURL.String(), "ws://localhost:5500/v1/events"; got != want {
		t.Fatalf("websocket URL = %q, want %q", got, want)
	}
	if got, want := httpURL.String(), "http://localhost:5500/v1"; got != want {
		t.Fatalf("HTTP URL = %q, want %q", got, want)
	}
}

func TestSatoriEndpointsBracketIPv6Host(t *testing.T) {
	wsURL, _, err := satoriEndpoints("v1", "::1", 5500)
	if err != nil {
		t.Fatalf("build IPv6 Satori endpoint: %v", err)
	}
	if got, want := wsURL.String(), "ws://[::1]:5500/v1/events"; got != want {
		t.Fatalf("websocket URL = %q, want %q", got, want)
	}
}

func TestSatoriEndpointsRejectInvalidConnectionConfig(t *testing.T) {
	if _, _, err := satoriEndpoints("", "localhost", 5500); err == nil {
		t.Fatal("empty version was accepted")
	}
	if _, _, err := satoriEndpoints("v1", "", 5500); err == nil {
		t.Fatal("empty host was accepted")
	}
	if _, _, err := satoriEndpoints("v1", "localhost", 0); err == nil {
		t.Fatal("zero port was accepted")
	}
}
