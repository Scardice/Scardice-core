package endpoint

import (
	"testing"

	"Scardice-core/adapterapi"
)

func TestCommandDigestIncludesEphemeralSecretDigest(t *testing.T) {
	base := Command{Kind: CommandCreate, Type: CommandCreate, CommandID: "idem-create", CorrelationID: "idem-create", EndpointID: adapterapi.EndpointID("idem-endpoint"), AdapterKey: adapterapi.AdapterKey("pureonebot"), Config: adapterapi.ValidatedConfig{Version: 1, Canonical: []byte(`{"mode":"server","listenAddress":"127.0.0.1:6700"}`)}, SecretDigest: "first-token-digest"}
	first, err := commandDigest(base, CommandCreate, base.CommandID, base.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	base.SecretDigest = "different-token-digest"
	second, err := commandDigest(base, CommandCreate, base.CommandID, base.CorrelationID)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("secret digest did not affect idempotency command digest")
	}
}
