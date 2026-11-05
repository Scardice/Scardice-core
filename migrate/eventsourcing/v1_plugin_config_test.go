package eventsourcing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"Scardice-core/core/extensionstate"
	"Scardice-core/migrate/eventsourcing/v1reader"
)

func TestV1PluginConfigFoldPreservesExplicitEmptyOverDefault(t *testing.T) {
	name, key := "plugin", "token"
	state := extensionstate.State{Version: 3, DiceID: "dice", ExtensionOrder: []string{name},
		Extensions:        map[string]extensionstate.ExtensionIdentity{name: {ID: name, Name: name, Source: "script"}},
		ConfigDefinitions: map[string]map[string]extensionstate.ConfigDefinition{name: {key: {ExtensionID: name, Key: key, Type: extensionstate.ConfigString}}}}
	payload, _ := json.Marshal(state)
	digest := sha256.Sum256([]byte(name))
	value, _ := json.Marshal(extensionstate.StringValue(""))
	items := []v1reader.PluginKV{{ExtensionID: "scardice.internal.config/v1/" + hex.EncodeToString(digest[:]), Key: base64.RawURLEncoding.EncodeToString([]byte(key)), Value: value}, {ExtensionID: "public", Key: key, Value: []byte{}}}
	rows, remaining, err := foldV1PluginConfig([]v1reader.ProjectionRow{{Name: extensionstate.ExtensionProjectionName, RowKey: "dice", Payload: payload}}, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(remaining) != 1 || remaining[0].ExtensionID != "public" {
		t.Fatalf("public plugin storage changed: %+v", remaining)
	}
	if err := json.Unmarshal(rows[0].Payload, &state); err != nil {
		t.Fatal(err)
	}
	stored, ok := state.ConfigValues[name][key]
	if !ok || stored.Type != extensionstate.ConfigString || stored.String != "" {
		t.Fatalf("explicit empty current config = %#v/%v", stored, ok)
	}
}
