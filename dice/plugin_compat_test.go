package dice

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestPluginCompatibilityManifestIsExplicit(t *testing.T) {
	data, err := os.ReadFile("testdata/plugin_compat/manifest.v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		ManifestVersion string `json:"manifestVersion"`
		FixtureVersion  string `json:"fixtureVersion"`
		Fixture         struct {
			Covers []string `json:"covers"`
		} `json:"fixture"`
		RealmRules []string `json:"realmRules"`
		Callbacks  struct {
			Fields []string `json:"fields"`
		} `json:"callbacks"`
		Categories map[string][]struct {
			Name    string   `json:"name"`
			Members []string `json:"members"`
			Reason  string   `json:"reason"`
		} `json:"categories"`
		MutationWhitelistCandidates map[string]json.RawMessage `json:"mutationWhitelistCandidates"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("manifest JSON: %v", err)
	}
	if manifest.ManifestVersion == "" {
		t.Fatal("manifestVersion is required")
	}
	requiredCoverage := []string{"host-bindings", "context-fields", "context-mutations", "callback-bindings", "unregistered-config-errors"}
	coverage := make(map[string]bool, len(manifest.Fixture.Covers))
	for _, item := range manifest.Fixture.Covers {
		coverage[item] = true
	}
	for _, item := range requiredCoverage {
		if !coverage[item] {
			t.Fatalf("fixture coverage %q is required", item)
		}
	}
	if manifest.FixtureVersion == "" {
		t.Fatal("fixtureVersion is required")
	}
	for _, category := range []string{"supported", "unsupported_compatibility", "unsupported_private", "external_effect_ambiguous"} {
		entries, ok := manifest.Categories[category]
		if !ok || len(entries) == 0 {
			t.Fatalf("category %q must be explicit and non-empty", category)
		}
		for _, entry := range entries {
			if entry.Name == "" {
				t.Fatalf("category %q has unnamed entry", category)
			}
			if category == "supported" && len(entry.Members) == 0 {
				t.Fatalf("supported entry %q has no members", entry.Name)
			}
			if category != "supported" && entry.Reason == "" {
				t.Fatalf("category %q entry %q has no reason", category, entry.Name)
			}
		}
	}
	if len(manifest.RealmRules) == 0 || len(manifest.Callbacks.Fields) == 0 {
		t.Fatal("realm rules and callback fields are required")
	}
	candidates, ok := manifest.MutationWhitelistCandidates["context"]
	var contextCandidates []json.RawMessage
	if !ok || json.Unmarshal(candidates, &contextCandidates) != nil || len(contextCandidates) == 0 {
		t.Fatal("context mutation whitelist candidates are required")
	}
}

func TestPluginCompatibilityFixtureHostAndContext(t *testing.T) {
	fixture, err := os.ReadFile("testdata/plugin_compat/fixture.js")
	if err != nil {
		t.Fatal(err)
	}
	loop := gojaengine.New()
	defer loop.Close()
	d, _ := newCanonicalTestDice(t)
	d.ExtLoopManager = NewJsLoopManager()
	generation := d.ExtLoopManager.SetLoop(loop)
	endpoint := newCanonicalTestEndpoint(d, "QQ:fixture-bot")
	message := newGroupMsg("QQ-Group:100", "QQ:200", "hello")
	message.Sender.Nickname = "Alice"
	context := newCanonicalTestMessageContext(t, d, endpoint, message, "plugin-compat-context")
	context.IsCurGroupBotOn = true
	context.PrivilegeLevel = 50
	context.DelegateText = "delegate"

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := d.installJSHostAPI(runtime, loop); err != nil {
			return err
		}
		return d.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), generation, nil)
	}); err != nil {
		t.Fatal(err)
	}
	realmOwner := &ExtInfo{Name: "plugin-compat-fixture", IsJsExt: true, dice: d, JSLoopVersion: generation}
	if err := jsengine.RunWithContext(loop, jsContextForMessage(realmOwner, context), func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("fixtureContext", context); err != nil {
			return err
		}
		if err := runtime.Bind("fixtureMessage", message); err != nil {
			return err
		}
		if _, err := runtime.RunString("plugin-compat-fixture.js", string(fixture)); err != nil {
			return err
		}
		value, err := runtime.RunString("plugin-compat-host.js", `JSON.stringify(pluginCompatFixture.host())`)
		if err != nil {
			return err
		}
		if got := value.Export(); got != `{"functionTypes":["function","function","function","function","function","function","function","function"],"extensionMethods":["function","function","function"],"roundTrip":"Scardice","forward":"1001","message":"hello","versionType":"string"}` {
			t.Fatalf("host fixture = %v", got)
		}
		value, err = runtime.RunString("plugin-compat-context.js", `JSON.stringify(pluginCompatFixture.context(fixtureContext, fixtureMessage))`)
		if err != nil {
			return err
		}
		if got := value.Export(); got != `{"groupId":"QQ-Group:100","message":"hello","sender":"QQ:200","private":false,"privilege":50,"delegate":"delegate"}` {
			t.Fatalf("context fixture = %v", got)
		}
		if _, err := runtime.RunString("plugin-compat-mutate.js", `pluginCompatFixture.mutateContext(fixtureContext)`); err != nil {
			return err
		}
		value, err = runtime.RunString("plugin-compat-errors.js", `pluginCompatFixture.errors()`)
		if err != nil {
			return err
		}
		if !strings.Contains(value.Export().(string), "请先完成此扩展的注册") {
			t.Fatalf("documented error = %q", value.Export())
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !context.IsPrivate || context.CommandHideFlag != "hidden" || context.DelegateText != "changed" {
		t.Fatalf("writable context fields = private=%v hide=%q delegate=%q", context.IsPrivate, context.CommandHideFlag, context.DelegateText)
	}
	if message.Message != "hello" {
		t.Fatalf("fixture unexpectedly changed message: %q", message.Message)
	}
}

func TestPluginCompatibilityPublicCallbackBindings(t *testing.T) {
	fixture, err := os.ReadFile("testdata/plugin_compat/fixture.js")
	if err != nil {
		t.Fatal(err)
	}
	loop := gojaengine.New()
	defer loop.Close()
	d, _ := newCanonicalTestDice(t)
	d.ExtLoopManager = NewJsLoopManager()
	generation := d.ExtLoopManager.SetLoop(loop)
	endpoint := newCanonicalTestEndpoint(d, "QQ:fixture-bot")
	msg := newGroupMsg("QQ-Group:callback-bindings", "QQ:fixture-user", "")
	ctx := newCanonicalTestMessageContext(t, d, endpoint, msg, "plugin-compat-callback-bindings")
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := d.installJSHostAPI(runtime, loop); err != nil {
			return err
		}
		return d.installJSExtHostAPI(runtime, loop, runtime.Get("seal").Object(), generation, nil)
	}); err != nil {
		t.Fatal(err)
	}
	if err := jsengine.RunWithContext(loop, jsContextForMessage(nil, ctx), func(runtime jsengine.Runtime) error {
		ext := &ExtInfo{}
		if err := runtime.Bind("fixtureExtension", ext); err != nil {
			return err
		}
		if _, err := runtime.RunString("plugin-compat-callback-fixture.js", string(fixture)+`
			pluginCompatFixture.callbacks(fixtureExtension);
		`); err != nil {
			return err
		}
		if ext.OnMessagePreprocess == nil || ext.OnMessageReceivedGoja == nil || ext.OnCommandReceivedGoja == nil || ext.OnMessageSendGoja == nil {
			return errors.New("fixture did not install callback fields")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
