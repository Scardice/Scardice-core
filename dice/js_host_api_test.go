package dice

import (
	"strings"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestInstallJSHostAPI(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
	}

	for _, engine := range engines {
		t.Run(engine.name, func(t *testing.T) {
			loop := engine.new(t)
			defer loop.Close()

			if err := loop.Run(func(runtime jsengine.Runtime) error {
				d := &Dice{}
				if err := d.installJSHostAPI(runtime); err != nil {
					return err
				}
				value, err := runtime.RunString("host-api.js", `
					typeof seal.vars.intGet === "function" &&
					typeof seal.ban.addBan === "function" &&
					typeof seal.coc.newRule === "function" &&
					typeof seal.deck.reload === "function" &&
					typeof seal.replyForward === "function" &&
					typeof seal.newForwardNode === "function" &&
					seal.newForwardNode("1001", "骰主", "转发内容").senderId === "1001" &&
					seal.newForwardElement().type === "forward" &&
					seal.newMessage().message === "" &&
					atob(btoa("Scardice")) === "Scardice" &&
					typeof seal.getVersion().version === "string"
				`)
				if err != nil {
					return err
				}
				if !value.ToBoolean() {
					details, diagnosticErr := runtime.RunString("host-api-diagnostic.js", `
						JSON.stringify({
							replyForward: typeof seal.replyForward,
							newForwardNode: typeof seal.newForwardNode,
							senderId: seal.newForwardNode("1001", "骰主", "转发内容").senderId,
							forwardType: seal.newForwardElement().type
						})
					`)
					if diagnosticErr != nil {
						return diagnosticErr
					}
					t.Fatalf("host API is incomplete: %v", details.Export())
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestJSExtensionCommandMapSupportsDeletion(t *testing.T) {
	loop := gojaengine.New()
	defer loop.Close()

	extension := &ExtInfo{CmdMap: CmdMapCls{"legacy": {Name: "legacy"}}}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("extension", extension); err != nil {
			return err
		}
		_, err := runtime.RunString("delete-command.js", `delete extension.cmdMap.legacy`)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, exists := extension.CmdMapSnapshot()["legacy"]; exists {
		t.Fatal("delete extension.cmdMap.legacy did not remove the Go command")
	}
}

func TestJSExtensionReplacementWarnsWithBothSources(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	dice := &Dice{
		Logger:      zap.New(core).Sugar(),
		ExtRegistry: new(SyncMap[string, *ExtInfo]),
	}
	loop := gojaengine.New()
	defer loop.Close()

	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := dice.installJSHostAPI(runtime); err != nil {
			return err
		}
		if err := dice.installJSExtHostAPI(runtime, runtime.Get("seal").Object(), 1, nil); err != nil {
			return err
		}
		dice.JsLoadingScript = &JsScriptInfo{Name: "first", Filename: "first.js"}
		if _, err := runtime.RunString("first.js", `seal.ext.register(seal.ext.new("same-name", "first", "1"))`); err != nil {
			return err
		}
		dice.JsLoadingScript = &JsScriptInfo{Name: "second", Filename: "second.js"}
		_, err := runtime.RunString("second.js", `seal.ext.register(seal.ext.new("same-name", "second", "1"))`)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	entries := logs.FilterMessageSnippet("正在替换同名扩展").All()
	if len(entries) != 1 || !strings.Contains(entries[0].Message, "first.js") || !strings.Contains(entries[0].Message, "second.js") {
		t.Fatalf("replacement warning = %#v, want both source filenames", entries)
	}
}

func TestJSExtensionSourceDescriptionIncludesOperatorIdentifiers(t *testing.T) {
	got := jsExtensionSourceDescription(&JsScriptInfo{
		Name:      "attacker",
		Filename:  "attacker.js",
		PackageID: "package-attacker",
		HomePage:  "https://example.test/attacker",
	})
	for _, want := range []string{"attacker", "attacker.js", "package-attacker", "https://example.test/attacker"} {
		if !strings.Contains(got, want) {
			t.Fatalf("source description %q does not include %q", got, want)
		}
	}
}
