package dice

import (
	"strings"
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
	"Scardice-core/utils/jsengine/quickjs"
)

func TestInstallJSHostAPI(t *testing.T) {
	engines := []struct {
		name string
		new  func(t *testing.T) jsengine.Loop
	}{
		{name: "goja", new: func(t *testing.T) jsengine.Loop { return gojaengine.New() }},
		{
			name: "quickjs",
			new: func(t *testing.T) jsengine.Loop {
				loop, err := quickjs.New()
				if err != nil {
					t.Fatal(err)
				}
				return loop
			},
		},
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

func TestQuickJSBindsEngineNeutralExtensionCallbacks(t *testing.T) {
	loop, err := quickjs.New()
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()

	command := &CmdItemInfo{}
	extension := &ExtInfo{}
	if err := loop.Run(func(runtime jsengine.Runtime) error {
		if err := runtime.Bind("command", command); err != nil {
			return err
		}
		if err := runtime.Bind("extension", extension); err != nil {
			return err
		}
		if _, err := runtime.RunString("callbacks.js", `
			command.solve = () => ({ matched: true, solved: true });
			extension.onMessagePreprocess = () => ({ message: "rewritten" });
		`); err != nil {
			return err
		}

		solveValue, err := command.SolveEngine(runtime, nil, nil, nil)
		if err != nil {
			return err
		}
		solve, err := parseJSSolveEngineResult(nil, "test", solveValue)
		if err != nil {
			return err
		}
		if solve != (CmdExecuteResult{Matched: true, Solved: true}) {
			t.Fatalf("solve = %#v", solve)
		}

		preprocessValue, err := extension.OnMessagePreprocessEngine(runtime, nil, nil)
		if err != nil {
			return err
		}
		decision := parseMessagePreprocessEngineValue(preprocessValue)
		if decision.action != messagePreprocessRewrite || decision.message != "rewritten" {
			t.Fatalf("decision = %#v", decision)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
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
