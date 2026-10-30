package dice

import (
	"errors"
	"reflect"
	"testing"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func newRuntimeRouteTestManager(t *testing.T) *JSRuntimeManager {
	t.Helper()
	manager := NewJSRuntimeManager(t.TempDir())
	for _, descriptor := range []jsengine.Descriptor{
		{ID: "suffix", Author: "test", Extensions: []string{".route"}},
		{ID: "global", Author: "test", Extensions: []string{".global"}},
		{ID: "extension-route", Author: "test", Extensions: []string{".extension"}},
		{ID: "explicit", Author: "test", Extensions: []string{".explicit"}},
	} {
		if err := manager.registry.RegisterCandidate(jsengine.RuntimeManifest{
			ID: descriptor.ID, Name: string(descriptor.ID), Author: descriptor.Author,
			Extensions: descriptor.Extensions,
		}); err != nil {
			t.Fatal(err)
		}
	}
	manager.refreshStatuses()
	return manager
}

func TestJSRuntimeDefaultsForPackageUsesExtensionRouteThenGlobal(t *testing.T) {
	d := &Dice{}
	d.Config.JsEngine = "global"
	d.Config.JsRuntimeRoutes = map[string]string{"author/extension": "extension-route"}

	got, count := d.jsRuntimeDefaultsForPackage("author/extension")
	want := []jsengine.EngineID{"extension-route", "global"}
	if !reflect.DeepEqual(got[:count], want) {
		t.Fatalf("runtime defaults = %v, want %v", got[:count], want)
	}
}

func TestJSRuntimeResolutionTriesExplicitThenPackageDefault(t *testing.T) {
	manager := newRuntimeRouteTestManager(t)
	var attempts []jsengine.EngineID
	resolve := func(id jsengine.EngineID) (jsengine.Loop, error) {
		attempts = append(attempts, id)
		if id != "explicit" {
			return nil, errors.New("unavailable")
		}
		return gojaengine.New(), nil
	}
	source := "// ==UserScript==\n// @runtime explicit:test\n// ==/UserScript=="

	got, loop, err := manager.resolveScriptWithDefaults("plugin.route", source, []jsengine.EngineID{"extension-route", "global"}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if got != "explicit" {
		t.Fatalf("selected runtime = %q, want explicit", got)
	}
	if want := []jsengine.EngineID{"explicit"}; !reflect.DeepEqual(attempts, want) {
		t.Fatalf("resolution attempts = %v, want %v", attempts, want)
	}
}

func TestJSRuntimeResolutionTriesPackageDefaultBeforeGlobalAndSuffix(t *testing.T) {
	manager := newRuntimeRouteTestManager(t)
	var attempts []jsengine.EngineID
	resolve := func(id jsengine.EngineID) (jsengine.Loop, error) {
		attempts = append(attempts, id)
		if id != "extension-route" {
			return nil, errors.New("unavailable")
		}
		return gojaengine.New(), nil
	}

	got, loop, err := manager.resolveScriptWithDefaults("plugin.route", "source", []jsengine.EngineID{"extension-route", "global"}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if got != "extension-route" {
		t.Fatalf("selected runtime = %q, want extension-route", got)
	}
	if want := []jsengine.EngineID{"extension-route"}; !reflect.DeepEqual(attempts, want) {
		t.Fatalf("resolution attempts = %v, want %v", attempts, want)
	}
}

func TestJSRuntimeResolutionFallsThroughPackageDefaultToGlobalThenSuffix(t *testing.T) {
	manager := newRuntimeRouteTestManager(t)
	var attempts []jsengine.EngineID
	resolve := func(id jsengine.EngineID) (jsengine.Loop, error) {
		attempts = append(attempts, id)
		if id == "global" {
			return gojaengine.New(), nil
		}
		return nil, errors.New("unavailable")
	}

	got, loop, err := manager.resolveScriptWithDefaults("plugin.route", "source", []jsengine.EngineID{"extension-route", "global"}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if got != "global" {
		t.Fatalf("selected runtime = %q, want global", got)
	}
	if want := []jsengine.EngineID{"extension-route", "global"}; !reflect.DeepEqual(attempts, want) {
		t.Fatalf("resolution attempts = %v, want %v", attempts, want)
	}
}

func TestJSRuntimeResolutionUsesSuffixAfterConfiguredDefaultsFail(t *testing.T) {
	manager := newRuntimeRouteTestManager(t)
	var attempts []jsengine.EngineID
	resolve := func(id jsengine.EngineID) (jsengine.Loop, error) {
		attempts = append(attempts, id)
		if id == "suffix" {
			return gojaengine.New(), nil
		}
		return nil, errors.New("unavailable")
	}

	got, loop, err := manager.resolveScriptWithDefaults("plugin.route", "source", []jsengine.EngineID{"extension-route", "global"}, resolve)
	if err != nil {
		t.Fatal(err)
	}
	defer loop.Close()
	if got != "suffix" {
		t.Fatalf("selected runtime = %q, want suffix", got)
	}
	if want := []jsengine.EngineID{"extension-route", "global", "suffix"}; !reflect.DeepEqual(attempts, want) {
		t.Fatalf("resolution attempts = %v, want %v", attempts, want)
	}
}
