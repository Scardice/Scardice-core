//lint:file-ignore testpackage Tests need access to internal helpers and types
package dice //nolint:testpackage // tests rely on unexported helpers

import (
	"context"
	"testing"
)

func persistCanonicalExtensionDefault(t *testing.T, d *Dice, extensionID string, autoActive bool) {
	t.Helper()
	extension, ok := d.ExtRegistry.Load(extensionID)
	if !ok {
		t.Fatalf("extension %q is not installed in the fixture registry", extensionID)
	}
	if err := d.DurableDiscoverExtension(context.Background(), extension); err != nil {
		t.Fatalf("discover extension identity: %v", err)
	}
	err := d.DurableCommitConfigRequest(context.Background(), DurableConfigRequest{
		PersistExtensionDefaults: true,
		ExtensionDefaults: []DurableExtensionDefault{{
			ExtensionID:      extensionID,
			AutoActive:       autoActive,
			DisabledCommands: nil,
		}},
	})
	if err != nil {
		t.Fatalf("persist extension defaults: %v", err)
	}
}

// An explicit historical deactivation must not permanently block a later
// source-versioned default change to AutoActive=true.
func TestApplyExtDefaultSettings_AutoActiveChangeClearsHistoricalDeactivation(t *testing.T) {
	extension := &ExtInfo{Name: "js-demo", Version: "1.0.0", CmdMap: CmdMapCls{}}
	d, _ := newCanonicalTestDice(t)
	installCanonicalTestExtensions(d, extension)
	endpoint := newCanonicalTestEndpoint(d, "QQ:default-settings-bot")
	ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg("QQ-Group:123", "QQ:owner", ""), "auto-active-default")
	if err := ctx.Group.SetExtension(extension.Name, false); err != nil {
		t.Fatal(err)
	}

	persistCanonicalExtensionDefault(t, d, extension.Name, true)
	d.ApplyExtDefaultSettings()
	if err := ctx.Group.SyncExtensionsOnMessage(d); err != nil {
		t.Fatal(err)
	}

	if ctx.Group.ExtGetActive(extension.Name) == nil {
		t.Fatalf("expected ext %q to be auto-activated after enabling AutoActive in canonical defaults", extension.Name)
	}
	if ctx.Group.ExtensionInactivated(extension.Name) {
		t.Fatalf("expected ext %q historical deactivation to be cleared", extension.Name)
	}
}

// Changing the default to AutoActive=false affects future activation only; it
// does not force-deactivate a group which already selected the extension.
func TestApplyExtDefaultSettings_DisableAutoActiveDoesNotForceDeactivate(t *testing.T) {
	extension := &ExtInfo{Name: "js-demo", Version: "1.0.0", AutoActive: true, CmdMap: CmdMapCls{}}
	d, _ := newCanonicalTestDice(t)
	installCanonicalTestExtensions(d, extension)
	endpoint := newCanonicalTestEndpoint(d, "QQ:default-settings-bot")
	ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg("QQ-Group:456", "QQ:owner", ""), "disable-auto-active-default")
	if err := ctx.Group.SetExtension(extension.Name, true); err != nil {
		t.Fatal(err)
	}

	persistCanonicalExtensionDefault(t, d, extension.Name, false)
	d.ApplyExtDefaultSettings()
	if err := ctx.Group.SyncExtensionsOnMessage(d); err != nil {
		t.Fatal(err)
	}

	if ctx.Group.ExtGetActive(extension.Name) == nil {
		t.Fatalf("expected ext %q to remain active after disabling AutoActive default", extension.Name)
	}
	if ctx.Group.ExtensionInactivated(extension.Name) {
		t.Fatalf("expected ext %q not to be marked inactivated while already active", extension.Name)
	}
}
