package dice

import "testing"

func seedCanonicalExtensionSelection(t *testing.T, d *Dice, endpoint *EndPointInfo, groupID string, extensionIDs ...string) {
	t.Helper()
	message := newGroupMsg(groupID, "QQ:extension-owner", "")
	withCanonicalTestMessageContext(t, d, endpoint, message, "seed-extension-selection", func(ctx *MsgContext) error {
		for _, extensionID := range extensionIDs {
			if err := ctx.Group.SetExtension(extensionID, true); err != nil {
				return err
			}
		}
		return nil
	})
}

func TestActivatedExtensionIDsKeepUninstalledSelectionsAcrossReload(t *testing.T) {
	core := &ExtInfo{Name: "core"}
	d, _ := newCanonicalTestDice(t)
	installCanonicalTestExtensions(d, core)
	endpoint := newCanonicalTestEndpoint(d, "QQ:extension-bot")
	const groupID = "QQ-Group:uninstalled-extension"
	seedCanonicalExtensionSelection(t, d, endpoint, groupID, "core", "deleted-plugin")

	ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg(groupID, "QQ:extension-owner", ""), "read-uninstalled-extension")
	got := ctx.Group.GetActivatedExtList(d)
	if len(got) != 2 {
		t.Fatalf("activated extensions = %v, want two canonical selections", extListToNames(got))
	}
	if got[1] == nil || got[1].Name != "deleted-plugin" {
		t.Fatalf("uninstalled selection = %#v, want named runtime placeholder", got[1])
	}
	if !ctx.Group.ExtensionActive("deleted-plugin") {
		t.Fatal("uninstalled extension ID was lost from canonical group state")
	}
}

func TestReinstallResolvesCanonicalSelectionToLiveExtension(t *testing.T) {
	core := &ExtInfo{Name: "core"}
	d, _ := newCanonicalTestDice(t)
	installCanonicalTestExtensions(d, core)
	endpoint := newCanonicalTestEndpoint(d, "QQ:extension-bot")
	const groupID = "QQ-Group:reinstalled-extension"
	seedCanonicalExtensionSelection(t, d, endpoint, groupID, "core", "plugin-x")

	ctx := newCanonicalTestMessageContext(t, d, endpoint, newGroupMsg(groupID, "QQ:extension-owner", ""), "read-reinstalled-extension")
	before := ctx.Group.GetActivatedExtList(d)
	if len(before) != 2 || before[1] == nil || before[1].Name != "plugin-x" {
		t.Fatalf("pre-reinstall extensions = %#v", before)
	}
	placeholder := before[1]

	plugin := &ExtInfo{Name: "plugin-x"}
	installCanonicalTestExtensions(d, core, plugin)
	if err := ctx.Group.SyncExtensionsOnMessage(d); err != nil {
		t.Fatal(err)
	}
	after := ctx.Group.GetActivatedExtList(d)
	if len(after) != 2 || after[1] != plugin {
		t.Fatalf("post-reinstall extensions = %#v, want live plugin %p", after, plugin)
	}
	if after[1] == placeholder {
		t.Fatal("reinstall retained the derived placeholder instead of the live definition")
	}
}
