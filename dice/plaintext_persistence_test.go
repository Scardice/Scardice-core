package dice

import (
	"context"
	"testing"
)

func TestDurablePluginStorageCreatesRequestedOpaqueKey(t *testing.T) {
	d, _ := newDomainExecutionFixture(t)
	for _, key := range []string{"new-key", "", " ", "\x00key"} {
		value := "value-for:" + key
		if err := d.durableStorageSet("plugin", key, value); err != nil {
			t.Fatalf("create key %q: %v", key, err)
		}
		got, err := d.durableStorageGet("plugin", key)
		if err != nil || got != value {
			t.Fatalf("read key %q: value=%q err=%v", key, got, err)
		}
	}
}

func TestCallbackCommitsMultipleOpaquePluginKeysWithGroupVariables(t *testing.T) {
	d, store := newCanonicalTestDice(t)
	values := map[string]string{"": "empty-key", " ": "space-key", "blank": ""}
	withCanonicalTestRoot(t, d, "mixed-plugin-values", func(transaction *DurableCallbackTransaction) error {
		messageCtx := newStateFacadeCallbackContext(t, d, transaction, transaction.metadata, "QQ-Group:2002", "QQ:1001")
		VarSetValueInt64(messageCtx, "$g:plaintextSmoke", 42)
		VarSetValueStr(messageCtx, "$g:plaintextEmpty", "")
		for key, value := range values {
			if err := transaction.StorageSet(context.Background(), "plugin", key, value); err != nil {
				return err
			}
		}
		return nil
	})
	for key, want := range values {
		item, err := store.GetPluginKV(context.Background(), "plugin", key)
		if err != nil || string(item.Value) != want {
			t.Fatalf("committed plugin key %q: value=%q err=%v", key, item.Value, err)
		}
	}
	withCanonicalTestRoot(t, d, "read-mixed-plugin-values", func(transaction *DurableCallbackTransaction) error {
		messageCtx := newStateFacadeCallbackContext(t, d, transaction, transaction.metadata, "QQ-Group:2002", "QQ:1001")
		if value, found := VarGetValueInt64(messageCtx, "$g:plaintextSmoke"); !found || value != 42 {
			t.Fatalf("committed group integer = %d, found=%t", value, found)
		}
		if value, found := VarGetValueStr(messageCtx, "$g:plaintextEmpty"); !found || value != "" {
			t.Fatalf("committed empty group string = %q, found=%t", value, found)
		}
		for key, want := range values {
			value, err := transaction.StorageGet(context.Background(), "plugin", key)
			if err != nil || value != want {
				t.Fatalf("transactional plugin key %q: value=%q err=%v", key, value, err)
			}
		}
		return nil
	})
}

func TestCallbackStorageListUsesObservedNamespaceRevision(t *testing.T) {
	d, _ := newCanonicalTestDice(t)
	if err := d.durableStorageSet("plugin", "existing", "value"); err != nil {
		t.Fatal(err)
	}
	withCanonicalTestRoot(t, d, "list-existing-plugin-values", func(transaction *DurableCallbackTransaction) error {
		keys, err := transaction.StorageList(context.Background(), "plugin")
		if err != nil {
			return err
		}
		if len(keys) != 1 || keys[0] != "existing" {
			t.Fatalf("plugin keys = %q, want existing", keys)
		}
		return nil
	})
}

func TestConfigReregistrationUpdatesDefaultButPreservesExplicitEmpty(t *testing.T) {
	ctx := context.Background()
	d, _ := newDomainExecutionFixture(t)
	d.ConfigManager = NewConfigManager("")
	d.ConfigManager.SetOwner(d)
	ext := &ExtInfo{Name: "config-reload", Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigManager.RegisterPluginConfig(ext.Name, &ConfigItem{
		Key: "access token", Type: "string", DefaultValue: "old-default", Value: "old-default",
	}); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigManager.SetConfig(ext.Name, "access token", ""); err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigManager.RegisterPluginConfig(ext.Name, &ConfigItem{
		Key: "access token", Type: "string", DefaultValue: "new-default", Value: "new-default",
	}); err != nil {
		t.Fatal(err)
	}
	item, err := d.DurableConfigItem(ctx, ext, "access token")
	if err != nil || item.Value != "" || item.DefaultValue != "new-default" {
		t.Fatalf("reregistered config = %#v, err=%v", item, err)
	}
}
