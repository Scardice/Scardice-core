package dice

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"Scardice-core/eventstore"
	"Scardice-core/projectionset"
)

func TestEventSourcedInitDiceLoadsHelpDocs(t *testing.T) {
	root := switchToTempWorkdir(t)
	writeTestHelpDocFile(t, root, "startup.json", map[string]string{"event-sourced-help-startup": "available"})

	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(root, "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store := eventstore.NewStore(database, projectionset.StoreOptions()...)
	t.Cleanup(func() { _ = store.Close() })

	runtime := &Dice{
		BaseConfig:    BaseConfig{Name: "default", DataDir: filepath.Join(root, "data", "default")},
		DurableStore:  store,
		ContainerMode: true,
	}
	runtime.Config = NewConfig(runtime)
	runtime.Config.BaseConfig = runtime.BaseConfig
	manager := &DiceManager{Dice: []*Dice{runtime}}
	if err := manager.InitializeRuntime(); err != nil {
		t.Fatal(err)
	}
	if err := manager.PrepareEventSourcedState(ctx); err != nil {
		t.Fatal(err)
	}
	runtime.Config.JsEnable = false
	t.Cleanup(func() {
		if manager.Cron != nil {
			manager.Cron.Stop()
		}
	})
	t.Cleanup(func() {
		manager.helpReloadLock.Lock()
		help := manager.Help
		manager.helpReloadLock.Unlock()
		if help != nil {
			help.Close()
		}
		if runtime.AttrsManager != nil {
			runtime.AttrsManager.Stop()
		}
		if runtime.Cron != nil {
			runtime.Cron.Stop()
		}
	})

	manager.InitDice(nil)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(helpIndexManifestPath); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(helpIndexManifestPath); err != nil {
		t.Fatalf("event-sourced startup did not create the help index manifest: %v", err)
	}

	manager.helpReloadLock.Lock()
	help := manager.Help
	manager.helpReloadLock.Unlock()
	if help == nil || !help.IsAvailable() {
		t.Fatal("event-sourced startup did not make the help manager available")
	}
	if !helpDocTreeHasName(help.HelpDocTree, "startup.json") {
		t.Fatalf("help tree does not contain startup.json: %#v", help.HelpDocTree)
	}
	_, items := help.GetHelpItemPage(1, 1000, "", "", "", "")
	if countHelpItemsFromFile(items, "startup.json") != 1 {
		t.Fatalf("help index does not contain startup.json: %#v", items)
	}
}
