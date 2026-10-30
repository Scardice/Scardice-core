package dice

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/robfig/cron/v3"

	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
)

func TestSetConfigInvalidTaskExpressionsDoNotPersistOrUnschedule(t *testing.T) {
	ctx := context.Background()
	d, db, extensionID, tasks := newDurableTaskConfigFixture(t, ctx)

	defer db.Close()

	before, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		key     string
		invalid string
	}{
		{key: "cron", invalid: "not a cron expression"},
		{key: "daily", invalid: "24:61"},
	} {
		t.Run(test.key, func(t *testing.T) {
			task := tasks[test.key]
			oldEntryID := *task.entryID
			oldEntry := task.cron.Entry(oldEntryID)
			if oldEntry.ID != oldEntryID || oldEntry.Schedule == nil {
				t.Fatalf("task setup has no active cron entry: %#v", oldEntry)
			}

			oldRawValue, oldCronExpr := task.rawValue, task.cronExpr
			oldValue := d.ConfigManager.getConfig(extensionID, test.key).Value

			if err := d.ConfigManager.SetConfig(extensionID, test.key, test.invalid); err == nil {
				t.Fatal("SetConfig accepted an invalid task expression")
			}
			after, err := d.DurableExtensionState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if after.Version != before.Version {
				t.Fatalf("extension version after invalid value = %d, want %d", after.Version, before.Version)
			}
			got, want := after.ConfigValues[extensionID][test.key], before.ConfigValues[extensionID][test.key]
			if got.Type != want.Type || got.String != want.String {
				t.Fatalf("persisted task value after invalid update = %#v, want %#v", got, want)
			}
			if got := d.ConfigManager.getConfig(extensionID, test.key).Value; got != oldValue {
				t.Fatalf("in-memory task value after invalid update = %#v, want %#v", got, oldValue)
			}
			if !task.IsActive() || task.rawValue != oldRawValue || task.cronExpr != oldCronExpr || task.entryID == nil || *task.entryID != oldEntryID {
				t.Fatalf("task changed after invalid update: active=%v raw=%q cron=%q entry=%v", task.IsActive(), task.rawValue, task.cronExpr, task.entryID)
			}

			if err := task.reset(test.invalid); err == nil {
				t.Fatal("reset accepted an invalid task expression")
			}
			entry := task.cron.Entry(oldEntryID)
			if entry.ID != oldEntryID || entry.Schedule == nil {
				t.Fatalf("old cron entry was removed after invalid reset: %#v", entry)
			}

			if !task.IsActive() || task.rawValue != oldRawValue || task.cronExpr != oldCronExpr || task.entryID == nil || *task.entryID != oldEntryID {
				t.Fatalf("direct reset changed task after invalid input: active=%v raw=%q cron=%q entry=%v", task.IsActive(), task.rawValue, task.cronExpr, task.entryID)
			}
		})
	}
}

func TestSetConfigValidTaskExpressionsNormalizeAndReschedule(t *testing.T) {
	ctx := context.Background()
	d, db, extensionID, tasks := newDurableTaskConfigFixture(t, ctx)
	defer db.Close()

	for _, test := range []struct {
		key      string
		value    string
		wantRaw  string
		wantCron string
	}{
		{key: "cron", value: "  */2   * * * *  ", wantRaw: "*/2 * * * *", wantCron: "*/2 * * * *"},
		{key: "daily", value: "06:07", wantRaw: "6:07", wantCron: "7 6 * * *"},
	} {
		t.Run(test.key, func(t *testing.T) {
			task := tasks[test.key]
			oldEntryID := *task.entryID
			if err := d.ConfigManager.SetConfig(extensionID, test.key, test.value); err != nil {
				t.Fatalf("SetConfig() error = %v", err)
			}

			if !task.IsActive() || task.entryID == nil || *task.entryID == oldEntryID {
				t.Fatalf("updated task was not rescheduled: active=%v entry=%v old=%d", task.IsActive(), task.entryID, oldEntryID)
			}
			entry := task.cron.Entry(*task.entryID)
			if entry.ID != *task.entryID || entry.Schedule == nil || entry.Schedule.Next(time.Now()).IsZero() {
				t.Fatalf("updated task has no active cron entry: %#v", entry)
			}
			if task.rawValue != test.wantRaw || task.cronExpr != test.wantCron {
				t.Fatalf("task expression = raw %q cron %q, want raw %q cron %q", task.rawValue, task.cronExpr, test.wantRaw, test.wantCron)
			}
			if got := d.ConfigManager.getConfig(extensionID, test.key).Value; got != test.wantRaw {
				t.Fatalf("in-memory value = %#v, want %q", got, test.wantRaw)
			}
			state, err := d.DurableExtensionState(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if got := state.ConfigValues[extensionID][test.key]; got.Type != extensionstate.ConfigType("task:"+test.key) || got.String != test.wantRaw {
				t.Fatalf("persisted task value = %#v, want type task:%s string %q", got, test.key, test.wantRaw)
			}
		})
	}
}

func TestSetConfigOnceKeepsTimerOnInvalidInputAndPersistsExactDeadline(t *testing.T) {
	ctx := context.Background()
	d, db, extensionID, tasks := newDurableTaskConfigFixture(t, ctx)
	defer db.Close()
	task := tasks["once"]
	before, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldTimer, oldDeadline, oldValue := task.timer, task.onceAt, task.rawValue
	if err := d.ConfigManager.SetConfig(extensionID, "once", "-1"); err == nil {
		t.Fatal("negative one-shot delay was accepted")
	}
	if err := task.reset("not a deadline"); err == nil {
		t.Fatal("invalid direct one-shot reset was accepted")
	}
	unchanged, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Version != before.Version || unchanged.ConfigValues[extensionID]["once"].String != oldValue ||
		d.ConfigManager.getConfig(extensionID, "once").Value != oldValue || task.rawValue != oldValue ||
		task.timer != oldTimer || !task.onceAt.Equal(oldDeadline) || !task.IsActive() {
		t.Fatal("invalid one-shot update changed its durable value or active deadline")
	}
	started := time.Now()
	if err := d.ConfigManager.SetConfig(extensionID, "once", "3600000"); err != nil {
		t.Fatal(err)
	}
	finished := time.Now()
	updated, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	value := updated.ConfigValues[extensionID]["once"]
	deadlineMillis, err := strconv.ParseInt(value.String, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	if deadlineMillis < started.Add(time.Hour).UnixMilli() || deadlineMillis > finished.Add(time.Hour).UnixMilli() {
		t.Fatalf("relative delay was not converted once: %s", value.String)
	}
	if updated.Version != before.Version+1 || value.Type != extensionstate.ConfigType("task:once") ||
		task.onceAt.UnixMilli() != deadlineMillis || task.rawValue != value.String ||
		d.ConfigManager.getConfig(extensionID, "once").Value != value.String || task.timer == oldTimer || !task.IsActive() {
		t.Fatal("durable one-shot deadline and rearmed timer disagree")
	}
}

func TestResetConfigTaskDefaultValidatesBeforePersisting(t *testing.T) {
	ctx := context.Background()
	d, db, extensionID, tasks := newDurableTaskConfigFixture(t, ctx)
	defer db.Close()

	before, err := d.DurableExtensionState(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		key     string
		invalid string
	}{
		{key: "cron", invalid: "not a cron expression"},
		{key: "daily", invalid: "24:61"},
		{key: "once", invalid: "-1"},
	} {
		configItem := d.ConfigManager.getConfig(extensionID, test.key)
		oldValue := configItem.Value.(string)
		task := tasks[test.key]
		oldRawValue, oldTimer, oldEntryID, oldDeadline := task.rawValue, task.timer, task.entryID, task.onceAt
		d.ConfigManager.lock.Lock()
		d.ConfigManager.Plugins[extensionID].Configs[test.key].DefaultValue = test.invalid
		d.ConfigManager.lock.Unlock()

		d.ConfigManager.ResetConfigToDefault(extensionID, test.key)
		after, err := d.DurableExtensionState(ctx)
		if err != nil {
			t.Fatal(err)
		}
		current := d.ConfigManager.getConfig(extensionID, test.key)
		if after.Version != before.Version || after.ConfigValues[extensionID][test.key].String != oldValue ||
			current.Value != oldValue || task.rawValue != oldRawValue || !task.IsActive() ||
			task.timer != oldTimer || task.entryID != oldEntryID || !task.onceAt.Equal(oldDeadline) {
			t.Fatalf("invalid %s default changed durable value or live schedule: state=%#v config=%#v task=%#v",
				test.key, after.ConfigValues[extensionID][test.key], current, task)
		}
	}
}

func newDurableTaskConfigFixture(t *testing.T, ctx context.Context) (*Dice, *eventstore.Database, string, map[string]*JsScriptTask) {
	t.Helper()
	db, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: t.TempDir() + "/task-config.db"})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db,
		eventstore.WithKeySource(compatKeySource{}),
		eventstore.WithProjection(extensionstate.ExtensionProjection()),
	)
	if err := store.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "task-config-test", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	extensionID := "task-config-ext"
	d := &Dice{BaseConfig: BaseConfig{Name: "dice-1"}, DurableStore: store}
	d.ConfigManager = NewConfigManager("")
	d.ConfigManager.SetOwner(d)
	ext := &ExtInfo{Name: extensionID, Version: "1.0.0", IsJsExt: true, dice: d}
	if err := d.DurableDiscoverExtension(ctx, ext); err != nil {
		t.Fatalf("discover extension: %v", err)
	}

	scheduler := cron.New(cron.WithParser(taskCronParser))
	t.Cleanup(func() { <-scheduler.Stop().Done() })
	onceAt := time.Now().Add(time.Hour).Truncate(time.Millisecond)
	tasks := map[string]*JsScriptTask{
		"cron": {
			taskType: "cron", key: "cron", rawValue: "0 * * * *", cronExpr: "0 * * * *", cron: scheduler,
		},
		"daily": {
			taskType: "daily", key: "daily", rawValue: "5:03", cronExpr: "3 5 * * *", cron: scheduler,
		},
		"once": {
			taskType: "once", key: "once", rawValue: strconv.FormatInt(onceAt.UnixMilli(), 10), onceAt: onceAt,
		},
	}
	items := make([]*ConfigItem, 0, len(tasks))
	for _, key := range []string{"cron", "daily", "once"} {
		task := tasks[key]
		if !task.On() {
			t.Fatalf("initial %s task failed to schedule", key)
		}
		t.Cleanup(func() { task.Off() })
		value := task.rawValue
		items = append(items, &ConfigItem{Key: key, Type: "task:" + key, DefaultValue: value, Value: value, task: task})
	}
	if err := d.ConfigManager.RegisterPluginConfig(extensionID, items...); err != nil {
		t.Fatalf("register task configs %v: %v", itemKeys(tasks), err)
	}
	return d, db, extensionID, tasks
}

func itemKeys(tasks map[string]*JsScriptTask) []string {
	keys := make([]string, 0, len(tasks))
	for key := range tasks {
		keys = append(keys, key)
	}
	return keys
}
