package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing"
	"Scardice-core/projectionset"
)

// migrationCommand is the command that imports the legacy data, quoted so a
// path with spaces can be pasted into a shell as it is.
func migrationCommand(executable string) string {
	name := executable
	if abs, err := filepath.Abs(executable); err == nil {
		name = abs
	}
	if strings.ContainsAny(name, " \t") {
		name = `"` + name + `"`
	}
	return name + " --import-legacy"
}

// migrationRequiredNotice is what the operator sees when legacy data exists but
// has not been imported into the event store yet.
func migrationRequiredNotice(executable string) string {
	var notice strings.Builder
	notice.WriteString("\n")
	notice.WriteString("==================== 需要先迁移数据 ====================\n")
	notice.WriteString("检测到 data 目录下存在旧版数据，但事件库尚未执行迁移，已终止启动。\n")
	notice.WriteString("请先停止正在运行的其它实例，并备份整个 data 目录。\n")
	notice.WriteString("可以在这里直接迁移，也可以稍后自行执行：\n\n")
	notice.WriteString("    " + migrationCommand(executable) + "\n\n")
	notice.WriteString("在此输入 y 迁移成功后会继续本次启动；命令行迁移成功后退出并输出 \"legacy import published\"。\n")
	notice.WriteString("迁移时无法解读的旧数据会被跳过，并记录在 data/migration-drops/ 下供人工核对。\n")
	notice.WriteString("========================================================\n")
	return notice.String()
}

const migrationPrompt = "现在迁移？输入 y 开始迁移，直接按 Enter 或输入 n 退出 [y/N]: "

// askMigrate reads one answer. Only an explicit yes starts the migration;
// Enter, n, end of input and anything unrecognised leave the data untouched.
func askMigrate(in *bufio.Reader, out io.Writer) bool {
	_, _ = fmt.Fprint(out, migrationPrompt)
	line, _ := in.ReadString('\n')
	answer := strings.ToLower(strings.TrimSpace(line))
	_, _ = fmt.Fprintln(out)
	return answer == "y" || answer == "yes"
}

// reportMigrationRequired refuses the start and lets the operator decide.
// release runs before the prompt: the importer replaces the event database
// file, so this process must not keep it open while the operator migrates from
// another terminal. migrate is called only for an explicit yes. Without a
// terminal (a service, a pipe, a closed stdin) nobody can answer, so the notice
// is printed and the process ends instead of hanging a supervisor.
func reportMigrationRequired(out io.Writer, in io.Reader, interactive bool, executable string, release func(), migrate func() bool) bool {
	return reportMigration(out, in, interactive, migrationRequiredNotice(executable), release, migrate)
}

// reportMigration is reportMigrationRequired with the notice chosen by the
// caller: legacy data and an encrypted v1 event store need different words.
func reportMigration(out io.Writer, in io.Reader, interactive bool, notice string, release func(), migrate func() bool) bool {
	if release != nil {
		release()
	}
	_, _ = fmt.Fprint(out, notice)
	if !interactive {
		return false
	}
	if !askMigrate(bufio.NewReader(in), out) || migrate == nil {
		return false
	}
	return migrate()
}

// runLegacyImport imports the legacy data under the working directory into the
// event store and reports whether it was published. It consumes the store: the
// importer closes it before replacing the database file.
func runLegacyImport(log *zap.SugaredLogger, store *eventstore.GORMStore, config eventstore.DatabaseConfig) bool {
	readiness, readinessErr := store.GetReadiness(context.Background())
	if readinessErr != nil {
		log.Errorf("read legacy import readiness failed: %v", readinessErr)
		return false
	}
	persistentState, persistentStateErr := captureImportPersistentState(context.Background(), store)
	if persistentStateErr != nil {
		log.Errorf("inspect active event database before legacy import failed: %v", persistentStateErr)
		return false
	}
	if readiness.Mode != string(eventsourcing.ModeFresh) || persistentState.value {
		log.Error("legacy import refuses a populated or already imported event store; choose the authoritative source explicitly instead of mixing or overwriting data")
		return false
	}
	if closeErr := store.Close(); closeErr != nil {
		log.Errorf("close active event database before import failed: %v", closeErr)
		return false
	}
	return runLegacyImportSnapshot(log, config, readiness, persistentState)
}

// The metadata is captured from either a closed plaintext store or an unopened
// empty fresh v1 schema. Neither path opens v1 with the plaintext migrator.
func runLegacyImportSnapshot(log *zap.SugaredLogger, config eventstore.DatabaseConfig, readiness eventstore.Readiness, persistentState importPersistentState) bool {
	installationRoot, sourceRootErr := os.Getwd()
	if sourceRootErr != nil {
		log.Errorf("resolve legacy installation root failed: %v", sourceRootErr)
		return false
	}
	sourceRoot, sourceRootErr := legacySourceRoot(installationRoot)
	if sourceRootErr != nil {
		log.Errorf("resolve legacy data root failed: %v", sourceRootErr)
		return false
	}
	result, importErr := importLegacyInstallation(context.Background(), config, readiness, persistentState, sourceRoot, time.Now())
	if warning := legacyImportDropWarning(result); warning != "" {
		log.Warn(warning)
	}
	if importErr != nil {
		log.Errorf("legacy import failed: %v", importErr)
		return false
	}
	for _, warning := range result.Warnings {
		log.Warnf("legacy import cleanup warning: %s", warning)
	}
	log.Infof("legacy import published: target=%s snapshot=%s records-batches=%d", result.TargetIdentity, result.Snapshot.Root, result.Batches)
	return true
}

// runInstallationImport selects A/B before opening the event database, for
// both --import-legacy and interactive startup.
func runInstallationImport(log *zap.SugaredLogger, config eventstore.DatabaseConfig) bool {
	old, err := detectV1Store(context.Background(), config)
	if err != nil {
		log.Errorf("detect event database before import failed: %v", err)
		return false
	}
	if old {
		source, sourceErr := v1InstallationSource(context.Background(), config, legacyStatePresent())
		if sourceErr != nil {
			log.Errorf("select authoritative migration source failed: %v", sourceErr)
			return false
		}
		if source == installationSourceLegacy {
			return runLegacyImportSnapshot(log, config, eventstore.Readiness{Mode: string(eventsourcing.ModeFresh), SchemaVersion: 1, DatabaseIdentity: config.DatabaseIdentity}, importPersistentState{})
		}
		return runV1Conversion(log, config)
	}
	database, err := openCurrentEventDatabase(context.Background(), config)
	if err != nil {
		log.Errorf("endpoint event database startup failed: %v", err)
		return false
	}
	defer database.Close()
	return runLegacyImport(log, eventstore.NewStore(database, projectionset.StoreOptions()...), config)
}

func currentExecutable() string {
	if path, err := os.Executable(); err == nil {
		return path
	}
	if len(os.Args) > 0 {
		return os.Args[0]
	}
	return "Scardice-core"
}

type installationImportSource string

const (
	installationSourceLegacy installationImportSource = "legacy"
	installationSourceV1     installationImportSource = "v1-current"
)

func v1InstallationSource(ctx context.Context, config eventstore.DatabaseConfig, legacy bool) (installationImportSource, error) {
	path, local := plainSQLitePath(config)
	if !local {
		return "", errors.New("encrypted v1 source inspection supports local SQLite files only")
	}
	state, err := eventsourcing.InspectV1CurrentState(ctx, path)
	if err != nil {
		return "", err
	}
	if state.DatabaseIdentity != config.DatabaseIdentity {
		return "", eventsourcing.ErrTargetIdentity
	}
	if state.Mode == string(eventsourcing.ModeFresh) && legacy {
		if state.HasPersistentState {
			return "", eventsourcing.ErrLegacyStateConflict
		}
		return installationSourceLegacy, nil
	}
	return installationSourceV1, nil
}
