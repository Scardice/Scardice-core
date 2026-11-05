package main

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"

	"Scardice-core/eventstore"
	"Scardice-core/migrate/eventsourcing"
	"Scardice-core/migrate/eventsourcing/v1reader"
)

// plainSQLitePath resolves the actual local file named by either a pathname or
// SQLite's file: URI syntax. Memory databases and remote URI authorities are
// not safe candidates for in-place conversion.
func plainSQLitePath(config eventstore.DatabaseConfig) (string, bool) {
	databaseType := strings.ToLower(strings.TrimSpace(config.Type))
	if databaseType != "" && databaseType != "sqlite" && databaseType != "sqlite3" {
		return "", false
	}
	path := strings.TrimSpace(config.DSN)
	if path == "" || path == ":memory:" || strings.ContainsRune(path, '\x00') {
		return "", false
	}
	if strings.HasPrefix(path, "file:") {
		uri, err := url.Parse(path)
		if err != nil || uri.User != nil || uri.Host != "" && uri.Host != "localhost" || uri.Fragment != "" {
			return "", false
		}
		if strings.EqualFold(uri.Query().Get("mode"), "memory") {
			return "", false
		}
		path = uri.Path
		if uri.Opaque != "" {
			path, err = url.PathUnescape(uri.Opaque)
			if err != nil {
				return "", false
			}
		}
	} else {
		base, query, _ := strings.Cut(path, "?")
		options, err := url.ParseQuery(query)
		if err != nil || strings.EqualFold(options.Get("mode"), "memory") {
			return "", false
		}
		path = base
	}
	if path == "" || path == ":memory:" || strings.ContainsRune(path, '\x00') {
		return "", false
	}
	if len(path) >= 3 && path[0] == '/' && path[2] == ':' && filepath.VolumeName(filepath.FromSlash(path[1:])) != "" {
		path = path[1:]
	}
	absolute, err := filepath.Abs(filepath.FromSlash(path))
	if err != nil {
		return "", false
	}
	return absolute, true
}

// detectV1Store reports whether the configured event database is an encrypted
// (v1) store. It must run before eventstore.OpenDatabase: opening would migrate
// the schema of whatever it opens, and the encrypted rows are not readable as
// what the plaintext store expects.
func detectV1Store(ctx context.Context, config eventstore.DatabaseConfig) (bool, error) {
	var format v1reader.Format
	var err error
	databaseType := strings.ToLower(strings.TrimSpace(config.Type))
	if databaseType == "" || databaseType == "sqlite" || databaseType == "sqlite3" {
		path, ok := plainSQLitePath(config)
		if !ok {
			return false, errors.New("cannot safely inspect the configured SQLite file")
		}
		format, err = eventsourcing.DetectSQLiteFormat(ctx, path)
	} else {
		format, err = eventsourcing.DetectRemoteFormat(ctx, config)
	}
	if err != nil {
		return false, err
	}
	if format == v1reader.FormatUnknown {
		return false, errors.New("unrecognized event database schema; refusing automatic schema migration")
	}
	return format == v1reader.FormatV1Encrypted, nil
}

// Every root import/startup opening shares this guard; no alternate CLI or
// interactive path may send an old or unknown schema to AutoMigrate.
func openCurrentEventDatabase(ctx context.Context, config eventstore.DatabaseConfig) (*eventstore.Database, error) {
	old, err := detectV1Store(ctx, config)
	if err != nil {
		return nil, err
	}
	if old {
		return nil, errors.New("encrypted v1 store must be converted before opening")
	}
	return eventstore.OpenDatabase(ctx, config)
}

// v1KeyPaths is where the v1 store kept its key files: next to the database,
// or where the variables the v1 version read point. Only the conversion looks
// at them.
func v1KeyPaths(databasePath string, getenv func(string) string) (indexPath, rootsDir string) {
	keys := filepath.Join(filepath.Dir(databasePath), "keys")
	indexPath = strings.TrimSpace(getenv("SCARDICE_ENDPOINT_KEY_INDEX"))
	if indexPath == "" {
		indexPath = filepath.Join(keys, "index.key")
	}
	rootsDir = strings.TrimSpace(getenv("SCARDICE_ENDPOINT_KEY_ROOTS"))
	if rootsDir == "" {
		rootsDir = filepath.Join(keys, "roots")
	}
	return indexPath, rootsDir
}

func v1MigrationRequiredNotice(executable string) string {
	var notice strings.Builder
	notice.WriteString("\n")
	notice.WriteString("==================== 需要先转换事件库 ====================\n")
	notice.WriteString("检测到上一版本留下的加密事件库。新版本不再加密事件库，需要一次性转换后才能启动。\n")
	notice.WriteString("请先停止正在运行的其它实例，并备份整个 data 目录。\n")
	notice.WriteString("可以在这里直接转换，也可以稍后自行执行：\n\n")
	notice.WriteString("    " + migrationCommand(executable) + "\n\n")
	notice.WriteString("转换只读取旧库，写出新库并整体替换；旧库保留为 events.db.v1.<时间>.bak，确认新版本正常后可删除。\n")
	notice.WriteString("未处理的入站消息、尚未发出的出站消息、操作及其 Story 回复意图属于瞬态队列，不会迁移；已归档 Story 条目保留。\n")
	notice.WriteString("在此输入 y 转换成功后会继续本次启动；命令行转换成功后退出。\n")
	notice.WriteString("===========================================================\n")
	return notice.String()
}

// runV1Conversion converts the encrypted event store into the plaintext one in
// place and reports whether it was published. The database must not be open.
func runV1Conversion(log *zap.SugaredLogger, config eventstore.DatabaseConfig) bool {
	path, ok := plainSQLitePath(config)
	if !ok {
		log.Error("encrypted v1 conversion supports local SQLite files only; remote old schemas are left untouched")
		return false
	}
	indexPath, rootsDir := v1KeyPaths(path, os.Getenv)
	result, err := eventsourcing.ConvertV1(context.Background(), eventsourcing.V1ConvertOptions{
		ActivePath: path, KeyIndexPath: indexPath, KeyRootsDir: rootsDir, Identity: config.DatabaseIdentity,
		Now:      func() time.Time { return time.Now().UTC() },
		Progress: func(format string, args ...any) { log.Infof("v1 转换: "+format, args...) },
	})
	if err != nil {
		log.Errorf("v1 event store conversion failed; original files/backups were preserved, inspect any rollback errors before restarting: %v", err)
		return false
	}
	if result.LeftBehindQueueRows > 0 || result.LeftBehindStoryIntents > 0 {
		log.Warnf("未迁移瞬态记录 %d 条，其中非终态 outbox %d 条；另有未发送 Story 回复意图 %d 条（已归档条目保留）", result.LeftBehindQueueRows, result.NonterminalOutboxRows, result.LeftBehindStoryIntents)
	}
	log.Infof("v1 event store converted: baseline-events=%d referenced-latest-secrets=%d orphan-secrets-omitted=%d plugin-kv=%d story-sessions=%d story-entries=%d story-states=%d projection-rows-verified=%d; v1 database kept as %s",
		result.Events, result.ReferencedSecrets, result.OmittedSecrets, result.PluginKV, result.StorySessions, result.StoryEntries, result.StoryStates, result.ProjectionRows, result.BackupPath)
	return true
}
