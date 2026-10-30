package main

import (
	"context"
	crand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"Scardice-core/eventstore"
	"Scardice-core/utils"
)

const (
	localEndpointBootstrapVersion = 1
	localEndpointRootID           = "root-v1"
	localEndpointKeyBytes         = 32

	endpointBootstrapResourceIndexKey    = "事件库索引密钥"
	endpointBootstrapResourceRootKey     = "事件库加密根密钥"
	endpointBootstrapResourceCurrentRoot = "事件库当前根选择"
	endpointBootstrapResourceConfig      = "事件库默认配置"
	endpointBootstrapResourceReuse       = "本地事件库配置与密钥"
)

var errLocalEndpointBootstrapIncomplete = errors.New("local endpoint bootstrap state is incomplete")

type endpointBootstrapEvent struct {
	Resource string
	Path     string
	Created  bool
}

type endpointBootstrapAudit func(endpointBootstrapEvent)

type localEndpointBootstrapConfig struct {
	Version          int    `json:"version"`
	DatabaseIdentity string `json:"databaseIdentity"`
}

func ensureEndpointDatabaseConfig(getenv func(string) string, rootDir string) (eventstore.DatabaseConfig, error) {
	return ensureEndpointDatabaseConfigWithAudit(getenv, rootDir, nil)
}

func ensureEndpointDatabaseConfigWithAudit(getenv func(string) string, rootDir string, audit endpointBootstrapAudit) (eventstore.DatabaseConfig, error) {
	if getenv == nil {
		return eventstore.DatabaseConfig{}, errEndpointBootstrapConfig
	}
	if endpointEnvironmentConfigured(getenv) {
		return endpointDatabaseConfigFromEnv(getenv)
	}
	return ensureLocalEndpointDatabaseConfig(rootDir, audit)
}

func endpointEnvironmentConfigured(getenv func(string) string) bool {
	for _, key := range []string{
		"SCARDICE_ENDPOINT_DB",
		"SCARDICE_ENDPOINT_DB_TYPE",
		"SCARDICE_ENDPOINT_DB_ID",
		"SCARDICE_ENDPOINT_DB_TLS_VERIFY",
		"SCARDICE_ENDPOINT_DB_ALLOW_INSECURE_LOOPBACK",
		"SCARDICE_ENDPOINT_DB_SLOT_FILE",
		"SCARDICE_ENDPOINT_IMPORT_SLOT",
		"SCARDICE_ENDPOINT_KEY_INDEX",
		"SCARDICE_ENDPOINT_KEY_ROOTS",
	} {
		if strings.TrimSpace(getenv(key)) != "" {
			return true
		}
	}
	return false
}

func endpointSQLiteDatabaseFilePath(dsn string) string {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" || dsn == ":memory:" {
		return ""
	}
	dsn = strings.TrimPrefix(dsn, "file:")
	if queryIndex := strings.IndexByte(dsn, '?'); queryIndex >= 0 {
		dsn = dsn[:queryIndex]
	}
	if dsn == "" || strings.HasPrefix(dsn, ":memory:") {
		return ""
	}
	return filepath.Clean(dsn)
}

func ensureLocalEndpointDatabaseConfig(rootDir string, audit endpointBootstrapAudit) (eventstore.DatabaseConfig, error) {
	if rootDir == "" {
		rootDir = "."
	}
	endpointDir := filepath.Join(rootDir, "data", "endpoint")
	configPath := filepath.Join(endpointDir, "config.json")
	databasePath := filepath.Join(endpointDir, "events.db")
	keysDir := filepath.Join(endpointDir, "keys")
	indexPath := filepath.Join(keysDir, "index.key")
	rootsDir := filepath.Join(keysDir, "roots")
	rootPath := filepath.Join(rootsDir, localEndpointRootID+".key")
	currentRootPath := filepath.Join(rootsDir, "current")

	if err := ensureLocalEndpointDirectory(endpointDir); err != nil {
		return eventstore.DatabaseConfig{}, err
	}
	config, exists, err := readLocalEndpointBootstrapConfig(configPath)
	if err != nil {
		return eventstore.DatabaseConfig{}, err
	}
	if !exists {
		entries, readErr := os.ReadDir(endpointDir)
		if readErr != nil {
			return eventstore.DatabaseConfig{}, readErr
		}
		if len(entries) != 0 {
			return eventstore.DatabaseConfig{}, fmt.Errorf("%w: %s", errLocalEndpointBootstrapIncomplete, endpointDir)
		}
	}
	if err := ensureLocalEndpointDirectory(keysDir); err != nil {
		return eventstore.DatabaseConfig{}, err
	}
	if err := ensureLocalEndpointDirectory(rootsDir); err != nil {
		return eventstore.DatabaseConfig{}, err
	}

	keySource := eventstore.NewLocalFileKeySource(indexPath, rootsDir)
	if exists {
		if err := validateLocalEndpointKeyMaterial(keySource); err != nil {
			return eventstore.DatabaseConfig{}, fmt.Errorf("%w: %w", errLocalEndpointBootstrapIncomplete, err)
		}
		if audit != nil {
			audit(endpointBootstrapEvent{Resource: endpointBootstrapResourceReuse, Path: configPath})
		}
		return eventstore.DatabaseConfig{
			Type: "sqlite", DSN: databasePath,
			KeySource: keySource, DatabaseIdentity: config.DatabaseIdentity,
		}, nil
	}

	indexMaterial := make([]byte, localEndpointKeyBytes)
	rootMaterial := make([]byte, localEndpointKeyBytes)
	identityMaterial := make([]byte, 16)
	for _, material := range [][]byte{indexMaterial, rootMaterial, identityMaterial} {
		if _, err := crand.Read(material); err != nil {
			return eventstore.DatabaseConfig{}, fmt.Errorf("generate local endpoint key material: %w", err)
		}
	}
	if err := eventstore.CreateLocalKeyFile(indexPath, indexMaterial); err != nil {
		return eventstore.DatabaseConfig{}, fmt.Errorf("create local endpoint index key: %w", err)
	}
	if audit != nil {
		audit(endpointBootstrapEvent{Resource: endpointBootstrapResourceIndexKey, Path: indexPath, Created: true})
	}
	if err := eventstore.CreateLocalKeyFile(rootPath, rootMaterial); err != nil {
		return eventstore.DatabaseConfig{}, fmt.Errorf("create local endpoint encryption root: %w", err)
	}
	if audit != nil {
		audit(endpointBootstrapEvent{Resource: endpointBootstrapResourceRootKey, Path: rootPath, Created: true})
	}
	if err := utils.AtomicWriteFile(currentRootPath, []byte(localEndpointRootID+"\n"), 0o600); err != nil {
		return eventstore.DatabaseConfig{}, fmt.Errorf("persist local endpoint current root: %w", err)
	}
	if audit != nil {
		audit(endpointBootstrapEvent{Resource: endpointBootstrapResourceCurrentRoot, Path: currentRootPath, Created: true})
	}

	config = localEndpointBootstrapConfig{
		Version:          localEndpointBootstrapVersion,
		DatabaseIdentity: "local-" + hex.EncodeToString(identityMaterial),
	}
	configData, err := json.Marshal(config)
	if err != nil {
		return eventstore.DatabaseConfig{}, fmt.Errorf("encode local endpoint config: %w", err)
	}
	configData = append(configData, '\n')
	if err := utils.AtomicWriteFile(configPath, configData, 0o600); err != nil {
		return eventstore.DatabaseConfig{}, fmt.Errorf("persist local endpoint config: %w", err)
	}
	if audit != nil {
		audit(endpointBootstrapEvent{Resource: endpointBootstrapResourceConfig, Path: configPath, Created: true})
	}
	if err := validateLocalEndpointKeyMaterial(keySource); err != nil {
		return eventstore.DatabaseConfig{}, fmt.Errorf("%w: %w", errLocalEndpointBootstrapIncomplete, err)
	}
	return eventstore.DatabaseConfig{
		Type: "sqlite", DSN: databasePath,
		KeySource: keySource, DatabaseIdentity: config.DatabaseIdentity,
	}, nil
}

func ensureLocalEndpointDirectory(path string) error {
	if path == "" || strings.ContainsRune(path, '\x00') {
		return errLocalEndpointBootstrapIncomplete
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create local endpoint directory %s: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect local endpoint directory %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: local endpoint path is not a directory: %s", errLocalEndpointBootstrapIncomplete, path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w: local endpoint directory is not owner-only: %s", errLocalEndpointBootstrapIncomplete, path)
	}
	return nil
}

func readLocalEndpointBootstrapConfig(path string) (localEndpointBootstrapConfig, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return localEndpointBootstrapConfig{}, false, nil
	}
	if err != nil {
		return localEndpointBootstrapConfig{}, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return localEndpointBootstrapConfig{}, false, fmt.Errorf("%w: invalid local endpoint config file: %s", errLocalEndpointBootstrapIncomplete, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return localEndpointBootstrapConfig{}, false, err
	}
	var config localEndpointBootstrapConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return localEndpointBootstrapConfig{}, false, fmt.Errorf("%w: decode local endpoint config: %w", errLocalEndpointBootstrapIncomplete, err)
	}
	if config.Version != localEndpointBootstrapVersion || !validLocalEndpointIdentity(config.DatabaseIdentity) {
		return localEndpointBootstrapConfig{}, false, fmt.Errorf("%w: invalid local endpoint config contents", errLocalEndpointBootstrapIncomplete)
	}
	return config, true, nil
}

func validLocalEndpointIdentity(identity string) bool {
	return identity == strings.TrimSpace(identity) &&
		identity != "" && len(identity) <= 128 &&
		!strings.ContainsAny(identity, "\x00\r\n")
}

func validateLocalEndpointKeyMaterial(source *eventstore.LocalFileKeySource) error {
	if source == nil {
		return eventstore.ErrKeySourceUnavailable
	}
	indexMaterial, err := source.IndexRootMaterial(context.Background())
	if err != nil || len(indexMaterial) != localEndpointKeyBytes {
		return eventstore.ErrKeyUnavailable
	}
	root, err := source.CurrentEncryptionRoot(context.Background())
	if err != nil || len(root.Material) != localEndpointKeyBytes || root.ID == "" {
		return eventstore.ErrKeyUnavailable
	}
	return nil
}

var errEndpointBootstrapConfig = errors.New("endpoint bootstrap requires database, key index, key roots, and database identity")

func endpointDatabaseConfigFromEnv(getenv func(string) string) (eventstore.DatabaseConfig, error) {
	if getenv == nil {
		return eventstore.DatabaseConfig{}, errEndpointBootstrapConfig
	}
	prefix := "SCARDICE_ENDPOINT_DB"
	if slotFile := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_DB_SLOT_FILE")); slotFile != "" {
		slot, err := readEndpointDatabaseSlot(slotFile)
		if err != nil {
			return eventstore.DatabaseConfig{}, err
		}
		prefix += "_" + strings.ToUpper(slot)
	}
	return endpointDatabaseConfigForPrefix(getenv, prefix)
}

func endpointDatabaseConfigForSlot(getenv func(string) string, slot string) (eventstore.DatabaseConfig, error) {
	if getenv == nil || !validEndpointDatabaseSlot(slot) {
		return eventstore.DatabaseConfig{}, errEndpointBootstrapConfig
	}
	return endpointDatabaseConfigForPrefix(getenv, "SCARDICE_ENDPOINT_DB_"+strings.ToUpper(slot))
}

func endpointDatabaseConfigForPrefix(getenv func(string) string, prefix string) (eventstore.DatabaseConfig, error) {
	dsn := strings.TrimSpace(getenv(prefix))
	if dsn == "" {
		return eventstore.DatabaseConfig{}, nil
	}
	indexPath := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_KEY_INDEX"))
	rootsPath := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_KEY_ROOTS"))
	identity := strings.TrimSpace(getenv(prefix + "_ID"))
	if indexPath == "" || rootsPath == "" || identity == "" {
		return eventstore.DatabaseConfig{}, errEndpointBootstrapConfig
	}
	dbType := strings.ToLower(strings.TrimSpace(getenv(prefix + "_TYPE")))
	if dbType == "" {
		dbType = "sqlite"
	}
	tlsVerify, err := optionalBool(getenv(prefix + "_TLS_VERIFY"))
	if err != nil {
		return eventstore.DatabaseConfig{}, err
	}
	allowLoopback, err := optionalBool(getenv(prefix + "_ALLOW_INSECURE_LOOPBACK"))
	if err != nil {
		return eventstore.DatabaseConfig{}, err
	}
	return eventstore.DatabaseConfig{
		Type: dbType, DSN: dsn,
		KeySource:             eventstore.NewLocalFileKeySource(indexPath, rootsPath),
		DatabaseIdentity:      identity,
		TLSVerify:             tlsVerify,
		AllowInsecureLoopback: allowLoopback,
	}, nil
}

func readEndpointDatabaseSlot(path string) (string, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, '\x00') {
		return "", errEndpointBootstrapConfig
	}
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() || before.Size() > 64 {
		return "", errEndpointBootstrapConfig
	}
	if runtime.GOOS != "windows" && before.Mode().Perm()&0o077 != 0 {
		return "", errEndpointBootstrapConfig
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errEndpointBootstrapConfig
	}
	data, readErr := io.ReadAll(io.LimitReader(file, 65))
	after, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(data) > 64 || !os.SameFile(before, after) {
		return "", errors.Join(errEndpointBootstrapConfig, readErr, statErr, closeErr)
	}
	slot := strings.TrimSpace(string(data))
	if !validEndpointDatabaseSlot(slot) {
		return "", errEndpointBootstrapConfig
	}
	return slot, nil
}

func validEndpointDatabaseSlot(slot string) bool {
	if len(slot) == 0 || len(slot) > 32 {
		return false
	}
	for _, char := range slot {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '_' {
			return false
		}
	}
	return true
}

func writeEndpointDatabaseSlot(path, slot string) (resultErr error) {
	if strings.TrimSpace(path) == "" || strings.ContainsRune(path, '\x00') || !validEndpointDatabaseSlot(slot) {
		return errEndpointBootstrapConfig
	}
	clean := filepath.Clean(path)
	parent := filepath.Dir(clean)
	parentInfo, err := os.Lstat(parent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return errEndpointBootstrapConfig
	}
	if current, statErr := os.Lstat(clean); statErr == nil {
		if current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() {
			return errEndpointBootstrapConfig
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}
	temporary, err := os.CreateTemp(parent, ".scardice-endpoint-slot-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporaryPath != "" {
			resultErr = errors.Join(resultErr, os.Remove(temporaryPath))
		}
	}()
	if err = temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err = temporary.WriteString(slot + "\n"); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = replaceEndpointDatabaseSlot(temporaryPath, clean); err != nil {
		return err
	}
	temporaryPath = ""
	return syncEndpointDatabaseSlotParent(parent)
}

func optionalBool(value string) (bool, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return false, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, errEndpointBootstrapConfig
	}
	return parsed, nil
}
