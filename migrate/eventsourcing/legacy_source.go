package eventsourcing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	_ "github.com/glebarez/go-sqlite"
	ds "github.com/sealdice/dicescript"
	"github.com/tidwall/buntdb"
	"gopkg.in/yaml.v3"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/managerstate"
	"Scardice-core/core/playerstate"
	"Scardice-core/dice"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

// LegacySource reads a stopped pre-event-store installation. It never starts
// Dice, adapters, scripts, or timers, and never writes source database files.
type LegacySource struct {
	Root      string
	keySource eventstore.KeySource
	// snapshotDataDirs pins copied instances to paths inside Root.
	snapshotDataDirs map[legacyDataDirKey]legacySnapshotDataDir
}

func NewLegacySource(root string) *LegacySource {
	return &LegacySource{Root: filepath.Clean(root)}
}

func NewLegacySourceWithKeySource(root string, keySource eventstore.KeySource) *LegacySource {
	return &LegacySource{Root: filepath.Clean(root), keySource: keySource}
}

type legacyInstance struct {
	config dice.BaseConfig
	dir    string
}

type legacyDataDirKey struct {
	name    string
	dataDir string
}

type legacySnapshotDataDir struct {
	relative string
	count    int
}

func legacyConfigDataDirKey(config dice.BaseConfig) legacyDataDirKey {
	return legacyDataDirKey{name: config.Name, dataDir: config.DataDir}
}

func newLegacySnapshotSource(
	target string,
	keySource eventstore.KeySource,
	root *legacySourceRoot,
	instances []legacyInstance,
) (*LegacySource, error) {
	source := NewLegacySourceWithKeySource(target, keySource)
	source.snapshotDataDirs = make(map[legacyDataDirKey]legacySnapshotDataDir, len(instances))
	for _, instance := range instances {
		relative, err := root.relative(instance.dir)
		if err != nil || relative == "." {
			return nil, ErrSourceMutation
		}
		key := legacyConfigDataDirKey(instance.config)
		captured := source.snapshotDataDirs[key]
		if captured.relative != "" && captured.relative != relative {
			return nil, ErrSourceMutation
		}
		captured.relative = relative
		captured.count++
		source.snapshotDataDirs[key] = captured
	}
	return source, nil
}

func (s *LegacySource) validateSnapshotDataDirs(configs []dice.BaseConfig) error {
	if s.snapshotDataDirs == nil {
		return nil
	}
	observed := make(map[legacyDataDirKey]int, len(configs))
	for _, config := range configs {
		observed[legacyConfigDataDirKey(config)]++
	}
	if len(observed) != len(s.snapshotDataDirs) {
		return ErrSourceMutation
	}
	for key, captured := range s.snapshotDataDirs {
		if captured.count <= 0 || captured.relative == "" || observed[key] != captured.count {
			return ErrSourceMutation
		}
	}
	return nil
}

type legacyServe struct {
	CommandPrefix []string `yaml:"commandPrefix"`
	DiceMasters   []string `yaml:"diceMasters"`
	dice.Config   `yaml:",inline"`
}

type legacyEndpointDocument struct {
	IMSession struct {
		EndPoints []legacyEndpoint `yaml:"endPoints"`
	} `yaml:"imSession"`
}

type legacyEndpoint struct {
	BaseInfo dice.EndPointInfoBase `yaml:"baseInfo"`
	Adapter  map[string]any        `yaml:"adapter"`
}

type legacyEndpointDatabaseStatistics struct {
	commandCount  sql.NullInt64
	lastCommandAt sql.NullInt64
	onlineSeconds sql.NullInt64
}

type legacyGroupRow struct {
	ID        string
	CreatedAt int64
	Data      []byte
}

type legacyPlayerRow struct {
	Name                string
	UserID              string
	LastCommandTime     int64
	AutoSetNameTemplate string
	DiceSideNum         int
	GroupID             string
}

type legacyBanRow struct {
	ID           string
	Data         []byte
	BanUpdatedAt int64
}

type legacyAttrsRow struct {
	ID             string
	Data           []byte
	AttrsType      string
	BindingSheetID string
	Name           string
	OwnerID        string
	SheetType      string
	Hidden         bool
	CreatedAt      int64
	UpdatedAt      int64
}

func (s *LegacySource) Inventory(ctx context.Context) (SourceInventory, error) {
	if s == nil || strings.TrimSpace(s.Root) == "" || s.Root == "." {
		return SourceInventory{}, ErrSourceRequired
	}
	root, err := openLegacySourceRoot(s.Root)
	if err != nil {
		return SourceInventory{}, err
	}
	defer root.Close()
	_, paths, err := s.layoutWithRoot(ctx, true, root)
	if err != nil {
		return SourceInventory{}, err
	}
	metadata, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return SourceInventory{}, err
	}
	pending, err := pendingLegacyMigrationsAt(root, filepath.Join(root.path, "upgrade_metadata.json"))
	if err != nil {
		return SourceInventory{}, err
	}
	return SourceInventory{
		Kind: SourceKindLegacy, Identity: metadata.Identity, Metadata: metadata,
		BackupIdentity: metadata.Identity, PendingMigrations: pending, LegacyOwnershipComplete: true,
	}, nil
}

func (s *LegacySource) StreamRecords(ctx context.Context, yield func([]SourceRecord) error) error {
	if yield == nil {
		return ErrValidation
	}
	if s == nil || strings.TrimSpace(s.Root) == "" || s.Root == "." {
		return ErrSourceRequired
	}
	root, err := openLegacySourceRoot(s.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	instances, paths, err := s.layoutWithRoot(ctx, true, root)
	if err != nil {
		return err
	}
	before, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return err
	}
	batcher := sourceRecordBatcher{yield: yield}
	records, err := s.readManagerConfig(root)
	if err != nil {
		return fmt.Errorf("legacy manager configuration: %w", err)
	}
	if err = batcher.add(records...); err != nil {
		return fmt.Errorf("batch legacy manager configuration: %w", err)
	}
	for _, instance := range instances {
		instanceErr := func() (instanceErr error) {
			dataDB, cleanup, openErr := openLegacySQLiteSnapshotReader(ctx, root, filepath.Join(instance.dir, "data.db"))
			if openErr != nil {
				return openErr
			}
			defer func() { instanceErr = errors.Join(instanceErr, cleanup()) }()
			instanceRecords, readErr := s.readInstanceState(ctx, root, instance, dataDB)
			if readErr != nil {
				return fmt.Errorf("state: %w", readErr)
			}
			if addErr := batcher.add(instanceRecords...); addErr != nil {
				return fmt.Errorf("batch state: %w", addErr)
			}
			if flushErr := batcher.flush(); flushErr != nil {
				return fmt.Errorf("flush state: %w", flushErr)
			}
			diceID := instance.config.Name
			if databaseErr := streamLegacySQLiteDatabase(ctx, dataDB, diceID, s.keySource, yield); databaseErr != nil {
				return fmt.Errorf("database: %w", databaseErr)
			}
			if logErr := streamLegacyStoryLogRecords(
				ctx,
				root,
				dataDB,
				filepath.Join(instance.dir, "data-logs.db"),
				diceID,
				before.Identity,
				yield,
			); logErr != nil {
				return fmt.Errorf("story logs: %w", logErr)
			}
			if pluginErr := streamLegacyPluginStores(ctx, root, instance.dir, yield); pluginErr != nil {
				return fmt.Errorf("plugin storage: %w", pluginErr)
			}
			return nil
		}()
		if instanceErr != nil {
			return fmt.Errorf("legacy instance %q: %w", instance.config.Name, instanceErr)
		}
	}
	if err = batcher.flush(); err != nil {
		return err
	}
	after, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return err
	}
	if !before.Equal(after) {
		return ErrSourceDrift
	}
	return nil
}

func (s *LegacySource) Snapshot(ctx context.Context, target string) (SnapshotResult, error) {
	if s == nil || strings.TrimSpace(s.Root) == "" || s.Root == "." {
		return SnapshotResult{}, ErrSourceRequired
	}
	root, err := openLegacySourceRoot(s.Root)
	if err != nil {
		return SnapshotResult{}, err
	}
	defer root.Close()
	instances, paths, err := s.layoutWithRoot(ctx, true, root)
	if err != nil {
		return SnapshotResult{}, err
	}
	metadata, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return SnapshotResult{}, err
	}
	if err = secureDestination(DefaultFileSystem(), target); err != nil {
		return SnapshotResult{}, err
	}
	files := make([]string, 0, len(paths))
	for _, sourcePath := range paths {
		relative, relativeErr := root.relative(sourcePath)
		if relativeErr != nil || relative == "." {
			return SnapshotResult{}, ErrSourceMutation
		}
		destination := filepath.Join(target, relative)
		if err = os.MkdirAll(filepath.Dir(destination), SnapshotTreeMode); err != nil {
			return SnapshotResult{}, err
		}
		if err = copyLegacyFileAt(ctx, root, sourcePath, destination); err != nil {
			return SnapshotResult{}, err
		}
		files = append(files, destination)
	}
	snapshotSource, err := newLegacySnapshotSource(target, s.keySource, root, instances)
	if err != nil {
		return SnapshotResult{}, err
	}
	return SnapshotResult{Root: target, Metadata: metadata, Files: files, Source: snapshotSource}, nil
}

func (s *LegacySource) Recheck(ctx context.Context, before SourceMetadata) error {
	if s == nil || strings.TrimSpace(s.Root) == "" || s.Root == "." {
		return ErrSourceRequired
	}
	root, err := openLegacySourceRoot(s.Root)
	if err != nil {
		return err
	}
	defer root.Close()
	_, paths, err := s.layoutWithRoot(ctx, true, root)
	if err != nil {
		return err
	}
	after, err := legacyMetadataWithRoot(ctx, root, paths)
	if err != nil {
		return err
	}
	if !before.Equal(after) {
		return ErrSourceDrift
	}
	return nil
}

func (s *LegacySource) layoutWithRoot(ctx context.Context, requireDatabase bool, root *legacySourceRoot) ([]legacyInstance, []string, error) {
	if root == nil {
		return nil, nil, ErrSourceRequired
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	dicePath := filepath.Join(root.path, "dice.yaml")
	data, err := root.ReadFile(dicePath)
	if err != nil {
		return nil, nil, err
	}
	var configs dice.Configs
	if err = yaml.Unmarshal(data, &configs); err != nil {
		return nil, nil, fmt.Errorf("legacy dice.yaml: %w", err)
	}
	if err = s.validateSnapshotDataDirs(configs.DiceConfigs); err != nil {
		return nil, nil, err
	}
	if len(configs.DiceConfigs) == 0 {
		return nil, nil, ErrSourceRequired
	}
	instances := make([]legacyInstance, 0, len(configs.DiceConfigs))
	paths := []string{dicePath}
	seen := map[string]struct{}{dicePath: {}}
	upgradeMetadataPath := filepath.Join(root.path, "upgrade_metadata.json")
	if _, statErr := root.Lstat(upgradeMetadataPath); statErr == nil {
		paths = append(paths, upgradeMetadataPath)
		seen[upgradeMetadataPath] = struct{}{}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, nil, statErr
	}
	for _, config := range configs.DiceConfigs {
		if strings.TrimSpace(config.Name) == "" {
			return nil, nil, ErrValidation
		}
		dir, resolveErr := s.resolveDataDir(root, config)
		if resolveErr != nil {
			return nil, nil, resolveErr
		}
		instances = append(instances, legacyInstance{config: config, dir: dir})
		names := []string{"serve.yaml", "advanced.yaml"}
		if requireDatabase {
			names = append(names, "data.db", "data.db-wal", "data.db-shm")
		}
		for _, name := range names {
			path := filepath.Join(dir, name)
			if info, statErr := root.Lstat(path); statErr == nil {
				if !info.Mode().IsRegular() {
					return nil, nil, ErrSourceMutation
				}
				if _, duplicate := seen[path]; !duplicate {
					paths = append(paths, path)
					seen[path] = struct{}{}
				}
			} else if !errors.Is(statErr, os.ErrNotExist) || name == "serve.yaml" || name == "data.db" {
				return nil, nil, statErr
			}
		}
		if requireDatabase {
			logPath := filepath.Join(dir, "data-logs.db")
			if _, statErr := root.Lstat(logPath); statErr == nil {
				for _, name := range []string{"data-logs.db", "data-logs.db-wal", "data-logs.db-shm"} {
					path := filepath.Join(dir, name)
					if info, fileErr := root.Lstat(path); fileErr == nil {
						if !info.Mode().IsRegular() {
							return nil, nil, ErrSourceMutation
						}
						if _, duplicate := seen[path]; !duplicate {
							paths = append(paths, path)
							seen[path] = struct{}{}
						}
					} else if !errors.Is(fileErr, os.ErrNotExist) || name == "data-logs.db" {
						return nil, nil, fileErr
					}
				}
			} else if errors.Is(statErr, os.ErrNotExist) {
				for _, suffix := range []string{"-wal", "-shm"} {
					if _, sidecarErr := root.Lstat(logPath + suffix); sidecarErr == nil {
						return nil, nil, ErrSourceMutation
					} else if !errors.Is(sidecarErr, os.ErrNotExist) {
						return nil, nil, sidecarErr
					}
				}
			} else {
				return nil, nil, statErr
			}
		}
		extensionsDir := filepath.Join(dir, "extensions")
		entries, readErr := root.ReadDir(extensionsDir)
		if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
			return nil, nil, readErr
		}
		for _, entry := range entries {
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() {
				continue
			}
			path := filepath.Join(extensionsDir, entry.Name(), "storage.db")
			if info, statErr := root.Lstat(path); statErr == nil {
				if !info.Mode().IsRegular() {
					return nil, nil, ErrSourceMutation
				}
				paths = append(paths, path)
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return nil, nil, statErr
			}
		}
	}
	sort.Slice(instances, func(i, j int) bool { return instances[i].config.Name < instances[j].config.Name })
	sort.Strings(paths)
	return instances, paths, nil
}

func pendingLegacyMigrations(path string) ([]string, error) {
	root, err := openLegacySourceRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return pendingLegacyMigrationsAt(root, path)
}

func pendingLegacyMigrationsAt(root *legacySourceRoot, path string) ([]string, error) {
	file, err := root.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxBatchBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxBatchBytes {
		return nil, ErrBatchLimit
	}
	var records []struct {
		ID      string `json:"id"`
		Success bool   `json:"success"`
	}
	if err = json.Unmarshal(data, &records); err != nil {
		return nil, ErrValidation
	}
	latest := make(map[string]bool, len(records))
	for _, record := range records {
		id := strings.TrimSpace(record.ID)
		if id == "" {
			return nil, ErrValidation
		}
		latest[id] = record.Success
	}
	pending := make([]string, 0)
	for id, success := range latest {
		if !success {
			pending = append(pending, id)
		}
	}
	sort.Strings(pending)
	return pending, nil
}

func (s *LegacySource) resolveDataDir(root *legacySourceRoot, config dice.BaseConfig) (string, error) {
	var candidate string
	if s.snapshotDataDirs != nil {
		captured, ok := s.snapshotDataDirs[legacyConfigDataDirKey(config)]
		if !ok {
			return "", ErrSourceMutation
		}
		candidate = filepath.Join(root.path, captured.relative)
	} else {
		candidate = strings.TrimSpace(config.DataDir)
		if candidate == "" {
			candidate = config.Name
		}
		if !filepath.IsAbs(candidate) {
			clean := filepath.Clean(candidate)
			rootBase := filepath.Base(root.path)
			if clean == rootBase || strings.HasPrefix(clean, rootBase+string(filepath.Separator)) {
				candidate = filepath.Join(filepath.Dir(root.path), clean)
			} else {
				candidate = filepath.Join(root.path, clean)
			}
		}
	}
	candidate, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	candidate, err = root.canonicalPath(candidate)
	if err != nil {
		return "", ErrSourceMutation
	}
	info, err := root.Lstat(candidate)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", ErrSourceMutation
	}
	return candidate, nil
}

func (s *LegacySource) readManagerConfig(root *legacySourceRoot) ([]SourceRecord, error) {
	data, err := root.ReadFile(filepath.Join(root.path, "dice.yaml"))
	if err != nil {
		return nil, err
	}
	var config dice.Configs
	if err = yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("legacy dice.yaml: %w", err)
	}
	auth, err := managerstate.MarshalAuth(managerstate.Auth{
		UIPasswordSalt: config.UIPasswordSalt,
		UIPasswordHash: config.UIPasswordHash,
		AccessTokens:   config.AccessTokens,
	})
	if err != nil {
		return nil, err
	}
	public := managerstate.PublicConfig{
		ServeAddress: config.ServeAddress, TrayTooltip: config.TrayTooltip,
		WebUIAddress: config.WebUIAddress, HelpDocEngineType: config.HelpDocEngineType,
		DiceRandomMode: config.DiceRandomMode, AutoBackupEnable: config.AutoBackupEnable,
		AutoBackupTime: config.AutoBackupTime, AutoBackupSelection: config.AutoBackupSelection,
		BackupClean: managerstate.BackupCleanConfig{
			Strategy: config.BackupClean.Strategy, KeepCount: config.BackupClean.KeepCount,
			KeepDuration: config.BackupClean.KeepDur, Trigger: config.BackupClean.Trigger,
			Cron: config.BackupClean.Cron,
		},
		ServiceName: config.ServiceName, ConfigVersion: config.ConfigVersion,
	}
	public.DiceDataDirs = make(map[string]string, len(config.DiceConfigs))
	for _, instance := range config.DiceConfigs {
		if instance.Name == "" {
			continue
		}
		dataDir := instance.DataDir
		if dataDir == "" {
			dataDir = filepath.Join("./data", instance.Name)
		}
		public.DiceDataDirs[instance.Name] = dataDir
	}
	event, err := managerstate.MarshalSnapshotV1(managerstate.NewSnapshotV1(public, 1))
	if err != nil {
		return nil, err
	}
	return []SourceRecord{
		sensitiveLegacyRecord(managerstate.AggregateType, managerstate.AuthSecretRef, managerstate.AggregateID, auth),
		legacyEventRecord(managerstate.Stream(), managerstate.EventBaselineImported, managerstate.EventSchemaVersion, 1, event),
	}, nil
}

func (s *LegacySource) readInstanceState(ctx context.Context, root *legacySourceRoot, instance legacyInstance, dataDB *sql.DB) ([]SourceRecord, error) {
	serveData, err := root.ReadFile(filepath.Join(instance.dir, "serve.yaml"))
	if err != nil {
		return nil, err
	}
	serve := legacyServe{Config: dice.DefaultConfig}
	if err = yaml.Unmarshal(serveData, &serve); err != nil {
		return nil, fmt.Errorf("legacy serve.yaml: %w", err)
	}
	var endpoints legacyEndpointDocument
	if err = yaml.Unmarshal(serveData, &endpoints); err != nil {
		return nil, fmt.Errorf("legacy endpoints: %w", err)
	}
	publicEndpoints := make(map[string]struct{})
	for _, legacy := range endpoints.IMSession.EndPoints {
		if legacy.BaseInfo.IsPublic && legacy.BaseInfo.ID != "" {
			publicEndpoints[legacy.BaseInfo.ID] = struct{}{}
		}
	}
	serve.EndpointIDs = make([]string, 0, len(publicEndpoints))
	for endpointID := range publicEndpoints {
		serve.EndpointIDs = append(serve.EndpointIDs, endpointID)
	}
	sort.Strings(serve.EndpointIDs)
	advanced := dice.AdvancedConfig{}
	advancedPath := filepath.Join(instance.dir, "advanced.yaml")
	if data, readErr := root.ReadFile(advancedPath); readErr == nil {
		if err = yaml.Unmarshal(data, &advanced); err != nil {
			return nil, fmt.Errorf("legacy advanced.yaml: %w", err)
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return nil, readErr
	}
	diceID := instance.config.Name
	mailRef, storyRef := "", ""
	records := make([]SourceRecord, 0)
	if serve.MailPassword != "" {
		mailRef = "vault:legacy-" + safeLegacyID(diceID) + "-mail"
		records = append(records, sensitiveLegacyRecord("config", mailRef, diceID, []byte(serve.MailPassword)))
		serve.MailPassword = ""
	}
	if advanced.StoryLogBackendToken != "" {
		storyRef = "vault:legacy-" + safeLegacyID(diceID) + "-story-log"
		records = append(records, sensitiveLegacyRecord("config", storyRef, diceID, []byte(advanced.StoryLogBackendToken)))
		advanced.StoryLogBackendToken = ""
	}
	baseline, err := dice.LegacyConfigBaseline(diceID, serve.Config, advanced, serve.CommandPrefix, serve.DiceMasters, mailRef, storyRef)
	if err != nil {
		return nil, err
	}
	decision, err := configstate.Decide(configstate.State{}, configstate.Command{Kind: configstate.CommandImportBaseline, Baseline: &baseline})
	if err != nil {
		return nil, err
	}
	for version, event := range decision.Events {
		payload, marshalErr := configstate.MarshalTypedEvent(event)
		if marshalErr != nil {
			return nil, marshalErr
		}
		records = append(records, legacyEventRecord(configstate.ConfigStream(diceID), string(event.EventType()), configstate.ConfigEventSchemaVersion, uint64(version+1), payload))
	}
	extensionBaseline := dice.LegacyExtensionBaseline(serve.Config)
	extensionDecision, err := extensionstate.Decide(extensionstate.State{}, extensionstate.Command{Kind: extensionstate.CommandImportBaseline, DiceID: diceID, Baseline: &extensionBaseline})
	if err != nil {
		return nil, err
	}
	for version, event := range extensionDecision.Events {
		payload, marshalErr := extensionstate.MarshalEvent(event)
		if marshalErr != nil {
			return nil, marshalErr
		}
		records = append(records, legacyEventRecord(extensionstate.ExtensionStream(diceID), string(event.EventType()), extensionstate.ExtensionEventSchemaVersion, uint64(version+1), payload))
	}
	endpointStatistics, err := readLegacyEndpointStatistics(ctx, dataDB)
	if err != nil {
		clearSensitiveSourceRecords(records)
		return nil, err
	}
	endpointRecords, err := legacyEndpointRecords(ctx, diceID, serveData, endpointStatistics)
	if err != nil {
		clearSensitiveSourceRecords(records)
		return nil, err
	}
	records = append(records, endpointRecords...)
	return records, nil
}

func readLegacyEndpointStatistics(ctx context.Context, database *sql.DB) (map[string]legacyEndpointDatabaseStatistics, error) {
	if database == nil {
		return nil, ErrValidation
	}
	var tableCount int
	if err := database.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, "endpoint_info").Scan(&tableCount); err != nil {
		return nil, fmt.Errorf("legacy endpoint_info schema: %w", err)
	}
	statistics := make(map[string]legacyEndpointDatabaseStatistics)
	if tableCount == 0 {
		return statistics, nil
	}
	rows, err := database.QueryContext(ctx, `SELECT user_id, cmd_num, cmd_last_time, online_time FROM endpoint_info`)
	if err != nil {
		return nil, fmt.Errorf("legacy endpoint_info query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var providerID sql.NullString
		var value legacyEndpointDatabaseStatistics
		if err = rows.Scan(&providerID, &value.commandCount, &value.lastCommandAt, &value.onlineSeconds); err != nil {
			return nil, fmt.Errorf("legacy endpoint_info scan: %w", err)
		}
		id := strings.TrimSpace(providerID.String)
		if id == "" {
			continue
		}
		if value.commandCount.Valid && value.commandCount.Int64 < 0 ||
			value.lastCommandAt.Valid && value.lastCommandAt.Int64 < 0 ||
			value.onlineSeconds.Valid && value.onlineSeconds.Int64 < 0 {
			return nil, fmt.Errorf("legacy endpoint_info %q: %w", id, ErrValidation)
		}
		statistics[id] = value
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("legacy endpoint_info rows: %w", err)
	}
	return statistics, nil
}

func applyLegacyEndpointDatabaseStatistics(current endpoint.Statistics, persisted legacyEndpointDatabaseStatistics) endpoint.Statistics {
	if persisted.commandCount.Valid {
		current.CommandCount = persisted.commandCount.Int64
	}
	if persisted.lastCommandAt.Valid {
		current.LastCommandAt = persisted.lastCommandAt.Int64
	}
	if persisted.onlineSeconds.Valid {
		current.OnlineSeconds = persisted.onlineSeconds.Int64
	}
	return current
}

func legacyEndpointRecords(ctx context.Context, diceID string, serveData []byte, endpointStatistics map[string]legacyEndpointDatabaseStatistics) ([]SourceRecord, error) {
	var document legacyEndpointDocument
	if err := yaml.Unmarshal(serveData, &document); err != nil {
		return nil, fmt.Errorf("legacy endpoints: %w", err)
	}
	descriptors := make(map[adapterapi.AdapterKey]adapterapi.Descriptor)
	for _, descriptor := range dice.NewAdapterDescriptors() {
		descriptors[descriptor.Key()] = descriptor
	}
	var records []SourceRecord
	for _, legacy := range document.IMSession.EndPoints {
		endpointID, err := adapterapi.NewEndpointID(strings.TrimSpace(legacy.BaseInfo.ID))
		if err != nil {
			if legacy.BaseInfo.Platform == "UI" && len(legacy.Adapter) == 0 {
				continue
			}
			return nil, fmt.Errorf("legacy endpoint %q: %w", legacy.BaseInfo.ID, err)
		}
		key, raw, secrets, err := legacyEndpointConfig(diceID, endpointID, legacy.BaseInfo.Platform, legacy.BaseInfo.ProtocolType, legacy.BaseInfo.UserID, legacy.Adapter)
		if err != nil {
			clearSensitiveSourceRecords(records)
			return nil, fmt.Errorf("legacy endpoint %q: %w", endpointID, err)
		}
		descriptor := descriptors[key]
		if descriptor == nil {
			clearSensitiveSourceRecords(records)
			return nil, &UnsupportedPreflightError{Feature: "legacy endpoint adapter " + string(key)}
		}
		config, err := descriptor.ValidateConfig(ctx, raw)
		if err != nil {
			clearSensitiveSourceRecords(records)
			return nil, fmt.Errorf("legacy endpoint %q configuration: %w", endpointID, err)
		}
		records = append(records, secrets...)
		var providerID adapterapi.PrincipalID
		if legacyID := strings.TrimSpace(legacy.BaseInfo.UserID); legacyID != "" {
			providerID, err = adapterapi.NewPrincipalID(legacyID)
			if err != nil {
				clearSensitiveSourceRecords(records)
				return nil, fmt.Errorf("legacy endpoint %q identity: %w", endpointID, err)
			}
		}
		statistics := endpoint.Statistics{
			GroupCount: legacy.BaseInfo.GroupNum, CommandCount: legacy.BaseInfo.CmdExecutedNum,
			LastCommandAt: legacy.BaseInfo.CmdExecutedLastTime, OnlineSeconds: legacy.BaseInfo.OnlineTotalTime,
		}
		if persisted, ok := endpointStatistics[strings.TrimSpace(legacy.BaseInfo.UserID)]; ok {
			statistics = applyLegacyEndpointDatabaseStatistics(statistics, persisted)
		}
		state := endpoint.State{}
		create, err := endpoint.Decide(state, endpoint.Command{
			Kind: endpoint.CommandCreate, CommandID: "legacy-create-" + string(endpointID),
			CorrelationID: "legacy-import-" + diceID, EndpointID: endpointID,
			DisplayName: strings.TrimSpace(legacy.BaseInfo.Nickname), ProviderID: providerID,
			Statistics: statistics, AdapterKey: key, Config: config,
		})
		if err != nil {
			return nil, err
		}
		events := append([]endpoint.Event(nil), create.Events...)
		for _, event := range create.Events {
			state, err = endpoint.Apply(state, event)
			if err != nil {
				return nil, err
			}
		}
		if legacy.BaseInfo.Enable {
			enable, decideErr := endpoint.Decide(state, endpoint.Command{
				Kind: endpoint.CommandEnable, CommandID: "legacy-enable-" + string(endpointID),
				CorrelationID: "legacy-import-" + diceID,
			})
			if decideErr != nil {
				return nil, decideErr
			}
			events = append(events, enable.Events...)
			for _, event := range enable.Events {
				state, err = endpoint.Apply(state, event)
				if err != nil {
					return nil, err
				}
			}
			completed, decideErr := endpoint.Decide(state, endpoint.Command{
				Kind: endpoint.CommandComplete, CommandID: "legacy-complete-" + string(endpointID),
				CorrelationID: "legacy-import-" + diceID, OperationID: state.OperationID,
				Generation: state.Generation, DesiredVersion: state.DesiredVersion,
				ObservedState: adapterapi.ObservedStateStopped, CompletionState: endpoint.OperationStateSucceeded,
			})
			if decideErr != nil {
				return nil, decideErr
			}
			events = append(events, completed.Events...)
		}
		stream := eventstore.StreamID{AggregateType: endpoint.EndpointAggregateType, AggregateID: string(endpointID)}
		for index, event := range events {
			payload, marshalErr := json.Marshal(event)
			if marshalErr != nil {
				return nil, marshalErr
			}
			record := legacyEventRecord(stream, string(event.Type), 1, uint64(index+1), payload)
			record.EventID = event.EventID
			record.CommandID = event.CommandID
			record.CorrelationID = event.CorrelationID
			records = append(records, record)
		}
	}
	return records, nil
}

func legacyEndpointAdapterKey(platform, protocol string, source map[string]any) (adapterapi.AdapterKey, error) {
	keyName := strings.ToLower(strings.TrimSpace(protocol))
	if keyName == "" {
		switch strings.ToLower(strings.TrimSpace(platform)) {
		case "discord":
			keyName = string(dice.DiscordAdapterKey)
		case "kook":
			keyName = string(dice.KookAdapterKey)
		case "tg", "telegram":
			keyName = string(dice.TelegramAdapterKey)
		case "slack":
			keyName = string(dice.SlackAdapterKey)
		case "dodo":
			keyName = string(dice.DodoAdapterKey)
		case "dingtalk":
			keyName = string(dice.DingTalkAdapterKey)
		case "mc", "minecraft":
			keyName = string(dice.MinecraftAdapterKey)
		case "sealchat", "seal-chat":
			keyName = string(dice.SealChatAdapterKey)
		default:
			return "", &UnsupportedPreflightError{Feature: "legacy endpoint platform " + strings.TrimSpace(platform)}
		}
	}
	switch keyName {
	case "onebot":
		keyName = string(dice.GocqAdapterKey)
		mode := strings.ToLower(legacyString(source["builtinMode"]))
		implementation := strings.ToLower(legacyString(source["implementation"]))
		if mode == "lagrange" || strings.Contains(implementation, "lagrange") {
			keyName = string(dice.LagrangeAdapterKey)
		}
	case "walle-q":
		keyName = string(dice.WalleQAdapterKey)
	case "official", "qqguild":
		keyName = string(dice.OfficialQQAdapterKey)
	}
	key, err := adapterapi.NewAdapterKey(keyName)
	if err != nil {
		return "", &UnsupportedPreflightError{Feature: "legacy endpoint protocol " + strings.TrimSpace(protocol)}
	}
	return key, nil
}

func legacyEndpointConfig(diceID string, endpointID adapterapi.EndpointID, platform, protocol, accountHint string, source map[string]any) (adapterapi.AdapterKey, []byte, []SourceRecord, error) {
	key, err := legacyEndpointAdapterKey(platform, protocol, source)
	if err != nil {
		return "", nil, nil, err
	}

	target := make(map[string]any)
	var allowed []string
	defaults := map[string]any{}
	secretFields := []string{}
	switch key {
	case dice.GocqAdapterKey, dice.LagrangeAdapterKey:
		allowed = []string{"connectUrl", "url", "insecureSkipVerify", "friendRequestPolicy", "ignoreFriendRequest", "ignore_friend_request", "accountHint", "imageAssetBaseUrl", "useInPackGoCqhttp", "builtinMode", "isReverse", "reverseAddr"}
		secretFields = []string{"token", "accessToken"}
	case dice.OnebotAdapterKey:
		allowed = []string{"mode", "url", "clientUrl", "connectUrl", "listenAddress", "reverseUrl", "reverseSuffix", "accountHint", "friendRequestPolicy", "ignoreFriendRequest", "ignore_friend_request", "imageAssetBaseUrl", "insecureSkipVerify"}
		secretFields = []string{"token"}
	case dice.WalleQAdapterKey:
		allowed = []string{"connectUrl", "url", "useInPackWalleQ", "insecureSkipVerify"}
	case dice.OfficialQQAdapterKey:
		allowed = []string{"appId", "appID", "accountHint", "onlyQQGuild"}
		secretFields = []string{"appSecret", "token"}
	case dice.SatoriAdapterKey:
		allowed = []string{"version", "platform", "host", "port"}
		secretFields = []string{"token"}
	case dice.MilkyAdapterKey:
		allowed = []string{"version", "ws_gateway", "rest_gateway", "built_in_mode", "ignore_friend_request"}
		secretFields = []string{"token"}
	case dice.RedAdapterKey:
		allowed = []string{"version", "device", "protocol", "appId", "host", "port", "redVersion"}
		defaults["version"] = "1"
		secretFields = []string{"token"}
	case dice.DiscordAdapterKey:
		allowed = []string{"version", "guild", "channel", "proxyURL", "reverseProxyUrl", "reverseProxyCDNUrl"}
		defaults["version"] = "1"
		secretFields = []string{"token"}
	case dice.KookAdapterKey:
		allowed = []string{"version", "guild", "channel", "apiBaseURL"}
		defaults["version"] = "1"
		secretFields = []string{"token"}
	case dice.TelegramAdapterKey:
		allowed = []string{"chatId", "webhookUrl", "proxyURL", "apiBaseURL"}
		secretFields = []string{"token"}
	case dice.SlackAdapterKey:
		allowed = []string{"version", "channel", "apiBaseURL"}
		defaults["version"] = "1"
		secretFields = []string{"appToken", "botToken"}
	case dice.DodoAdapterKey:
		allowed = []string{"islandId", "botId", "clientID", "apiBaseURL"}
		secretFields = []string{"token"}
	case dice.DingTalkAdapterKey:
		allowed = []string{"clientId", "robotCode", "coolAppCode", "stream"}
		defaults["stream"] = true
		secretFields = []string{"token"}
	case dice.MinecraftAdapterKey:
		allowed = []string{"serverAddress", "username", "authMode", "connectUrl"}
	case dice.SealChatAdapterKey:
		allowed = []string{"version", "appId", "tenant", "connectUrl"}
		defaults["version"] = "1"
		secretFields = []string{"token"}
	case dice.HTTPAdapterKey:
		allowed = []string{"version", "url", "method", "path", "timeoutSeconds"}
		defaults["version"] = "1"
		secretFields = []string{"token"}
	default:
		return "", nil, nil, &UnsupportedPreflightError{Feature: "legacy endpoint adapter " + string(key)}
	}
	for name, value := range defaults {
		target[name] = value
	}
	if key == dice.DingTalkAdapterKey {
		if value, ok := source["clientID"]; ok {
			target["clientId"] = value
		}
	}
	for _, name := range allowed {
		if value, ok := source[name]; ok {
			target[name] = value
		}
	}
	if accountHint = strings.TrimSpace(accountHint); accountHint != "" {
		switch key {
		case dice.GocqAdapterKey, dice.LagrangeAdapterKey, dice.OnebotAdapterKey, dice.OfficialQQAdapterKey:
			target["accountHint"] = accountHint
		case dice.MilkyAdapterKey:
			if strings.TrimSpace(legacyString(target["built_in_mode"])) != "" {
				target["account"] = accountHint
			}
		}
	}
	secrets := make([]SourceRecord, 0, len(secretFields))
	for _, name := range secretFields {
		plaintext := legacyString(source[name])
		if plaintext == "" {
			continue
		}
		ref := "vault:legacy-" + safeLegacyID(diceID) + "-endpoint-" + safeLegacyID(string(endpointID)) + "-" + strings.ToLower(name)
		target[name] = map[string]any{"secretRef": ref, "version": uint64(1)}
		secrets = append(secrets, sensitiveLegacyRecord(string(key), ref, string(endpointID), []byte(plaintext)))
	}
	raw, err := json.Marshal(target)
	if err != nil {
		clearSensitiveSourceRecords(secrets)
		return "", nil, nil, err
	}
	return key, raw, secrets, nil
}

func legacyString(value any) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return ""
	}
}

func streamLegacySQLite(ctx context.Context, path, diceID string, yield func([]SourceRecord) error) error {
	return streamLegacySQLiteWithKeySource(ctx, path, diceID, nil, yield)
}

func streamLegacySQLiteWithKeySource(ctx context.Context, path, diceID string, keySource eventstore.KeySource, yield func([]SourceRecord) error) (streamErr error) {
	if yield == nil {
		return ErrValidation
	}
	root, err := openLegacySourceRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, root.Close()) }()
	database, cleanup, err := openLegacySQLiteSnapshotReader(ctx, root, path)
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, cleanup()) }()
	return streamLegacySQLiteDatabase(ctx, database, diceID, keySource, yield)
}

func streamLegacySQLiteDatabase(ctx context.Context, database *sql.DB, diceID string, keySource eventstore.KeySource, yield func([]SourceRecord) error) error {
	if database == nil || yield == nil {
		return ErrValidation
	}
	if err := validateLegacySQLiteSchema(ctx, database); err != nil {
		return err
	}
	batcher := sourceRecordBatcher{yield: yield}
	if err := streamLegacyGroups(ctx, database, diceID, &batcher); err != nil {
		return fmt.Errorf("legacy group_info: %w", err)
	}
	if err := streamLegacyPlayers(ctx, database, diceID, &batcher); err != nil {
		return fmt.Errorf("legacy group_player_info: %w", err)
	}
	if err := streamLegacyAttrs(ctx, database, diceID, &batcher); err != nil {
		return fmt.Errorf("legacy attrs: %w", err)
	}
	if err := streamLegacyBans(ctx, database, diceID, keySource, &batcher); err != nil {
		return fmt.Errorf("legacy ban_info: %w", err)
	}
	return batcher.flush()
}

// openLegacySQLiteSnapshotReader uses a query-only connection on a private
// writable copy so SQLite can rebuild volatile WAL-index locks without
// changing the source or snapshot. legacyMetadata still hashes every original
// main/WAL/SHM byte.
func openLegacySQLiteSnapshotReader(ctx context.Context, root *legacySourceRoot, path string) (*sql.DB, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "eventsourcing-legacy-sqlite-reader-")
	if err != nil {
		return nil, nil, err
	}
	removeScratch := func() error { return os.RemoveAll(dir) }
	if err = copySQLiteFilesFromLegacyRoot(ctx, root, path, dir); err != nil {
		return nil, nil, errors.Join(err, removeScratch())
	}
	scratchPath := filepath.Join(dir, filepath.Base(path))
	// SHM is a rebuildable WAL-index containing volatile lock bytes. Exclude
	// only this private copy; the original SHM remains inventoried and hashed.
	if err = os.Remove(scratchPath + "-shm"); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, nil, errors.Join(err, removeScratch())
	}
	database, err := sql.Open("sqlite", "file:"+filepath.ToSlash(scratchPath)+"?mode=rw&_pragma=query_only(1)")
	if err != nil {
		return nil, nil, errors.Join(err, removeScratch())
	}
	database.SetMaxOpenConns(1)
	if err = database.PingContext(ctx); err != nil {
		return nil, nil, errors.Join(err, database.Close(), removeScratch())
	}
	cleanup := func() error { return errors.Join(database.Close(), removeScratch()) }
	return database, cleanup, nil
}

func validateLegacySQLiteSchema(ctx context.Context, database *sql.DB) error {
	required := map[string][]string{
		"group_info":        {"id", "created_at", "data"},
		"group_player_info": {"name", "user_id", "last_command_time", "auto_set_name_template", "dice_side_num", "group_id"},
		"attrs":             {"id", "data", "attrs_type", "binding_sheet_id", "name", "owner_id", "sheet_type", "is_hidden", "created_at", "updated_at"},
		"ban_info":          {"id", "data"},
	}
	tables := make([]string, 0, len(required))
	for table := range required {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	var missing []string
	for _, table := range tables {
		columns := make(map[string]struct{}, len(required[table]))
		if err := func() (resultErr error) {
			rows, err := database.QueryContext(ctx, "SELECT name FROM pragma_table_info(?)", table)
			if err != nil {
				return err
			}
			defer func() { resultErr = errors.Join(resultErr, rows.Close()) }()
			for rows.Next() {
				var column string
				if err := rows.Scan(&column); err != nil {
					return err
				}
				columns[column] = struct{}{}
			}
			return rows.Err()
		}(); err != nil {
			return err
		}
		for _, column := range required[table] {
			if _, ok := columns[column]; !ok {
				missing = append(missing, table+"."+column)
			}
		}
	}
	if len(missing) != 0 {
		return &UnsupportedPreflightError{Feature: "legacy SQLite schema missing " + strings.Join(missing, ", ")}
	}
	return nil
}

type sourceRecordBatcher struct {
	records []SourceRecord
	bytes   uint64
	yield   func([]SourceRecord) error
}

func (b *sourceRecordBatcher) add(records ...SourceRecord) error {
	for _, record := range records {
		if record.Size > MaxBatchBytes {
			return ErrBatchLimit
		}
		if len(b.records) != 0 && (len(b.records) >= MaxBatchRecords || b.bytes > MaxBatchBytes-record.Size) {
			if err := b.flush(); err != nil {
				return err
			}
		}
		b.records = append(b.records, record)
		b.bytes += record.Size
	}
	return nil
}

func (b *sourceRecordBatcher) flush() error {
	if len(b.records) == 0 {
		return nil
	}
	if err := b.yield(b.records); err != nil {
		return err
	}
	b.records = make([]SourceRecord, 0, MaxBatchRecords)
	b.bytes = 0
	return nil
}

func legacyBanRecords(ctx context.Context, diceID string, keySource eventstore.KeySource, row legacyBanRow) ([]SourceRecord, error) {
	var item dice.BanListInfoItem
	if err := json.Unmarshal(row.Data, &item); err != nil {
		return nil, fmt.Errorf("legacy ban %q: %w", row.ID, err)
	}
	if item.ID == "" {
		item.ID = row.ID
	}
	item.BanUpdatedAt = row.BanUpdatedAt
	reason, err := json.Marshal(struct {
		Times   []int64  `json:"times"`
		Reasons []string `json:"reasons"`
		Places  []string `json:"places"`
	}{item.Times, item.Reasons, item.Places})
	if err != nil {
		return nil, err
	}
	event := playerstate.NewModerationCreatedV1(diceID, "global", item.ID, int(item.Rank), item.Score)
	payload, err := playerstate.MarshalModerationEvent(event)
	if err != nil {
		return nil, err
	}
	stream := playerstate.ModerationStream(diceID, "global", item.ID)
	records := []SourceRecord{legacyEventRecord(stream, string(event.EventType()), playerstate.EventSchemaVersion, 1, payload)}
	if len(reason) != 0 {
		digest, digestErr := legacyModerationReasonDigest(ctx, keySource, reason)
		if digestErr != nil {
			return nil, digestErr
		}
		changed := playerstate.NewModerationScoreChangedV1(item.Score, digest)
		payload, err = playerstate.MarshalModerationEvent(changed)
		if err != nil {
			return nil, err
		}
		records = append(records, legacyEventRecord(stream, string(changed.EventType()), playerstate.EventSchemaVersion, 2, payload))
	}
	details, err := json.Marshal(struct {
		dice.BanListInfoItem
		BanUpdatedAt int64 `json:"banUpdatedAt"`
	}{BanListInfoItem: item, BanUpdatedAt: row.BanUpdatedAt})
	if err != nil {
		return nil, err
	}
	detailsRef, err := moderationDetailsSecretRef(diceID, item.ID)
	if err != nil {
		return nil, err
	}
	records = append(records, sensitiveLegacyRecord("moderation", detailsRef, "moderation-details", details))
	return records, nil
}

func moderationDetailsSecretRef(diceID, subjectID string) (string, error) {
	stream := playerstate.ModerationStream(diceID, "global", subjectID)
	if stream.AggregateID == "" {
		return "", playerstate.ErrInvalidIdentity
	}
	digest := sha256.Sum256([]byte(stream.AggregateID))
	return "vault:moderation-details:" + hex.EncodeToString(digest[:16]), nil
}

func legacyModerationReasonDigest(ctx context.Context, keySource eventstore.KeySource, reason []byte) (string, error) {
	if keySource == nil {
		return "", eventstore.ErrKeySourceUnavailable
	}
	key, err := keySource.IndexRootMaterial(ctx)
	if err != nil || len(key) < sha256.Size {
		clear(key)
		return "", eventstore.ErrKeySourceUnavailable
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("legacy-moderation-reason/v1\x00"))
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(reason)))
	_, _ = mac.Write(length[:])
	_, _ = mac.Write(reason)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func legacyGroupRecords(diceID string, group *dice.GroupInfo, createdAt int64) ([]SourceRecord, error) {
	enteredAt := group.EnteredTime
	if enteredAt == 0 {
		enteredAt = createdAt
	}
	events := []groupstate.TypedEvent{groupstate.NewGroupCreatedWithInviteV1(diceID, group.GroupID, group.GroupName, group.InviteUserID, enteredAt)}
	if group.GuildID != "" || group.ChannelID != "" {
		events = append(events, groupstate.NewGroupIdentityChangedV1(group.GuildID, group.ChannelID))
	}
	active := legacyBoolMap(group.DiceIDActiveMap)
	exists := legacyBoolMap(group.DiceIDExistsMap)
	keys := unionLegacyKeys(active, exists)
	for _, key := range keys {
		events = append(events, groupstate.NewGroupActivationChangedV1(key, active[key], exists[key]))
	}
	for _, ext := range group.GetActivatedExtListRaw() {
		if ext != nil && strings.TrimSpace(ext.Name) != "" {
			events = append(events, groupstate.NewGroupExtensionChangedV1(ext.Name, true))
		}
	}
	inactive := make([]string, 0, len(group.InactivatedExtSet))
	for name := range group.InactivatedExtSet {
		inactive = append(inactive, name)
	}
	sort.Strings(inactive)
	for _, name := range inactive {
		events = append(events, groupstate.NewGroupExtensionChangedV1(name, false))
	}
	if group.System != "" {
		events = append(events, groupstate.NewGroupSystemChangedV1(group.System))
	}
	if group.DiceSideNum != 0 || group.DiceSideExpr != "" || group.RollShaperMode != "" || group.CocRuleIndex != 0 {
		events = append(events, groupstate.NewGroupTemplateWithCocRuleV1(group.DiceSideNum, group.DiceSideExpr, group.RollShaperMode, group.CocRuleIndex))
	}
	if group.DefaultHelpGroup != "" || len(group.HelpPackages) != 0 {
		events = append(events, groupstate.NewGroupHelpChangedV1(group.DefaultHelpGroup, group.HelpPackages))
	}
	if group.ShowGroupWelcome || group.GroupWelcomeMessage != "" {
		events = append(events, groupstate.NewGroupWelcomeChangedV1(group.ShowGroupWelcome, group.GroupWelcomeMessage))
	}
	bots := legacyBoolMap(group.BotList)
	for _, key := range sortedLegacyBoolKeys(bots) {
		events = append(events, groupstate.NewGroupBotListChangedV1(key, bots[key]))
	}
	stream := groupstate.GroupStream(diceID, group.GroupID)
	records := make([]SourceRecord, 0, len(events))
	for index, event := range events {
		payload, err := groupstate.MarshalTypedEvent(event)
		if err != nil {
			return nil, err
		}
		records = append(records, legacyEventRecord(stream, string(event.EventType()), groupstate.GroupEventSchemaVersion, uint64(index+1), payload))
	}
	return records, nil
}

func legacyPlayerRecords(diceID string, player legacyPlayerRow) ([]SourceRecord, error) {
	if player.GroupID == "" || player.UserID == "" {
		return nil, ErrValidation
	}
	events := []playerstate.PlayerEvent{playerstate.NewPlayerCreatedV1(diceID, player.GroupID, player.UserID, player.Name)}
	if player.AutoSetNameTemplate != "" {
		events = append(events, playerstate.NewPlayerAutoSetNameTemplateChangedV1(player.AutoSetNameTemplate))
	}
	if player.DiceSideNum != 0 {
		events = append(events, playerstate.NewPlayerDiceSideChangedV1(int64(player.DiceSideNum)))
	}
	if player.LastCommandTime != 0 {
		events = append(events, playerstate.NewPlayerLastCommandChangedV1(player.LastCommandTime))
	}
	stream := playerstate.PlayerStream(diceID, player.GroupID, player.UserID)
	records := make([]SourceRecord, 0, len(events))
	for index, event := range events {
		payload, err := playerstate.MarshalPlayerEvent(event)
		if err != nil {
			return nil, err
		}
		records = append(records, legacyEventRecord(stream, string(event.EventType()), playerstate.EventSchemaVersion, uint64(index+1), payload))
	}
	return records, nil
}

func legacyAttrsRecords(diceID string, row legacyAttrsRow) ([]SourceRecord, error) {
	if len(row.Data) == 0 {
		return nil, fmt.Errorf("legacy attrs %q has no serialized dictionary: %w", row.ID, ErrValidation)
	}
	value, err := ds.VMValueFromJSON(row.Data)
	if err != nil {
		return nil, fmt.Errorf("legacy attrs %q: %w", row.ID, err)
	}
	dict, ok := value.ReadDictData()
	if !ok {
		return nil, fmt.Errorf("legacy attrs %q: %w", row.ID, ErrValidation)
	}
	if strings.TrimSpace(row.ID) == "" {
		metadataEmpty := strings.TrimSpace(row.AttrsType) == "" && strings.TrimSpace(row.BindingSheetID) == "" &&
			strings.TrimSpace(row.Name) == "" && strings.TrimSpace(row.OwnerID) == "" && strings.TrimSpace(row.SheetType) == ""
		if row.Hidden && metadataEmpty && (dict.Dict == nil || dict.Dict.Length() == 0) {
			// Older binding failures could leave an unreachable hidden row with
			// no identity, metadata, or values. It has no semantic state to import.
			return nil, nil
		}
		return nil, fmt.Errorf("legacy attrs %q has semantic state but no identity: %w", row.ID, ErrValidation)
	}
	refDigest := sha256.Sum256([]byte(diceID + "\x00" + row.ID))
	secretRef := "vault:legacy-attrs-" + hex.EncodeToString(refDigest[:16])
	state := attributestate.State{
		DiceID: diceID, ID: row.ID, AttrsType: row.AttrsType, BindingSheetID: row.BindingSheetID,
		Name: row.Name, OwnerID: row.OwnerID, SheetType: row.SheetType, Hidden: row.Hidden,
		SecretRef: secretRef, SecretVersion: 1, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt,
	}
	event := attributestate.NewBaselineImportedV1(state)
	payload, err := attributestate.MarshalBaselineImportedV1(event)
	if err != nil {
		return nil, err
	}
	return []SourceRecord{
		sensitiveLegacyRecord("attributes", secretRef, row.ID, append([]byte(nil), row.Data...)),
		legacyEventRecord(attributestate.Stream(diceID, row.ID), attributestate.EventBaselineImported, attributestate.EventSchemaVersion, 1, payload),
	}, nil
}

func streamLegacyGroups(ctx context.Context, database *sql.DB, diceID string, batcher *sourceRecordBatcher) (streamErr error) {
	rows, err := database.QueryContext(ctx, "SELECT id, COALESCE(created_at, 0), data FROM group_info ORDER BY id")
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, rows.Close()) }()
	for rows.Next() {
		var row legacyGroupRow
		if err = rows.Scan(&row.ID, &row.CreatedAt, &row.Data); err != nil {
			return err
		}
		var group dice.GroupInfo
		if err = json.Unmarshal(row.Data, &group); err != nil {
			return fmt.Errorf("legacy group %q: %w", row.ID, err)
		}
		if group.GroupID == "" {
			group.GroupID = row.ID
		}
		records, convertErr := legacyGroupRecords(diceID, &group, row.CreatedAt)
		if convertErr != nil {
			return fmt.Errorf("legacy group %q: %w", row.ID, convertErr)
		}
		if err = batcher.add(records...); err != nil {
			return err
		}
	}
	return rows.Err()
}

func streamLegacyPlayers(ctx context.Context, database *sql.DB, diceID string, batcher *sourceRecordBatcher) (streamErr error) {
	rows, err := database.QueryContext(ctx, "SELECT COALESCE(name, ''), COALESCE(user_id, ''), COALESCE(last_command_time, 0), COALESCE(auto_set_name_template, ''), COALESCE(dice_side_num, 0), COALESCE(group_id, '') FROM group_player_info ORDER BY group_id, user_id")
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, rows.Close()) }()
	for rows.Next() {
		var row legacyPlayerRow
		if err = rows.Scan(&row.Name, &row.UserID, &row.LastCommandTime, &row.AutoSetNameTemplate, &row.DiceSideNum, &row.GroupID); err != nil {
			return err
		}
		records, convertErr := legacyPlayerRecords(diceID, row)
		if convertErr != nil {
			return fmt.Errorf("legacy player group=%q user=%q: %w", row.GroupID, row.UserID, convertErr)
		}
		if err = batcher.add(records...); err != nil {
			return err
		}
	}
	return rows.Err()
}

func streamLegacyAttrs(ctx context.Context, database *sql.DB, diceID string, batcher *sourceRecordBatcher) (streamErr error) {
	rows, err := database.QueryContext(ctx, `SELECT id, data, COALESCE(attrs_type, ''), COALESCE(binding_sheet_id, ''), COALESCE(name, ''), COALESCE(owner_id, ''), COALESCE(sheet_type, ''), COALESCE(is_hidden, false), COALESCE(created_at, 0), COALESCE(updated_at, 0) FROM attrs ORDER BY id`)
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, rows.Close()) }()
	for rows.Next() {
		var row legacyAttrsRow
		if err = rows.Scan(&row.ID, &row.Data, &row.AttrsType, &row.BindingSheetID, &row.Name, &row.OwnerID, &row.SheetType, &row.Hidden, &row.CreatedAt, &row.UpdatedAt); err != nil {
			return err
		}
		records, convertErr := legacyAttrsRecords(diceID, row)
		if convertErr != nil {
			return fmt.Errorf("legacy attrs %q: %w", row.ID, convertErr)
		}
		if err = batcher.add(records...); err != nil {
			return err
		}
	}
	return rows.Err()
}

func streamLegacyBans(ctx context.Context, database *sql.DB, diceID string, keySource eventstore.KeySource, batcher *sourceRecordBatcher) (streamErr error) {
	query := "SELECT id, COALESCE(ban_updated_at, 0), data FROM ban_info ORDER BY id"
	probe, probeErr := database.QueryContext(ctx, "SELECT ban_updated_at FROM ban_info WHERE 1=0")
	if probeErr != nil {
		if !isMissingBanUpdatedAtColumn(probeErr) {
			return probeErr
		}
		query = "SELECT id, data FROM ban_info ORDER BY id"
	} else {
		probeErr = func() (checkErr error) {
			defer func() { checkErr = errors.Join(checkErr, probe.Close()) }()
			return probe.Err()
		}()
		if probeErr != nil {
			return probeErr
		}
	}
	rows, err := database.QueryContext(ctx, query)
	if err != nil {
		return err
	}
	defer func() { streamErr = errors.Join(streamErr, rows.Close()) }()
	for rows.Next() {
		var row legacyBanRow
		if query == "SELECT id, data FROM ban_info ORDER BY id" {
			err = rows.Scan(&row.ID, &row.Data)
		} else {
			err = rows.Scan(&row.ID, &row.BanUpdatedAt, &row.Data)
		}
		if err != nil {
			return err
		}
		records, convertErr := legacyBanRecords(ctx, diceID, keySource, row)
		if convertErr != nil {
			return fmt.Errorf("legacy ban %q: %w", row.ID, convertErr)
		}
		if err = batcher.add(records...); err != nil {
			return err
		}
	}
	return rows.Err()
}

func streamLegacyPluginStores(ctx context.Context, root *legacySourceRoot, dataDir string, yield func([]SourceRecord) error) error {
	if yield == nil {
		return ErrValidation
	}
	extensionsDir := filepath.Join(dataDir, "extensions")
	entries, err := root.ReadDir(extensionsDir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	batcher := sourceRecordBatcher{yield: yield}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		path := filepath.Join(extensionsDir, entry.Name(), "storage.db")
		if _, statErr := root.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
			continue
		} else if statErr != nil {
			return statErr
		}
		temporaryDir, tempErr := os.MkdirTemp("", "scardice-legacy-bunt-")
		if tempErr != nil {
			return tempErr
		}
		temporaryPath := filepath.Join(temporaryDir, "storage.db")
		if tempErr = copyLegacyFileAt(ctx, root, path, temporaryPath); tempErr != nil {
			_ = os.RemoveAll(temporaryDir)
			return tempErr
		}
		database, openErr := buntdb.Open(temporaryPath)
		if openErr != nil {
			_ = os.RemoveAll(temporaryDir)
			return openErr
		}
		var batchErr error
		viewErr := database.View(func(transaction *buntdb.Tx) error {
			return transaction.Ascend("", func(key, value string) bool {
				if batchErr = ctx.Err(); batchErr != nil {
					return false
				}
				batchErr = batcher.add(SourceRecord{
					RecordType: RecordTypePluginKV, Domain: entry.Name(), Identity: key,
					Kind: entry.Name(), SchemaVersion: 1, Version: 1, Sensitive: true,
					Payload: []byte(value), Size: uint64(len(value)),
				})
				return batchErr == nil
			})
		})
		closeErr := database.Close()
		removeErr := os.RemoveAll(temporaryDir)
		if batchErr != nil || viewErr != nil || closeErr != nil || removeErr != nil {
			return errors.Join(batchErr, viewErr, closeErr, removeErr)
		}
	}
	return batcher.flush()
}

func legacyMetadataWithRoot(ctx context.Context, root *legacySourceRoot, paths []string) (SourceMetadata, error) {
	metadata := SourceMetadata{Files: make([]FileMetadata, 0, len(paths))}
	hash := sha256.New()
	var total int64
	for _, path := range paths {
		relative, err := root.relative(path)
		if err != nil || relative == "." {
			return SourceMetadata{}, ErrSourceMutation
		}
		file, err := root.Open(path)
		if err != nil {
			return SourceMetadata{}, err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > MaxSnapshotFileBytes {
			_ = file.Close()
			return SourceMetadata{}, ErrSourceMutation
		}
		digest := sha256.New()
		size, copyErr := io.Copy(digest, io.LimitReader(file, MaxSnapshotFileBytes+1))
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil {
			return SourceMetadata{}, errors.Join(copyErr, closeErr)
		}
		if size > MaxSnapshotFileBytes {
			return SourceMetadata{}, ErrBatchLimit
		}
		var sum [sha256.Size]byte
		copy(sum[:], digest.Sum(nil))
		entry := FileMetadata{
			Name: filepath.ToSlash(relative), Size: size, Mode: info.Mode(),
			ModTimeUnixNano: info.ModTime().UnixNano(), Digest: sum,
		}
		total += size
		if total > MaxSnapshotBytes {
			return SourceMetadata{}, ErrBatchLimit
		}
		metadata.Files = append(metadata.Files, entry)
		_, _ = fmt.Fprintf(hash, "%s\x00%d\x00%x\x00", entry.Name, entry.Size, entry.Digest)
	}
	metadata.Identity = "legacy-" + hex.EncodeToString(hash.Sum(nil))
	return metadata, nil
}

func copyLegacyFileAt(ctx context.Context, root *legacySourceRoot, source, destination string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := root.ReadFile(source)
	if err != nil {
		return err
	}
	if int64(len(data)) > MaxSnapshotFileBytes {
		return ErrBatchLimit
	}
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, SnapshotFileMode)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}

func legacyEventRecord(stream eventstore.StreamID, kind string, schema uint16, version uint64, payload []byte) SourceRecord {
	digest := sha256.Sum256(payload)
	return SourceRecord{
		RecordType: RecordTypeEvent, Domain: stream.AggregateType, Identity: stream.AggregateID,
		Kind: kind, SchemaVersion: schema, Version: version, Payload: payload,
		ContentDigest: digest[:], Size: uint64(len(payload)),
	}
}

func sensitiveLegacyRecord(domain, identity, kind string, payload []byte) SourceRecord {
	return SourceRecord{
		RecordType: RecordTypeSecret, Domain: domain, Identity: identity, Kind: kind,
		SchemaVersion: 1, Version: 1, Sensitive: true, Payload: payload, Size: uint64(len(payload)),
	}
}

func safeLegacyID(value string) string {
	value = strings.Map(func(character rune) rune {
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || character == '-' || character == '_' {
			return character
		}
		return '-'
	}, value)
	return strings.Trim(value, "-")
}

func legacyBoolMap(value *dice.SyncMap[string, bool]) map[string]bool {
	result := map[string]bool{}
	if value != nil {
		value.Range(func(key string, enabled bool) bool {
			result[key] = enabled
			return true
		})
	}
	return result
}

func unionLegacyKeys(first, second map[string]bool) []string {
	keys := make(map[string]struct{}, len(first)+len(second))
	for key := range first {
		keys[key] = struct{}{}
	}
	for key := range second {
		keys[key] = struct{}{}
	}
	result := make([]string, 0, len(keys))
	for key := range keys {
		result = append(result, key)
	}
	sort.Strings(result)
	return result
}

func sortedLegacyBoolKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

var _ Source = (*LegacySource)(nil)
