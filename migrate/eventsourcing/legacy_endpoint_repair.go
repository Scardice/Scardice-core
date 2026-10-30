package eventsourcing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"

	"gopkg.in/yaml.v3"
)

const legacyEndpointMetadataRepairVersion = "v1"

type legacyEndpointMetadata struct {
	displayName string
	providerID  adapterapi.PrincipalID
	statistics  endpoint.Statistics
}

// RepairLegacyEndpointMetadata appends one idempotent fact for endpoint streams
// produced by the early importer that omitted account metadata. Existing
// non-empty aggregate fields always win over the legacy source.
func RepairLegacyEndpointMetadata(ctx context.Context, sourceRoot string, service *endpoint.Service) (repaired int, repairErr error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if service == nil || service.Repository == nil {
		return 0, ErrValidation
	}
	views, err := service.List(ctx)
	if err != nil {
		return 0, fmt.Errorf("list endpoint projections: %w", err)
	}
	candidates := make([]endpoint.EndpointView, 0)
	for _, view := range views {
		if view.DesiredState != endpoint.DesiredStateDeleted && strings.TrimSpace(view.DisplayName) == "" {
			candidates = append(candidates, view)
		}
	}
	if len(candidates) == 0 {
		return 0, nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].EndpointID < candidates[j].EndpointID })

	root, err := openLegacySourceRoot(sourceRoot)
	if err != nil {
		return 0, err
	}
	defer func() { repairErr = errors.Join(repairErr, root.Close()) }()
	source := NewLegacySource(sourceRoot)
	instances, _, err := source.layoutWithRoot(ctx, true, root)
	if err != nil {
		return 0, err
	}
	metadata := make(map[adapterapi.EndpointID]legacyEndpointMetadata)
	for _, instance := range instances {
		instanceMetadata, readErr := readLegacyEndpointRepairMetadata(ctx, root, instance)
		if readErr != nil {
			return 0, fmt.Errorf("legacy instance %q endpoint metadata: %w", instance.config.Name, readErr)
		}
		for endpointID, value := range instanceMetadata {
			if previous, exists := metadata[endpointID]; exists && previous != value {
				return 0, fmt.Errorf("legacy endpoint %q metadata conflict: %w", endpointID, ErrValidation)
			}
			metadata[endpointID] = value
		}
	}

	for _, candidate := range candidates {
		state, loadErr := service.Repository.Load(ctx, candidate.EndpointID)
		if loadErr != nil {
			return repaired, fmt.Errorf("load endpoint %q for legacy repair: %w", candidate.EndpointID, loadErr)
		}
		commandID := legacyEndpointMetadataRepairVersion + "-legacy-endpoint-metadata-" + string(candidate.EndpointID)
		if _, alreadyRepaired := state.ProcessedCommands[commandID]; alreadyRepaired {
			continue
		}
		legacy, exists := metadata[candidate.EndpointID]
		if !exists {
			continue
		}
		displayName := state.DisplayName
		if displayName == "" {
			displayName = legacy.displayName
		}
		providerID := state.ProviderID
		if providerID == "" {
			providerID = legacy.providerID
		}
		statistics := mergeMissingEndpointStatistics(state.Statistics, legacy.statistics)
		if _, executeErr := service.Execute(ctx, endpoint.Command{
			Kind: endpoint.CommandRestoreLegacyMetadata, CommandID: commandID,
			CorrelationID: legacyEndpointMetadataRepairVersion + "-legacy-endpoint-metadata",
			EndpointID:    candidate.EndpointID, ExpectedVersion: state.Version, ExpectedVersionSet: true,
			DisplayName: displayName, ProviderID: providerID, Statistics: statistics,
		}); executeErr != nil {
			return repaired, fmt.Errorf("repair endpoint %q legacy metadata: %w", candidate.EndpointID, executeErr)
		}
		repaired++
	}
	return repaired, nil
}

func readLegacyEndpointRepairMetadata(ctx context.Context, root *legacySourceRoot, instance legacyInstance) (map[adapterapi.EndpointID]legacyEndpointMetadata, error) {
	serveData, err := root.ReadFile(filepath.Join(instance.dir, "serve.yaml"))
	if err != nil {
		return nil, err
	}
	var document legacyEndpointDocument
	if err = yaml.Unmarshal(serveData, &document); err != nil {
		return nil, fmt.Errorf("legacy endpoints: %w", err)
	}
	database, cleanup, err := openLegacySQLiteMetadataReader(ctx, root, filepath.Join(instance.dir, "data.db"))
	if err != nil {
		return nil, err
	}
	persistedStatistics, queryErr := readLegacyEndpointStatistics(ctx, database)
	if cleanupErr := cleanup(); queryErr != nil || cleanupErr != nil {
		return nil, errors.Join(queryErr, cleanupErr)
	}

	metadata := make(map[adapterapi.EndpointID]legacyEndpointMetadata, len(document.IMSession.EndPoints))
	for _, legacy := range document.IMSession.EndPoints {
		endpointID, idErr := adapterapi.NewEndpointID(strings.TrimSpace(legacy.BaseInfo.ID))
		if idErr != nil {
			if legacy.BaseInfo.Platform == "UI" && len(legacy.Adapter) == 0 {
				continue
			}
			return nil, fmt.Errorf("legacy endpoint %q: %w", legacy.BaseInfo.ID, idErr)
		}
		var providerID adapterapi.PrincipalID
		if value := strings.TrimSpace(legacy.BaseInfo.UserID); value != "" {
			providerID, idErr = adapterapi.NewPrincipalID(value)
			if idErr != nil {
				return nil, fmt.Errorf("legacy endpoint %q identity: %w", endpointID, idErr)
			}
		}
		statistics := endpoint.Statistics{
			GroupCount: legacy.BaseInfo.GroupNum, CommandCount: legacy.BaseInfo.CmdExecutedNum,
			LastCommandAt: legacy.BaseInfo.CmdExecutedLastTime, OnlineSeconds: legacy.BaseInfo.OnlineTotalTime,
		}
		if persisted, ok := persistedStatistics[strings.TrimSpace(legacy.BaseInfo.UserID)]; ok {
			statistics = applyLegacyEndpointDatabaseStatistics(statistics, persisted)
		}
		if statistics.GroupCount < 0 || statistics.CommandCount < 0 || statistics.LastCommandAt < 0 || statistics.OnlineSeconds < 0 {
			return nil, fmt.Errorf("legacy endpoint %q statistics: %w", endpointID, ErrValidation)
		}
		value := legacyEndpointMetadata{
			displayName: strings.TrimSpace(legacy.BaseInfo.Nickname), providerID: providerID, statistics: statistics,
		}
		if previous, exists := metadata[endpointID]; exists && previous != value {
			return nil, fmt.Errorf("legacy endpoint %q metadata conflict: %w", endpointID, ErrValidation)
		}
		metadata[endpointID] = value
	}
	return metadata, nil
}

func mergeMissingEndpointStatistics(current, legacy endpoint.Statistics) endpoint.Statistics {
	if current.GroupCount == 0 {
		current.GroupCount = legacy.GroupCount
	}
	if current.CommandCount == 0 {
		current.CommandCount = legacy.CommandCount
	}
	if current.LastCommandAt == 0 {
		current.LastCommandAt = legacy.LastCommandAt
	}
	if current.OnlineSeconds == 0 {
		current.OnlineSeconds = legacy.OnlineSeconds
	}
	return current
}

// SQLite immutable mode is fast and cannot create journals. A live WAL needs
// the existing private-copy reader so committed WAL pages remain visible.
func openLegacySQLiteMetadataReader(ctx context.Context, root *legacySourceRoot, path string) (*sql.DB, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if root == nil {
		return nil, nil, ErrSourceRequired
	}
	if info, err := root.Lstat(path + "-wal"); err == nil {
		if !info.Mode().IsRegular() {
			return nil, nil, ErrSourceMutation
		}
		if info.Size() > 0 {
			return openLegacySQLiteSnapshotReader(ctx, root, path)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	info, err := root.Lstat(path)
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, ErrSourceMutation
	}
	canonical, err := root.canonicalPath(path)
	if err != nil {
		return nil, nil, err
	}
	location := (&url.URL{Scheme: "file", Path: filepath.ToSlash(canonical)}).String()
	database, err := sql.Open("sqlite", location+"?mode=ro&immutable=1")
	if err != nil {
		return nil, nil, err
	}
	database.SetMaxOpenConns(1)
	if err = database.PingContext(ctx); err != nil {
		return nil, nil, errors.Join(err, database.Close())
	}
	return database, database.Close, nil
}
