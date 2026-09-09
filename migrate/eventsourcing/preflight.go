package eventsourcing

import (
	"context"
	"strings"

	"Scardice-core/eventstore"
)

type Request struct { Mode Mode }

type PreflightDecision struct {
	Mode Mode
	TargetIdentity string
	Source SourceInventory
}

func DecidePreflight(ctx context.Context, request Request, targetIdentity string, inventory *SourceInventory, readiness eventstore.Readiness) (PreflightDecision, error) {
	if err := ctx.Err(); err != nil { return PreflightDecision{}, err }
	if request.Mode != ModeFresh && request.Mode != ModeImport { return PreflightDecision{}, ErrInvalidMode }
	if strings.TrimSpace(targetIdentity) == "" || strings.ContainsAny(targetIdentity, "/\\\x00") { return PreflightDecision{}, ErrTargetIdentity }
	if targetIdentity == strings.TrimSpace(readiness.DatabaseIdentity) { return PreflightDecision{}, ErrTargetIdentity }
	if request.Mode == ModeFresh {
		if inventory != nil { return PreflightDecision{}, ErrSourceMutation }
		if strings.TrimSpace(readiness.IndexRootID) == "" { return PreflightDecision{}, eventstore.ErrReadinessInvalid }
		return PreflightDecision{Mode: ModeFresh, TargetIdentity: targetIdentity}, nil
	}
	if inventory == nil { return PreflightDecision{}, ErrSourceRequired }
	if inventory.Kind != SourceKindLegacy && inventory.Kind != SourceKindSQLite {
		return PreflightDecision{}, &UnsupportedPreflightError{Feature: "source kind"}
	}
	if strings.TrimSpace(inventory.Identity) == "" { return PreflightDecision{}, &UnsupportedPreflightError{Feature: "source identity"} }
	if strings.TrimSpace(inventory.Metadata.Identity) != "" && inventory.Metadata.Identity != inventory.Identity {
		return PreflightDecision{}, &UnsupportedPreflightError{Feature: "source metadata identity"}
	}
	if inventory.Identity == targetIdentity { return PreflightDecision{}, ErrTargetIdentity }
	if !inventory.LegacyOwnershipComplete {
		return PreflightDecision{}, &UnsupportedPreflightError{Feature: "complete legacy ownership map"}
	}
	if strings.TrimSpace(readiness.IndexRootID) == "" { return PreflightDecision{}, eventstore.ErrReadinessInvalid }
	if len(inventory.Records) > MaxManifestRecords { return PreflightDecision{}, ErrBatchLimit }
	return PreflightDecision{Mode: ModeImport, TargetIdentity: targetIdentity, Source: *inventory}, nil
}
