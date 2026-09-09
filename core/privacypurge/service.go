package privacypurge

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"strings"
	"time"

	"Scardice-core/eventstore"
	"github.com/google/uuid"
)

var (
	ErrInvalidRequest       = errors.New("privacypurge: invalid request")
	ErrConfirmationMismatch = errors.New("privacypurge: confirmation is stale or invalid")
	ErrUncoveredData        = errors.New("privacypurge: selected stores are not covered")
)

type Request struct {
	GroupID             string
	DiceIDs             []string
	Scopes              []string
	ActiveDiceIDs       []string
	AllowActive         bool
	DryRun              bool
	ConfirmationDigest  []byte
	ConfirmationVersion uint64
	OperationID         string
	Resume              bool
}

type Result struct {
	OperationID         string                   `json:"operationId,omitempty"`
	Status              string                   `json:"status"`
	Phase               string                   `json:"phase"`
	Version             uint64                   `json:"-"`
	ConfirmationDigest  []byte                   `json:"confirmationDigest,omitempty"`
	ConfirmationVersion uint64                   `json:"confirmationVersion,omitempty"`
	Counts              eventstore.PrivacyCounts `json:"counts"`
	Deleted             eventstore.PrivacyCounts `json:"deleted"`
	Uncovered           []string                 `json:"uncoveredData,omitempty"`
	Completed           bool                     `json:"completed"`
}

type Service struct {
	repo eventstore.PrivacyHistoryRepository
	now  func() time.Time
}

func NewService(repo eventstore.PrivacyHistoryRepository) *Service {
	return &Service{repo: repo, now: func() time.Time { return time.Now().UTC() }}
}
func canonicalScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"group_record"}, nil
	}
	seen := map[string]bool{}
	for _, raw := range scopes {
		switch scope := strings.TrimSpace(raw); scope {
		case "group_record", "players", "attrs":
			seen[scope] = true
		default:
			return nil, ErrInvalidRequest
		}
	}
	out := make([]string, 0, len(seen))
	for _, scope := range []string{"group_record", "players", "attrs"} {
		if seen[scope] {
			out = append(out, scope)
		}
	}
	return out, nil
}
func validateRequest(req Request) error {
	if strings.TrimSpace(req.GroupID) == "" || len(req.DiceIDs) == 0 {
		return ErrInvalidRequest
	}
	_, err := canonicalScopes(req.Scopes)
	return err
}

func (s *Service) DryRun(ctx context.Context, req Request) (Result, error) {
	if s == nil || s.repo == nil || validateRequest(req) != nil {
		return Result{}, ErrInvalidRequest
	}
	scopes, _ := canonicalScopes(req.Scopes)
	req.Scopes = scopes
	result, err := s.repo.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: req.GroupID, ActiveDiceIDs: append([]string(nil), req.ActiveDiceIDs...), DiceIDs: req.DiceIDs, Scopes: req.Scopes})
	if err != nil {
		return Result{}, err
	}
	activeIDs := result.ActiveDiceIDs
	if activeIDs == nil {
		activeIDs = req.ActiveDiceIDs
	}
	for _, active := range activeIDs {
		if !req.AllowActive && strings.TrimSpace(active) != "" {
			return Result{Counts: result.Counts, Uncovered: result.Uncovered}, eventstore.ErrInvalidTransition
		}
	}
	return Result{Status: "dry-run", Phase: "dry-run", Version: result.Version, ConfirmationDigest: append([]byte(nil), result.Digest...), ConfirmationVersion: result.Version, Counts: result.Counts, Uncovered: append([]string(nil), result.Uncovered...)}, nil
}

func (s *Service) Confirm(ctx context.Context, req Request) (Result, error) {
	if s == nil || s.repo == nil || strings.TrimSpace(req.GroupID) == "" {
		return Result{}, ErrInvalidRequest
	}
	if req.DryRun {
		if validateRequest(req) != nil {
			return Result{}, ErrInvalidRequest
		}
		return s.DryRun(ctx, req)
	}
	if req.Resume || req.OperationID != "" {
		return s.resume(ctx, req)
	}
	if validateRequest(req) != nil {
		return Result{}, ErrInvalidRequest
	}
	scopes, _ := canonicalScopes(req.Scopes)
	req.Scopes = scopes
	scan, err := s.repo.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: req.GroupID, ActiveDiceIDs: append([]string(nil), req.ActiveDiceIDs...), DiceIDs: req.DiceIDs, Scopes: req.Scopes})
	if err != nil {
		return Result{}, err
	}
	if !constantTimeEqual(req.ConfirmationDigest, scan.Digest) || req.ConfirmationVersion != scan.Version {
		return Result{Status: "rejected", Phase: "dry-run", ConfirmationDigest: scan.Digest, ConfirmationVersion: scan.Version, Counts: scan.Counts, Uncovered: scan.Uncovered}, ErrConfirmationMismatch
	}
	if !req.AllowActive && scan.ActiveDiceIDs == nil {
		return Result{}, eventstore.ErrInvalidTransition
	}
	for _, active := range scan.ActiveDiceIDs {
		if !req.AllowActive && strings.TrimSpace(active) != "" {
			return Result{}, eventstore.ErrInvalidTransition
		}
	}
	operationID := req.OperationID
	if operationID == "" {
		operationID = uuid.NewString()
	}
	private := eventstore.PrivacyOperationContext{GroupID: req.GroupID, DiceIDs: append([]string(nil), req.DiceIDs...), Scopes: append([]string(nil), req.Scopes...), ActiveDiceIDs: append([]string(nil), req.ActiveDiceIDs...), Phase: "fence", Counts: scan.Counts, ConfirmationDigest: append([]byte(nil), scan.Digest...), ConfirmationVersion: scan.Version}
	if err := s.repo.PrivacyCreateOperation(ctx, operationID, scan.SubjectKey, private); err != nil {
		return Result{}, err
	}
	if _, err := s.repo.PrivacyFence(ctx, scan.SubjectKey, "group", operationID); err != nil {
		if errors.Is(err, eventstore.ErrParticipantConflict) {
			if cleanupErr := s.cancelOrphan(ctx, operationID); cleanupErr != nil {
				return Result{OperationID: operationID, Status: "failed", Phase: "fence"}, fmt.Errorf("%w: orphan cleanup: %v", err, cleanupErr)
			}
			return Result{OperationID: operationID, Status: "cancelled", Phase: "fence"}, err
		}
		return Result{OperationID: operationID, Status: "failed", Phase: "fence"}, err
	}

	fencedScan, err := s.repo.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: req.GroupID, ActiveDiceIDs: append([]string(nil), req.ActiveDiceIDs...), DiceIDs: req.DiceIDs, Scopes: req.Scopes})
	if err != nil {
		return s.failed(ctx, operationID, private, scan.SubjectKey, "fence", err)
	}
	if !constantTimeEqual(fencedScan.Digest, scan.Digest) || fencedScan.Version != scan.Version {
		return s.failed(ctx, operationID, private, scan.SubjectKey, "fence", ErrConfirmationMismatch)
	}
	return s.run(ctx, operationID, scan.SubjectKey, private, fencedScan)
}
func (s *Service) cancelOrphan(ctx context.Context, operationID string) error {
	view, _, err := s.repo.PrivacyLoadOperation(ctx, operationID)
	if err != nil {
		return err
	}
	if _, err := s.repo.PrivacyUpdateOperation(ctx, operationID, view.Version, eventstore.PrivacyOperationContext{}, "cancelled"); err != nil {
		return err
	}
	view, _, err = s.repo.PrivacyLoadOperation(ctx, operationID)
	if err != nil {
		return err
	}
	return s.repo.PrivacyScrubOperation(ctx, operationID, view.Version)
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}

func (s *Service) resume(ctx context.Context, req Request) (Result, error) {
	view, private, err := s.repo.PrivacyLoadOperation(ctx, req.OperationID)
	if err != nil {
		return Result{}, err
	}
	if (view.Status == "completed" || view.Status == "completed-uncovered") && private.GroupID == "" {
		verifier, ok := s.repo.(eventstore.PrivacySubjectVerifier)
		if !ok || verifier.PrivacyVerifyOperationSubject(ctx, req.OperationID, req.GroupID) != nil {
			return Result{}, ErrInvalidRequest
		}
		return Result{OperationID: view.OperationID, Status: view.Status, Phase: "completed", Completed: true}, ErrUncoveredData
	}
	if private.GroupID == "" || private.GroupID != req.GroupID {
		return Result{}, ErrInvalidRequest
	}
	scan, err := s.repo.PrivacyDryRun(ctx, eventstore.PrivacyDryRunRequest{GroupID: private.GroupID, ActiveDiceIDs: append([]string(nil), private.ActiveDiceIDs...), DiceIDs: private.DiceIDs, Scopes: private.Scopes})
	if err != nil {
		return Result{}, err
	}
	if private.Phase == "fence" && (!constantTimeEqual(private.ConfirmationDigest, scan.Digest) || private.ConfirmationVersion != scan.Version) {
		return Result{}, ErrConfirmationMismatch
	}
	if view.Status == "completed" || view.Status == "completed-uncovered" {
		fenceVersion, fenceErr := s.repo.PrivacyFenceVersion(ctx, scan.SubjectKey, "group")
		if fenceErr != nil {
			return Result{}, fenceErr
		}
		if fenceVersion == 0 {
			return Result{OperationID: view.OperationID, Status: view.Status, Phase: "completed", Counts: private.Counts, Uncovered: scan.Uncovered, Completed: true}, nil
		}
		if err := s.repo.PrivacyScrubOperation(ctx, req.OperationID, view.Version); err != nil {
			return Result{}, err
		}
		if err := s.repo.PrivacyUnfence(ctx, scan.SubjectKey, "group", fenceVersion, req.OperationID); err != nil {
			return Result{}, err
		}
		return Result{OperationID: view.OperationID, Status: view.Status, Phase: "completed", Counts: private.Counts, Uncovered: scan.Uncovered, Completed: true}, ErrUncoveredData
	}
	fenceVersion, fenceErr := s.repo.PrivacyFenceVersion(ctx, scan.SubjectKey, "group")
	if fenceErr != nil {
		return Result{}, fenceErr
	}
	if fenceVersion == 0 {
		if _, err := s.repo.PrivacyFence(ctx, scan.SubjectKey, "group", req.OperationID); err != nil {
			return Result{}, err
		}
	}
	return s.run(ctx, req.OperationID, scan.SubjectKey, private, scan)
}

func (s *Service) run(ctx context.Context, operationID string, subjectKey []byte, private eventstore.PrivacyOperationContext, scan eventstore.PrivacyDryRunResult) (Result, error) {
	status := "running"
	phase := "quiesce"
	if err := s.repo.PrivacyResolvePending(ctx, subjectKey, operationID); err != nil {
		return s.failed(ctx, operationID, private, subjectKey, phase, err)
	}
	private.Phase = "delete"
	view, _, loadErr := s.repo.PrivacyLoadOperation(ctx, operationID)
	if loadErr != nil {
		return s.failed(ctx, operationID, private, subjectKey, "delete", loadErr)
	}
	if _, err := s.repo.PrivacyUpdateOperation(ctx, operationID, view.Version, private, status); err != nil {
		return s.failed(ctx, operationID, private, subjectKey, "delete", err)
	}
	deleted := eventstore.PrivacyCounts{}
	for {
		batch, err := s.repo.PrivacyDeleteBatch(ctx, eventstore.PrivacyBatchRequest{OperationID: operationID, GroupID: private.GroupID, Phase: private.Phase, DiceIDs: private.DiceIDs, Scopes: private.Scopes, Cursor: private.Cursor, Limit: eventstore.PrivacyBatchRecords})
		if err != nil {
			return s.failed(ctx, operationID, private, subjectKey, "delete", err)
		}
		deleted.GroupRecord += batch.Deleted.GroupRecord
		deleted.Players += batch.Deleted.Players
		deleted.Attrs += batch.Deleted.Attrs
		private.Cursor, private.Phase = batch.NextCursor, "delete"
		view, _, loadErr := s.repo.PrivacyLoadOperation(ctx, operationID)
		if loadErr != nil {
			return s.failed(ctx, operationID, private, subjectKey, "delete", loadErr)
		}
		if _, err := s.repo.PrivacyUpdateOperation(ctx, operationID, view.Version, private, status); err != nil {
			return s.failed(ctx, operationID, private, subjectKey, "delete", err)
		}
		if batch.Done {
			break
		}
	}
	private.TargetHighWater = scan.TargetHighWater
	private.Phase = "rebuild"
	view, _, err := s.repo.PrivacyLoadOperation(ctx, operationID)
	if err != nil {
		return s.failed(ctx, operationID, private, subjectKey, "rebuild", err)
	}
	if _, err := s.repo.PrivacyUpdateOperation(ctx, operationID, view.Version, private, status); err != nil {
		return s.failed(ctx, operationID, private, subjectKey, "rebuild", err)
	}
	if err := s.repo.PrivacyRebuildPublish(ctx, private.TargetHighWater); err != nil {
		return s.failed(ctx, operationID, private, subjectKey, "rebuild", err)
	}
	private.Phase = "reopen"
	view, _, err = s.repo.PrivacyLoadOperation(ctx, operationID)
	if err != nil {
		return s.failed(ctx, operationID, private, subjectKey, "reopen", err)
	}
	if _, err := s.repo.PrivacyUpdateOperation(ctx, operationID, view.Version, private, "running"); err != nil {
		return s.failed(ctx, operationID, private, subjectKey, "reopen", err)
	}
	view, _, err = s.repo.PrivacyLoadOperation(ctx, operationID)
	if err != nil {
		return s.failed(ctx, operationID, private, subjectKey, "reopen", err)
	}
	if finalizer, ok := s.repo.(eventstore.PrivacyFinalizer); ok {
		if _, err := finalizer.PrivacyFinalizeOperation(ctx, operationID, view.Version, "completed-uncovered"); err != nil {
			return s.failed(ctx, operationID, private, subjectKey, "reopen", err)
		}
	} else {
		return s.failed(ctx, operationID, private, subjectKey, "reopen", eventstore.ErrParticipantFailure)
	}
	out := Result{OperationID: operationID, Status: "completed-uncovered", Phase: "completed", Counts: scan.Counts, Deleted: deleted, Uncovered: scan.Uncovered, Completed: true}
	return out, ErrUncoveredData
}

func (s *Service) failed(ctx context.Context, operationID string, private eventstore.PrivacyOperationContext, _ []byte, phase string, cause error) (Result, error) {
	private.Phase = phase
	view, loaded, loadErr := s.repo.PrivacyLoadOperation(ctx, operationID)
	if loadErr != nil {
		return Result{OperationID: operationID, Status: "failed", Phase: phase}, fmt.Errorf("%w: checkpoint load: %v", cause, loadErr)
	}
	if (view.Status == "completed" || view.Status == "completed-uncovered") && loaded.GroupID == "" {
		result := Result{OperationID: operationID, Status: view.Status, Phase: "completed", Completed: true}
		if view.Status == "completed-uncovered" {
			return result, ErrUncoveredData
		}
		return result, nil
	}
	private = loaded
	if _, updateErr := s.repo.PrivacyUpdateOperation(ctx, operationID, view.Version, private, "resumable-failure"); updateErr != nil {
		return Result{OperationID: operationID, Status: "failed", Phase: phase}, fmt.Errorf("%w: checkpoint update: %v", cause, updateErr)
	}
	return Result{OperationID: operationID, Status: "resumable-failure", Phase: phase}, cause
}
