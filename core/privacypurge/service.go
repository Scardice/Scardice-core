package privacypurge

import (
	"context"
	"errors"
	"strings"

	"Scardice-core/eventstore"
)

var (
	ErrInvalidRequest       = errors.New("privacypurge: invalid request")
	ErrConfirmationMismatch = eventstore.ErrPrivacyConfirmationMismatch
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
}
type Result struct {
	Status              string                   `json:"status"`
	ConfirmationDigest  []byte                   `json:"confirmationDigest,omitempty"`
	ConfirmationVersion uint64                   `json:"confirmationVersion,omitempty"`
	Counts              eventstore.PrivacyCounts `json:"counts"`
	Deleted             eventstore.PrivacyCounts `json:"deleted"`
	Uncovered           []string                 `json:"uncoveredData,omitempty"`
	Completed           bool                     `json:"completed"`
}

type Option func(*Service)

// WithGroupCacheInvalidator evicts local state after the deletion commits. A
// failed invalidation does not make the already committed deletion resumable.
func WithGroupCacheInvalidator(invalidate func(context.Context, string) error) Option {
	return func(service *Service) { service.invalidateGroupCache = invalidate }
}

type Service struct {
	repo                 eventstore.GroupPrivacyRepository
	invalidateGroupCache func(context.Context, string) error
}

func NewService(repo eventstore.GroupPrivacyRepository, options ...Option) *Service {
	service := &Service{repo: repo}
	for _, option := range options {
		if option != nil {
			option(service)
		}
	}
	return service
}
func canonicalScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return []string{"group_record"}, nil
	}
	seen := make(map[string]bool)
	for _, raw := range scopes {
		switch scope := strings.TrimSpace(raw); scope {
		case "group_record", "players", "attrs", "logs":
			seen[scope] = true
		default:
			return nil, ErrInvalidRequest
		}
	}
	out := make([]string, 0, len(seen))
	for _, scope := range []string{"group_record", "players", "attrs", "logs"} {
		if seen[scope] {
			out = append(out, scope)
		}
	}
	return out, nil
}
func privacyRequest(req Request) (eventstore.PrivacyDryRunRequest, error) {
	if strings.TrimSpace(req.GroupID) == "" || len(req.DiceIDs) == 0 {
		return eventstore.PrivacyDryRunRequest{}, ErrInvalidRequest
	}
	scopes, err := canonicalScopes(req.Scopes)
	if err != nil {
		return eventstore.PrivacyDryRunRequest{}, err
	}
	return eventstore.PrivacyDryRunRequest{GroupID: req.GroupID, DiceIDs: append([]string(nil), req.DiceIDs...), Scopes: scopes, ActiveDiceIDs: append([]string(nil), req.ActiveDiceIDs...)}, nil
}
func resultFromScan(scan eventstore.PrivacyDryRunResult, status string) Result {
	return Result{Status: status, ConfirmationDigest: append([]byte(nil), scan.Digest...), ConfirmationVersion: scan.Version, Counts: scan.Counts, Uncovered: append([]string(nil), scan.Uncovered...)}
}
func (s *Service) DryRun(ctx context.Context, req Request) (Result, error) {
	if s == nil || s.repo == nil {
		return Result{}, ErrInvalidRequest
	}
	selection, err := privacyRequest(req)
	if err != nil {
		return Result{}, err
	}
	scan, err := s.repo.PrivacyDryRun(ctx, selection)
	if err != nil {
		return Result{}, err
	}
	result := resultFromScan(scan, "dry-run")
	if !req.AllowActive && len(scan.ActiveDiceIDs) != 0 {
		return result, eventstore.ErrInvalidTransition
	}
	return result, nil
}
func (s *Service) Confirm(ctx context.Context, req Request) (Result, error) {
	if req.DryRun {
		return s.DryRun(ctx, req)
	}
	if s == nil || s.repo == nil {
		return Result{}, ErrInvalidRequest
	}
	selection, err := privacyRequest(req)
	if err != nil {
		return Result{}, err
	}
	deleted, err := s.repo.PrivacyDeleteGroup(ctx, eventstore.PrivacyDeleteRequest{PrivacyDryRunRequest: selection, AllowActive: req.AllowActive, ConfirmationDigest: append([]byte(nil), req.ConfirmationDigest...), ConfirmationVersion: req.ConfirmationVersion})
	if err != nil {
		return resultFromScan(deleted.Scan, "rejected"), err
	}
	result := resultFromScan(deleted.Scan, "completed")
	result.Deleted = deleted.Deleted
	result.Completed = true
	if len(result.Uncovered) != 0 {
		result.Status = "completed-uncovered"
	}
	if s.invalidateGroupCache != nil {
		if err := s.invalidateGroupCache(ctx, req.GroupID); err != nil {
			return result, err
		}
	}
	if len(result.Uncovered) != 0 {
		return result, ErrUncoveredData
	}
	return result, nil
}
