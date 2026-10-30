package eventstore

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"
)

const (
	DefaultManagementActivityLimit = 20
	MaxManagementActivityLimit     = 100
)

// ManagementActivity contains only the fixed operation summary permitted in
// the administrator activity feed. Request and response payloads are never
// represented by this type.
type ManagementActivity struct {
	ID         string
	OccurredAt time.Time
	Action     string
	Label      string
	Resource   string
	Status     string
	HTTPStatus int
	Actor      string
	SourceIP   string
}

// ManagementActivityRepository is the narrow persistence seam for the
// append-only administrator operation feed.
type ManagementActivityRepository interface {
	AppendManagementActivity(ctx context.Context, activity ManagementActivity) error
	RecentManagementActivities(ctx context.Context, limit int) ([]ManagementActivity, error)
}

func validateManagementActivity(activity ManagementActivity) error {
	if activity.ID == "" || activity.OccurredAt.IsZero() || activity.OccurredAt.UnixMilli() <= 0 ||
		activity.Action == "" || activity.Label == "" || activity.Resource == "" ||
		activity.Actor == "" || activity.SourceIP == "" ||
		activity.HTTPStatus < 100 || activity.HTTPStatus > 599 {
		return ErrInvalidMetadata
	}
	if _, err := netip.ParseAddr(activity.SourceIP); err != nil {
		return ErrInvalidMetadata
	}

	if len(activity.ID) > 255 || len(activity.Action) > 255 || len(activity.Label) > 255 ||
		len(activity.Resource) > 255 || len(activity.Actor) > 255 || len(activity.SourceIP) > 128 {
		return ErrInvalidMetadata
	}
	switch activity.Status {
	case "succeeded", "accepted", "failed":
		return nil
	default:
		return ErrInvalidMetadata
	}
}

// AppendManagementActivity durably appends one audit summary to the existing
// event database. It does not add request data to any persistence row.
func (s *GORMStore) AppendManagementActivity(ctx context.Context, activity ManagementActivity) error {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return errors.New("eventstore: management activity store unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := validateManagementActivity(activity); err != nil {
		return err
	}
	row := managementActivityRow{
		ID: activity.ID, OccurredAtUnixMilli: activity.OccurredAt.UnixMilli(),
		Action: activity.Action, Label: activity.Label, Resource: activity.Resource,
		Status: activity.Status, HTTPStatus: activity.HTTPStatus, Actor: activity.Actor,
		SourceIP: activity.SourceIP,
	}
	if err := s.db.GORM().WithContext(ctx).Create(&row).Error; err != nil {
		return fmt.Errorf("eventstore: append management activity: %w", err)
	}
	return nil
}

// RecentManagementActivities returns a bounded newest-first page. Global
// insertion position provides a stable ordering when requests share one
// millisecond timestamp.
func (s *GORMStore) RecentManagementActivities(ctx context.Context, limit int) ([]ManagementActivity, error) {
	if s == nil || s.db == nil || s.db.GORM() == nil {
		return nil, errors.New("eventstore: management activity store unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if limit <= 0 {
		limit = DefaultManagementActivityLimit
	}
	if limit > MaxManagementActivityLimit {
		limit = MaxManagementActivityLimit
	}
	var rows []managementActivityRow
	if err := s.db.GORM().WithContext(ctx).
		Order("occurred_at_unix_milli DESC").
		Order("global_position DESC").
		Limit(limit).
		Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("eventstore: read management activity: %w", err)
	}
	items := make([]ManagementActivity, 0, len(rows))
	for _, row := range rows {
		items = append(items, ManagementActivity{
			ID: row.ID, OccurredAt: time.UnixMilli(row.OccurredAtUnixMilli).UTC(),
			Action: row.Action, Label: row.Label, Resource: row.Resource,
			Status: row.Status, HTTPStatus: row.HTTPStatus, Actor: row.Actor,
			SourceIP: row.SourceIP,
		})
	}
	return items, nil
}
