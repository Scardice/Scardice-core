package v1reader

import (
	"context"
	"database/sql"
	"fmt"
)

// ManagementActivity is one row of the administrator activity feed. The v1
// store kept it in plain columns.
type ManagementActivity struct {
	ID                  string
	OccurredAtUnixMilli int64
	Action              string
	Label               string
	Resource            string
	Status              string
	HTTPStatus          int
	Actor               string
	SourceIP            string
}

// ManagementActivities returns the whole feed in insertion order.
func (s *Source) ManagementActivities(ctx context.Context) ([]ManagementActivity, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, occurred_at_unix_milli, action, label, resource, status, http_status, actor, source_ip FROM management_activities ORDER BY global_position`)
	if err != nil {
		return nil, fmt.Errorf("v1reader: read management activities: %w", err)
	}
	defer rows.Close()
	var out []ManagementActivity
	for rows.Next() {
		var activity ManagementActivity
		var label, resource, actor, sourceIP sql.NullString
		if err = rows.Scan(&activity.ID, &activity.OccurredAtUnixMilli, &activity.Action, &label, &resource,
			&activity.Status, &activity.HTTPStatus, &actor, &sourceIP); err != nil {
			return nil, err
		}
		activity.Label, activity.Resource, activity.Actor, activity.SourceIP = label.String, resource.String, actor.String, sourceIP.String
		out = append(out, activity)
	}
	return out, rows.Err()
}

// DatabaseIdentity is the database identity the v1 store pinned in its
// readiness row.
func (s *Source) DatabaseIdentity(ctx context.Context) (string, error) {
	var identity string
	err := s.db.QueryRowContext(ctx, `SELECT database_identity FROM store_readiness WHERE singleton_id = 'default'`).Scan(&identity)
	return identity, err
}

// ReadinessMode is the mode of the v1 store's readiness row: "fresh" for a
// store that started empty, "import" for one filled by a legacy import.
func (s *Source) ReadinessMode(ctx context.Context) (string, error) {
	var mode string
	err := s.db.QueryRowContext(ctx, `SELECT mode FROM store_readiness WHERE singleton_id = 'default'`).Scan(&mode)
	return mode, err
}
