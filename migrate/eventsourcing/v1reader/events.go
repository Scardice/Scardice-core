package v1reader

import (
	"context"
	"database/sql"
	"fmt"
)

// Event is one row of domain_events. The payloads are plain JSON in the v1
// store already: only the adapter secrets, plugin storage and Story log were
// encrypted.
type Event struct {
	EventID               string
	AggregateType         string
	AggregateID           string
	AggregateVersion      uint64
	GlobalPosition        uint64
	EventType             string
	SchemaVersion         uint16
	Payload               []byte
	CommandID             string
	CorrelationID         string
	CausationID           string
	PrincipalID           string
	Producer              string
	OccurredAtUnixNanoUTC int64
}

// Events streams every event in global order. yield may keep the event; its
// slices are not reused.
func (s *Source) Events(ctx context.Context, yield func(Event) error) error {
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, aggregate_type, aggregate_id, aggregate_version, global_position, event_type, schema_version, payload, command_id, correlation_id, causation_id, principal_id, producer, occurred_at_unix_nano_utc FROM domain_events ORDER BY global_position`)
	if err != nil {
		return fmt.Errorf("v1reader: read events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var event Event
		var command, correlation, causation, principal, producer sql.NullString
		var schema int
		if err = rows.Scan(&event.EventID, &event.AggregateType, &event.AggregateID, &event.AggregateVersion, &event.GlobalPosition,
			&event.EventType, &schema, &event.Payload, &command, &correlation, &causation, &principal, &producer, &event.OccurredAtUnixNanoUTC); err != nil {
			return fmt.Errorf("v1reader: scan event: %w", err)
		}
		event.SchemaVersion = uint16(schema)
		event.CommandID, event.CorrelationID, event.CausationID = command.String, correlation.String, causation.String
		event.PrincipalID, event.Producer = principal.String, producer.String
		if err = yield(event); err != nil {
			return err
		}
	}
	return rows.Err()
}

// EventCount is the number of events, straight from the database.
func (s *Source) EventCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domain_events`).Scan(&n)
	return n, err
}
