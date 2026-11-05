package extensionstate

import (
	"context"
	"sync"

	"Scardice-core/eventstore"
)

// projectionStamper is the part of a store that lets ReadCache validate a
// cached projection without fetching its payload.
type projectionStamper interface {
	ReadProjectionStamp(ctx context.Context, stream eventstore.StreamID) (eventstore.ProjectionStamp, error)
	ReadProjectionRowStamped(ctx context.Context, projectionName, rowKey string, stream eventstore.StreamID) (eventstore.ProjectionRow, eventstore.ProjectionStamp, error)
}

type readCacheEntry struct {
	stamp eventstore.ProjectionStamp
	state State
}

// ReadCache remembers the decoded projection of each Dice's extension state.
//
// ReadProjected re-reads and re-decodes the whole projection row, then clones
// it, on every call. With a hundred plugins that is a megabyte and thousands of
// allocations per plugin config read. A cached entry is valid for as long as
// the stream's ProjectionStamp (published generation and stream head version)
// is unchanged, and checking that costs two tiny
// indexed reads, so a hit never touches the payload.
//
// The zero value is ready to use.
type ReadCache struct {
	mu      sync.Mutex
	entries map[string]*readCacheEntry
}

// NewReadCache returns an empty cache.
func NewReadCache() *ReadCache { return &ReadCache{} }

// ReadShared returns the projected extension state of diceID without copying
// it. The maps inside the result are shared with every other caller and with
// the cache: the caller MUST treat it as read-only. Use ReadProjected when a
// private copy is needed.
//
// Stores that cannot stamp their projections, and any read that does not find
// the projection row, take the ordinary ReadProjected path and are not cached.
func (c *ReadCache) ReadShared(ctx context.Context, store any, diceID string) (State, error) {
	stamper, ok := store.(projectionStamper)
	if c == nil || !ok || stamper == nil {
		return ReadProjected(ctx, store, diceID)
	}
	if err := validateIdentity(diceID); err != nil {
		return State{}, err
	}
	stream := ExtensionStream(diceID)
	if stamp, err := stamper.ReadProjectionStamp(ctx, stream); err == nil {
		c.mu.Lock()
		entry := c.entries[diceID]
		c.mu.Unlock()
		if entry != nil && entry.stamp == stamp {
			return entry.state, nil
		}
	}
	row, stamp, err := stamper.ReadProjectionRowStamped(ctx, ExtensionProjectionName, stream.AggregateID, stream)
	if err != nil {
		return ReadProjected(ctx, store, diceID)
	}
	state, err := decodeProjectionState(row.Payload)
	if err != nil {
		return State{}, err
	}
	if ExtensionStream(state.DiceID).AggregateID != stream.AggregateID {
		return State{}, ErrInvalidState
	}
	c.remember(diceID, stamp, state)
	return state, nil
}

func (c *ReadCache) remember(diceID string, stamp eventstore.ProjectionStamp, state State) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if existing := c.entries[diceID]; existing != nil &&
		existing.stamp.Generation == stamp.Generation &&
		existing.stamp.StreamVersion > stamp.StreamVersion {
		// A concurrent reader already cached a newer head.
		return
	}
	if c.entries == nil {
		c.entries = make(map[string]*readCacheEntry)
	}
	c.entries[diceID] = &readCacheEntry{stamp: stamp, state: state}
}
