package extensionstate

import (
	"context"
	"sync"

	"Scardice-core/eventstore"
)

// SnapshotCache remembers the last replayed state of each extension stream so
// the next load continues from it instead of replaying the whole history.
//
// The cache never has to be invalidated. Each use asks the store for the events
// from the cached version onward and checks that the first of them is the very
// event the snapshot ended on (same id and checksum); a stream that was
// replaced, restored or rewritten fails that check and is replayed in full.
type SnapshotCache struct {
	mu      sync.Mutex
	entries map[string]*snapshotEntry
}

type snapshotEntry struct {
	// state is private to the cache: callers only ever receive clones.
	state    State
	eventID  string
	checksum eventstore.EventChecksum
}

// NewSnapshotCache returns an empty cache.
func NewSnapshotCache() *SnapshotCache { return &SnapshotCache{} }

// current returns the state at the head of stream. The caller owns the result.
func (c *SnapshotCache) current(ctx context.Context, store eventstore.Store, stream eventstore.StreamID) (State, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if entry := c.entries[stream.AggregateID]; entry != nil {
		events, err := store.Load(ctx, stream, entry.state.Version)
		if err != nil {
			return State{}, err
		}
		if len(events) > 0 && entry.endsWith(events[0]) {
			fresh := events[1:]
			if len(fresh) == 0 {
				return entry.state.Clone(), nil
			}
			next := entry.state.Clone()
			if err := replayInto(&next, fresh); err != nil {
				return State{}, err
			}
			c.remember(stream, next, fresh[len(fresh)-1])
			return next, nil
		}
	}

	events, err := store.Load(ctx, stream, 1)
	if err != nil {
		return State{}, err
	}
	if len(events) == 0 {
		delete(c.entries, stream.AggregateID)
		return State{}, nil
	}
	state, err := ReplayEnvelopes(events)
	if err != nil {
		return State{}, err
	}
	c.remember(stream, state, events[len(events)-1])
	return state, nil
}

func (e *snapshotEntry) endsWith(envelope eventstore.Envelope) bool {
	return envelope.StreamVersion == e.state.Version && envelope.EventID == e.eventID && envelope.Checksum == e.checksum
}

// remember keeps a private copy of state, which ends with last.
func (c *SnapshotCache) remember(stream eventstore.StreamID, state State, last eventstore.Envelope) {
	if c.entries == nil {
		c.entries = make(map[string]*snapshotEntry)
	}
	c.entries[stream.AggregateID] = &snapshotEntry{state: state.Clone(), eventID: last.EventID, checksum: last.Checksum}
}
