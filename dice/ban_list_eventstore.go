package dice

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"Scardice-core/core/playerstate"
	"Scardice-core/eventstore"
)

const (
	moderationDetailsEndpoint = "moderation-details"
	moderationDetailsAdapter  = "moderation"
)

type moderationEventStore interface {
	eventstore.Store
	ListStreamHeads(ctx context.Context, namespace string) ([]eventstore.StreamHead, error)
	ListProjectionRows(ctx context.Context, namespace string) ([]eventstore.ProjectionRow, error)
	KeyedDigestBytes(ctx context.Context, namespace string, payload []byte) ([]byte, string, error)
	ResolveSecret(ctx context.Context, reference string, version uint64) (eventstore.SecretResolution, error)
	PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error)
}

type moderationDetails struct {
	BanListInfoItem
	BanUpdatedAt int64 `json:"banUpdatedAt"`
}

type moderationBanRepository struct {
	store  moderationEventStore
	states *playerstate.Repository
	diceID string
}

func newModerationBanRepository(d *Dice) (*moderationBanRepository, error) {
	if d == nil || d.DurableStore == nil || d.BaseConfig.Name == "" {
		return nil, errors.New("dice: EventStore moderation identity is unavailable")
	}
	store, ok := d.DurableStore.(moderationEventStore)
	if !ok {
		return nil, errors.New("dice: EventStore does not support encrypted moderation details")
	}
	return &moderationBanRepository{
		store:  store,
		states: playerstate.NewRepository(store),
		diceID: d.BaseConfig.Name,
	}, nil
}

func moderationDetailsSecretRef(diceID, subjectID string) (string, error) {
	stream := playerstate.ModerationStream(diceID, "global", subjectID)
	if stream.AggregateID == "" {
		return "", playerstate.ErrInvalidIdentity
	}
	digest := sha256.Sum256([]byte(stream.AggregateID))
	return "vault:moderation-details:" + hex.EncodeToString(digest[:16]), nil
}

func (r *moderationBanRepository) load(ctx context.Context) (map[string]*BanListInfoItem, error) {
	if r == nil || r.store == nil {
		return nil, errors.New("dice: EventStore moderation repository is unavailable")
	}
	heads, err := r.store.ListStreamHeads(ctx, playerstate.ModerationAggregateType)
	if err != nil {
		return nil, fmt.Errorf("dice: list moderation streams: %w", err)
	}
	prefix := playerstate.ModerationStreamPrefix(r.diceID, "global").Prefix
	expectedVersions := make(map[string]uint64)
	for _, head := range heads {
		if strings.HasPrefix(head.Stream.AggregateID, prefix) {
			expectedVersions[head.Stream.AggregateID] = head.Version
		}
	}
	rows, err := r.store.ListProjectionRows(ctx, playerstate.ModerationProjectionName)
	if err != nil {
		return nil, fmt.Errorf("dice: list moderation projections: %w", err)
	}
	loaded := make(map[string]*BanListInfoItem)
	for _, row := range rows {
		if !strings.HasPrefix(row.RowKey, prefix) {
			continue
		}
		var state playerstate.ModerationState
		if err := json.Unmarshal(row.Payload, &state); err != nil {
			return nil, fmt.Errorf("dice: decode moderation projection %q: %w", row.RowKey, err)
		}
		stream := playerstate.ModerationStream(state.DiceID, state.GroupID, state.SubjectID)
		if state.Version == 0 || stream.AggregateID == "" || stream.AggregateID != row.RowKey ||
			state.DiceID != r.diceID || state.GroupID != "global" {
			return nil, fmt.Errorf("dice: invalid moderation projection identity %q", row.RowKey)
		}
		expectedVersion, exists := expectedVersions[row.RowKey]
		if !exists || expectedVersion != state.Version {
			return nil, fmt.Errorf("dice: moderation projection version mismatch for %q", state.SubjectID)
		}
		envelopes, err := r.store.Load(ctx, stream, 1)
		if err != nil {
			return nil, fmt.Errorf("dice: load moderation events for %q: %w", state.SubjectID, err)
		}
		var replayed playerstate.ModerationState
		for _, envelope := range envelopes {
			replayed, err = playerstate.ApplyModerationEnvelope(replayed, envelope, stream)
			if err != nil {
				return nil, fmt.Errorf("dice: replay moderation events for %q: %w", state.SubjectID, err)
			}
		}
		if len(envelopes) == 0 || replayed != state {
			return nil, fmt.Errorf("dice: moderation projection does not match stream %q", row.RowKey)
		}
		delete(expectedVersions, row.RowKey)
		if state.Deleted {
			continue
		}
		ref, err := moderationDetailsSecretRef(state.DiceID, state.SubjectID)
		if err != nil {
			return nil, err
		}
		secret, err := r.store.ResolveSecret(ctx, ref, 0)
		if errors.Is(err, eventstore.ErrNotFound) {
			return nil, fmt.Errorf("dice: encrypted moderation history is missing for %q", state.SubjectID)
		}
		if err != nil {
			return nil, fmt.Errorf("dice: resolve moderation history for %q: %w", state.SubjectID, err)
		}
		var details moderationDetails
		if secret.SecretVersion == 0 || json.Unmarshal(secret.Plaintext, &details) != nil {
			return nil, fmt.Errorf("dice: invalid encrypted moderation history for %q", state.SubjectID)
		}
		if details.ID != "" && details.ID != state.SubjectID {
			return nil, fmt.Errorf("dice: encrypted moderation history identity mismatch for %q", state.SubjectID)
		}
		item := &BanListInfoItem{
			ID: state.SubjectID, Rank: BanRankType(state.Rank), Score: state.Score,
			EventStoreVersion: state.Version,
		}
		item.Name = details.Name
		item.Times = append([]int64(nil), details.Times...)
		item.Reasons = append([]string(nil), details.Reasons...)
		item.Places = append([]string(nil), details.Places...)
		item.BanTime = details.BanTime
		item.BanUpdatedAt = details.BanUpdatedAt
		loaded[item.ID] = item
	}
	if len(expectedVersions) != 0 {
		return nil, fmt.Errorf("dice: %d moderation streams have no projection row", len(expectedVersions))
	}
	return loaded, nil
}

func (r *moderationBanRepository) save(ctx context.Context, item *BanListInfoItem) error {
	if r == nil || r.store == nil || r.states == nil || item == nil || item.ID == "" {
		return errors.New("dice: invalid EventStore moderation update")
	}
	state, err := r.states.LoadModeration(ctx, r.diceID, "global", item.ID)
	if err != nil {
		return fmt.Errorf("dice: load moderation state for %q: %w", item.ID, err)
	}
	if state.Version != item.EventStoreVersion {
		if item.EventStoreVersion != 0 || !state.Deleted {
			return fmt.Errorf("dice: moderation state for %q changed since load: %w", item.ID, eventstore.ErrConflict)
		}
	}
	detailsBytes, err := json.Marshal(moderationDetails{BanListInfoItem: *cloneBanListItem(item), BanUpdatedAt: item.BanUpdatedAt})
	if err != nil {
		return fmt.Errorf("dice: encode moderation history for %q: %w", item.ID, err)
	}
	historyBytes, err := json.Marshal(struct {
		Times   []int64  `json:"times"`
		Reasons []string `json:"reasons"`
		Places  []string `json:"places"`
	}{item.Times, item.Reasons, item.Places})
	if err != nil {
		return fmt.Errorf("dice: encode moderation history digest for %q: %w", item.ID, err)
	}
	digest, _, err := r.store.KeyedDigestBytes(ctx, "moderation-history/v1", historyBytes)
	if err != nil {
		return fmt.Errorf("dice: digest moderation history for %q: %w", item.ID, err)
	}
	ref, err := moderationDetailsSecretRef(r.diceID, item.ID)
	if err != nil {
		return err
	}
	secretVersion := uint64(0)
	if previous, resolveErr := r.store.ResolveSecret(ctx, ref, 0); resolveErr == nil {
		secretVersion = previous.SecretVersion
	} else if !errors.Is(resolveErr, eventstore.ErrNotFound) {
		return fmt.Errorf("dice: load moderation history version for %q: %w", item.ID, resolveErr)
	}
	request := eventstore.SecretPutRequest{
		SecretRef:       ref,
		EndpointID:      moderationDetailsEndpoint,
		AdapterID:       moderationDetailsAdapter,
		ExpectedVersion: secretVersion,
		SecretVersion:   secretVersion + 1,
		Plaintext:       detailsBytes,
	}

	events := make([]playerstate.ModerationEvent, 0, 3)
	switch {
	case state.Version == 0:
		events = append(events, playerstate.NewModerationCreatedV1(r.diceID, "global", item.ID, int(item.Rank), item.Score))
	case state.Deleted:
		events = append(events, playerstate.NewModerationRestoredV1(int(item.Rank), item.Score))
	default:
		if state.Rank != int(item.Rank) {
			events = append(events, playerstate.NewModerationRankChangedV1(int(item.Rank)))
		}
	}
	events = append(events, playerstate.NewModerationScoreChangedV1(item.Score, hex.EncodeToString(digest)))
	metadata := eventstore.Metadata{CommandID: "ban-list-upsert", CorrelationID: "ban-list-upsert"}
	stream := playerstate.ModerationStream(r.diceID, "global", item.ID)
	result, err := r.states.AppendModerationTypedWithSecret(ctx, r.diceID, "global", item.ID, state.Version, metadata, events, request)
	if err != nil {
		return fmt.Errorf("dice: commit moderation update for %q: %w", item.ID, err)
	}
	version, ok := result.StreamVersions[stream]
	if !ok {
		return fmt.Errorf("dice: committed moderation version is missing for %q", item.ID)
	}
	item.EventStoreVersion = version
	return nil
}

func (r *moderationBanRepository) delete(ctx context.Context, item *BanListInfoItem) error {
	if r == nil || r.states == nil || item == nil || item.ID == "" {
		return errors.New("dice: invalid EventStore moderation deletion")
	}
	state, err := r.states.LoadModeration(ctx, r.diceID, "global", item.ID)
	if err != nil {
		return fmt.Errorf("dice: load moderation state for %q: %w", item.ID, err)
	}
	if state.Version == 0 || state.Deleted {
		return nil
	}
	if state.Version != item.EventStoreVersion {
		return fmt.Errorf("dice: moderation state for %q changed since load: %w", item.ID, eventstore.ErrConflict)
	}
	metadata := eventstore.Metadata{CommandID: "ban-list-delete", CorrelationID: "ban-list-delete"}
	if _, err = r.states.AppendModerationTyped(ctx, r.diceID, "global", item.ID, item.EventStoreVersion, metadata, []playerstate.ModerationEvent{playerstate.NewModerationDeletedV1()}); err != nil {
		return fmt.Errorf("dice: commit moderation deletion for %q: %w", item.ID, err)
	}
	return nil
}

func (r *moderationBanRepository) setScore(ctx context.Context, item *BanListInfoItem, score int64) error {
	if r == nil || r.states == nil || item == nil || item.ID == "" {
		return errors.New("dice: invalid EventStore moderation score update")
	}
	state, err := r.states.LoadModeration(ctx, r.diceID, "global", item.ID)
	if err != nil {
		return fmt.Errorf("dice: load moderation state for %q: %w", item.ID, err)
	}
	if state.Version == 0 || state.Deleted {
		return fmt.Errorf("dice: moderation state for %q is not active", item.ID)
	}
	if state.Version != item.EventStoreVersion {
		return fmt.Errorf("dice: moderation state for %q changed since load: %w", item.ID, eventstore.ErrConflict)
	}
	metadata := eventstore.Metadata{CommandID: "ban-list-score-decay", CorrelationID: "ban-list-score-decay"}
	event := playerstate.NewModerationScoreChangedV1(score, state.ReasonDigest)
	stream := playerstate.ModerationStream(r.diceID, "global", item.ID)
	result, err := r.states.AppendModerationTyped(ctx, r.diceID, "global", item.ID, item.EventStoreVersion, metadata, []playerstate.ModerationEvent{event})
	if err != nil {
		return fmt.Errorf("dice: commit moderation score for %q: %w", item.ID, err)
	}
	version, ok := result.StreamVersions[stream]
	if !ok {
		return fmt.Errorf("dice: committed moderation version is missing for %q", item.ID)
	}
	item.EventStoreVersion = version
	return nil
}

func (i *BanListInfo) decayEventSourced(d *Dice, now int64) (bool, error) {
	if i == nil || d == nil {
		return false, nil
	}
	if err := i.PersistenceError(); err != nil {
		return false, err
	}
	repository, err := newModerationBanRepository(d)
	if err != nil {
		return false, err
	}
	i.itemsMu.Lock()
	defer i.itemsMu.Unlock()
	if i.Map == nil {
		return false, nil
	}
	var (
		changed bool
		saveErr error
	)
	i.Map.Range(func(id string, item *BanListInfoItem) bool {
		if item == nil || (item.Rank != BanRankNormal && item.Rank != BanRankWarn) {
			return true
		}
		updated := cloneBanListItem(item)
		updated.Score -= i.ScoreReducePerMinute
		if updated.Score == item.Score {
			return true
		}
		updated.UpdatedAt = now
		var persistErr error
		if updated.Score <= 0 {
			persistErr = repository.delete(context.Background(), updated)
			if persistErr == nil {
				i.Map.Delete(id)
			}
		} else {
			persistErr = repository.setScore(context.Background(), updated, updated.Score)
			if persistErr == nil {
				i.Map.Store(id, updated)
			}
		}
		if persistErr != nil {
			saveErr = errors.Join(saveErr, persistErr)
			return true
		}
		changed = true
		return true
	})
	return changed, saveErr
}
