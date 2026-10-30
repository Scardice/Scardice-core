package dice

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	ds "github.com/sealdice/dicescript"
	"go.uber.org/zap"

	"Scardice-core/adapterapi"
	"Scardice-core/core/attributestate"
	"Scardice-core/core/messageflow"
	"Scardice-core/dice/service"
	"Scardice-core/eventstore"
)

type attrsManagerRaceSecretStore interface {
	PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error)
	ResolveSecret(ctx context.Context, reference string, version uint64) (eventstore.SecretResolution, error)
}

type attrsManagerRaceStore struct {
	// Keep the concrete store so the wrapper forwards projection reads as well as Store methods.
	*eventstore.GORMStore
	secrets attrsManagerRaceSecretStore

	prepareEntered chan struct{}
	prepareRelease chan struct{}
	prepareOnce    sync.Once
	prepareMu      sync.Mutex
	prepareErr     error
	prepareFailAt  int
	prepareCount   int

	commitEntered  chan struct{}
	commitRelease  chan struct{}
	commitOnce     sync.Once
	resolveEntered chan struct{}
	resolveRelease chan struct{}
	resolveOnce    sync.Once
}

func (s *attrsManagerRaceStore) PrepareSecretUpdate(ctx context.Context, request eventstore.SecretPutRequest) (eventstore.SecretUpdate, error) {
	if s.prepareEntered != nil {
		s.prepareOnce.Do(func() {
			close(s.prepareEntered)
			<-s.prepareRelease
		})
	}
	s.prepareMu.Lock()
	s.prepareCount++
	prepareErr := s.prepareErr
	fail := prepareErr != nil && (s.prepareFailAt == 0 || s.prepareCount == s.prepareFailAt)
	s.prepareMu.Unlock()
	if fail {
		return eventstore.SecretUpdate{}, prepareErr
	}
	return s.secrets.PrepareSecretUpdate(ctx, request)
}

func (s *attrsManagerRaceStore) setPrepareFailure(err error, failAt int) {
	s.prepareMu.Lock()
	s.prepareErr = err
	s.prepareFailAt = failAt
	s.prepareCount = 0
	s.prepareMu.Unlock()
}

func (s *attrsManagerRaceStore) ResolveSecret(ctx context.Context, ref string, version uint64) (eventstore.SecretResolution, error) {
	resolution, err := s.secrets.ResolveSecret(ctx, ref, version)
	if err == nil && s.resolveEntered != nil {
		pause := false
		s.resolveOnce.Do(func() {
			pause = true
			close(s.resolveEntered)
		})
		if pause {
			<-s.resolveRelease
		}
	}
	return resolution, err
}

func (s *attrsManagerRaceStore) Commit(ctx context.Context, work eventstore.UnitOfWork) (eventstore.CommitResult, error) {
	result, err := s.GORMStore.Commit(ctx, work)
	if err == nil && s.commitEntered != nil {
		s.commitOnce.Do(func() {
			close(s.commitEntered)
			<-s.commitRelease
		})
	}
	return result, err
}

func newAttrsManagerRaceFixture(t *testing.T, wrapped *attrsManagerRaceStore) (*AttrsManager, *eventstore.Database) {
	t.Helper()
	ctx := context.Background()
	database, err := eventstore.OpenDatabase(ctx, eventstore.DatabaseConfig{Type: "sqlite", DSN: filepath.Join(t.TempDir(), "attrs.db")})
	if err != nil {
		t.Fatal(err)
	}
	base := eventstore.NewStore(database, eventstore.WithKeySource(compatKeySource{}), eventstore.WithProjection(attributestate.Projection()))
	if err = base.SetReadiness(ctx, eventstore.Readiness{
		Mode: "import", SchemaVersion: 1, DatabaseIdentity: "attrs-race-test", IndexRootID: "index-v1",
		EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32),
		TargetManifestDigest: make([]byte, 32), CompletedAt: time.Unix(1, 0).UTC(),
	}); err != nil {
		database.Close()
		t.Fatal(err)
	}
	if wrapped == nil {
		wrapped = &attrsManagerRaceStore{}
	}
	wrapped.GORMStore = base
	wrapped.secrets = base
	manager := &AttrsManager{}
	die := &Dice{BaseConfig: BaseConfig{Name: "dice-attrs-race"}, DurableStore: wrapped, Logger: zap.NewNop().Sugar()}
	if err = manager.InitDurable(die); err != nil {
		database.Close()
		t.Fatal(err)
	}
	return manager, database
}

func waitAttrsRaceSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for attribute persistence barrier")
	}
}

func activeAttrsCacheGenerationSlots(manager *AttrsManager) int {
	manager.cacheMu.Lock()
	defer manager.cacheMu.Unlock()
	return len(manager.cacheGenerations)
}

func TestAttrsManagerPostSerializationMutationRemainsDirty(t *testing.T) {
	store := &attrsManagerRaceStore{prepareEntered: make(chan struct{}), prepareRelease: make(chan struct{})}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()
	defer func() {
		select {
		case <-store.prepareRelease:
		default:
			close(store.prepareRelease)
		}
	}()

	item, err := manager.LoadById("QQ-Group:301-QQ:401")
	if err != nil {
		t.Fatal(err)
	}
	item.Store("hp", ds.NewIntVal(1))
	saveDone := make(chan error, 1)
	go func() { saveDone <- manager.saveItem(item) }()
	waitAttrsRaceSignal(t, store.prepareEntered)
	item.Store("hp", ds.NewIntVal(2))
	close(store.prepareRelease)
	if err = <-saveDone; err != nil {
		t.Fatal(err)
	}
	if item.IsSaved {
		t.Fatal("save marked an item clean after a post-serialization mutation")
	}

	if err = manager.CheckForSave(); err != nil {
		t.Fatal(err)
	}
	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	state, data, err := repository.Load(context.Background(), manager.diceID, item.ID)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ds.VMValueFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	values, ok := decoded.ReadDictData()
	if !ok {
		t.Fatal("persisted attributes are not a dictionary")
	}
	hp, exists := values.Dict.Load("hp")
	if !exists || hp.ToString() != "2" || state.Version != 2 {
		t.Fatalf("next save did not persist the post-serialization mutation: hp=%v exists=%v version=%d", hp, exists, state.Version)
	}
}

func TestAttrsManagerGroupInvalidationWinsAgainstPausedSavePublication(t *testing.T) {
	store := &attrsManagerRaceStore{commitEntered: make(chan struct{}), commitRelease: make(chan struct{})}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()
	defer func() {
		select {
		case <-store.commitRelease:
		default:
			close(store.commitRelease)
		}
	}()

	groupID, userID := "QQ-Group:302", "QQ:402"
	id := groupID + "-" + userID
	item, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	state, _ := manager.states.Load(id)
	state.BindingSheetID = "stale-character"
	manager.states.Store(id, state)
	item.Store("hp", ds.NewIntVal(10))
	saveDone := make(chan error, 1)
	go func() { saveDone <- manager.saveItem(item) }()
	waitAttrsRaceSignal(t, store.commitEntered)

	manager.DeleteCachedGroupData(groupID, true, true)
	close(store.commitRelease)
	if err = <-saveDone; err != nil {
		t.Fatal(err)
	}
	if _, exists := manager.states.Load(id); exists {
		t.Fatal("save republished group state after privacy invalidation completed")
	}
	if _, exists := manager.m.Load(id); exists {
		t.Fatal("save republished the invalidated group-user attribute item")
	}
}
func TestAttrsManagerCallbackInvalidationWinsAgainstPausedSavePublication(t *testing.T) {
	store := &attrsManagerRaceStore{commitEntered: make(chan struct{}), commitRelease: make(chan struct{})}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()
	defer func() {
		select {
		case <-store.commitRelease:
		default:
			close(store.commitRelease)
		}
	}()

	id := "QQ-Group:304-QQ:404"
	item, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	item.Store("hp", ds.NewIntVal(10))
	saveDone := make(chan error, 1)
	go func() { saveDone <- manager.saveItem(item) }()
	waitAttrsRaceSignal(t, store.commitEntered)

	manager.InvalidateCachedAttributes([]string{id})
	close(store.commitRelease)
	if err = <-saveDone; err != nil {
		t.Fatal(err)
	}
	if _, exists := manager.states.Load(id); exists {
		t.Fatal("save republished callback-invalidated attribute state")
	}
	if _, exists := manager.m.Load(id); exists {
		t.Fatal("save republished callback-invalidated attribute item")
	}
}

func TestAttrsManagerInvalidatedItemCannotSaveButFreshGenerationCan(t *testing.T) {
	store := &attrsManagerRaceStore{}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()

	groupID, userID := "QQ-Group:303", "QQ:403"
	id := groupID + "-" + userID
	staleItem, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	staleItem.Store("hp", ds.NewIntVal(1))
	if err = manager.saveItem(staleItem); err != nil {
		t.Fatal(err)
	}
	staleItem.Store("hp", ds.NewIntVal(2))

	manager.DeleteCachedGroupData(groupID, true, true)
	if err = manager.saveItem(staleItem); !errors.Is(err, errInvalidatedAttributeCache) {
		t.Fatalf("stale attribute item was not rejected after invalidation: %v", err)
	}

	repository, err := attributestate.NewRepository(store)
	if err != nil {
		t.Fatal(err)
	}
	state, data, err := repository.Load(context.Background(), manager.diceID, id)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := ds.VMValueFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	values, ok := decoded.ReadDictData()
	if !ok {
		t.Fatal("persisted attributes are not a dictionary")
	}
	hp, exists := values.Dict.Load("hp")
	if !exists || hp.ToString() != "1" || state.Version != 1 {
		t.Fatalf("rejected stale save changed durable attributes: hp=%v exists=%v version=%d", hp, exists, state.Version)
	}

	freshItem, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	if freshItem == staleItem {
		t.Fatal("post-invalidation load returned the stale attribute item")
	}
	freshItem.Store("hp", ds.NewIntVal(3))
	if err = manager.saveItem(freshItem); err != nil {
		t.Fatalf("fresh attribute generation could not save: %v", err)
	}
	state, data, err = repository.Load(context.Background(), manager.diceID, id)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = ds.VMValueFromJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	values, ok = decoded.ReadDictData()
	if !ok {
		t.Fatal("fresh generation persisted attributes are not a dictionary")
	}
	hp, exists = values.Dict.Load("hp")
	if !exists || hp.ToString() != "3" || state.Version != 2 {
		t.Fatalf("fresh generation did not persist: hp=%v exists=%v version=%d", hp, exists, state.Version)
	}
}

func TestAttrsManagerFailedCharBindIsInvisibleToCharacterReads(t *testing.T) {
	store := &attrsManagerRaceStore{}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()

	groupID, userID := "SEALCHAT-Group:race-group", "SEALCHAT:race-user"
	characterID := "SEALCHAT:race-character"
	character, err := manager.LoadById(characterID)
	if err != nil {
		t.Fatal(err)
	}
	character.Store("hp", ds.NewIntVal(90))
	if err = manager.saveItem(character); err != nil {
		t.Fatal(err)
	}
	defaultAttrs, err := manager.LoadById(groupID + "-" + userID)
	if err != nil {
		t.Fatal(err)
	}
	defaultAttrs.Store("hp", ds.NewIntVal(1))

	store.setPrepareFailure(errors.New("injected secret preparation failure"), 0)
	if err = manager.CharBind(characterID, groupID, userID); err == nil {
		t.Fatal("CharBind succeeded despite durable save failure")
	}
	binding, err := manager.CharGetBindingId(groupID, userID)
	if err != nil || binding != "" {
		t.Fatalf("failed binding became visible to AttrsManager: binding=%q err=%v", binding, err)
	}
	response := NewCharacterService(&Dice{AttrsManager: manager}).get(adapterapi.CharacterRequest{GroupID: "race-group", UserID: "race-user"})
	if !response.OK || fmt.Sprint(response.Attributes["hp"]) != "1" {
		t.Fatalf("failed binding became visible to CharacterService reads: response=%#v", response)
	}
}
func TestAttrsManagerEvictionFencesOldItem(t *testing.T) {
	manager, database := newAttrsManagerRaceFixture(t, &attrsManagerRaceStore{})
	defer database.Close()
	defer manager.Stop()

	id := "QQ-Group:405-QQ:505"
	item, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	item.Store("hp", ds.NewIntVal(1))
	if err = manager.saveItem(item); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-11 * time.Minute).Unix()
	item.LastUsedTime = old
	item.LastModifiedTime = old
	if err = manager.CheckAndFreeUnused(); err != nil {
		t.Fatal(err)
	}

	item.Store("hp", ds.NewIntVal(2))
	if err = manager.saveItem(item); !errors.Is(err, errInvalidatedAttributeCache) {
		t.Fatalf("evicted item save err=%v, want invalidated cache", err)
	}
	fresh, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == item {
		t.Fatal("load after eviction returned the retained item")
	}
	if hp := fresh.Load("hp"); hp == nil || hp.ToString() != "1" {
		t.Fatalf("evicted item overwrote durable value: hp=%v", hp)
	}
}

func TestAttrsManagerEvictionSkipsSaveInProgress(t *testing.T) {
	store := &attrsManagerRaceStore{}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()

	const id = "QQ-Group:406-QQ:506"
	item, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	item.Store("hp", ds.NewIntVal(1))
	if err = manager.saveItem(item); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-11 * time.Minute).Unix()
	item.LastUsedTime = old
	item.LastModifiedTime = old

	store.commitEntered = make(chan struct{})
	store.commitRelease = make(chan struct{})
	defer func() {
		select {
		case <-store.commitRelease:
		default:
			close(store.commitRelease)
		}
	}()
	saveDone := make(chan error, 1)
	go func() { saveDone <- manager.saveItem(item) }()
	waitAttrsRaceSignal(t, store.commitEntered)

	cleanupDone := make(chan error, 1)
	go func() { cleanupDone <- manager.CheckAndFreeUnused() }()
	select {
	case err = <-cleanupDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cache cleanup blocked behind an in-progress save")
	}
	if cached, exists := manager.m.Load(id); !exists || cached != item {
		t.Fatal("cache cleanup evicted an item while its save was in progress")
	}

	close(store.commitRelease)
	if err = <-saveDone; err != nil {
		t.Fatal(err)
	}
}

func TestAttrsManagerFailedCharDeleteKeepsDurableStateVisible(t *testing.T) {
	store := &attrsManagerRaceStore{}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()

	character, err := manager.CharNew("QQ:606", "Alice", "coc7")
	if err != nil {
		t.Fatal(err)
	}
	item, err := manager.LoadById(character.Id)
	if err != nil {
		t.Fatal(err)
	}
	item.Store("hp", ds.NewIntVal(90))
	if err = manager.saveItem(item); err != nil {
		t.Fatal(err)
	}

	store.setPrepareFailure(errors.New("injected secret preparation failure"), 0)
	if err = manager.CharDelete(character.Id); err == nil {
		t.Fatal("character deletion succeeded despite secret preparation failure")
	}
	store.setPrepareFailure(nil, 0)

	fresh, err := manager.LoadById(character.Id)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == item || fresh.Name != "Alice" {
		t.Fatalf("failed deletion published its tombstone: item=%p old=%p name=%q", fresh, item, fresh.Name)
	}
	if hp := fresh.Load("hp"); hp == nil || hp.ToString() != "90" {
		t.Fatalf("failed deletion hid persisted attributes: hp=%v", hp)
	}
	state, _, err := manager.durable.Load(context.Background(), manager.diceID, character.Id)
	if err != nil || state.AttrsType != "character" || state.Name != "Alice" {
		t.Fatalf("failed deletion changed projected character state: state=%+v err=%v", state, err)
	}
}

func TestAttrsManagerCharUnbindAllIsAtomicOnPreparationFailure(t *testing.T) {
	store := &attrsManagerRaceStore{}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()

	character, err := manager.CharNew("QQ:606", "Atomic", "coc7")
	if err != nil {
		t.Fatal(err)
	}
	targets := []struct {
		groupID string
		userID  string
	}{
		{groupID: "QQ-Group:410", userID: "QQ:610"},
		{groupID: "QQ-Group:420", userID: "QQ:620"},
	}
	for _, target := range targets {
		if err = manager.CharBind(character.Id, target.groupID, target.userID); err != nil {
			t.Fatal(err)
		}
	}

	store.setPrepareFailure(errors.New("injected second secret preparation failure"), 2)
	if groups := manager.CharUnbindAll(character.Id); groups != nil {
		t.Fatalf("failed atomic unbind returned success groups %v", groups)
	}
	store.setPrepareFailure(nil, 0)
	for _, target := range targets {
		state, _, loadErr := manager.durable.Load(context.Background(), manager.diceID, target.groupID+"-"+target.userID)
		if loadErr != nil || state.BindingSheetID != character.Id {
			t.Fatalf("failed batch partially unbound %s: binding=%q err=%v", target.groupID, state.BindingSheetID, loadErr)
		}
	}
}

func TestAttrsManagerCallbackUnbindLoadsEveryTargetBeforeStaging(t *testing.T) {
	store := &attrsManagerRaceStore{}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()

	character, err := manager.CharNew("QQ:606", "Callback", "coc7")
	if err != nil {
		t.Fatal(err)
	}
	validID := "QQ-Group:410-QQ:610"
	missingSecretID := "QQ-Group:420-QQ:620"
	for _, id := range []string{validID, missingSecretID} {
		groupID, userID, ok := UnpackGroupUserId(id)
		if !ok {
			t.Fatalf("invalid test group-user id %q", id)
		}
		if err = manager.CharBind(character.Id, groupID, userID); err != nil {
			t.Fatal(err)
		}
	}
	if err = database.GORM().Exec("DELETE FROM adapter_secrets WHERE secret_ref = ?", attributestate.SecretRef(manager.diceID, missingSecretID)).Error; err != nil {
		t.Fatal(err)
	}
	if _, _, err = manager.durable.Load(context.Background(), manager.diceID, missingSecretID); !errors.Is(err, attributestate.ErrSecretUnavailable) || errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("missing snapshot secret load err=%v, want only ErrSecretUnavailable", err)
	}
	manager.invalidateCachedAttribute(missingSecretID)
	if _, err = manager.LoadById(missingSecretID); !errors.Is(err, attributestate.ErrSecretUnavailable) || errors.Is(err, eventstore.ErrNotFound) {
		t.Fatalf("missing snapshot secret created an empty cached attribute: err=%v", err)
	}

	transaction, err := NewDurableCallbackTransaction(store, messageflow.NewMutationCollector(eventstore.EventFactory{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := &MsgContext{callbackTransaction: transaction}
	if groups := manager.stageCallbackUnbinds(ctx, []string{validID, missingSecretID}); groups != nil {
		t.Fatalf("callback unbind succeeded despite a missing later target: %v", groups)
	}
	state, exists := transaction.AttributeState(manager.diceID, validID)
	if !exists || state.BindingSheetID != character.Id {
		t.Fatalf("callback staged an early unbind before all loads succeeded: state=%+v exists=%v", state, exists)
	}
	if _, exists := transaction.AttributeState(manager.diceID, missingSecretID); exists {
		t.Fatal("callback staged a target whose encrypted state could not be loaded")
	}
}
func TestAttrsManagerPrivateGroupInvalidationFencesPausedLoad(t *testing.T) {
	tests := []struct {
		name    string
		groupID string
		userID  string
	}{
		{name: "qq-private", groupID: "PG-QQ:700", userID: "QQ:701"},
		{name: "official-qq-private", groupID: "PG-OpenQQCH:private-700", userID: "OpenQQCH:private-700"},
		{name: "official-qq-channel", groupID: "OpenQQCH-Channel:guild-1-channel-1", userID: "OpenQQCH:user-701"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assertAttrsManagerGroupUserInvalidationFencesPausedLoad(t, test.groupID, test.userID)
		})
	}
}

func assertAttrsManagerGroupUserInvalidationFencesPausedLoad(t *testing.T, groupID, userID string) {
	t.Helper()
	store := &attrsManagerRaceStore{resolveEntered: make(chan struct{}), resolveRelease: make(chan struct{})}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()
	defer func() {
		select {
		case <-store.resolveRelease:
		default:
			close(store.resolveRelease)
		}
	}()

	id := groupID + "-" + userID
	parsedGroupID, parsedUserID, ok := UnpackGroupUserId(id)
	if !ok || parsedGroupID != groupID || parsedUserID != userID {
		t.Fatalf("invalid group-user test ID %q: group=%q user=%q ok=%v", id, parsedGroupID, parsedUserID, ok)
	}
	item, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	item.Store("hp", ds.NewIntVal(1))
	if err = manager.saveItem(item); err != nil {
		t.Fatal(err)
	}
	manager.invalidateCachedAttribute(id)

	type loadResult struct {
		item *AttributesItem
		err  error
	}
	loaded := make(chan loadResult, 1)
	go func() {
		attribute, loadErr := manager.LoadById(id)
		loaded <- loadResult{item: attribute, err: loadErr}
	}()
	waitAttrsRaceSignal(t, store.resolveEntered)

	rowKey := attributestate.Stream(manager.diceID, id).AggregateID
	if err = database.GORM().Exec("DELETE FROM projection_read_models WHERE projection_name = ? AND row_key = ?", attributestate.ProjectionName, rowKey).Error; err != nil {
		t.Fatal(err)
	}
	if err = database.GORM().Exec("DELETE FROM adapter_secrets WHERE secret_ref = ?", attributestate.SecretRef(manager.diceID, id)).Error; err != nil {
		t.Fatal(err)
	}
	manager.DeleteCachedGroupData(groupID, false, true)
	close(store.resolveRelease)

	var result loadResult
	select {
	case result = <-loaded:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for paused group-user load")
	}
	if result.err != nil {
		t.Fatal(result.err)
	}
	if result.item.Len() != 0 {
		t.Fatal("pre-invalidation group-user plaintext was republished")
	}
	state, exists := manager.states.Load(id)
	if !exists || state.Version != 0 || state.AttrsType != service.AttrsTypeGroupUser {
		t.Fatalf("post-invalidation state = %+v, exists=%v; want empty group-user source state", state, exists)
	}
	manager.invalidateCachedAttribute(id)
	if slots := activeAttrsCacheGenerationSlots(manager); slots != 0 {
		t.Fatalf("group invalidation left %d active cache generation slots after the retry result was released", slots)
	}
	reloaded, err := manager.LoadById(id)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Len() != 0 {
		t.Fatal("reclaimed group generation allowed pre-invalidation plaintext to reappear")
	}
}

func TestAttrsManagerBareGroupAttributesUseGroupPrivacyScope(t *testing.T) {
	tests := []struct {
		name    string
		groupID string
	}{
		{name: "private-qq", groupID: "PG-QQ:702"},
		{name: "official-qq-channel", groupID: "OpenQQCH-Channel:guild-1-channel-2"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manager, database := newAttrsManagerRaceFixture(t, nil)
			defer database.Close()
			defer manager.Stop()

			item, err := manager.LoadById(test.groupID)
			if err != nil {
				t.Fatal(err)
			}
			item.Store("g", ds.NewIntVal(1))
			if err = manager.saveItem(item); err != nil {
				t.Fatal(err)
			}
			state, exists := manager.states.Load(test.groupID)
			if !exists {
				t.Fatal("group attribute state was not published")
			}
			if state.AttrsType != service.AttrsTypeGroup || len(state.PrivacySubjectKey) == 0 {
				t.Fatalf("group state lacks group privacy scope: %+v", state)
			}
			wantGroupKey := groupCacheKeyFor(test.groupID, service.AttrsTypeGroup)
			if item.cacheGroupKey != wantGroupKey {
				t.Fatalf("group cache key = %q, want %q", item.cacheGroupKey, wantGroupKey)
			}

			manager.DeleteCachedGroupData(test.groupID, true, false)
			if _, exists = manager.m.Load(test.groupID); exists {
				t.Fatal("group invalidation did not evict group attributes")
			}
		})
	}
}

func TestAttrsManagerGenerationReclamationDoesNotReviveRetainedItem(t *testing.T) {
	manager, database := newAttrsManagerRaceFixture(t, nil)
	defer database.Close()
	defer manager.Stop()

	const retainedID = "QQ-Group:811-QQ:911"
	retained, err := manager.LoadById(retainedID)
	if err != nil {
		t.Fatal(err)
	}
	retained.Store("hp", ds.NewIntVal(1))
	if err = manager.saveItem(retained); err != nil {
		t.Fatal(err)
	}
	manager.invalidateCachedAttribute(retainedID)

	for index := range 512 {
		id := fmt.Sprintf("QQ-Group:%d-QQ:%d", 10000+index, 20000+index)
		if _, err = manager.LoadById(id); err != nil {
			t.Fatal(err)
		}
		manager.invalidateCachedAttribute(id)
	}
	if slots := activeAttrsCacheGenerationSlots(manager); slots != 0 {
		t.Fatalf("cache generations retained %d historical slots after high churn", slots)
	}

	retained.Store("hp", ds.NewIntVal(2))
	if err = manager.saveItem(retained); !errors.Is(err, errInvalidatedAttributeCache) {
		t.Fatalf("retained item became saveable after generation reclamation: %v", err)
	}
	fresh, err := manager.LoadById(retainedID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh == retained {
		t.Fatal("generation reclamation returned the retained invalidated item")
	}
	if hp := fresh.Load("hp"); hp == nil || hp.ToString() != "1" {
		t.Fatalf("retained invalidated item changed durable data: hp=%v", hp)
	}
}

func TestAttrsManagerFailedLoadsReleaseGenerationSlots(t *testing.T) {
	t.Run("decode", func(t *testing.T) {
		manager, database := newAttrsManagerRaceFixture(t, nil)
		defer database.Close()
		defer manager.Stop()

		const id = "malformed-cache-generation"
		if _, err := manager.durable.Save(context.Background(), attributestate.State{
			DiceID: manager.diceID,
			ID:     id,
		}, []byte("{")); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.LoadById(id); err == nil {
			t.Fatal("malformed attribute payload unexpectedly loaded")
		}
		if slots := activeAttrsCacheGenerationSlots(manager); slots != 0 {
			t.Fatalf("failed decode leaked %d active cache generation slots", slots)
		}
	})

	t.Run("secret resolution", func(t *testing.T) {
		manager, database := newAttrsManagerRaceFixture(t, nil)
		defer database.Close()
		defer manager.Stop()

		const (
			groupID = "QQ-Group:812"
			id      = groupID + "-QQ:912"
		)
		item, err := manager.LoadById(id)
		if err != nil {
			t.Fatal(err)
		}
		item.Store("hp", ds.NewIntVal(1))
		if err = manager.saveItem(item); err != nil {
			t.Fatal(err)
		}
		manager.invalidateCachedAttribute(id)
		if err = database.GORM().Exec(
			"DELETE FROM adapter_secrets WHERE secret_ref = ?",
			attributestate.SecretRef(manager.diceID, id),
		).Error; err != nil {
			t.Fatal(err)
		}

		if _, err = manager.LoadById(id); !errors.Is(err, attributestate.ErrSecretUnavailable) {
			t.Fatalf("load with a missing secret err=%v, want ErrSecretUnavailable", err)
		}
		if slots := activeAttrsCacheGenerationSlots(manager); slots != 0 {
			t.Fatalf("failed group-user load leaked %d active cache generation slots", slots)
		}
	})
}

func TestAttrsManagerDeletedStateRebindsInferredGeneration(t *testing.T) {
	store := &attrsManagerRaceStore{resolveEntered: make(chan struct{}), resolveRelease: make(chan struct{})}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()
	defer func() {
		select {
		case <-store.resolveRelease:
		default:
			close(store.resolveRelease)
		}
	}()
	const (
		groupID = "OpenQQ-Group-T:bot-group"
		id      = groupID + "-OpenQQ-Member-T:member"
	)
	values := &ds.ValueMap{}
	values.Store("hp", ds.NewIntVal(1))
	payload, err := ds.NewDictVal(values).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.durable.Save(context.Background(), attributestate.State{
		DiceID: manager.diceID, ID: id, AttrsType: service.AttrsTypeGroupUser,
	}, payload); err != nil {
		t.Fatal(err)
	}
	type result struct {
		item *AttributesItem
		err  error
	}
	done := make(chan result, 1)
	go func() {
		item, loadErr := manager.LoadById(id)
		done <- result{item, loadErr}
	}()
	<-store.resolveEntered
	if err = database.GORM().Exec("DELETE FROM projection_read_models WHERE projection_name = ? AND row_key = ?",
		attributestate.ProjectionName, attributestate.Stream(manager.diceID, id).AggregateID).Error; err != nil {
		t.Fatal(err)
	}
	if err = database.GORM().Exec("DELETE FROM adapter_secrets WHERE secret_ref = ?", attributestate.SecretRef(manager.diceID, id)).Error; err != nil {
		t.Fatal(err)
	}
	manager.DeleteCachedGroupData(groupID, false, true)
	close(store.resolveRelease)
	loaded := <-done
	if loaded.err != nil {
		t.Fatal(loaded.err)
	}
	if loaded.item.Load("hp") != nil {
		t.Fatal("deleted snapshot was restored from the first group's scope")
	}
	loaded.item.Store("hp", ds.NewIntVal(2))
	// Only the projection and secret were removed: the durable stream still
	// exists, so the optimistic conflict is expected. The fresh object must
	// not instead be permanently poisoned by the previous group's token.
	if err = manager.saveItem(loaded.item); !errors.Is(err, eventstore.ErrConflict) {
		t.Fatalf("fresh missing-state save = %v, want stream conflict, not invalidated cache", err)
	}
}

func TestAttrsManagerConcurrentColdReadersPersistEveryMutation(t *testing.T) {
	store := &attrsManagerRaceStore{resolveEntered: make(chan struct{}), resolveRelease: make(chan struct{})}
	manager, database := newAttrsManagerRaceFixture(t, store)
	defer database.Close()
	defer manager.Stop()
	defer func() {
		select {
		case <-store.resolveRelease:
		default:
			close(store.resolveRelease)
		}
	}()
	const id = "concurrent-cold-card"
	payload, err := ds.NewDictVal(&ds.ValueMap{}).V().ToJSON()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = manager.durable.Save(context.Background(), attributestate.State{
		DiceID: manager.diceID, ID: id, AttrsType: service.AttrsTypeCharacter,
	}, payload); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 32)
	var attemptingLoads sync.WaitGroup
	attemptingLoads.Add(32)
	for index := range 32 {
		go func() {
			<-start
			attemptingLoads.Done()
			item, loadErr := manager.LoadById(id)
			if loadErr == nil {
				item.Store(fmt.Sprintf("parallel-%d", index), ds.NewIntVal(ds.IntType(index)))
			}
			results <- loadErr
		}()
	}
	close(start)
	<-store.resolveEntered
	attemptingLoads.Wait()
	close(store.resolveRelease)
	for range 32 {
		if err = <-results; err != nil {
			t.Fatal(err)
		}
	}
	if err = manager.CheckForSave(); err != nil {
		t.Fatal(err)
	}
	_, saved, err := manager.durable.Load(context.Background(), manager.diceID, id)
	if err != nil {
		t.Fatal(err)
	}
	value, err := ds.VMValueFromJSON(saved)
	if err != nil {
		t.Fatal(err)
	}
	dict, ok := value.ReadDictData()
	if !ok {
		t.Fatal("parallel mutations did not persist as a dictionary")
	}
	for index := range 32 {
		got, exists := dict.Dict.Load(fmt.Sprintf("parallel-%d", index))
		if !exists || got.ToString() != strconv.Itoa(index) {
			t.Fatalf("concurrent cold reader lost mutation %d: %v", index, got)
		}
	}
}

func TestAttrsManagerInvalidatedColdLoadDoesNotBlockNextGeneration(t *testing.T) {
	for _, scope := range []string{"id", "group"} {
		t.Run(scope, func(t *testing.T) {
			store := &attrsManagerRaceStore{resolveEntered: make(chan struct{}), resolveRelease: make(chan struct{})}
			manager, database := newAttrsManagerRaceFixture(t, store)
			defer database.Close()
			defer manager.Stop()
			defer func() {
				select {
				case <-store.resolveRelease:
				default:
					close(store.resolveRelease)
				}
			}()
			const (
				groupID = "QQ-Group:coalesced"
				id      = groupID + "-QQ:reader"
			)
			payload := func(hp ds.IntType) []byte {
				values := &ds.ValueMap{}
				values.Store("hp", ds.NewIntVal(hp))
				data, err := ds.NewDictVal(values).V().ToJSON()
				if err != nil {
					t.Fatal(err)
				}
				return data
			}
			state, err := manager.durable.Save(context.Background(), attributestate.State{
				DiceID: manager.diceID, ID: id, AttrsType: service.AttrsTypeGroupUser,
			}, payload(1))
			if err != nil {
				t.Fatal(err)
			}
			type result struct {
				item *AttributesItem
				err  error
			}
			oldDone := make(chan result, 1)
			go func() {
				item, loadErr := manager.LoadById(id)
				oldDone <- result{item, loadErr}
			}()
			<-store.resolveEntered
			if _, err = manager.durable.Save(context.Background(), state, payload(2)); err != nil {
				t.Fatal(err)
			}
			if scope == "id" {
				manager.InvalidateCachedAttributes([]string{id})
			} else {
				manager.DeleteCachedGroupData(groupID, false, true)
			}
			newDone := make(chan result, 1)
			go func() {
				item, loadErr := manager.LoadById(id)
				newDone <- result{item, loadErr}
			}()
			var fresh result
			select {
			case fresh = <-newDone:
			case <-time.After(3 * time.Second):
				t.Fatal("new generation waited for invalidated I/O")
			}
			if fresh.err != nil {
				t.Fatal(fresh.err)
			}
			if hp := fresh.item.Load("hp"); hp == nil || hp.ToString() != "2" {
				t.Fatalf("new generation returned old plaintext: hp=%v", hp)
			}
			close(store.resolveRelease)
			old := <-oldDone
			if old.err != nil || old.item != fresh.item {
				t.Fatalf("stale completion did not converge on current data: err=%v", old.err)
			}
			fresh.item.Store("hp", ds.NewIntVal(3))
			if err = manager.CheckForSave(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
