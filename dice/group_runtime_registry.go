package dice

import (
	"sync"
	"sync/atomic"

	"golang.org/x/time/rate"
)

type groupRuntimeKey struct {
	diceID  string
	groupID string
}

type playerRuntimeKey struct {
	diceID  string
	groupID string
	userID  string
}

// GroupPlayerRuntimeRegistry owns process-local resources whose lifetime must
// outlive any one callback. It contains no durable group or player facts.
type GroupPlayerRuntimeRegistry struct {
	mu      sync.Mutex
	groups  map[groupRuntimeKey]*GroupRuntimeResources
	players map[playerRuntimeKey]*PlayerRuntimeResources
	// extensionDefaultsEpoch advances on every full extension-defaults apply.
	// Groups whose resources predate an advance re-enable AutoActive extensions
	// they had deactivated; groups first seen afterwards keep their decisions.
	extensionDefaultsEpoch atomic.Int64
}

func NewGroupPlayerRuntimeRegistry() *GroupPlayerRuntimeRegistry {
	return &GroupPlayerRuntimeRegistry{
		groups:  make(map[groupRuntimeKey]*GroupRuntimeResources),
		players: make(map[playerRuntimeKey]*PlayerRuntimeResources),
	}
}

func (r *GroupPlayerRuntimeRegistry) Group(diceID, groupID string) *GroupRuntimeResources {
	if r == nil || diceID == "" || groupID == "" {
		return nil
	}
	key := groupRuntimeKey{diceID: diceID, groupID: groupID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if resources := r.groups[key]; resources != nil {
		return resources
	}
	resources := &GroupRuntimeResources{
		logSequence:            &groupLogRuntime{},
		extensionDefaultsEpoch: &r.extensionDefaultsEpoch,
		extensionResetEpoch:    r.extensionDefaultsEpoch.Load(),
	}
	r.groups[key] = resources
	return resources
}

// AdvanceExtensionDefaultsEpoch marks every currently cached group as needing
// to re-apply AutoActive defaults over its historical deactivations.
func (r *GroupPlayerRuntimeRegistry) AdvanceExtensionDefaultsEpoch() {
	if r != nil {
		r.extensionDefaultsEpoch.Add(1)
	}
}

func (r *GroupRuntimeResources) currentExtensionDefaultsEpoch() int64 {
	if r == nil || r.extensionDefaultsEpoch == nil {
		return 0
	}
	return r.extensionDefaultsEpoch.Load()
}

func (r *GroupPlayerRuntimeRegistry) LookupGroup(diceID, groupID string) *GroupRuntimeResources {
	if r == nil || diceID == "" || groupID == "" {
		return nil
	}
	r.mu.Lock()
	resources := r.groups[groupRuntimeKey{diceID: diceID, groupID: groupID}]
	r.mu.Unlock()
	return resources
}

func (r *GroupPlayerRuntimeRegistry) Player(diceID, groupID, userID string) *PlayerRuntimeResources {
	if r == nil || diceID == "" || groupID == "" || userID == "" {
		return nil
	}
	key := playerRuntimeKey{diceID: diceID, groupID: groupID, userID: userID}
	r.mu.Lock()
	defer r.mu.Unlock()
	if resources := r.players[key]; resources != nil {
		return resources
	}
	resources := &PlayerRuntimeResources{}
	r.players[key] = resources
	return resources
}

func (r *GroupPlayerRuntimeRegistry) DeleteGroup(diceID, groupID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	key := groupRuntimeKey{diceID: diceID, groupID: groupID}
	if resources := r.groups[key]; resources != nil {
		resources.revoked.Store(true)
		delete(r.groups, key)
	}
	for playerKey, resources := range r.players {
		if playerKey.diceID == diceID && playerKey.groupID == groupID {
			resources.revoked.Store(true)
			delete(r.players, playerKey)
		}
	}
}

func (r *GroupPlayerRuntimeRegistry) DeletePlayer(diceID, groupID, userID string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	key := playerRuntimeKey{diceID: diceID, groupID: groupID, userID: userID}
	if resources := r.players[key]; resources != nil {
		resources.revoked.Store(true)
		delete(r.players, key)
	}
	r.mu.Unlock()
}

type GroupRuntimeResources struct {
	revoked              atomic.Bool
	limiterMu            sync.Mutex
	limiter              *rate.Limiter
	rateLimitWarned      bool
	spamLastCommand      string
	spamLastCommandAt    int64
	spamSameCommandCount int

	recentDiceSendTime atomic.Int64

	customReplyMu       sync.Mutex
	lastCustomReplyTime float64

	extensionMu                  sync.Mutex
	activatedExtensions          []*ExtInfo
	activatedExtensionIDs        []string
	extensionStateVersion        uint64
	extensionRegistryVersion     int64
	extensionAppliedTime         int64
	extensionDefaultsInitialized bool
	extensionDefaultsVersion     int64
	extensionCacheEpoch          uint64
	extensionDefaultsEpoch       *atomic.Int64
	extensionResetEpoch          int64

	rollShaperMu sync.Mutex
	rollShaper   *diceRollShaper

	logSequence *groupLogRuntime
}

// groupLogRuntime tracks provider sequence gaps independently from durable
// Story log selection.
type groupLogRuntime struct {
	mu        sync.Mutex
	logID     uint64
	lastSeq   int64
	lastMsgID interface{}
	selfSent  int64
	fillMu    sync.Mutex
}

type logSeqPosition struct {
	lastSeq   int64
	lastMsgID interface{}
	selfSent  int64
	rebuilt   bool
}

func (r *GroupRuntimeResources) allowCommand() bool {
	if r == nil || r.revoked.Load() {
		return false
	}
	r.limiterMu.Lock()
	defer r.limiterMu.Unlock()
	return r.limiter != nil && r.limiter.Allow()
}

type PlayerRuntimeResources struct {
	limiterMu            sync.Mutex
	revoked              atomic.Bool
	limiter              *rate.Limiter
	rateLimitWarned      bool
	spamLastCommand      string
	spamLastCommandAt    int64
	spamSameCommandCount int
}
