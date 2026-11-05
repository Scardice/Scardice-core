package dice

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"Scardice-core/core/configstate"
	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
)

type canonicalFixtureClock struct{}

func (canonicalFixtureClock) Now() time.Time {
	return time.Unix(1, 0).UTC()
}

type canonicalFixtureIDs struct {
	prefix string
	next   atomic.Uint64
}

func (ids *canonicalFixtureIDs) NewID() (string, error) {
	return fmt.Sprintf("%s:event:%06d", ids.prefix, ids.next.Add(1)), nil
}

type canonicalTestRoot struct {
	Context     context.Context
	Transaction *DurableCallbackTransaction
	Collector   *execution.MutationCollector
	Metadata    eventstore.Metadata
}

func canonicalFixtureLabel(t *testing.T, label string) string {
	t.Helper()
	return fmt.Sprintf("fixture:%s:%s", t.Name(), label)
}

// newCanonicalTestDice builds the common real EventStore-backed test owner.
// Its SQLite database, projection set, keys, and immutable config view come
// from newDomainExecutionFixture; every invocation receives an isolated DB.
func newCanonicalTestDice(t *testing.T) (*Dice, *eventstore.GORMStore) {
	t.Helper()
	d, store := newDomainExecutionFixture(t)
	dataDir := t.TempDir()
	d.BaseConfig.DataDir = dataDir
	d.Logger = zap.NewNop().Sugar()
	d.CmdMap = CmdMapCls{}
	d.ExtRegistry = new(SyncMap[string, *ExtInfo])
	d.GameSystemMap = new(SyncMap[string, *GameSystemTemplate])
	d.Parent = &DiceManager{}
	d.ImSession = &IMSession{Parent: d, PendingQuits: new(SyncMap[string, *PendingQuitInfo])}
	d.AttrsManager = &AttrsManager{}
	if err := d.AttrsManager.InitDurable(d); err != nil {
		t.Fatalf("initialize durable attributes: %v", err)
	}
	t.Cleanup(d.AttrsManager.Stop)
	updateCanonicalTestConfig(t, d, func(config *Config) {
		config.BaseConfig.Name = d.BaseConfig.Name
		config.DataDir = dataDir
	})
	return d, store
}

// newCanonicalTestRoot opens an invocation-local root for read-your-writes
// tests. It is aborted automatically; tests which require persistence must use
// withCanonicalTestRoot instead.
func newCanonicalTestRoot(t *testing.T, d *Dice, label string) *canonicalTestRoot {
	t.Helper()
	if d == nil || d.DurableStore == nil {
		t.Fatal("canonical test root requires a durable Dice")
	}
	name := canonicalFixtureLabel(t, label)
	ctx := context.Background()
	metadata := eventstore.Metadata{
		CommandID:     name,
		CorrelationID: name,
		Producer:      "dice/test-fixture",
		OccurredAt:    canonicalFixtureClock{}.Now(),
	}
	collector := execution.NewMutationCollector(eventstore.EventFactory{
		Clock: canonicalFixtureClock{},
		IDs:   &canonicalFixtureIDs{prefix: name},
	})
	transaction, err := NewDurableCallbackTransaction(ctx, d.DurableStore, collector, metadata)
	if err != nil {
		t.Fatalf("open canonical test root: %v", err)
	}
	if err = d.ContributeConfigView(ctx, transaction.Domain()); err != nil {
		transaction.Abort()
		t.Fatalf("attach canonical config view: %v", err)
	}
	root := &canonicalTestRoot{Context: ctx, Transaction: transaction, Collector: collector, Metadata: metadata}
	t.Cleanup(transaction.Abort)
	return root
}

func newCanonicalTestMessageContext(t *testing.T, d *Dice, endpoint *EndPointInfo, message *Message, label string) *MsgContext {
	t.Helper()
	if d == nil || d.ImSession == nil || endpoint == nil || message == nil {
		t.Fatal("canonical message fixture is incomplete")
	}
	endpoint.Session = d.ImSession
	root := newCanonicalTestRoot(t, d, label)
	ctx, err := NewDomainMsgContext(root.Transaction, d, d.ImSession, endpoint, message)
	if err != nil {
		t.Fatalf("build canonical message context: %v", err)
	}
	ctx.callbackMetadata = root.Metadata
	ctx.executionContext = root.Context
	t.Cleanup(ctx.releaseExecutionState)
	return ctx
}

func withCanonicalTestRoot(t *testing.T, d *Dice, label string, run func(*DurableCallbackTransaction) error) {
	t.Helper()
	name := canonicalFixtureLabel(t, label)
	identity := d.DomainExecutionIdentity("test-fixture", name)
	if err := d.WithDomainExecution(context.Background(), identity, []byte(name), run); err != nil {
		t.Fatalf("commit canonical test root %q: %v", label, err)
	}
}

func withCanonicalTestMessageContext(t *testing.T, d *Dice, endpoint *EndPointInfo, message *Message, label string, run func(*MsgContext) error) {
	t.Helper()
	if endpoint == nil || message == nil {
		t.Fatal("canonical message fixture is incomplete")
	}
	endpoint.Session = d.ImSession
	withCanonicalTestRoot(t, d, label, func(transaction *DurableCallbackTransaction) error {
		ctx, err := NewDomainMsgContext(transaction, d, d.ImSession, endpoint, message)
		if err != nil {
			return err
		}
		ctx.callbackMetadata = transaction.metadata
		ctx.executionContext = transaction.executionContext
		defer ctx.releaseExecutionState()
		return run(ctx)
	})
}

func canonicalTestMessageExecutionIdentity(t *testing.T, d *Dice, endpoint *EndPointInfo, message *Message, parser messageParserMode) string {
	t.Helper()
	if parser == messageParserSegments {
		// executeIndependentMessage fills the text from segments before it
		// derives the execution identity.
		ensureMessageTextFromSegments(message)
	}
	canonical, err := json.Marshal(struct {
		EndpointID string            `json:"endpointId"`
		Parser     messageParserMode `json:"parser"`
		Message    *Message          `json:"message"`
	}{EndpointID: endpoint.ID, Parser: parser, Message: message})
	if err != nil {
		t.Fatalf("encode canonical message request: %v", err)
	}
	digest := sha256.Sum256(canonical)
	return d.DomainExecutionIdentity("direct-message", fmt.Sprintf("%s:%x", endpoint.ID, digest))
}

func awaitCanonicalTestExecutionCommit(t *testing.T, d *Dice, identity string) {
	t.Helper()
	repository, ok := d.DurableStore.(eventstore.ExecutionReceiptRepository)
	if !ok {
		t.Fatal("canonical test store does not expose execution receipts")
	}
	deadline := time.Now().Add(2 * time.Second)
	var (
		receipt eventstore.ExecutionReceipt
		lookup  error
	)
	for time.Now().Before(deadline) {
		receipt, lookup = repository.LookupExecution(context.Background(), identity)
		if lookup == nil && receipt.Status == eventstore.ExecutionStatusCommitted {
			return
		}
		if lookup == nil && receipt.Status == eventstore.ExecutionStatusAmbiguous {
			t.Fatalf("canonical message execution became ambiguous: %#v", receipt)
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("canonical message execution did not commit: receipt=%#v err=%v", receipt, lookup)
}

func executeNewAndWaitForCanonicalCommit(t *testing.T, d *Dice, endpoint *EndPointInfo, message *Message) {
	t.Helper()
	identity := canonicalTestMessageExecutionIdentity(t, d, endpoint, message, messageParserSegments)
	d.ImSession.ExecuteNew(endpoint, message)
	awaitCanonicalTestExecutionCommit(t, d, identity)
}

var canonicalTestMessageSequence atomic.Uint64

// executeCanonicalTestMessage runs one message through executeMessage inside
// its own invocation root, as executeIndependentMessage does, but returns the
// execution result for assertions. The root commits when the message returns.
func executeCanonicalTestMessage(ctx context.Context, d *Dice, endpoint *EndPointInfo, message *Message, options messageExecutionOptions) messageExecutionResult {
	identity := d.DomainExecutionIdentity("test-direct-message", fmt.Sprintf("%s:%d", endpoint.ID, canonicalTestMessageSequence.Add(1)))
	var result messageExecutionResult
	runErr := d.WithDomainExecution(ctx, identity, []byte(identity), func(transaction *DurableCallbackTransaction) error {
		options.callbackTransaction = transaction
		// A root cannot commit while command/hooks still mutate it.
		options.runInSync = true
		result = d.ImSession.executeMessage(endpoint, message, options)
		return result.err
	})
	if result.context != nil {
		result.context.releaseExecutionState()
	}
	if result.err == nil {
		result.err = runErr
	}
	return result
}

// seedCanonicalTestConfigBaseline imports the default config baseline into a
// hand-built EventStore owner and publishes its immutable config view. Config
// participants cannot open without a stored config stream.
func seedCanonicalTestConfigBaseline(t *testing.T, d *Dice) {
	t.Helper()
	ctx := context.Background()
	config, advanced := d.ConfigEditSnapshot()
	baseline, err := LegacyConfigBaseline(d.BaseConfig.Name, config, advanced, config.CommandPrefix, config.DiceMasters, "", "")
	if err != nil {
		t.Fatalf("build canonical config baseline: %v", err)
	}
	if _, err := configstate.NewRepository(d.DurableStore).DecideAndAppend(ctx, configstate.State{}, 0, eventstore.Metadata{}, configstate.Command{
		Kind: configstate.CommandImportBaseline, Baseline: &baseline,
	}); err != nil {
		t.Fatalf("import canonical config baseline: %v", err)
	}
	if err := d.ReloadConfigView(ctx); err != nil {
		t.Fatalf("publish canonical config view: %v", err)
	}
}

func updateCanonicalTestConfig(t *testing.T, d *Dice, mutate func(*Config)) {
	t.Helper()
	config, _ := d.ConfigEditSnapshot()
	if mutate != nil {
		mutate(&config)
	}
	if err := d.DurableCommitConfigSnapshot(context.Background(), config, config.CommandPrefix, config.DiceMasters, nil); err != nil {
		t.Fatalf("persist canonical config fixture: %v", err)
	}
}
func updateCanonicalTestAdvancedConfig(t *testing.T, d *Dice, mutate func(*AdvancedConfig)) {
	t.Helper()
	_, advanced := d.ConfigEditSnapshot()
	if mutate != nil {
		mutate(&advanced)
	}
	if err := d.DurableCommitAdvancedSnapshot(context.Background(), advanced, nil); err != nil {
		t.Fatalf("persist canonical advanced config fixture: %v", err)
	}
}

func installCanonicalTestExtensions(d *Dice, extensions ...*ExtInfo) {
	d.ExtRegistry = new(SyncMap[string, *ExtInfo])
	d.ExtList = append([]*ExtInfo(nil), extensions...)
	for _, extension := range extensions {
		if extension == nil || extension.Name == "" {
			continue
		}
		extension.dice = d
		d.ExtRegistry.Store(extension.Name, extension)
		for _, alias := range extension.Aliases {
			if alias != "" {
				d.ExtRegistry.Store(alias, extension)
			}
		}
	}
	atomic.AddInt64(&d.ExtRegistryVersion, 1)
}

func newCanonicalTestEndpoint(d *Dice, userID string) *EndPointInfo {
	endpoint := &EndPointInfo{EndPointInfoBase: EndPointInfoBase{
		ID:       "fixture-endpoint:" + userID,
		UserID:   userID,
		Nickname: "FixtureBot",
		Platform: "QQ",
		Enable:   true,
	}}
	if d != nil {
		endpoint.Session = d.ImSession
	}
	return endpoint
}
