package dice

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"Scardice-core/adapterapi"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
)

type smokeKeyMaterial struct{ roots map[string][]byte }

func smokeKeySource() *smokeKeyMaterial {
	return &smokeKeyMaterial{roots: map[string][]byte{"root-v1": []byte("abcdefghijklmnopqrstuvwxyz123456")}}
}
func (s *smokeKeyMaterial) IndexRootID(context.Context) (string, error) { return "index-v1", nil }
func (s *smokeKeyMaterial) IndexRootMaterial(context.Context) ([]byte, error) {
	return []byte("01234567890123456789012345678901"), nil
}
func (s *smokeKeyMaterial) CurrentEncryptionRoot(ctx context.Context) (eventstore.EncryptionRoot, error) {
	material, err := s.EncryptionRoot(ctx, "root-v1")
	return eventstore.EncryptionRoot{ID: "root-v1", Material: material}, err
}

type smokeListenerHandoff struct {
	mu        sync.Mutex
	listeners map[string]net.Listener
}

func newSmokeListenerHandoff() *smokeListenerHandoff {
	return &smokeListenerHandoff{listeners: make(map[string]net.Listener)}
}
func (h *smokeListenerHandoff) reserve(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	h.mu.Lock()
	h.listeners[address] = listener
	h.mu.Unlock()
	t.Cleanup(func() {
		h.mu.Lock()
		if current := h.listeners[address]; current == listener {
			delete(h.listeners, address)
			_ = listener.Close()
		}
		h.mu.Unlock()
	})
	return address
}
func (h *smokeListenerHandoff) listen(network, address string) (net.Listener, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if listener := h.listeners[address]; listener != nil {
		delete(h.listeners, address)
		return listener, nil
	}
	return net.Listen(network, address)
}
func (h *smokeListenerHandoff) reserveAddress(t *testing.T, address string) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.listeners[address] = listener
	h.mu.Unlock()
	t.Cleanup(func() {
		h.mu.Lock()
		if current := h.listeners[address]; current == listener {
			delete(h.listeners, address)
			_ = listener.Close()
		}
		h.mu.Unlock()
	})
}
func (s *smokeKeyMaterial) EncryptionRoot(_ context.Context, id string) ([]byte, error) {
	material, ok := s.roots[id]
	if !ok {
		return nil, eventstore.ErrKeyUnavailable
	}
	return append([]byte(nil), material...), nil
}
func openSmokeBootstrap(t *testing.T, path string, source *smokeKeyMaterial, descriptor adapterapi.Descriptor) (*endpoint.Bootstrap, *eventstore.Database) {
	t.Helper()
	db, err := eventstore.OpenDatabase(context.Background(), eventstore.DatabaseConfig{Type: "sqlite", DSN: path, KeySource: source, DatabaseIdentity: "smoke-db"})
	if err != nil {
		t.Fatal(err)
	}
	store := eventstore.NewStore(db, eventstore.WithKeySource(source))
	readiness, readinessErr := store.GetReadiness(context.Background())
	if readinessErr != nil || (readiness.Mode == "fresh" && readiness.TerminalGlobalPosition == 0) {
		if err := store.SetReadiness(context.Background(), eventstore.Readiness{Mode: "import", SchemaVersion: 1, DatabaseIdentity: "smoke-db", IndexRootID: "index-v1", EncryptionRootIDs: []string{"root-v1"}, SourceManifestDigest: make([]byte, 32), TargetManifestDigest: make([]byte, 32), CompletedAt: time.Now().UTC()}); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	bootstrap, err := endpoint.NewBootstrap(store, nil, descriptor)
	if err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return bootstrap, db
}
func registerSmokeCleanup(t *testing.T, bootstrap *endpoint.Bootstrap, db *eventstore.Database) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if bootstrap != nil {
			_ = bootstrap.Shutdown(ctx)
		}
		if db != nil {
			_ = db.Close()
		}
	})
}
func syncSmokeReadiness(t *testing.T, store *eventstore.GORMStore, db *eventstore.Database) {
	t.Helper()
	readiness, err := store.GetReadiness(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var global struct {
		Position uint64 `gorm:"column:position"`
	}
	if err := db.GORM().Table("domain_events").Select("COALESCE(MAX(global_position), 0) AS position").Scan(&global).Error; err != nil {
		t.Fatal(err)
	}
	var projection struct {
		Position uint64 `gorm:"column:position"`
	}
	if err := db.GORM().Table("projection_control").Select("terminal_position AS position").Where("singleton_id = ?", "default").Scan(&projection).Error; err != nil {
		t.Fatal(err)
	}
	readiness.TerminalGlobalPosition = global.Position
	t.Logf("sync readiness global=%d projection=%d prior=%+v", global.Position, projection.Position, readiness)
	if err := store.SetReadiness(context.Background(), readiness); err != nil {
		t.Fatal(err)
	}
}
func waitSmokeReadinessQuiescent(t *testing.T, store *eventstore.GORMStore, db *eventstore.Database) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var global struct {
			Position uint64 `gorm:"column:position"`
		}
		var projection struct {
			Position uint64 `gorm:"column:position"`
		}
		if db.GORM().Table("domain_events").Select("COALESCE(MAX(global_position), 0) AS position").Scan(&global).Error == nil &&
			db.GORM().Table("projection_control").Select("terminal_position AS position").Where("singleton_id = ?", "default").Scan(&projection).Error == nil &&
			global.Position == projection.Position {
			time.Sleep(20 * time.Millisecond)
			var check struct {
				Position uint64 `gorm:"column:position"`
			}
			if db.GORM().Table("domain_events").Select("COALESCE(MAX(global_position), 0) AS position").Scan(&check).Error == nil && check.Position == global.Position {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("eventstore readiness did not quiesce")
}

func smokeConfig(t *testing.T, descriptor adapterapi.Descriptor, address, secretRef string) adapterapi.ValidatedConfig {
	t.Helper()
	raw := []byte(fmt.Sprintf(`{"mode":"server","listenAddress":%q,"reverseSuffix":"/ws","accountHint":"smoke","token":{"secretRef":%q,"version":1}}`, address, secretRef))
	config, err := descriptor.ValidateConfig(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func putSmokeSecret(t *testing.T, store eventstore.SecretRepository, id adapterapi.EndpointID, ref string) {
	t.Helper()
	if _, err := store.PutSecret(context.Background(), eventstore.SecretPutRequest{SecretRef: ref, EndpointID: string(id), AdapterID: "pureonebot", Plaintext: []byte("runtime-token")}); err != nil {
		t.Fatal(err)
	}
}

func waitSmokeView(t *testing.T, service *endpoint.Service, id adapterapi.EndpointID, predicate func(endpoint.EndpointView) bool) endpoint.EndpointView {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	var last endpoint.EndpointView
	for time.Now().Before(deadline) {
		view, err := service.Get(context.Background(), id)
		if err == nil {
			last = view
			if predicate(view) {
				return view
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for endpoint %s, last view=%+v", id, last)
	return last
}
func waitSmokeObservedState(t *testing.T, service *endpoint.Service, id adapterapi.EndpointID, state adapterapi.ObservedState) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		view, err := service.Get(context.Background(), id)
		if err == nil && view.ObservedState == state {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return false
}

func smokeDial(t *testing.T, address string) *websocket.Conn {
	t.Helper()
	var client *websocket.Conn
	var err error
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client, _, err = websocket.DefaultDialer.Dial("ws://"+address+"/ws", http.Header{"Authorization": []string{"Bearer runtime-token"}})
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	_, payload, readErr := client.ReadMessage()
	if readErr != nil {
		client.Close()
		t.Fatal(readErr)
	}
	var action struct {
		Action string `json:"action"`
		Echo   string `json:"echo"`
	}
	if err := json.Unmarshal(payload, &action); err != nil {
		client.Close()
		t.Fatal(err)
	}
	if action.Action != "get_login_info" || action.Echo == "" {
		client.Close()
		t.Fatalf("unexpected provider action=%q echo=%q", action.Action, action.Echo)
	}

	response := fmt.Sprintf(`{"status":"ok","retcode":0,"data":{"user_id":12345,"nickname":"smoke-bot"},"echo":%q}`, action.Echo)
	if err := client.WriteMessage(websocket.TextMessage, []byte(response)); err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}
func waitSmokePortClosed(t *testing.T, address string) {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 80*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("listener %s remained open", address)
}

func TestOnebotEndpointLifecycleReloginAndRestartReconciliation(t *testing.T) {
	ctx := context.Background()
	source := smokeKeySource()
	handoff := newSmokeListenerHandoff()
	descriptor := newOnebotDescriptorWithListenerFactory(handoff.listen)
	dbPath := filepath.Join(t.TempDir(), "pureonebot-smoke.db")
	bootstrap, db := openSmokeBootstrap(t, dbPath, source, descriptor)
	store, ok := bootstrap.Store.(eventstore.SecretRepository)
	if !ok {
		t.Fatal("bootstrap store does not expose secret repository")
	}
	registerSmokeCleanup(t, bootstrap, db)
	id := adapterapi.EndpointID("smoke-onebot")
	address := handoff.reserve(t)
	id2 := adapterapi.EndpointID("smoke-replay-enabled")
	address2 := handoff.reserve(t)
	putSmokeSecret(t, store, id2, "smoke-token-replay")
	putSmokeSecret(t, store, id, "smoke-token")
	config := smokeConfig(t, descriptor, address, "smoke-token")
	created, err := bootstrap.Execute(ctx, endpoint.Command{Kind: endpoint.CommandCreate, Type: endpoint.CommandCreate, CommandID: "smoke-create", CorrelationID: "smoke-create", EndpointID: id, AdapterKey: adapterapi.AdapterKey("pureonebot"), Config: config})
	if err != nil {
		t.Fatal(err)
	}
	if created.State.Version == 0 {
		t.Fatalf("create state=%+v", created.State)
	}
	if _, err := bootstrap.Execute(ctx, endpoint.Command{Kind: endpoint.CommandEnable, Type: endpoint.CommandEnable, CommandID: "smoke-enable", CorrelationID: "smoke-enable", EndpointID: id, ExpectedVersion: created.State.Version, ExpectedVersionSet: true}); err != nil {
		t.Fatal(err)
	}
	startingWorker, ok := bootstrap.Supervisor.Worker(id)
	if !ok || startingWorker.Generation == 0 || startingWorker.Exited {
		t.Fatalf("starting worker inspection=%+v present=%v", startingWorker, ok)
	}
	t.Logf("lifecycle starting endpoint=%s generation=%d worker_count=%d", id, startingWorker.Generation, bootstrap.Supervisor.WorkerCount())
	// A TCP-open listener is the observable starting boundary; the login response
	// below is the real provider handshake that advances the aggregate to connected.
	conn := smokeDial(t, address)
	connected := waitSmokeView(t, bootstrap.Service, id, func(view endpoint.EndpointView) bool {
		return view.ObservedState == adapterapi.ObservedStateConnected && view.OperationState == endpoint.OperationStateSucceeded
	})
	if connected.OperationID == "" || connected.Generation == 0 {
		t.Fatalf("connected view lost operation identity: %+v", connected)
	}
	t.Logf("lifecycle connected endpoint=%s generation=%d operation=%s", id, connected.Generation, connected.OperationID)
	// The protocol end drops the connection and comes back to the same
	// listener: the runtime keeps its generation and records both changes.
	if err := conn.UnderlyingConn().Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("remote disconnect observed on real WebSocket endpoint %s", id)
	_ = conn.Close()
	if !waitSmokeObservedState(t, bootstrap.Service, id, adapterapi.ObservedStateFailed) {
		t.Fatalf("remote disconnect did not publish a failed observation")
	}
	back := smokeDial(t, address)
	restored := waitSmokeView(t, bootstrap.Service, id, func(view endpoint.EndpointView) bool {
		return view.ObservedState == adapterapi.ObservedStateConnected && view.OperationState == endpoint.OperationStateSucceeded
	})
	if restored.Generation != connected.Generation {
		t.Fatalf("reconnection changed the generation: first=%d restored=%d", connected.Generation, restored.Generation)
	}
	if worker, ok := bootstrap.Supervisor.Worker(id); !ok || worker.Exited || worker.Generation != connected.Generation {
		t.Fatalf("worker after reconnection=%+v present=%v", worker, ok)
	}
	t.Logf("lifecycle reconnected endpoint=%s on the same generation %d", id, restored.Generation)
	_ = back.UnderlyingConn().Close()
	_ = back.Close()
	if !waitSmokeObservedState(t, bootstrap.Service, id, adapterapi.ObservedStateFailed) {
		t.Fatalf("second disconnect did not publish a failed observation")
	}

	// An explicit relogin still replaces the runtime with a new generation.
	if _, err := bootstrap.Execute(ctx, endpoint.Command{Kind: endpoint.CommandRelogin, Type: endpoint.CommandRelogin, CommandID: fmt.Sprintf("smoke-relogin-%d", time.Now().UnixNano()), CorrelationID: "smoke-relogin", EndpointID: id}); err != nil {
		worker, present := bootstrap.Supervisor.Worker(id)
		t.Fatalf("relogin failed: %v; supervisor=%v worker=%+v present=%v", err, bootstrap.Supervisor.LastError(), worker, present)
	}
	reconnected := smokeDial(t, address)
	reconnectedView := waitSmokeView(t, bootstrap.Service, id, func(view endpoint.EndpointView) bool {
		return view.ObservedState == adapterapi.ObservedStateConnected && view.OperationState == endpoint.OperationStateSucceeded && view.Generation > connected.Generation
	})
	if reconnectedView.OperationID == connected.OperationID {
		t.Fatalf("relogin operation identity did not change: %q", reconnectedView.OperationID)
	}
	reconnectedWorker, ok := bootstrap.Supervisor.Worker(id)
	if !ok || reconnectedWorker.Generation != reconnectedView.Generation || reconnectedWorker.Exited {
		t.Fatalf("relogin worker inspection=%+v view=%+v present=%v", reconnectedWorker, reconnectedView, ok)
	}
	if bootstrap.Supervisor.WorkerCount() != 1 {
		t.Fatalf("relogin worker count=%d", bootstrap.Supervisor.WorkerCount())
	}
	t.Logf("lifecycle relogged in endpoint=%s generation=%d operation=%s", id, reconnectedView.Generation, reconnectedView.OperationID)
	_ = reconnected.UnderlyingConn().Close()
	_ = reconnected.Close()
	if !waitSmokeObservedState(t, bootstrap.Service, id, adapterapi.ObservedStateFailed) {
		t.Fatalf("disconnect after relogin did not publish a failed observation")
	}
	if gormStore, ok := bootstrap.Store.(*eventstore.GORMStore); ok {
		waitSmokeReadinessQuiescent(t, gormStore, db)
		syncSmokeReadiness(t, gormStore, db)
	}
	if _, err := bootstrap.Execute(ctx, endpoint.Command{Kind: endpoint.CommandDisable, Type: endpoint.CommandDisable, CommandID: fmt.Sprintf("smoke-disable-%d", time.Now().UnixNano()), CorrelationID: "smoke-disable", EndpointID: id}); err != nil {
		t.Fatal(err)
	}
	disabled := waitSmokeView(t, bootstrap.Service, id, func(view endpoint.EndpointView) bool {
		return view.DesiredState == endpoint.DesiredStateDisabled && view.OperationState == endpoint.OperationStateSucceeded
	})
	t.Logf("lifecycle disabled endpoint=%s observed=%d operation=%s", id, disabled.ObservedState, disabled.OperationState)
	if disabled.ObservedState != adapterapi.ObservedStateStopped {
		t.Fatalf("disable state=%+v", disabled)
	}
	if _, err := bootstrap.Execute(ctx, endpoint.Command{Kind: endpoint.CommandRemove, Type: endpoint.CommandRemove, CommandID: "smoke-remove", CorrelationID: "smoke-remove", EndpointID: id}); err != nil {
		t.Fatal(err)
	}
	deleted := waitSmokeView(t, bootstrap.Service, id, func(view endpoint.EndpointView) bool { return view.DesiredState == endpoint.DesiredStateDeleted })
	t.Logf("lifecycle deleted endpoint=%s operation=%s", id, deleted.OperationState)
	if deleted.OperationState != endpoint.OperationStateIdle {
		t.Fatalf("delete state=%+v", deleted)
	}
	waitSmokePortClosed(t, address)
	config2 := smokeConfig(t, descriptor, address2, "smoke-token-replay")
	created2, err := bootstrap.Execute(ctx, endpoint.Command{Kind: endpoint.CommandCreate, Type: endpoint.CommandCreate, CommandID: "smoke-replay-create", CorrelationID: "smoke-replay-create", EndpointID: id2, AdapterKey: adapterapi.AdapterKey("pureonebot"), Config: config2})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrap.Execute(ctx, endpoint.Command{Kind: endpoint.CommandEnable, Type: endpoint.CommandEnable, CommandID: "smoke-replay-enable", CorrelationID: "smoke-replay-enable", EndpointID: id2, ExpectedVersion: created2.State.Version, ExpectedVersionSet: true}); err != nil {
		t.Fatal(err)
	}
	conn2 := smokeDial(t, address2)
	waitSmokeView(t, bootstrap.Service, id2, func(view endpoint.EndpointView) bool {
		return view.ObservedState == adapterapi.ObservedStateConnected && view.OperationState == endpoint.OperationStateSucceeded
	})
	_ = conn2.UnderlyingConn().Close()
	_ = conn2.Close()
	// The runtime keeps listening for the protocol end; shutdown stops it.
	if !waitSmokeObservedState(t, bootstrap.Service, id2, adapterapi.ObservedStateFailed) {
		t.Fatalf("replay endpoint disconnect did not publish a failed observation")
	}
	if gormStore, ok := bootstrap.Store.(*eventstore.GORMStore); ok {
		waitSmokeReadinessQuiescent(t, gormStore, db)
		syncSmokeReadiness(t, gormStore, db)
	}
	if err := bootstrap.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	bootstrap, db = openSmokeBootstrap(t, dbPath, source, descriptor)
	registerSmokeCleanup(t, bootstrap, db)
	before, err := bootstrap.Service.Get(ctx, id2)
	if err != nil {
		t.Fatal(err)
	}
	if before.DesiredState != endpoint.DesiredStateEnabled {
		t.Fatalf("replay endpoint desired=%s", before.DesiredState)
	}
	if bootstrap.Supervisor.WorkerCount() != 0 {
		t.Fatalf("replay opened worker before reconcile: %d", bootstrap.Supervisor.WorkerCount())
	}
	waitSmokePortClosed(t, address2)
	handoff.reserveAddress(t, address2)
	t.Logf("replay endpoint desired=%s observed=%d listener prebound=true", before.DesiredState, before.ObservedState)
	reconciled, err := bootstrap.ReconcileAll(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if reconciled.Reconciled != 1 || bootstrap.Supervisor.WorkerCount() != 1 {
		t.Fatalf("reconcile=%+v workers=%d", reconciled, bootstrap.Supervisor.WorkerCount())
	}
	conn3 := smokeDial(t, address2)
	t.Logf("replay before reconcile desired=%s observed=%d port_closed=true; reconciled=%d workers=%d", before.DesiredState, before.ObservedState, reconciled.Reconciled, bootstrap.Supervisor.WorkerCount())
	waitSmokeView(t, bootstrap.Service, id2, func(view endpoint.EndpointView) bool { return view.ObservedState == adapterapi.ObservedStateConnected })
	_ = conn3.UnderlyingConn().Close()
	_ = conn3.Close()
	if err := bootstrap.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	waitSmokePortClosed(t, address2)
}
