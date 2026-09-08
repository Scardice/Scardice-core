package socketio

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/lxzan/gws"
)

const (
	// TextMessage 表示文本消息。
	TextMessage = 1
	// BinaryMessage 表示二进制消息。
	BinaryMessage = 2
	// CloseMessage 表示关闭控制帧。
	CloseMessage = 8
	// PingMessage 表示 Ping 控制帧。
	PingMessage = 9
	// PongMessage 表示 Pong 控制帧。
	PongMessage = 10
)

const maxWrapperEventQueue = 32
const maxWrapperMessageBytes = 256 * 1024

const (
	defaultClientHandshakeTimeout = 10 * time.Second
	defaultClientPingInterval     = 15 * time.Second
	defaultClientPingWait         = 45 * time.Second
)

const (
	// EventMessage 在收到文本或二进制消息时触发。
	EventMessage = "message"
	// EventPing 在收到 Ping 帧时触发。
	EventPing = "ping"
	// EventPong 在收到 Pong 帧时触发。
	EventPong = "pong"
	// EventDisconnect 在连接断开时触发。
	EventDisconnect = "disconnect"
	// EventConnect 在连接建立后触发。
	EventConnect = "connect"
	// EventClose 在主动调用 Close 时触发。
	EventClose = "close"
	// EventError 在发送、关闭或底层连接出现错误时触发。
	EventError = "error"
)

var (
	// ErrorInvalidConnection 表示目标连接不存在或已失效。
	ErrorInvalidConnection = errors.New("message cannot be delivered invalid/gone connection")
	// ErrorUUIDDuplication 表示 UUID 与现有连接冲突。
	ErrorUUIDDuplication = errors.New("UUID already exists in the available connections pool")
	// ErrorSessionClosed 表示当前会话已经关闭，不能继续发送。
	ErrorSessionClosed = errors.New("session is closed")
	// ErrorShutdown 表示整个 SocketInstance 已关闭。
	ErrorShutdown              = errors.New("socket instance has been shutdown")
	errClientConnectInProgress = errors.New("client connection is already in progress")
)

type clientTransportState uint8

const (
	clientTransportStateDisconnected clientTransportState = iota
	clientTransportStateConnecting
	clientTransportStateConnected
)

// ClientOptions 定义 v2 客户端连接参数。
//
// v2 不再沿用 v1 的原始连接暴露和 `ClientConnect` 模式；
// 客户端会返回一个稳定的 facade 对象，由 facade 在内部持有 transport。
type ClientOptions struct {
	// UseCompression 控制是否启用 permessage-deflate。
	UseCompression bool
	// Subprotocols 定义期望协商的子协议列表。
	Subprotocols []string
	// RequestHeader 允许附加自定义请求头。
	RequestHeader http.Header
	// TLSConfig 仅在 `wss://` 场景下生效。
	// 如果为空，则使用系统默认 TLS 配置。
	TLSConfig *tls.Config
	// HandshakeTimeout 控制客户端握手超时时间。
	HandshakeTimeout time.Duration
	// PingInterval 控制客户端主动发送 Ping 的间隔。
	PingInterval time.Duration
	// PingWait 控制客户端等待入站有效帧的最长时间。
	PingWait time.Duration
	// NewDialer 允许自定义底层拨号器，例如代理或特殊网络环境。
	NewDialer func() (gws.Dialer, error)
}

// EventPayload 是事件回调收到的统一载荷。
type EventPayload struct {
	Kws              *WebsocketWrapper
	Name             string
	SocketUUID       string
	SocketAttributes map[string]any
	Error            error
	Data             []byte
}

type eventEnvelope struct {
	payload   *EventPayload
	callbacks []eventCallback
	opcode    gws.Opcode
	terminal  bool
}

type eventCallback func(payload *EventPayload)

type safeListeners struct {
	mu        sync.RWMutex
	listeners map[string][]eventCallback
}

func (l *safeListeners) set(event string, callback eventCallback) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.listeners == nil {
		l.listeners = make(map[string][]eventCallback)
	}
	l.listeners[event] = append(l.listeners[event], callback)
}

func (l *safeListeners) get(event string) []eventCallback {
	l.mu.RLock()
	defer l.mu.RUnlock()
	callbacks := l.listeners[event]
	return append([]eventCallback(nil), callbacks...)
}

func (l *safeListeners) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.listeners = make(map[string][]eventCallback)
}

type safePool struct {
	mu   sync.RWMutex
	conn map[string]*WebsocketWrapper
}

func (p *safePool) set(ws *WebsocketWrapper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.conn == nil {
		p.conn = make(map[string]*WebsocketWrapper)
	}
	p.conn[ws.GetUUID()] = ws
}

func (p *safePool) get(key string) (*WebsocketWrapper, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.conn == nil {
		return nil, ErrorInvalidConnection
	}
	ret, ok := p.conn[key]
	if !ok {
		return nil, ErrorInvalidConnection
	}
	return ret, nil
}

func (p *safePool) contains(key string) bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	_, ok := p.conn[key]
	return ok
}

func (p *safePool) delete(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.conn, key)
}

func (p *safePool) deleteIf(key string, expected *WebsocketWrapper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if current := p.conn[key]; current == expected {
		delete(p.conn, key)
	}
}

func (p *safePool) all() map[string]*WebsocketWrapper {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ret := make(map[string]*WebsocketWrapper, len(p.conn))
	for key, value := range p.conn {
		ret[key] = value
	}
	return ret
}

type SocketInstance struct {
	pool        safePool
	listeners   safeListeners
	isShutdown  atomic.Bool
	readerMu    sync.Mutex
	readers     int
	readersDone chan struct{}
	pending     map[*gws.Conn]struct{}
	wrappersMu  sync.Mutex
	wrappers    map[*WebsocketWrapper]struct{}
	ServerOptions *gws.ServerOption
}
func NewSocketInstance() *SocketInstance {
	instance := &SocketInstance{}
	instance.listeners.reset()
	instance.readersDone = make(chan struct{})
	close(instance.readersDone)
	instance.pending = make(map[*gws.Conn]struct{})
	instance.wrappers = make(map[*WebsocketWrapper]struct{})
	instance.ServerOptions = &gws.ServerOption{}
	return instance
}
func (sm *SocketInstance) registerWrapper(wrapper *WebsocketWrapper) {
	sm.wrappersMu.Lock()
	sm.wrappers[wrapper] = struct{}{}
	sm.wrappersMu.Unlock()
}

func (sm *SocketInstance) unregisterWrapper(wrapper *WebsocketWrapper) {
	if wrapper == nil {
		return
	}
	sm.wrappersMu.Lock()
	delete(sm.wrappers, wrapper)
	sm.wrappersMu.Unlock()
}

// IsShutdown 返回实例是否已经关闭。
func (sm *SocketInstance) IsShutdown() bool {
	return sm.isShutdown.Load()
}

// On 为指定事件注册一个全局监听器。
func (sm *SocketInstance) On(event string, callback eventCallback) {
	if sm.IsShutdown() {
		return
	}
	sm.listeners.set(event, callback)
}

// EmitToList 将消息发送到指定 UUID 列表。
func (sm *SocketInstance) EmitToList(uuids []string, message []byte, mType ...int) {
	for _, wsUUID := range uuids {
		_ = sm.EmitTo(wsUUID, message, mType...)
	}
}

// Broadcast 将消息广播给当前实例中的所有活动连接。
func (sm *SocketInstance) Broadcast(message []byte, mType ...int) {
	if sm.IsShutdown() {
		return
	}
	for _, kws := range sm.pool.all() {
		kws.Emit(message, mType...)
	}
}

// EmitTo 向指定 UUID 的连接发送消息。
func (sm *SocketInstance) EmitTo(uuid string, message []byte, mType ...int) error {
	if sm.IsShutdown() {
		return ErrorShutdown
	}
	conn, err := sm.pool.get(uuid)
	if err != nil {
		return err
	}
	if !conn.IsAlive() {
		return ErrorInvalidConnection
	}
	return conn.emitInternal(message, mType...)
}

// Fire 将一个逻辑事件广播给当前实例中的所有活动连接。
func (sm *SocketInstance) Fire(event string, data []byte) {
	if sm.IsShutdown() {
		return
	}
	for _, kws := range sm.pool.all() {
		kws.fireEvent(event, data, nil)
	}
}

// Shutdown 关闭整个 SocketInstance，并通知所有活动连接断开。
func (sm *SocketInstance) Shutdown() error {
	if !sm.isShutdown.CompareAndSwap(false, true) {
		return nil
	}
	sm.readerMu.Lock()
	pending := make([]*gws.Conn, 0, len(sm.pending))
	for socket := range sm.pending {
		pending = append(pending, socket)
	}
	sm.readerMu.Unlock()
	for _, socket := range pending {
		_ = socket.NetConn().Close()
	}
	connections := sm.pool.all()
	for _, conn := range connections {
		if conn.IsAlive() {
			socket := conn.transport.Load()
			conn.Close()
			conn.finalizeTransportClose(socket, nil)
		}
	}
	sm.listeners.reset()
	return nil
}

// ShutdownWait closes transports and waits for every transport ReadLoop
// and wrapper event callback started by this instance to return.
func (sm *SocketInstance) ShutdownWait(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	_ = sm.Shutdown()
	sm.readerMu.Lock()
	done := sm.readersDone
	sm.readerMu.Unlock()
	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	sm.wrappersMu.Lock()
	wrappers := make([]*WebsocketWrapper, 0, len(sm.wrappers))
	for wrapper := range sm.wrappers {
		wrappers = append(wrappers, wrapper)
	}
	sm.wrappersMu.Unlock()
	for _, wrapper := range wrappers {
		if err := wrapper.WaitEvents(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (sm *SocketInstance) startReader(socket *gws.Conn) bool {
	sm.readerMu.Lock()
	defer sm.readerMu.Unlock()
	if sm.isShutdown.Load() {
		return false
	}
	if sm.readers == 0 {
		sm.readersDone = make(chan struct{})
	}
	sm.readers++
	sm.pending[socket] = struct{}{}
	go func() {
		defer func() {
			sm.readerMu.Lock()
			delete(sm.pending, socket)
			sm.readers--
			if sm.readers == 0 {
				close(sm.readersDone)
			}
			sm.readerMu.Unlock()
		}()
		socket.ReadLoop()
	}()
	return true
}

// New 返回一个可直接挂到 `http.HandleFunc` 的服务端 WebSocket 处理函数。
//
// 当升级成功后，会创建一个新的 `WebsocketWrapper` facade。
// 初始化 facade 属性、设置回调请使用 EventConnect / OnConnected 异步连接事件。
func (sm *SocketInstance) New() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if sm.IsShutdown() {
			http.Error(w, ErrorShutdown.Error(), http.StatusServiceUnavailable)
			return
		}
		wrapper := newServerWrapper(sm)
		sm.registerWrapper(wrapper)
		wrapper.setRequestHeader(r.Header)
		handler := &transportHandler{wrapper: wrapper}
		upgrader := gws.NewUpgrader(handler, cloneServerOption(sm.ServerOptions))
		socket, err := upgrader.Upgrade(w, r)
		if err != nil {
			sm.unregisterWrapper(wrapper)
			return
		}
		if !sm.startReader(socket) {
			sm.unregisterWrapper(wrapper)
			_ = socket.WriteClose(1001, []byte("socket instance is shutting down"))
		}
	}
}

// NewClient 创建一个尚未建立底层连接的客户端 facade。
//
// 业务可以先注册快捷回调或设置属性，再调用 `Connect` 或 `Dial` 建立连接。
func (sm *SocketInstance) NewClient(rawURL string, options ClientOptions) *WebsocketWrapper {
	wrapper := newClientWrapper(sm, rawURL, options)
	sm.registerWrapper(wrapper)
	return wrapper
}

// Dial 创建客户端 facade 并立即发起连接。
func (sm *SocketInstance) Dial(rawURL string, options ClientOptions) (*WebsocketWrapper, error) {
	if sm.IsShutdown() {
		return nil, ErrorShutdown
	}
	wrapper := sm.NewClient(rawURL, options)
	if err := wrapper.Connect(); err != nil {
		return nil, err
	}
	return wrapper, nil
}

type WebsocketWrapper struct {
	mu          sync.RWMutex
	stateMu     sync.Mutex
	heartbeatMu sync.Mutex

	UUID          string
	attributes    map[string]any
	requestHeader http.Header
	manager       *SocketInstance

	clientURL     string
	clientOptions ClientOptions
	clientMode    bool

	alive         atomic.Bool
	transport     atomic.Pointer[gws.Conn]
	connectedOnce atomic.Bool
	serverClosed  atomic.Bool
	serverTerminalPending atomic.Int32
	transportDropBaseline atomic.Uint64
	clientState   clientTransportState
	heartbeatStop chan struct{}
	heartbeatConn *gws.Conn
	eventMu       sync.Mutex
	eventQueue    []eventEnvelope
	eventDraining bool
	droppedEvents atomic.Uint64
	eventWG       sync.WaitGroup
	// connectReady is a one-shot readiness gate. It remains closed after the
	// first successful connection so reconnects cannot strand an existing drain.
	connectReady     chan struct{}
	connectReadyOnce sync.Once
	OnConnected    func()
	OnDisconnected func(err error)
	OnConnectError func(err error)
	// OnConnectFailed 只在“第一次连接尝试失败”时触发。
	//
	// 重连失败不会触发这个回调，而是只触发 OnConnectError。
	OnConnectFailed func(err error)
	OnTextMessage   func(message string)
	OnBinaryMessage func(data []byte)
	OnPingReceived  func(data string)
	OnPongReceived  func(data string)
}

func (kws *WebsocketWrapper) onConnected() {
	kws.mu.RLock()
	cb := kws.OnConnected
	kws.mu.RUnlock()
	if cb != nil {
		cb()
	}
}

func (kws *WebsocketWrapper) onDisconnected(err error) {
	kws.mu.RLock()
	cb := kws.OnDisconnected
	kws.mu.RUnlock()
	if cb != nil {
		cb(err)
	}
}

func (kws *WebsocketWrapper) onConnectError(err error) {
	kws.mu.RLock()
	cb := kws.OnConnectError
	kws.mu.RUnlock()
	if cb != nil {
		cb(err)
	}
}

func (kws *WebsocketWrapper) onConnectFailed(err error) {
	kws.mu.RLock()
	cb := kws.OnConnectFailed
	kws.mu.RUnlock()
	if cb != nil {
		cb(err)
	}
}

func (kws *WebsocketWrapper) onTextMessage(message string) {
	kws.mu.RLock()
	cb := kws.OnTextMessage
	kws.mu.RUnlock()
	if cb != nil {
		cb(message)
	}
}

func (kws *WebsocketWrapper) onBinaryMessage(data []byte) {
	kws.mu.RLock()
	cb := kws.OnBinaryMessage
	kws.mu.RUnlock()
	if cb != nil {
		cb(data)
	}
}

func (kws *WebsocketWrapper) onPing(payload string) {
	kws.mu.RLock()
	cb := kws.OnPingReceived
	kws.mu.RUnlock()
	if cb != nil {
		cb(payload)
	}
}

func (kws *WebsocketWrapper) onPong(payload string) {
	kws.mu.RLock()
	cb := kws.OnPongReceived
	kws.mu.RUnlock()
	if cb != nil {
		cb(payload)
	}
}
func (kws *WebsocketWrapper) dispatchEvent(event string, data []byte, eventErr error) bool {
	return kws.dispatchEventWithTerminal(event, data, eventErr, false)
}

func (kws *WebsocketWrapper) dispatchTerminalEvent(event string, data []byte, eventErr error) bool {
	return kws.dispatchEventWithTerminal(event, data, eventErr, true)
}

func (kws *WebsocketWrapper) dispatchEventWithTerminal(event string, data []byte, eventErr error, terminal bool) bool {
	payload := kws.newEventPayload(event, data, eventErr)
	callbacks := kws.manager.listeners.get(event)
	envelope := eventEnvelope{payload: payload, callbacks: callbacks, terminal: terminal}
	if kws.shouldQueueEvent(event) {
		return kws.enqueueEvent(envelope)
	}
	kws.eventWG.Add(1)
	go func() {
		defer kws.eventWG.Done()
		kws.invokeEventCallbacks(envelope)
	}()
	return true
}

func (kws *WebsocketWrapper) dispatchMessage(opcode gws.Opcode, data []byte) {
	payload := kws.newEventPayload(EventMessage, data, nil)
	callbacks := kws.manager.listeners.get(EventMessage)
	kws.enqueueEvent(eventEnvelope{payload: payload, callbacks: callbacks, opcode: opcode})
}

func (kws *WebsocketWrapper) shouldQueueEvent(event string) bool {
	switch event {
	case EventMessage, EventPing, EventPong, EventConnect, EventDisconnect, EventError, EventClose:
		return true
	default:
		return false
	}
}

func isTerminalWrapperEvent(event eventEnvelope) bool {
	if event.payload == nil {
		return false
	}
	switch event.payload.Name {
	case EventDisconnect, EventError, EventClose, EventConnect:
		return true
	default:
		return false
	}
}

func (kws *WebsocketWrapper) enqueueEvent(event eventEnvelope) bool {
	kws.eventMu.Lock()
	if len(kws.eventQueue) >= maxWrapperEventQueue {
		if isTerminalWrapperEvent(event) {
			if event.payload.Name == EventConnect {
				for _, queued := range kws.eventQueue {
					if queued.payload != nil && queued.payload.Name == EventConnect {
						kws.droppedEvents.Add(1)
						kws.eventMu.Unlock()
						return false
					}
				}
			}
			replaced := -1
			for i, queued := range kws.eventQueue {
				if !isTerminalWrapperEvent(queued) {
					replaced = i
					break
				}
			}
			if event.payload.Name == EventDisconnect {
				for i, queued := range kws.eventQueue {
					if queued.payload == nil || queued.payload.Name != EventDisconnect {
						replaced = i
						break
					}
				}
			} else if event.payload.Name == EventConnect {
				for i, queued := range kws.eventQueue {
					if queued.payload == nil || (queued.payload.Name != EventDisconnect && queued.payload.Name != EventConnect) {
						replaced = i
						break
					}
				}
			}
			if replaced >= 0 {
				dropped := kws.eventQueue[replaced]
				copy(kws.eventQueue[replaced:], kws.eventQueue[replaced+1:])
				kws.eventQueue[len(kws.eventQueue)-1] = eventEnvelope{}
				kws.eventQueue = kws.eventQueue[:len(kws.eventQueue)-1]
				kws.eventWG.Done()
				if dropped.terminal && !kws.clientMode {
					kws.serverTerminalPending.Add(-1)
				}
				kws.droppedEvents.Add(1)
			} else {
				kws.droppedEvents.Add(1)
				kws.eventMu.Unlock()
				return false
			}
		} else {
			kws.droppedEvents.Add(1)
			kws.eventMu.Unlock()
			return false
		}
	}
	kws.eventWG.Add(1)
	kws.eventQueue = append(kws.eventQueue, event)
	if kws.eventDraining {
		kws.eventMu.Unlock()
		return true
	}
	kws.eventDraining = true
	kws.eventMu.Unlock()
	go kws.drainEvents()
	return true
}


func (kws *WebsocketWrapper) markConnectedReady() {
	kws.connectReadyOnce.Do(func() {
		close(kws.connectReady)
	})
}
func (kws *WebsocketWrapper) DroppedEventCount() uint64 {
	if kws == nil { return 0 }
	return kws.droppedEvents.Load()
}

func (kws *WebsocketWrapper) TransportDropBaseline() uint64 {
	if kws == nil {
		return 0
	}
	return kws.transportDropBaseline.Load()
}

func (kws *WebsocketWrapper) drainEvents() {
	kws.eventMu.Lock()
	ready := kws.connectReady
	kws.eventMu.Unlock()
	<-ready
	for {
		kws.eventMu.Lock()
		if len(kws.eventQueue) == 0 {
			kws.eventDraining = false
			readyToUnregister := !kws.clientMode && kws.serverClosed.Load() && kws.serverTerminalPending.Load() == 0
			kws.eventMu.Unlock()
			if readyToUnregister {
				kws.manager.unregisterWrapper(kws)
			}
			return
		}
		event := kws.eventQueue[0]
		kws.eventQueue = kws.eventQueue[1:]
		kws.eventMu.Unlock()
		kws.invokeEventCallbacks(event)
		if !kws.clientMode && event.terminal {
			if kws.serverTerminalPending.Add(-1) == 0 {
				kws.eventMu.Lock()
				empty := len(kws.eventQueue) == 0
				kws.eventMu.Unlock()
				if empty {
					kws.manager.unregisterWrapper(kws)
				}
			}
		}
		kws.eventWG.Done()
	}
}
// WaitEvents waits until all asynchronous callbacks queued on this wrapper
// have finished. Shutdown callers use it after transport reader quiescence.
func (kws *WebsocketWrapper) WaitEvents(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		kws.eventWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (kws *WebsocketWrapper) invokeEventCallbacks(event eventEnvelope) {
	switch event.payload.Name {
	case EventConnect:
		kws.onConnected()
	case EventDisconnect:
		kws.onDisconnected(event.payload.Error)
	case EventMessage:
		switch event.opcode {
		case gws.OpcodeBinary:
			kws.onBinaryMessage(event.payload.Data)
		default:
			kws.onTextMessage(string(event.payload.Data))
		}
	case EventPing:
		kws.onPing(string(event.payload.Data))
	case EventPong:
		kws.onPong(string(event.payload.Data))
	}
	for _, callback := range event.callbacks {
		callback(event.payload)
	}
}

func (kws *WebsocketWrapper) newEventPayload(event string, data []byte, eventErr error) *EventPayload {
	attrs := kws.snapshotAttributes()
	return &EventPayload{
		Kws:              kws,
		Name:             event,
		SocketUUID:       kws.GetUUID(),
		SocketAttributes: attrs,
		Error:            eventErr,
		Data:             append([]byte(nil), data...),
	}
}

func newServerWrapper(sm *SocketInstance) *WebsocketWrapper {
	return &WebsocketWrapper{
		UUID:         uuid.NewString(),
		attributes:   make(map[string]any),
		manager:      sm,
		connectReady: make(chan struct{}),
	}
}

func newClientWrapper(sm *SocketInstance, rawURL string, options ClientOptions) *WebsocketWrapper {
	return &WebsocketWrapper{
		UUID:          uuid.NewString(),
		attributes:    make(map[string]any),
		manager:       sm,
		clientURL:     rawURL,
		clientOptions: normalizeClientOptions(options),
		clientMode:    true,
		connectReady:  make(chan struct{}),
	}
}

func normalizeClientOptions(options ClientOptions) ClientOptions {
	options.RequestHeader = cloneHeader(options.RequestHeader)
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = defaultClientHandshakeTimeout
	}
	if options.PingInterval <= 0 {
		options.PingInterval = defaultClientPingInterval
	}
	if options.PingWait <= 0 {
		options.PingWait = defaultClientPingWait
	}
	return options
}

func (kws *WebsocketWrapper) GetUUID() string {
	kws.mu.RLock()
	defer kws.mu.RUnlock()
	return kws.UUID
}

// SetUUID 显式设置 facade 的逻辑 UUID。
//
// 该方法主要用于业务方希望使用自定义标识进行 EmitTo/Broadcast 路由。
func (kws *WebsocketWrapper) SetUUID(id string) error {
	kws.manager.pool.mu.Lock()
	defer kws.manager.pool.mu.Unlock()

	kws.mu.Lock()
	currentID := kws.UUID
	kws.mu.Unlock()

	if existing, ok := kws.manager.pool.conn[id]; ok && existing != kws {
		return ErrorUUIDDuplication
	}

	if currentID != "" && currentID != id {
		delete(kws.manager.pool.conn, currentID)
	}

	kws.mu.Lock()
	kws.UUID = id
	kws.mu.Unlock()

	if kws.manager.pool.conn == nil {
		kws.manager.pool.conn = make(map[string]*WebsocketWrapper)
	}
	kws.manager.pool.conn[id] = kws
	return nil
}

// SetAttribute 为当前 facade 保存一个连接属性。
func (kws *WebsocketWrapper) SetAttribute(key string, attribute any) {
	kws.mu.Lock()
	defer kws.mu.Unlock()
	kws.attributes[key] = attribute
}

// GetAttribute 返回指定属性。
func (kws *WebsocketWrapper) GetAttribute(key string) any {
	kws.mu.RLock()
	defer kws.mu.RUnlock()
	return kws.attributes[key]
}

// GetIntAttribute 以 int 形式读取属性，不存在时返回 0。
func (kws *WebsocketWrapper) GetIntAttribute(key string) int {
	kws.mu.RLock()
	defer kws.mu.RUnlock()
	value, ok := kws.attributes[key]
	if !ok {
		return 0
	}
	return value.(int)
}

// GetStringAttribute 以 string 形式读取属性，不存在时返回空字符串。
func (kws *WebsocketWrapper) GetStringAttribute(key string) string {
	kws.mu.RLock()
	defer kws.mu.RUnlock()
	value, ok := kws.attributes[key]
	if !ok {
		return ""
	}
	return value.(string)
}

// GetRequestHeader 返回握手阶段请求头中的指定值。
func (kws *WebsocketWrapper) GetRequestHeader(key string) string {
	kws.mu.RLock()
	defer kws.mu.RUnlock()
	return kws.requestHeader.Get(key)
}

// IsAlive 返回 facade 当前是否持有一个活动 transport。
func (kws *WebsocketWrapper) IsAlive() bool {
	return kws.alive.Load()
}

// EmitToList 从当前 facade 发起一次多播。
func (kws *WebsocketWrapper) EmitToList(uuids []string, message []byte, mType ...int) {
	for _, wsUUID := range uuids {
		if err := kws.EmitTo(wsUUID, message, mType...); err != nil {
			kws.fireEvent(EventError, message, err)
		}
	}
}

// EmitTo 通过当前实例的路由表向指定 UUID 发送消息。
func (kws *WebsocketWrapper) EmitTo(id string, message []byte, mType ...int) error {
	return kws.manager.EmitTo(id, message, mType...)
}

// Broadcast 使用当前实例的连接池进行广播。
//
// 当 except 为 true 时，会跳过当前 facade 自己。
func (kws *WebsocketWrapper) Broadcast(message []byte, except bool, mType ...int) {
	for id, session := range kws.manager.pool.all() {
		if except && id == kws.GetUUID() {
			continue
		}
		if err := session.emitInternal(message, mType...); err != nil {
			kws.fireEvent(EventError, message, err)
		}
	}
}

// Fire 仅在当前 facade 上触发一个逻辑事件。
func (kws *WebsocketWrapper) Fire(event string, data []byte) {
	kws.fireEvent(event, data, nil)
}

// Emit 向当前 facade 对应的 transport 发送消息。
func (kws *WebsocketWrapper) Emit(message []byte, mType ...int) {
	_ = kws.emitInternal(message, mType...)
}

func (kws *WebsocketWrapper) emitInternal(message []byte, mType ...int) error {
	socket := kws.transport.Load()
	if socket == nil || !kws.IsAlive() {
		return ErrorSessionClosed
	}
	opcode := gws.OpcodeText
	if len(mType) > 0 {
		switch mType[0] {
		case BinaryMessage:
			opcode = gws.OpcodeBinary
		case PingMessage:
			opcode = gws.OpcodePing
		case PongMessage:
			opcode = gws.OpcodePong
		case CloseMessage:
			return socket.WriteClose(1000, message)
		}
	}
	if err := socket.WriteMessage(opcode, message); err != nil {
		kws.fireEvent(EventError, message, err)
		return err
	}
	return nil
}

func (kws *WebsocketWrapper) Close() {
	socket := kws.transport.Load()
	if socket == nil {
		return
	}
	_ = socket.WriteClose(1000, []byte("Connection closed"))
	kws.fireEvent(EventClose, nil, nil)
}

// Connect 为客户端 facade 建立第一次连接。
//
// 如果该 facade 不是客户端模式，则返回错误。
// 如果连接已经存活，则直接返回 nil。
func (kws *WebsocketWrapper) Connect() error {
	if !kws.clientMode {
		return errors.New("connect is only supported for client sessions")
	}
	if kws.manager.IsShutdown() {
		return ErrorShutdown
	}
	alreadyConnected, err := kws.beginClientDial(false)
	if err != nil {
		return err
	}
	if alreadyConnected {
		return nil
	}
	if err := kws.connectClientTransport(false); err != nil {
		kws.setClientState(clientTransportStateDisconnected)
		return err
	}
	return nil
}

// Reconnect 在当前 facade 上重新建立 transport。
//
// facade 对象、UUID、attributes、事件绑定都会保留。
func (kws *WebsocketWrapper) Reconnect() error {
	if !kws.clientMode {
		return errors.New("reconnect is only supported for client sessions")
	}
	if kws.manager.IsShutdown() {
		return ErrorShutdown
	}
	if _, err := kws.beginClientDial(true); err != nil {
		return err
	}
	if socket := kws.transport.Load(); socket != nil {
		_ = socket.WriteClose(1000, []byte("reconnect"))
	}
	if err := kws.connectClientTransport(true); err != nil {
		kws.setClientState(clientTransportStateDisconnected)
		return err
	}
	return nil
}

func (kws *WebsocketWrapper) beginClientDial(reconnecting bool) (bool, error) {
	kws.stateMu.Lock()
	defer kws.stateMu.Unlock()
	if kws.clientState == clientTransportStateConnecting {
		return false, errClientConnectInProgress
	}
	if !reconnecting && kws.clientState == clientTransportStateConnected && kws.IsAlive() {
		return true, nil
	}
	kws.clientState = clientTransportStateConnecting
	return false, nil
}

func (kws *WebsocketWrapper) setClientState(state clientTransportState) {
	kws.stateMu.Lock()
	defer kws.stateMu.Unlock()
	kws.clientState = state
}

func (kws *WebsocketWrapper) connectClientTransport(reconnecting bool) error {
	opened := make(chan struct{})
	handler := &transportHandler{wrapper: kws, opened: opened}
	requestHeader := cloneHeader(kws.clientOptions.RequestHeader)
	if len(kws.clientOptions.Subprotocols) > 0 && requestHeader.Get("Sec-WebSocket-Protocol") == "" {
		requestHeader.Set("Sec-WebSocket-Protocol", strings.Join(kws.clientOptions.Subprotocols, ", "))
	}
	kws.setRequestHeader(requestHeader)
	clientOption := &gws.ClientOption{
		Addr:          kws.clientURL,
		RequestHeader: requestHeader,
	}
	if kws.clientOptions.UseCompression {
		clientOption.PermessageDeflate.Enabled = true
	}
	if kws.clientOptions.TLSConfig != nil {
		clientOption.TlsConfig = kws.clientOptions.TLSConfig.Clone()
	}
	if kws.clientOptions.HandshakeTimeout > 0 {
		clientOption.HandshakeTimeout = kws.clientOptions.HandshakeTimeout
	}
	if kws.clientOptions.NewDialer != nil {
		clientOption.NewDialer = kws.clientOptions.NewDialer
	}
	clientOption.NewSession = func() gws.SessionStorage { return gws.NewConcurrentMap[string, any]() }
	socket, _, err := gws.NewClient(handler, clientOption)
	if err != nil {
		go kws.onConnectError(err)
		if !reconnecting && !kws.connectedOnce.Load() {
			go kws.onConnectFailed(err)
		}
		return err
	}
	if !kws.manager.startReader(socket) {
		_ = socket.WriteClose(1001, []byte("socket instance is shutting down"))
		return errors.New("socket instance has been shut down")
	}
	select {
	case <-opened:
		return nil
	case <-time.After(2 * time.Second):
		_ = socket.WriteClose(1000, []byte("dial timeout"))
		return errors.New("timed out waiting for websocket session open")
	}
}

func (kws *WebsocketWrapper) startClientHeartbeat(socket *gws.Conn) {
	if !kws.clientMode {
		return
	}
	kws.refreshClientDeadline(socket)
	if kws.clientOptions.PingInterval <= 0 {
		kws.stopClientHeartbeat(nil)
		return
	}
	stopCh := make(chan struct{})
	kws.heartbeatMu.Lock()
	if kws.heartbeatStop != nil {
		close(kws.heartbeatStop)
	}
	kws.heartbeatStop = stopCh
	kws.heartbeatConn = socket
	kws.heartbeatMu.Unlock()
	go kws.runClientHeartbeat(socket, stopCh)
}

func (kws *WebsocketWrapper) stopClientHeartbeat(socket *gws.Conn) {
	kws.heartbeatMu.Lock()
	defer kws.heartbeatMu.Unlock()
	if socket != nil && kws.heartbeatConn != socket {
		return
	}
	if kws.heartbeatStop != nil {
		close(kws.heartbeatStop)
		kws.heartbeatStop = nil
	}
	kws.heartbeatConn = nil
}

func (kws *WebsocketWrapper) runClientHeartbeat(socket *gws.Conn, stopCh <-chan struct{}) {
	ticker := time.NewTicker(kws.clientOptions.PingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			if kws.transport.Load() != socket || !kws.IsAlive() {
				return
			}
			if err := socket.WritePing(nil); err != nil {
				return
			}
		}
	}
}

func (kws *WebsocketWrapper) refreshClientDeadline(socket *gws.Conn) {
	if !kws.clientMode || socket == nil || kws.clientOptions.PingWait <= 0 {
		return
	}
	_ = socket.SetReadDeadline(time.Now().Add(kws.clientOptions.PingWait))
}

func (kws *WebsocketWrapper) finalizeTransportClose(socket *gws.Conn, err error) bool {
	if socket == nil {
		return false
	}
	if current := kws.transport.Load(); current != socket {
		return false
	}
	if !kws.alive.CompareAndSwap(true, false) {
		return false
	}
	kws.stopClientHeartbeat(socket)
	kws.transport.Store(nil)
	kws.manager.pool.deleteIf(kws.GetUUID(), kws)
	kws.stateMu.Lock()
	if kws.clientState != clientTransportStateConnecting {
		kws.clientState = clientTransportStateDisconnected
	}
	kws.stateMu.Unlock()
	if !kws.clientMode {
		kws.serverClosed.Store(true)
		kws.serverTerminalPending.Store(0)
		kws.serverTerminalPending.Add(1)
	}
	if !kws.dispatchTerminalEvent(EventDisconnect, nil, err) && !kws.clientMode {
		kws.serverTerminalPending.Add(-1)
	}
	if err != nil {
		if !kws.clientMode {
			kws.serverTerminalPending.Add(1)
		}
		if !kws.dispatchTerminalEvent(EventError, nil, err) && !kws.clientMode {
			kws.serverTerminalPending.Add(-1)
		}
	}
	return true
}

func (kws *WebsocketWrapper) fireEvent(event string, data []byte, eventErr error) {
	callbacks := kws.manager.listeners.get(event)
	attrs := kws.snapshotAttributes()
	payload := &EventPayload{
		Kws:              kws,
		Name:             event,
		SocketUUID:       kws.GetUUID(),
		SocketAttributes: attrs,
		Error:            eventErr,
		Data:             append([]byte(nil), data...),
	}
	for _, callback := range callbacks {
		callback(payload)
	}
}

func (kws *WebsocketWrapper) snapshotAttributes() map[string]any {
	kws.mu.RLock()
	defer kws.mu.RUnlock()
	attrs := make(map[string]any, len(kws.attributes))
	for key, value := range kws.attributes {
		attrs[key] = value
	}
	return attrs
}

func (kws *WebsocketWrapper) setRequestHeader(header http.Header) {
	kws.mu.Lock()
	defer kws.mu.Unlock()
	kws.requestHeader = cloneHeader(header)
}

type transportHandler struct {
	gws.BuiltinEventHandler
	wrapper *WebsocketWrapper
	opened  chan struct{}
}

func (h *transportHandler) OnOpen(socket *gws.Conn) {
	wrapper := h.wrapper
	wrapper.transport.Store(socket)
	wrapper.alive.Store(true)
	wrapper.connectedOnce.Store(true)
	wrapper.setClientState(clientTransportStateConnected)
	wrapper.startClientHeartbeat(socket)
	wrapper.manager.pool.set(wrapper)
	wrapper.transportDropBaseline.Store(wrapper.DroppedEventCount())
	if h.opened != nil {
		close(h.opened)
		h.opened = nil
	}
	wrapper.markConnectedReady()
	wrapper.dispatchEvent(EventConnect, nil, nil)
}

func (h *transportHandler) OnMessage(socket *gws.Conn, message *gws.Message) {
	defer message.Close()
	h.wrapper.refreshClientDeadline(socket)
	if len(message.Bytes()) > maxWrapperMessageBytes {
		h.wrapper.droppedEvents.Add(1)
		if socket != nil {
			_ = socket.WriteClose(1009, []byte("message too large"))
		}
		return
	}
	data := append([]byte(nil), message.Bytes()...)
	h.wrapper.dispatchMessage(message.Opcode, data)
}

func (h *transportHandler) OnPing(socket *gws.Conn, payload []byte) {
	h.wrapper.refreshClientDeadline(socket)
	h.wrapper.dispatchEvent(EventPing, payload, nil)
	_ = socket.WritePong(payload)
}

func (h *transportHandler) OnPong(socket *gws.Conn, payload []byte) {
	h.wrapper.refreshClientDeadline(socket)
	h.wrapper.dispatchEvent(EventPong, payload, nil)
}

func (h *transportHandler) OnClose(socket *gws.Conn, err error) {
	wrapper := h.wrapper
	wrapper.finalizeTransportClose(socket, err)
}

func insecureTLSConfig() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

func cloneHeader(header http.Header) http.Header {
	if header == nil {
		return http.Header{}
	}
	return header.Clone()
}

func cloneServerOption(option *gws.ServerOption) *gws.ServerOption {
	if option == nil {
		return &gws.ServerOption{}
	}
	clone := *option
	clone.ResponseHeader = cloneHeader(option.ResponseHeader)
	clone.SubProtocols = append([]string(nil), option.SubProtocols...)
	if option.TlsConfig != nil {
		clone.TlsConfig = option.TlsConfig.Clone()
	}
	return &clone
}

