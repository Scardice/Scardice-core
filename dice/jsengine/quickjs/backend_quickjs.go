//go:build quickjs

package quickjs

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"Scardice-core/dice/jsengine"
	sealcrypto "Scardice-core/utils/plugin/crypto"

	bq "github.com/buke/quickjs-go"
	"github.com/gorilla/websocket"
)

var invalidIdentCharRe = regexp.MustCompile(`[^a-zA-Z0-9_]`)

type nativeBackend struct {
	runtime   *bq.Runtime
	ctx       *bq.Context
	moduleDir string
	opt       Options
	apis      []jsengine.HostAPI
	// QuickJS Context 非线程安全，所有 Eval/JS 调用必须串行。
	vmMu sync.Mutex

	runtimeMu              sync.Mutex
	runtimeGetArgN         func(int64) string
	runtimeIsArgEqual      func(int64, []string) bool
	runtimeGetKwargJSON    func(string) string
	runtimeGetRestArgsFrom func(int64) string
	runtimeReply           func(string)
	runtimeValuesMu        sync.RWMutex
	runtimeValues          map[string]any
	runtimeBusy            atomic.Int32
	deferredCallbacksMu    sync.Mutex
	deferredCallbacks      []deferredExtCallback

	httpClient  *http.Client
	cryptoStore *sealcrypto.KeyStore

	wsMu    sync.Mutex
	wsSeq   int64
	wsConns map[int64]*wsBridgeConn

	// WebSocket 后台泵：提升空闲期事件实时性。
	wsPumpStop chan struct{}
	wsPumpDone chan struct{}
}

type deferredExtCallback struct {
	extName      string
	callbackName string
	runtime      map[string]any
}

type wsBridgeEvent struct {
	Type   string `json:"type"`
	Data   string `json:"data,omitempty"`
	Code   int    `json:"code,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type wsBridgeConn struct {
	conn   *websocket.Conn
	events []wsBridgeEvent
	state  int // 0 CONNECTING, 1 OPEN, 2 CLOSING, 3 CLOSED
	mu     sync.Mutex
}

func newNativeBackend(cfg jsengine.Config, opt Options) (*nativeBackend, error) {
	rt := bq.NewRuntime()
	if rt == nil {
		return nil, fmt.Errorf("创建 QuickJS Runtime 失败")
	}
	if opt.MemoryLimitBytes > 0 {
		rt.SetMemoryLimit(uint64(opt.MemoryLimitBytes))
	}
	ctx := rt.NewContext()
	if ctx == nil {
		rt.Close()
		return nil, fmt.Errorf("创建 QuickJS Context 失败")
	}

	n := &nativeBackend{
		runtime:       rt,
		ctx:           ctx,
		moduleDir:     cfg.ModuleDir,
		opt:           opt,
		apis:          make([]jsengine.HostAPI, 0, 8),
		runtimeValues: map[string]any{},
		httpClient:    &http.Client{Timeout: 30 * time.Second},
		cryptoStore:   sealcrypto.NewKeyStore(),
		wsConns:       map[int64]*wsBridgeConn{},
		wsPumpStop:    make(chan struct{}),
		wsPumpDone:    make(chan struct{}),
	}
	n.installBaseGlobals()
	_ = n.evalGlobalLocked(quickJSPolyfillScript)
	n.startWSPump()
	return n, nil
}

func (n *nativeBackend) startWSPump() {
	go func() {
		defer close(n.wsPumpDone)
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// 后台泵送：在没有 JS 主动执行时也能分发 WebSocket 事件。
				_ = n.evalGlobal(`if (typeof globalThis.__sd_ws_pump === 'function') { globalThis.__sd_ws_pump(); }`)
			case <-n.wsPumpStop:
				return
			}
		}
	}()
}

func (n *nativeBackend) installBaseGlobals() {
	n.ctx.Globals().Set("__sd_runtime_getArgN", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if n.runtimeGetArgN == nil || len(args) == 0 {
			return ctx.String("")
		}
		return ctx.String(n.runtimeGetArgN(args[0].ToInt64()))
	}))
	n.ctx.Globals().Set("__sd_runtime_isArgEqual", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if n.runtimeIsArgEqual == nil || len(args) == 0 {
			return ctx.Bool(false)
		}
		items := make([]string, 0, len(args)-1)
		for _, arg := range args[1:] {
			items = append(items, arg.ToString())
		}
		return ctx.Bool(n.runtimeIsArgEqual(args[0].ToInt64(), items))
	}))
	n.ctx.Globals().Set("__sd_runtime_getKwarg", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if n.runtimeGetKwargJSON == nil || len(args) == 0 {
			return ctx.String("null")
		}
		return ctx.String(n.runtimeGetKwargJSON(args[0].ToString()))
	}))
	n.ctx.Globals().Set("__sd_runtime_getRestArgsFrom", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if n.runtimeGetRestArgsFrom == nil || len(args) == 0 {
			return ctx.String("")
		}
		return ctx.String(n.runtimeGetRestArgsFrom(args[0].ToInt64()))
	}))
	n.ctx.Globals().Set("__sd_runtime_reply", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if n.runtimeReply != nil && len(args) > 0 {
			n.runtimeReply(args[0].ToString())
		}
		return ctx.Undefined()
	}))
	n.ctx.Globals().Set("__sd_fetch_sync", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 1 {
			return ctx.ThrowError(fmt.Errorf("fetch: missing url"))
		}
		url := args[0].ToString()
		initJSON := "{}"
		if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
			initJSON = args[1].ToString()
		}
		resp, err := n.fetchSync(url, initJSON)
		if err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.String(resp)
	}))
	n.ctx.Globals().Set("__sd_ws_create", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 1 {
			return ctx.ThrowError(fmt.Errorf("WebSocket: missing url"))
		}
		id, err := n.wsCreate(args[0].ToString())
		if err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.Int64(id)
	}))
	n.ctx.Globals().Set("__sd_ws_send", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 2 {
			return ctx.ThrowError(fmt.Errorf("WebSocket.send: missing args"))
		}
		if err := n.wsSend(args[0].ToInt64(), args[1].ToString()); err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.Undefined()
	}))
	n.ctx.Globals().Set("__sd_ws_close", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 1 {
			return ctx.ThrowError(fmt.Errorf("WebSocket.close: missing id"))
		}
		code := 1000
		reason := ""
		if len(args) > 1 && !args[1].IsUndefined() && !args[1].IsNull() {
			code = int(args[1].ToInt64())
		}
		if len(args) > 2 && !args[2].IsUndefined() && !args[2].IsNull() {
			reason = args[2].ToString()
		}
		if err := n.wsClose(args[0].ToInt64(), code, reason); err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.Undefined()
	}))
	n.ctx.Globals().Set("__sd_ws_poll", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 1 {
			return ctx.String(`{"state":3,"events":[]}`)
		}
		data := n.wsPoll(args[0].ToInt64())
		return ctx.String(data)
	}))
	n.ctx.Globals().Set("__sd_utf8_encode", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 1 {
			return ctx.String("[]")
		}
		// NOTE: json.Marshal([]byte) 会生成 base64 字符串，不是字节数组。
		// TextEncoder 需要的是数字数组（如 [115,101,...]），否则 JS 侧会把字符串按字符码读取成脏数据。
		src := []byte(args[0].ToString())
		nums := make([]int, len(src))
		for i, v := range src {
			nums[i] = int(v)
		}
		b, _ := json.Marshal(nums)
		return ctx.String(string(b))
	}))
	n.ctx.Globals().Set("__sd_utf8_decode", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 1 {
			return ctx.String("")
		}
		var data []byte
		if err := json.Unmarshal([]byte(args[0].ToString()), &data); err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.String(string(data))
	}))
	n.ctx.Globals().Set("__sd_crypto_random_uuid", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		uuid, err := randomUUID()
		if err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.String(uuid)
	}))
	n.ctx.Globals().Set("__sd_crypto_get_random_bytes", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 1 {
			return ctx.ThrowError(errors.New("missing length"))
		}
		n := int(args[0].ToInt64())
		if n < 0 {
			n = 0
		}
		b := make([]byte, n)
		if _, err := rand.Read(b); err != nil {
			return ctx.ThrowError(err)
		}
		raw, _ := json.Marshal(b)
		return ctx.String(string(raw))
	}))
	n.ctx.Globals().Set("__sd_crypto_subtle_call", n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) *bq.Value {
		if len(args) < 2 {
			return ctx.ThrowError(errors.New("missing subtle args"))
		}
		if n.cryptoStore == nil {
			n.cryptoStore = sealcrypto.NewKeyStore()
		}
		raw, err := n.cryptoStore.CallJSON(args[0].ToString(), args[1].ToString())
		if err != nil {
			return ctx.ThrowError(err)
		}
		return ctx.String(raw)
	}))
}

func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uint32(b[0])<<24|uint32(b[1])<<16|uint32(b[2])<<8|uint32(b[3]),
		uint16(b[4])<<8|uint16(b[5]),
		uint16(b[6])<<8|uint16(b[7]),
		uint16(b[8])<<8|uint16(b[9]),
		uint64(b[10])<<40|uint64(b[11])<<32|uint64(b[12])<<24|uint64(b[13])<<16|uint64(b[14])<<8|uint64(b[15]),
	), nil
}

func (n *nativeBackend) fetchSync(url string, initJSON string) (string, error) {
	reqInit := struct {
		Method  string            `json:"method"`
		Headers map[string]string `json:"headers"`
		Body    string            `json:"body"`
	}{}
	_ = json.Unmarshal([]byte(initJSON), &reqInit)
	method := strings.ToUpper(strings.TrimSpace(reqInit.Method))
	if method == "" {
		method = http.MethodGet
	}
	req, err := http.NewRequest(method, url, bytes.NewBufferString(reqInit.Body))
	if err != nil {
		return "", err
	}
	for k, v := range reqInit.Headers {
		req.Header.Set(k, v)
	}
	resp, err := n.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	headers := map[string]string{}
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	out := map[string]any{
		"ok":         resp.StatusCode >= 200 && resp.StatusCode < 300,
		"status":     resp.StatusCode,
		"statusText": resp.Status,
		"url":        url,
		"headers":    headers,
		"bodyText":   string(body),
	}
	b, _ := json.Marshal(out)
	return string(b), nil
}

func (n *nativeBackend) wsCreate(url string) (int64, error) {
	dialer := websocket.Dialer{HandshakeTimeout: 15 * time.Second}
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		return 0, err
	}
	id := atomic.AddInt64(&n.wsSeq, 1)
	c := &wsBridgeConn{
		conn:   conn,
		events: []wsBridgeEvent{{Type: "open"}},
		state:  1,
	}
	n.wsMu.Lock()
	n.wsConns[id] = c
	n.wsMu.Unlock()
	go n.wsReadLoop(id, c)
	return id, nil
}

func (n *nativeBackend) wsReadLoop(id int64, c *wsBridgeConn) {
	for {
		mt, data, err := c.conn.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.state = 3
			c.events = append(c.events, wsBridgeEvent{Type: "close"})
			c.mu.Unlock()
			_ = c.conn.Close()
			return
		}
		if mt == websocket.TextMessage || mt == websocket.BinaryMessage {
			c.mu.Lock()
			c.events = append(c.events, wsBridgeEvent{Type: "message", Data: string(data)})
			c.mu.Unlock()
		}
	}
}

func (n *nativeBackend) wsSend(id int64, text string) error {
	n.wsMu.Lock()
	c, ok := n.wsConns[id]
	n.wsMu.Unlock()
	if !ok || c == nil {
		return fmt.Errorf("WebSocket connection not found: %d", id)
	}
	return c.conn.WriteMessage(websocket.TextMessage, []byte(text))
}

func (n *nativeBackend) wsClose(id int64, code int, reason string) error {
	n.wsMu.Lock()
	c, ok := n.wsConns[id]
	n.wsMu.Unlock()
	if !ok || c == nil {
		return nil
	}
	c.mu.Lock()
	c.state = 2
	c.events = append(c.events, wsBridgeEvent{Type: "close", Code: code, Reason: reason})
	c.mu.Unlock()
	_ = c.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason))
	_ = c.conn.Close()
	c.mu.Lock()
	c.state = 3
	c.mu.Unlock()
	return nil
}

func (n *nativeBackend) wsPoll(id int64) string {
	n.wsMu.Lock()
	c, ok := n.wsConns[id]
	n.wsMu.Unlock()
	if !ok || c == nil {
		return `{"state":3,"events":[]}`
	}
	c.mu.Lock()
	ev := append([]wsBridgeEvent(nil), c.events...)
	c.events = c.events[:0]
	state := c.state
	c.mu.Unlock()
	out := map[string]any{"state": state, "events": ev}
	b, _ := json.Marshal(out)
	return string(b)
}

func (n *nativeBackend) setRuntimeValue(name string, value any) {
	n.runtimeValuesMu.Lock()
	defer n.runtimeValuesMu.Unlock()
	if value == nil {
		delete(n.runtimeValues, name)
		return
	}
	n.runtimeValues[name] = value
}

func (n *nativeBackend) clearRuntimeValues(names ...string) {
	n.runtimeValuesMu.Lock()
	defer n.runtimeValuesMu.Unlock()
	for _, name := range names {
		delete(n.runtimeValues, name)
	}
}

func (n *nativeBackend) runtimeValue(name string) (any, bool) {
	n.runtimeValuesMu.RLock()
	defer n.runtimeValuesMu.RUnlock()
	v, ok := n.runtimeValues[name]
	return v, ok
}

func (n *nativeBackend) CurrentRuntimeValues() map[string]any {
	n.runtimeValuesMu.RLock()
	defer n.runtimeValuesMu.RUnlock()
	out := make(map[string]any, len(n.runtimeValues))
	for k, v := range n.runtimeValues {
		out[k] = v
	}
	return out
}

func (n *nativeBackend) resolveScriptPath(moduleID string, parentID string) (string, error) {
	target := strings.TrimSpace(moduleID)
	if target == "" {
		return "", fmt.Errorf("module id 为空")
	}
	if parentID != "" && strings.HasPrefix(target, ".") {
		parentDir := filepath.Dir(parentID)
		candidate := filepath.Join(parentDir, target)
		if abs, err := n.resolveScriptPath(candidate, ""); err == nil {
			return abs, nil
		}
	}
	if filepath.IsAbs(target) {
		return n.resolveExistingPath(target)
	}
	if abs, err := n.resolveExistingPath(target); err == nil {
		return abs, nil
	}
	trimmed := strings.TrimPrefix(target, "./")
	if abs, err := n.resolveExistingPath(trimmed); err == nil {
		return abs, nil
	}
	if n.moduleDir != "" {
		joined := filepath.Join(n.moduleDir, target)
		if abs, err := n.resolveExistingPath(joined); err == nil {
			return abs, nil
		}
	}
	return "", fmt.Errorf("无法定位脚本文件: %s", moduleID)
}

func (n *nativeBackend) resolveExistingPath(path string) (string, error) {
	candidates := []string{path}
	if filepath.Ext(path) == "" {
		candidates = append(candidates, path+".js", filepath.Join(path, "index.js"))
	}
	for _, candidate := range candidates {
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() {
			return filepath.Abs(candidate)
		}
	}
	return "", fmt.Errorf("无法定位脚本文件: %s", path)
}

func (n *nativeBackend) readModule(moduleID string, parentID string) (string, error) {
	absPath, err := n.resolveScriptPath(moduleID, parentID)
	if err != nil {
		return "", err
	}
	code, err := os.ReadFile(absPath)
	if err != nil {
		return "", fmt.Errorf("读取脚本失败: %w", err)
	}
	out := map[string]string{
		"id":   filepath.ToSlash(absPath),
		"code": string(code),
	}
	raw, err := json.Marshal(out)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func (n *nativeBackend) evalGlobal(code string) error {
	n.vmMu.Lock()
	defer n.vmMu.Unlock()
	return n.evalGlobalLocked(code)
}

func (n *nativeBackend) evalGlobalValue(code string) (string, error) {
	n.vmMu.Lock()
	defer n.vmMu.Unlock()
	return n.evalGlobalValueLocked(code)
}

func (n *nativeBackend) evalGlobalLocked(code string) error {
	if n.ctx == nil {
		return fmt.Errorf("QuickJS VM 未初始化")
	}
	v := n.ctx.Eval(code, bq.EvalFlagGlobal(true))
	defer v.Free()
	// 若脚本返回 Promise（例如 async IIFE），需要主动驱动 QuickJS pending jobs，否则会表现为“执行无响应”。
	if v.IsPromise() {
		ret := n.ctx.Await(v)
		defer ret.Free()
		if ret.IsException() {
			if err := n.ctx.Exception(); err != nil {
				return err
			}
			return fmt.Errorf("quickjs await exception")
		}
	}
	if v.IsException() {
		if err := n.ctx.Exception(); err != nil {
			return err
		}
		return fmt.Errorf("quickjs eval exception")
	}
	return nil
}

func (n *nativeBackend) evalGlobalValueLocked(code string) (string, error) {
	if n.ctx == nil {
		return "", fmt.Errorf("QuickJS VM 未初始化")
	}
	v := n.ctx.Eval(code, bq.EvalFlagGlobal(true))
	defer v.Free()
	if v.IsPromise() {
		ret := n.ctx.Await(v)
		defer ret.Free()
		if ret.IsException() {
			if err := n.ctx.Exception(); err != nil {
				return "", err
			}
			return "", fmt.Errorf("quickjs await exception")
		}
		v = ret
	}
	if v.IsException() {
		if err := n.ctx.Exception(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("quickjs eval exception")
	}
	return v.String(), nil
}

func hostAPIBindingName(name string) string {
	s := invalidIdentCharRe.ReplaceAllString(name, "_")
	if s == "" {
		s = "unnamed"
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "_" + s
	}
	return "__sd_host_" + s
}

func buildAssignPathScript(path []string, binding string) (string, error) {
	if len(path) == 0 {
		return "", fmt.Errorf("host api path 为空")
	}
	rootJSON, err := json.Marshal(path[0])
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("globalThis[")
	b.Write(rootJSON)
	b.WriteString("] = globalThis[")
	b.Write(rootJSON)
	b.WriteString("] || {};")
	parentExpr := "globalThis[" + string(rootJSON) + "]"
	for i := 1; i < len(path)-1; i++ {
		segJSON, err := json.Marshal(path[i])
		if err != nil {
			return "", err
		}
		b.WriteString(parentExpr)
		b.WriteString("[")
		b.Write(segJSON)
		b.WriteString("] = ")
		b.WriteString(parentExpr)
		b.WriteString("[")
		b.Write(segJSON)
		b.WriteString("] || {};")
		parentExpr += "[" + string(segJSON) + "]"
	}
	lastJSON, err := json.Marshal(path[len(path)-1])
	if err != nil {
		return "", err
	}
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("] = globalThis.")
	b.WriteString(binding)
	b.WriteString(";")
	return b.String(), nil
}

func buildAssignPathScriptJSON(path []string, binding string) (string, error) {
	base, err := buildAssignPathScript(path, binding)
	if err != nil {
		return "", err
	}
	last := path[len(path)-1]
	lastJSON, err := json.Marshal(last)
	if err != nil {
		return "", err
	}
	parentExpr := "globalThis"
	for _, seg := range path[:len(path)-1] {
		segJSON, err := json.Marshal(seg)
		if err != nil {
			return "", err
		}
		parentExpr += "[" + string(segJSON) + "]"
	}
	var b strings.Builder
	b.WriteString(base)
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("] = ((f) => (...args) => { const r = f(...args); return r == null ? null : JSON.parse(r); })(")
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("]);")
	return b.String(), nil
}

func buildAssignPathScriptFind(path []string, binding string) (string, error) {
	base, err := buildAssignPathScript(path, binding)
	if err != nil {
		return "", err
	}
	last := path[len(path)-1]
	lastJSON, err := json.Marshal(last)
	if err != nil {
		return "", err
	}
	parentExpr := "globalThis"
	for _, seg := range path[:len(path)-1] {
		segJSON, err := json.Marshal(seg)
		if err != nil {
			return "", err
		}
		parentExpr += "[" + string(segJSON) + "]"
	}
	var b strings.Builder
	b.WriteString(base)
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("] = ((f) => (...args) => {")
	b.WriteString("const r = f(...args);")
	b.WriteString("const ext = r == null ? null : JSON.parse(r);")
	b.WriteString("if (!ext || typeof ext !== 'object') { return ext; }")
	b.WriteString("const extName = ext && ext.name ? String(ext.name) : '';")
	b.WriteString("if (!ext.cmdMap || typeof ext.cmdMap !== 'object') { ext.cmdMap = {}; }")
	b.WriteString("for (const cmdName of Object.keys(ext.cmdMap)) {")
	b.WriteString("const cmd = ext.cmdMap[cmdName];")
	b.WriteString("if (!cmd || typeof cmd !== 'object') { continue; }")
	b.WriteString("if (cmd.__sdHasSolve && extName && typeof globalThis.seal === 'object' && globalThis.seal && globalThis.seal.ext && typeof globalThis.seal.ext._invokeCmdSolve === 'function') {")
	b.WriteString("cmd.solve = (ctx, msg, cmdArgs) => globalThis.seal.ext._invokeCmdSolve(extName, String(cmdName), ctx, msg, cmdArgs);")
	b.WriteString("}")
	b.WriteString("if (cmd.__sdHasHelpFunc && extName && typeof globalThis.seal === 'object' && globalThis.seal && globalThis.seal.ext && typeof globalThis.seal.ext._invokeCmdHelp === 'function') {")
	b.WriteString("cmd.helpFunc = (isShort) => globalThis.seal.ext._invokeCmdHelp(extName, String(cmdName), !!isShort);")
	b.WriteString("}")
	b.WriteString("}")
	b.WriteString("return ext;")
	b.WriteString("})(")
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("]);")
	return b.String(), nil
}

func buildAssignPathScriptRegister(path []string, binding string) (string, error) {
	base, err := buildAssignPathScript(path, binding)
	if err != nil {
		return "", err
	}
	last := path[len(path)-1]
	lastJSON, err := json.Marshal(last)
	if err != nil {
		return "", err
	}
	parentExpr := "globalThis"
	for _, seg := range path[:len(path)-1] {
		segJSON, err := json.Marshal(seg)
		if err != nil {
			return "", err
		}
		parentExpr += "[" + string(segJSON) + "]"
	}
	var b strings.Builder
	b.WriteString(base)
	b.WriteString("globalThis.__sd_cmd_solve_map = globalThis.__sd_cmd_solve_map || {};")
	b.WriteString("globalThis.__sd_cmd_help_func_map = globalThis.__sd_cmd_help_func_map || {};")
	b.WriteString("globalThis.__sd_ext_on_not_cmd_map = globalThis.__sd_ext_on_not_cmd_map || {};")
	b.WriteString("globalThis.__sd_ext_callback_map = globalThis.__sd_ext_callback_map || {};")
	b.WriteString("if (!globalThis.__sd_wrap_ext_register) {")
	b.WriteString("const __sd_reg_orig = ")
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("];")
	b.WriteString("const __sd_sync_cmd = (name, cmdName, cmdObj) => {")
	b.WriteString("if (!name || !cmdName) { return; }")
	b.WriteString("if (cmdObj && typeof cmdObj.solve === 'function') { globalThis.__sd_cmd_solve_map[name + ':' + cmdName] = cmdObj.solve; }")
	b.WriteString("else { delete globalThis.__sd_cmd_solve_map[name + ':' + cmdName]; }")
	b.WriteString("if (cmdObj && typeof cmdObj.helpFunc === 'function') { globalThis.__sd_cmd_help_func_map[name + ':' + cmdName] = cmdObj.helpFunc; }")
	b.WriteString("else { delete globalThis.__sd_cmd_help_func_map[name + ':' + cmdName]; }")
	b.WriteString("if (typeof globalThis.seal === 'object' && globalThis.seal && globalThis.seal.ext && typeof globalThis.seal.ext._syncCmd === 'function') {")
	b.WriteString("const cleanCmd = (cmdObj && typeof cmdObj === 'object') ? JSON.parse(JSON.stringify(cmdObj, (_k, v) => (typeof v === 'function' ? undefined : v))) : null;")
	b.WriteString("if (cleanCmd && cmdObj && typeof cmdObj.helpFunc === 'function') { cleanCmd.__sdHasHelpFunc = true; }")
	b.WriteString("globalThis.seal.ext._syncCmd(name, cmdName, cleanCmd);")
	b.WriteString("}")
	b.WriteString("};")
	b.WriteString("const __sd_wrap_cmd_map = (ext) => {")
	b.WriteString("if (!ext || typeof ext !== 'object') { return; }")
	b.WriteString("const name = ext && ext.name ? String(ext.name) : '';")
	b.WriteString("if (!name) { return; }")
	b.WriteString("let map = (ext.cmdMap && typeof ext.cmdMap === 'object') ? ext.cmdMap : {};")
	b.WriteString("if (!map.__sd_cmd_proxy) {")
	b.WriteString("const p = new Proxy(map, {")
	b.WriteString("set(target, prop, value) { target[prop] = value; if (typeof prop === 'string' && prop) { __sd_sync_cmd(name, prop, value); } return true; },")
	b.WriteString("deleteProperty(target, prop) { if (typeof prop === 'string' && prop) { __sd_sync_cmd(name, prop, null); } return delete target[prop]; }")
	b.WriteString("});")
	b.WriteString("Object.defineProperty(p, '__sd_cmd_proxy', { value: true, configurable: false, enumerable: false, writable: false });")
	b.WriteString("map = p;")
	b.WriteString("ext.cmdMap = map;")
	b.WriteString("}")
	b.WriteString("for (const k of Object.keys(map)) { __sd_sync_cmd(name, k, map[k]); }")
	b.WriteString("};")
	b.WriteString("const __sd_reg_now = (one) => {")
	b.WriteString("if (!one || typeof one !== 'object') { return; }")
	b.WriteString("const name = one && one.name ? String(one.name) : '';")
	b.WriteString("if (!name) { return; }")
	b.WriteString("const callbacks = [];")
	b.WriteString("const __sd_store_cb = (cbName) => {")
	b.WriteString("const key = name + ':' + cbName;")
	b.WriteString("if (typeof one[cbName] === 'function') { globalThis.__sd_ext_callback_map[key] = one[cbName]; callbacks.push(cbName); }")
	b.WriteString("else { delete globalThis.__sd_ext_callback_map[key]; }")
	b.WriteString("};")
	b.WriteString("for (const cbName of ['onLoad','onNotCommandReceived','onCommandOverride','onCommandReceived','onMessageReceived','onMessageSend','onMessageDeleted','onMessageEdit','onGroupJoined','onGroupMemberJoined','onGuildJoined','onBecomeFriend','onPoke','onGroupLeave','getDescText']) { __sd_store_cb(cbName); }")
	b.WriteString("if (typeof one.onNotCommandReceived === 'function') { globalThis.__sd_ext_on_not_cmd_map[name] = one.onNotCommandReceived; }")
	b.WriteString("else { delete globalThis.__sd_ext_on_not_cmd_map[name]; }")
	b.WriteString("__sd_wrap_cmd_map(one);")
	b.WriteString("const clean = JSON.parse(JSON.stringify(one, (_k, v) => (typeof v === 'function' ? undefined : v)));")
	b.WriteString("clean.__sdCallbacks = callbacks;")
	b.WriteString("__sd_reg_orig(JSON.stringify(clean));")
	b.WriteString("if (typeof one.onLoad === 'function') { try { one.onLoad(); } catch (e) { if (globalThis.console && typeof globalThis.console.error === 'function') { globalThis.console.error(e); } } }")
	b.WriteString("};")
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("] = (ext) => {")
	b.WriteString("__sd_reg_now(ext);")
	b.WriteString("};")
	b.WriteString("globalThis.__sd_wrap_ext_register = true;")
	b.WriteString("}")
	return b.String(), nil
}

func buildAssignPathScriptRegisterTask(path []string, binding string) (string, error) {
	base, err := buildAssignPathScript(path, binding)
	if err != nil {
		return "", err
	}
	last := path[len(path)-1]
	lastJSON, err := json.Marshal(last)
	if err != nil {
		return "", err
	}
	parentExpr := "globalThis"
	for _, seg := range path[:len(path)-1] {
		segJSON, err := json.Marshal(seg)
		if err != nil {
			return "", err
		}
		parentExpr += "[" + string(segJSON) + "]"
	}
	var b strings.Builder
	b.WriteString(base)
	b.WriteString("globalThis.__sd_task_fn_map = globalThis.__sd_task_fn_map || {};")
	b.WriteString("globalThis.__sd_task_fn_seq = globalThis.__sd_task_fn_seq || 1;")
	b.WriteString("if (!globalThis.__sd_wrap_ext_register_task) {")
	b.WriteString("const __sd_task_orig = ")
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("];")
	b.WriteString(parentExpr)
	b.WriteString("[")
	b.Write(lastJSON)
	b.WriteString("] = (ei, taskType, value, fn, key, desc, group) => {")
	b.WriteString("let fnRef = '';")
	b.WriteString("if (typeof fn === 'function') { fnRef = 't' + String(globalThis.__sd_task_fn_seq++); globalThis.__sd_task_fn_map[fnRef] = fn; }")
	b.WriteString("return __sd_task_orig(ei, taskType, value, fnRef, key, desc, group);")
	b.WriteString("};")
	b.WriteString("globalThis.__sd_wrap_ext_register_task = true;")
	b.WriteString("}")
	return b.String(), nil
}

func (n *nativeBackend) marshalResult(v any) *bq.Value {
	if v == nil {
		return n.ctx.Null()
	}
	switch x := v.(type) {
	case *bq.Value:
		return x
	case string:
		return n.ctx.String(x)
	case bool:
		return n.ctx.Bool(x)
	case int:
		return n.ctx.Int64(int64(x))
	case int64:
		return n.ctx.Int64(x)
	case int32:
		return n.ctx.Int32(x)
	case float64:
		return n.ctx.Float64(x)
	case error:
		return n.ctx.ThrowError(x)
	default:
		mv, err := n.ctx.Marshal(v)
		if err != nil {
			return n.ctx.ThrowError(err)
		}
		return mv
	}
}

func (n *nativeBackend) runtimeRefValue(arg *bq.Value, t reflect.Type) (reflect.Value, bool, error) {
	if arg == nil || arg.IsUndefined() || arg.IsNull() {
		return reflect.Value{}, false, nil
	}
	refVal := arg.Get("__sdRuntimeRef")
	if refVal == nil {
		return reflect.Value{}, false, nil
	}
	defer refVal.Free()
	if refVal.IsUndefined() || refVal.IsNull() {
		return reflect.Value{}, false, nil
	}
	marker := refVal.ToString()
	if strings.TrimSpace(marker) == "" {
		return reflect.Value{}, false, nil
	}
	stored, ok := n.runtimeValue(marker)
	if !ok || stored == nil {
		return reflect.Value{}, true, fmt.Errorf("runtime ref not found: %s", marker)
	}
	sv := reflect.ValueOf(stored)
	if t.Kind() == reflect.Interface {
		if sv.Type().AssignableTo(t) {
			return sv, true, nil
		}
		if sv.Type().ConvertibleTo(t) {
			return sv.Convert(t), true, nil
		}
		return reflect.ValueOf(stored), true, nil
	}
	if sv.Type().AssignableTo(t) {
		return sv, true, nil
	}
	if sv.Type().ConvertibleTo(t) {
		return sv.Convert(t), true, nil
	}
	if sv.Kind() == reflect.Pointer && t.Kind() != reflect.Pointer && sv.Elem().IsValid() {
		ev := sv.Elem()
		if ev.Type().AssignableTo(t) {
			return ev, true, nil
		}
		if ev.Type().ConvertibleTo(t) {
			return ev.Convert(t), true, nil
		}
	}
	return reflect.Value{}, true, fmt.Errorf("runtime ref type mismatch: have %s want %s", sv.Type(), t)
}

func (n *nativeBackend) unmarshalArg(arg *bq.Value, t reflect.Type) (reflect.Value, error) {
	if v, ok, err := n.runtimeRefValue(arg, t); ok {
		return v, err
	}
	if t.Kind() == reflect.Interface {
		if arg.IsUndefined() || arg.IsNull() {
			return reflect.Zero(t), nil
		}
		var decoded any
		if err := json.Unmarshal([]byte(arg.JSONStringify()), &decoded); err == nil {
			return reflect.ValueOf(decoded), nil
		}
		return reflect.ValueOf(arg.ToString()), nil
	}
	switch t.Kind() {
	case reflect.String:
		return reflect.ValueOf(arg.ToString()).Convert(t), nil
	case reflect.Bool:
		return reflect.ValueOf(arg.ToBool()).Convert(t), nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflect.ValueOf(arg.ToInt64()).Convert(t), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return reflect.ValueOf(uint64(arg.ToInt64())).Convert(t), nil
	case reflect.Float32, reflect.Float64:
		return reflect.ValueOf(arg.ToFloat64()).Convert(t), nil
	case reflect.Pointer, reflect.Struct, reflect.Map, reflect.Slice, reflect.Array:
		b := []byte(arg.JSONStringify())
		if t.Kind() == reflect.Pointer {
			dst := reflect.New(t.Elem())
			if err := json.Unmarshal(b, dst.Interface()); err != nil {
				return reflect.Value{}, err
			}
			return dst, nil
		}
		dst := reflect.New(t)
		if err := json.Unmarshal(b, dst.Interface()); err != nil {
			return reflect.Value{}, err
		}
		return dst.Elem(), nil
	default:
		return reflect.Value{}, fmt.Errorf("不支持的参数类型: %s", t.String())
	}
}

func (n *nativeBackend) registerAPI(api jsengine.HostAPI) error {
	n.vmMu.Lock()
	defer n.vmMu.Unlock()
	if strings.TrimSpace(api.Name) == "" {
		return fmt.Errorf("host api 名称为空")
	}
	if api.Handler == nil || reflect.TypeOf(api.Handler).Kind() != reflect.Func {
		return fmt.Errorf("host api %s 处理器不是函数类型", api.Name)
	}

	fnVal := reflect.ValueOf(api.Handler)
	fnType := fnVal.Type()
	binding := hostAPIBindingName(api.Name)
	wrapped := n.ctx.NewFunction(func(ctx *bq.Context, this *bq.Value, args []*bq.Value) (ret *bq.Value) {
		defer func() {
			if r := recover(); r != nil {
				ret = ctx.ThrowError(fmt.Errorf("host api panic (%s): %v", api.Name, r))
			}
		}()
		in := make([]reflect.Value, 0, fnType.NumIn())
		argIdx := 0
		for i := 0; i < fnType.NumIn(); i++ {
			pt := fnType.In(i)
			if fnType.IsVariadic() && i == fnType.NumIn()-1 {
				elemT := pt.Elem()
				for ; argIdx < len(args); argIdx++ {
					v, err := n.unmarshalArg(args[argIdx], elemT)
					if err != nil {
						return ctx.ThrowError(err)
					}
					in = append(in, v)
				}
				break
			}
			if argIdx >= len(args) {
				in = append(in, reflect.Zero(pt))
				continue
			}
			v, err := n.unmarshalArg(args[argIdx], pt)
			if err != nil {
				return ctx.ThrowError(err)
			}
			in = append(in, v)
			argIdx++
		}
		out := fnVal.Call(in)
		if len(out) == 0 {
			return ctx.Undefined()
		}
		if len(out) >= 2 {
			if errV := out[len(out)-1]; errV.Type().Implements(reflect.TypeOf((*error)(nil)).Elem()) && !errV.IsNil() {
				return ctx.ThrowError(errV.Interface().(error))
			}
		}
		return n.marshalResult(out[0].Interface())
	})
	defer wrapped.Free()
	n.ctx.Globals().Set(binding, wrapped)

	path := strings.Split(api.Name, ".")
	scriptBuilder := buildAssignPathScript
	if api.Name == "seal.ext.new" || api.Name == "seal.ext.newCmdItemInfo" || api.Name == "seal.ext.newCmdExecuteResult" {
		scriptBuilder = buildAssignPathScriptJSON
	} else if api.Name == "seal.ext.find" {
		scriptBuilder = buildAssignPathScriptFind
	} else if api.Name == "seal.ext.register" {
		scriptBuilder = buildAssignPathScriptRegister
	} else if api.Name == "seal.ext.registerTask" {
		scriptBuilder = buildAssignPathScriptRegisterTask
	}
	script, err := scriptBuilder(path, binding)
	if err != nil {
		return err
	}
	return n.evalGlobalLocked(script)
}

func (n *nativeBackend) registerAllAPIs() error {
	for _, api := range n.apis {
		if err := n.registerAPI(api); err != nil {
			return err
		}
	}
	return nil
}

func (n *nativeBackend) Dispose() error {
	if err := n.Quiesce(); err != nil {
		return err
	}
	n.vmMu.Lock()
	defer n.vmMu.Unlock()
	if n.ctx != nil {
		n.ctx.Close()
		n.ctx = nil
	}
	if n.runtime != nil {
		n.runtime.Close()
		n.runtime = nil
	}
	return nil
}

func (n *nativeBackend) Quiesce() error {
	n.wsMu.Lock()
	for _, c := range n.wsConns {
		if c != nil && c.conn != nil {
			_ = c.conn.Close()
		}
	}
	n.wsConns = map[int64]*wsBridgeConn{}
	n.wsMu.Unlock()
	select {
	case <-n.wsPumpDone:
		// 已结束
	default:
		close(n.wsPumpStop)
		<-n.wsPumpDone
	}
	n.runtimeMu.Lock()
	n.runtimeGetArgN = nil
	n.runtimeIsArgEqual = nil
	n.runtimeGetKwargJSON = nil
	n.runtimeGetRestArgsFrom = nil
	n.runtimeReply = nil
	n.runtimeMu.Unlock()
	n.runtimeValuesMu.Lock()
	n.runtimeValues = map[string]any{}
	n.runtimeValuesMu.Unlock()
	if n.cryptoStore == nil {
		n.cryptoStore = sealcrypto.NewKeyStore()
	} else {
		n.cryptoStore.Reset()
	}
	return nil
}

const quickJSPolyfillScript = `(function(){
// Intentionally do not install a global require.
// /js/exec relies on require being unavailable in its sandbox, and exposing
// a global module loader here would let scripts bypass that by calling
// globalThis.require(...).
if (typeof globalThis.__dirname === 'undefined') globalThis.__dirname = '';
if (typeof globalThis.__filename === 'undefined') globalThis.__filename = '';

if (typeof globalThis.fetch !== 'function') {
  globalThis.fetch = function(input, init) {
    const url = typeof input === 'string' ? input : String(input && input.url ? input.url : input);
    const payload = JSON.stringify({
      method: init && init.method ? String(init.method) : 'GET',
      headers: init && init.headers && typeof init.headers === 'object' ? init.headers : {},
      body: init && init.body != null ? String(init.body) : ''
    });
    const raw = __sd_fetch_sync(url, payload);
    const data = JSON.parse(String(raw));
    const response = {
      ok: !!data.ok,
      status: Number(data.status || 0),
      statusText: String(data.statusText || ''),
      url: String(data.url || url),
      headers: data.headers || {},
      text() { return Promise.resolve(String(data.bodyText || '')); },
      json() { return Promise.resolve(JSON.parse(String(data.bodyText || 'null'))); }
    };
    return Promise.resolve(response);
  };
}

if (typeof globalThis.WebSocket !== 'function') {
  globalThis.__sd_ws_instances = globalThis.__sd_ws_instances || [];
  globalThis.__sd_ws_pump = function() {
    const list = Array.isArray(globalThis.__sd_ws_instances) ? globalThis.__sd_ws_instances : [];
    for (const ws of list) { if (ws && typeof ws.__poll === 'function') ws.__poll(); }
  };
  class QuickJSWebSocket {
    static CONNECTING = 0;
    static OPEN = 1;
    static CLOSING = 2;
    static CLOSED = 3;
    constructor(url) {
      this.url = String(url);
      this.readyState = QuickJSWebSocket.CONNECTING;
      this.onopen = null;
      this.onmessage = null;
      this.onerror = null;
      this.onclose = null;
      this.__listeners = Object.create(null);
      this.__id = 0;
      try {
        this.__id = __sd_ws_create(this.url);
      } catch (e) {
        this.readyState = QuickJSWebSocket.CLOSED;
        setTimeout(() => {
          this.__emit('error', { error: e });
          this.__emit('close', { code: 1006, reason: String(e && e.message ? e.message : e) });
        }, 0);
      }
      globalThis.__sd_ws_instances.push(this);
    }
    addEventListener(type, listener) {
      const t = String(type || '');
      if (!t || typeof listener !== 'function') return;
      if (!Array.isArray(this.__listeners[t])) this.__listeners[t] = [];
      this.__listeners[t].push(listener);
    }
    removeEventListener(type, listener) {
      const t = String(type || '');
      if (!t || typeof listener !== 'function') return;
      const list = Array.isArray(this.__listeners[t]) ? this.__listeners[t] : [];
      this.__listeners[t] = list.filter((fn) => fn !== listener);
    }
    __emit(type, event) {
      const handlerName = 'on' + String(type || '');
      if (typeof this[handlerName] === 'function') {
        try { this[handlerName](event); } catch (_e) {}
      }
      const list = Array.isArray(this.__listeners[type]) ? this.__listeners[type] : [];
      for (const fn of list) {
        try { fn(event); } catch (_e) {}
      }
    }
    send(data) {
      if (!this.__id) throw new Error('WebSocket is not connected');
      __sd_ws_send(this.__id, String(data));
    }
    close(code, reason) {
      if (!this.__id) {
        this.readyState = QuickJSWebSocket.CLOSED;
        return;
      }
      __sd_ws_close(this.__id, code == null ? 1000 : Number(code), reason == null ? '' : String(reason));
    }
    __poll() {
      if (!this.__id) return;
      const raw = __sd_ws_poll(this.__id);
      const data = JSON.parse(String(raw));
      this.readyState = Number(data.state || 0);
      const events = Array.isArray(data.events) ? data.events : [];
      for (const ev of events) {
        if (ev.type === 'open') this.__emit('open', {});
        if (ev.type === 'message') this.__emit('message', { data: ev.data });
        if (ev.type === 'error') this.__emit('error', { error: ev.error || 'ws error' });
        if (ev.type === 'close') this.__emit('close', { code: ev.code || 1000, reason: ev.reason || '' });
      }
    }
  }
  globalThis.WebSocket = QuickJSWebSocket;
}

if (typeof globalThis.TextEncoder !== 'function') {
  globalThis.TextEncoder = class TextEncoder {
    encode(input) {
      const raw = __sd_utf8_encode(String(input == null ? '' : input));
      return Uint8Array.from(JSON.parse(String(raw)));
    }
  };
}

if (typeof globalThis.TextDecoder !== 'function') {
  globalThis.TextDecoder = class TextDecoder {
    decode(input) {
      const bytes = Array.from(new Uint8Array(input || new Uint8Array(0)));
      return __sd_utf8_decode(JSON.stringify(bytes));
    }
  };
}

if (typeof globalThis.crypto !== 'object' || globalThis.crypto === null) {
  globalThis.crypto = {};
}
globalThis.__sd_qjs_crypto_encode = function(v) {
  if (v instanceof ArrayBuffer) return {t:'bin', v:Array.from(new Uint8Array(v))};
  // QuickJS 下 ArrayBuffer.isView 在部分对象上不稳定，增加字节视图兜底检测。
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' && ArrayBuffer.isView(v)) {
    return {t:'bin', v:Array.from(new Uint8Array(v.buffer, v.byteOffset || 0, v.byteLength || 0))};
  }
  if (v && typeof v === 'object' && v.buffer instanceof ArrayBuffer && typeof v.byteLength === 'number') {
    const off = (typeof v.byteOffset === 'number') ? v.byteOffset : 0;
    return {t:'bin', v:Array.from(new Uint8Array(v.buffer, off, v.byteLength))};
  }
  if (v && typeof v === 'object' && typeof v.__sdKeyID === 'string') {
    return {t:'key', v:{id:v.__sdKeyID}};
  }
  if (Array.isArray(v)) return {t:'arr', v:v.map(globalThis.__sd_qjs_crypto_encode)};
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v)) out[k] = globalThis.__sd_qjs_crypto_encode(v[k]);
    return {t:'obj', v:out};
  }
  return {t:'prim', v:v};
};
globalThis.__sd_qjs_crypto_decode = function(node) {
  if (!node || typeof node !== 'object') return node;
  switch (node.t) {
    case 'bin': return Uint8Array.from(Array.isArray(node.v) ? node.v : []).buffer;
    case 'key': {
      const kv = node.v || {};
      return {
        __sdKeyID: String(kv.id || ''),
        type: kv.type || '',
        extractable: !!kv.extractable,
        algorithm: kv.algorithm || {},
        usages: Array.isArray(kv.usages) ? kv.usages : []
      };
    }
    case 'arr': return (Array.isArray(node.v) ? node.v : []).map(globalThis.__sd_qjs_crypto_decode);
    case 'obj': {
      const out = {};
      const src = node.v && typeof node.v === 'object' ? node.v : {};
      for (const k of Object.keys(src)) out[k] = globalThis.__sd_qjs_crypto_decode(src[k]);
      return out;
    }
    default: return node.v;
  }
};
globalThis.__sd_qjs_crypto_call = function(op, args) {
  const opText = String(op || '');
  const callArgs = Array.isArray(args) ? args : [];
  if (opText === 'randomUUID') {
    return __sd_crypto_random_uuid();
  }
  if (opText === 'getRandomValues') {
    const len = Number(callArgs[0] || 0);
    const raw = __sd_crypto_get_random_bytes(len);
    const nums = JSON.parse(String(raw || '[]'));
    return Uint8Array.from(Array.isArray(nums) ? nums : []).buffer;
  }
  if (opText.startsWith('subtle.')) {
    const subtleOp = opText.slice('subtle.'.length);
    const encodedArgs = callArgs.map((one) => globalThis.__sd_qjs_crypto_encode(one));
    const raw = __sd_crypto_subtle_call(subtleOp, JSON.stringify(encodedArgs));
    const node = JSON.parse(String(raw || '{"t":"prim","v":null}'));
    return globalThis.__sd_qjs_crypto_decode(node);
  }
  throw new Error('unsupported subtle method: ' + opText);
};
globalThis.crypto.randomUUID = function() {
  return globalThis.__sd_qjs_crypto_call('randomUUID', []);
};
globalThis.crypto.getRandomValues = function(target) {
  const ctor = target && target.constructor && typeof target.constructor.name === 'string' ? target.constructor.name : '';
  const allow = {
    Int8Array: true,
    Uint8Array: true,
    Uint8ClampedArray: true,
    Int16Array: true,
    Uint16Array: true,
    Int32Array: true,
    Uint32Array: true,
    BigInt64Array: true,
    BigUint64Array: true
  };
  if (!target || typeof target.byteLength !== 'number' || !allow[ctor]) {
    throw new TypeError('crypto.getRandomValues: input must be an integer TypedArray');
  }
  if (target.byteLength > 65536) throw new TypeError('crypto.getRandomValues: byteLength exceeds 65536');
  const buf = globalThis.__sd_qjs_crypto_call('getRandomValues', [Number(target.byteLength)]);
  const arr = new Uint8Array(buf);
  new Uint8Array(target.buffer, target.byteOffset, target.byteLength).set(arr);
  return target;
};
if (typeof globalThis.crypto.subtle !== 'object' || globalThis.crypto.subtle === null) globalThis.crypto.subtle = {};
for (const fn of ['digest','generateKey','importKey','exportKey','sign','verify','encrypt','decrypt','deriveBits','deriveKey','wrapKey','unwrapKey']) {
  globalThis.crypto.subtle[fn] = (...args) => {
    try {
      return Promise.resolve(globalThis.__sd_qjs_crypto_call('subtle.' + fn, args));
    } catch (e) {
      return Promise.reject(e);
    }
  };
}
})();`

func (n *nativeBackend) Eval(code string) error {
	if err := n.evalGlobal(code); err != nil {
		return err
	}
	_ = n.evalGlobal(`if (typeof globalThis.__sd_ws_pump === 'function') { globalThis.__sd_ws_pump(); }`)
	return nil
}

func (n *nativeBackend) EvalWithResult(code string) (any, error) {
	codeJSON, _ := json.Marshal(code)
	script := fmt.Sprintf(`(async function(){
const ret = (0, eval)(%s);
const out = (ret && typeof ret.then === 'function') ? await ret : ret;
return JSON.stringify(out, (_k, v) => {
  if (typeof v === 'bigint') return Number(v);
  if (typeof v === 'function') return undefined;
  return v;
});
})()`, string(codeJSON))
	n.vmMu.Lock()
	defer n.vmMu.Unlock()
	if n.ctx == nil {
		return nil, fmt.Errorf("QuickJS VM 未初始化")
	}
	v := n.ctx.Eval(script, bq.EvalFlagGlobal(true))
	defer v.Free()
	if v.IsPromise() {
		ret := n.ctx.Await(v)
		defer ret.Free()
		if ret.IsException() {
			if err := n.ctx.Exception(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("quickjs await exception")
		}
		v = ret
	}
	if v.IsException() {
		if err := n.ctx.Exception(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("quickjs eval exception")
	}
	raw := strings.TrimSpace(v.String())
	if raw == "" || raw == "undefined" || raw == "null" {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("QuickJS EvalWithResult 返回值解析失败: %w", err)
	}
	return out, nil
}

func (n *nativeBackend) Require(moduleID string) error {
	payload, err := n.readModule(moduleID, "")
	if err != nil {
		return err
	}
	var data struct {
		ID   string `json:"id"`
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return fmt.Errorf("解析脚本失败: %w", err)
	}
	if err := n.evalGlobal(data.Code); err != nil {
		return fmt.Errorf("执行脚本失败(%s): %w", moduleID, err)
	}
	_ = n.evalGlobal(`if (typeof globalThis.__sd_ws_pump === 'function') { globalThis.__sd_ws_pump(); }`)
	return nil
}

func (n *nativeBackend) RegisterHostAPI(api jsengine.HostAPI) error {
	n.apis = append(n.apis, api)
	if n.ctx == nil {
		return fmt.Errorf("QuickJS VM 未初始化")
	}
	return n.registerAPI(api)
}

func (n *nativeBackend) Reset() error {
	// 软重置：复用 Runtime，避免频繁 JS_FreeRuntime 触发底层断言。
	n.wsMu.Lock()
	for _, c := range n.wsConns {
		if c != nil && c.conn != nil {
			_ = c.conn.Close()
		}
	}
	n.wsConns = map[int64]*wsBridgeConn{}
	n.wsMu.Unlock()
	select {
	case <-n.wsPumpDone:
	default:
		close(n.wsPumpStop)
		<-n.wsPumpDone
	}
	if n.cryptoStore == nil {
		n.cryptoStore = sealcrypto.NewKeyStore()
	} else {
		n.cryptoStore.Reset()
	}
	if n.ctx != nil {
		n.ctx.Close()
		n.ctx = nil
	}
	if n.runtime == nil {
		rt := bq.NewRuntime()
		if rt == nil {
			return fmt.Errorf("创建 QuickJS Runtime 失败")
		}
		if n.opt.MemoryLimitBytes > 0 {
			rt.SetMemoryLimit(uint64(n.opt.MemoryLimitBytes))
		}
		n.runtime = rt
	}
	ctx := n.runtime.NewContext()
	if ctx == nil {
		return fmt.Errorf("创建 QuickJS Context 失败")
	}
	n.ctx = ctx
	n.installBaseGlobals()
	_ = n.evalGlobalLocked(quickJSPolyfillScript)
	n.wsPumpStop = make(chan struct{})
	n.wsPumpDone = make(chan struct{})
	n.startWSPump()
	return n.registerAllAPIs()
}

func jsonLiteral(v any) string {
	if v == nil {
		return "null"
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(raw)
}

func buildRuntimeVarScript(varName string, refName string, data any) string {
	if refName == "" {
		return fmt.Sprintf("const %s = %s;\n", varName, jsonLiteral(data))
	}
	return fmt.Sprintf(`const %s = (() => {
const data = %s;
if (data && typeof data === 'object' && !Array.isArray(data)) {
  try { Object.defineProperty(data, '__sdRuntimeRef', { value: %q, configurable: true, enumerable: false }); } catch (_e) { data.__sdRuntimeRef = %q; }
  return data;
}
const holder = {};
try { Object.defineProperty(holder, '__sdRuntimeRef', { value: %q, configurable: true, enumerable: false }); } catch (_e) { holder.__sdRuntimeRef = %q; }
return holder;
})();
`, varName, jsonLiteral(data), refName, refName, refName, refName)
}

func (n *nativeBackend) applyRuntime(runtime map[string]any) func() {
	n.runtimeGetArgN, _ = runtime["getArgN"].(func(int64) string)
	n.runtimeIsArgEqual, _ = runtime["isArgEqual"].(func(int64, []string) bool)
	n.runtimeGetKwargJSON, _ = runtime["getKwargJSON"].(func(string) string)
	n.runtimeGetRestArgsFrom, _ = runtime["getRestArgsFrom"].(func(int64) string)
	n.runtimeReply, _ = runtime["replyToSender"].(func(string))
	for _, key := range []string{"ctx", "msg", "cmdArgs", "event"} {
		n.setRuntimeValue(key, runtime[key])
	}
	return func() {
		n.runtimeGetArgN = nil
		n.runtimeIsArgEqual = nil
		n.runtimeGetKwargJSON = nil
		n.runtimeGetRestArgsFrom = nil
		n.runtimeReply = nil
		n.clearRuntimeValues("ctx", "msg", "cmdArgs", "event")
	}
}

func cloneRuntimeMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (n *nativeBackend) deferExtCallback(extName string, callbackName string, runtime map[string]any) {
	n.deferredCallbacksMu.Lock()
	n.deferredCallbacks = append(n.deferredCallbacks, deferredExtCallback{
		extName:      extName,
		callbackName: callbackName,
		runtime:      cloneRuntimeMap(runtime),
	})
	n.deferredCallbacksMu.Unlock()
}

func (n *nativeBackend) popDeferredExtCallback() (deferredExtCallback, bool) {
	n.deferredCallbacksMu.Lock()
	defer n.deferredCallbacksMu.Unlock()
	if len(n.deferredCallbacks) == 0 {
		return deferredExtCallback{}, false
	}
	item := n.deferredCallbacks[0]
	n.deferredCallbacks = n.deferredCallbacks[1:]
	return item, true
}

func (n *nativeBackend) flushDeferredExtCallbacks() {
	for {
		item, ok := n.popDeferredExtCallback()
		if !ok {
			return
		}
		_ = n.invokeStoredExtCallbackNow(item.extName, item.callbackName, item.runtime)
	}
}

func (n *nativeBackend) InvokeStoredSolve(extName string, cmdName string, runtime map[string]any) (map[string]any, error) {
	if n.ctx == nil {
		return nil, fmt.Errorf("QuickJS VM 未初始化")
	}
	key := extName + ":" + cmdName
	n.runtimeMu.Lock()
	n.runtimeBusy.Store(1)
	defer func() {
		n.runtimeBusy.Store(0)
		n.runtimeMu.Unlock()
		n.flushDeferredExtCallbacks()
	}()
	cleanup := n.applyRuntime(runtime)
	defer cleanup()
	replySetup := ""
	replyRestore := ""
	if n.runtimeReply != nil {
		replySetup = "const sealObj = globalThis.seal || {};\nconst oldReply = sealObj.replyToSender;\nsealObj.replyToSender = (_ctx, _msg, text) => __sd_runtime_reply(String(text));\n"
		replyRestore = "sealObj.replyToSender = oldReply;\n"
	}

	callScript := fmt.Sprintf(`(function() {
%s%sconst cmdArgs = (() => {
%s
cmdArgs.getArgN = (n) => __sd_runtime_getArgN(Number(n));
cmdArgs.isArgEqual = (n, ...ss) => __sd_runtime_isArgEqual(Number(n), ...ss.map((v) => String(v)));
cmdArgs.getKwarg = (name) => JSON.parse(String(__sd_runtime_getKwarg(String(name))));
cmdArgs.getRestArgsFrom = (index) => __sd_runtime_getRestArgsFrom(Number(index));
return cmdArgs;
})();
const solve = globalThis.__sd_cmd_solve_map && globalThis.__sd_cmd_solve_map[%q];
if (typeof solve !== 'function') { throw new Error('未找到命令solve: %s'); }
%s
const __sd_call = async () => {
  try {
    const ret = solve(ctx, msg, cmdArgs);
    globalThis.__sd_last_solve_ret = (ret && typeof ret.then === 'function') ? await ret : ret;
    return 1;
  } finally {
    %s
  }
};
return __sd_call();
})()`, buildRuntimeVarScript("ctx", "ctx", runtime["ctxData"]), buildRuntimeVarScript("msg", "msg", runtime["msgData"]), buildRuntimeVarScript("cmdArgs", "cmdArgs", runtime["cmdArgsData"]), key, key, replySetup, replyRestore)
	if err := n.evalGlobal(callScript); err != nil {
		return nil, err
	}
	retScript := `(function() {
const ret = globalThis.__sd_last_solve_ret;
if (ret == null) { throw new Error('solve returned empty result'); }
if (typeof ret !== 'object') { throw new Error('invalid solve result'); }
const hasMatched = Object.prototype.hasOwnProperty.call(ret, 'matched');
const hasSolved = Object.prototype.hasOwnProperty.call(ret, 'solved');
const hasShowHelp = Object.prototype.hasOwnProperty.call(ret, 'showHelp');
if (!hasMatched && !hasSolved && !hasShowHelp) {
  throw new Error('invalid solve result: missing matched/solved/showHelp');
}
const out = {};
if (hasMatched) { out.matched = !!ret.matched; }
if (hasSolved) { out.solved = !!ret.solved; }
if (hasShowHelp) { out.showHelp = !!ret.showHelp; }
return JSON.stringify(out);
})()`
	n.vmMu.Lock()
	if n.ctx == nil {
		n.vmMu.Unlock()
		return nil, fmt.Errorf("QuickJS VM 未初始化")
	}
	retVal := n.ctx.Eval(retScript, bq.EvalFlagGlobal(true))
	if retVal.IsException() {
		retVal.Free()
		n.vmMu.Unlock()
		if err := n.ctx.Exception(); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("quickjs eval exception")
	}
	retJSON := retVal.String()
	retVal.Free()
	n.vmMu.Unlock()
	_ = n.evalGlobal(`if (typeof globalThis.__sd_ws_pump === 'function') { globalThis.__sd_ws_pump(); }`)
	if strings.TrimSpace(retJSON) == "" {
		return map[string]any{}, nil
	}
	retMap := map[string]any{}
	if err := json.Unmarshal([]byte(retJSON), &retMap); err != nil {
		return nil, fmt.Errorf("解析命令solve返回值失败: %w", err)
	}
	return retMap, nil
}

func (n *nativeBackend) InvokeStoredCmdHelp(extName string, cmdName string, isShort bool) (string, error) {
	n.vmMu.Lock()
	defer n.vmMu.Unlock()
	if n.ctx == nil {
		return "", fmt.Errorf("QuickJS VM 未初始化")
	}
	keyJSON, _ := json.Marshal(extName + ":" + cmdName)
	boolJSON := "false"
	if isShort {
		boolJSON = "true"
	}
	script := fmt.Sprintf(`(function() {
const fn = globalThis.__sd_cmd_help_func_map && globalThis.__sd_cmd_help_func_map[%s];
if (typeof fn !== 'function') { return ''; }
const ret = fn(%s);
return ret == null ? '' : String(ret);
})()`, string(keyJSON), boolJSON)
	v := n.ctx.Eval(script, bq.EvalFlagGlobal(true))
	defer v.Free()
	if v.IsException() {
		if err := n.ctx.Exception(); err != nil {
			return "", err
		}
		return "", fmt.Errorf("quickjs eval exception")
	}
	return v.String(), nil
}

func (n *nativeBackend) invokeStoredExtCallbackNow(extName string, callbackName string, runtime map[string]any) error {
	if n.ctx == nil {
		return fmt.Errorf("QuickJS VM 未初始化")
	}
	n.runtimeMu.Lock()
	n.runtimeBusy.Store(1)
	defer func() {
		n.runtimeBusy.Store(0)
		n.runtimeMu.Unlock()
	}()
	cleanup := n.applyRuntime(runtime)
	defer cleanup()
	replySetup := ""
	replyRestore := ""
	if n.runtimeReply != nil {
		replySetup = "const sealObj = globalThis.seal || {};\nconst oldReply = sealObj.replyToSender;\nsealObj.replyToSender = (_ctx, _msg, text) => __sd_runtime_reply(String(text));\n"
		replyRestore = "sealObj.replyToSender = oldReply;\n"
	}

	var setup strings.Builder
	var callExpr string
	switch callbackName {
	case "onLoad":
		callExpr = "fn();"
	case "onNotCommandReceived", "onMessageReceived", "onMessageDeleted", "onMessageEdit",
		"onGroupJoined", "onGroupMemberJoined", "onGuildJoined", "onBecomeFriend":
		setup.WriteString(buildRuntimeVarScript("ctx", "ctx", runtime["ctxData"]))
		setup.WriteString(buildRuntimeVarScript("msg", "msg", runtime["msgData"]))
		callExpr = "fn(ctx, msg);"
	case "onCommandReceived":
		setup.WriteString(buildRuntimeVarScript("ctx", "ctx", runtime["ctxData"]))
		setup.WriteString(buildRuntimeVarScript("msg", "msg", runtime["msgData"]))
		setup.WriteString(buildRuntimeVarScript("cmdArgs", "cmdArgs", runtime["cmdArgsData"]))
		setup.WriteString("cmdArgs.getArgN = (n) => __sd_runtime_getArgN(Number(n));\n")
		setup.WriteString("cmdArgs.isArgEqual = (n, ...ss) => __sd_runtime_isArgEqual(Number(n), ...ss.map((v) => String(v)));\n")
		setup.WriteString("cmdArgs.getKwarg = (name) => JSON.parse(String(__sd_runtime_getKwarg(String(name))));\n")
		setup.WriteString("cmdArgs.getRestArgsFrom = (index) => __sd_runtime_getRestArgsFrom(Number(index));\n")
		callExpr = "fn(ctx, msg, cmdArgs);"
	case "onMessageSend":
		setup.WriteString(buildRuntimeVarScript("ctx", "ctx", runtime["ctxData"]))
		setup.WriteString(buildRuntimeVarScript("msg", "msg", runtime["msgData"]))
		setup.WriteString(fmt.Sprintf("const flag = %s;\n", jsonLiteral(runtime["flag"])))
		callExpr = "fn(ctx, msg, flag);"
	case "onPoke", "onGroupLeave":
		setup.WriteString(buildRuntimeVarScript("ctx", "ctx", runtime["ctxData"]))
		setup.WriteString(buildRuntimeVarScript("event", "event", runtime["eventData"]))
		callExpr = "fn(ctx, event);"
	default:
		return fmt.Errorf("不支持的扩展回调: %s", callbackName)
	}

	keyJSON, _ := json.Marshal(extName + ":" + callbackName)
	script := fmt.Sprintf(`(function() {
const fn = globalThis.__sd_ext_callback_map && globalThis.__sd_ext_callback_map[%s];
if (typeof fn !== 'function') { return; }
%s
%s
try {
  %s
} finally {
  %s
}
})()`, string(keyJSON), setup.String(), replySetup, callExpr, replyRestore)
	if err := n.evalGlobal(script); err != nil {
		return err
	}
	_ = n.evalGlobal(`if (typeof globalThis.__sd_ws_pump === 'function') { globalThis.__sd_ws_pump(); }`)
	return nil
}

func (n *nativeBackend) InvokeStoredExtCallback(extName string, callbackName string, runtime map[string]any) error {
	// onMessageSend 可能在 solve 持有 runtimeMu 时同步触发；此处延后执行避免重入死锁。
	if callbackName == "onMessageSend" && n.runtimeBusy.Load() != 0 {
		n.deferExtCallback(extName, callbackName, runtime)
		return nil
	}
	err := n.invokeStoredExtCallbackNow(extName, callbackName, runtime)
	n.flushDeferredExtCallbacks()
	return err
}

func (n *nativeBackend) InvokeStoredCommandOverride(extName string, runtime map[string]any) (bool, error) {
	if n.ctx == nil {
		return false, fmt.Errorf("QuickJS VM 未初始化")
	}
	n.runtimeMu.Lock()
	n.runtimeBusy.Store(1)
	defer func() {
		n.runtimeBusy.Store(0)
		n.runtimeMu.Unlock()
		n.flushDeferredExtCallbacks()
	}()
	cleanup := n.applyRuntime(runtime)
	defer cleanup()

	keyJSON, _ := json.Marshal(extName + ":onCommandOverride")
	script := fmt.Sprintf(`(function() {
const fn = globalThis.__sd_ext_callback_map && globalThis.__sd_ext_callback_map[%s];
if (typeof fn !== 'function') { return 'false'; }
%s
%s
const cmdArgs = (() => {
%s
cmdArgs.getArgN = (n) => __sd_runtime_getArgN(Number(n));
cmdArgs.isArgEqual = (n, ...ss) => __sd_runtime_isArgEqual(Number(n), ...ss.map((v) => String(v)));
cmdArgs.getKwarg = (name) => JSON.parse(String(__sd_runtime_getKwarg(String(name))));
cmdArgs.getRestArgsFrom = (index) => __sd_runtime_getRestArgsFrom(Number(index));
return cmdArgs;
})();
return String(!!fn(ctx, msg, cmdArgs));
})()`,
		string(keyJSON),
		buildRuntimeVarScript("ctx", "ctx", runtime["ctxData"]),
		buildRuntimeVarScript("msg", "msg", runtime["msgData"]),
		buildRuntimeVarScript("cmdArgs", "cmdArgs", runtime["cmdArgsData"]),
	)
	v, err := n.evalGlobalValue(script)
	if err != nil {
		return false, err
	}
	_ = n.evalGlobal(`if (typeof globalThis.__sd_ws_pump === 'function') { globalThis.__sd_ws_pump(); }`)
	return strings.EqualFold(strings.TrimSpace(v), "true"), nil
}

func (n *nativeBackend) InvokeStoredGetDescText(extName string, extData map[string]any) (string, error) {
	if n.ctx == nil {
		return "", fmt.Errorf("QuickJS VM 未初始化")
	}
	n.runtimeMu.Lock()
	n.runtimeBusy.Store(1)
	defer func() {
		n.runtimeBusy.Store(0)
		n.runtimeMu.Unlock()
		n.flushDeferredExtCallbacks()
	}()
	keyJSON, _ := json.Marshal(extName + ":getDescText")
	extJSON := jsonLiteral(extData)
	script := fmt.Sprintf(`(function() {
const fn = globalThis.__sd_ext_callback_map && globalThis.__sd_ext_callback_map[%s];
if (typeof fn !== 'function') { return ''; }
const ext = %s;
const ret = fn(ext);
return ret == null ? '' : String(ret);
})()`, string(keyJSON), extJSON)
	v, err := n.evalGlobalValue(script)
	if err != nil {
		return "", err
	}
	_ = n.evalGlobal(`if (typeof globalThis.__sd_ws_pump === 'function') { globalThis.__sd_ws_pump(); }`)
	return v, nil
}

func (n *nativeBackend) InvokeStoredOnNotCommand(extName string, runtime map[string]any) error {
	return n.InvokeStoredExtCallback(extName, "onNotCommandReceived", runtime)
}

func (n *nativeBackend) InvokeStoredTask(fnRef string, taskCtx map[string]any) error {
	n.vmMu.Lock()
	defer n.vmMu.Unlock()
	if n.ctx == nil {
		return fmt.Errorf("QuickJS VM 未初始化")
	}
	refJSON, _ := json.Marshal(fnRef)
	ctxJSON, _ := json.Marshal(taskCtx)
	ctxStrJSON, _ := json.Marshal(string(ctxJSON))
	script := fmt.Sprintf(`(function(){
const fn = globalThis.__sd_task_fn_map && globalThis.__sd_task_fn_map[%s];
if (typeof fn !== 'function') { throw new Error("task callback not found: " + %s); }
const arg = JSON.parse(%s);
fn(arg);
})();`, string(refJSON), string(refJSON), string(ctxStrJSON))
	v := n.ctx.Eval(script, bq.EvalFlagGlobal(true))
	defer v.Free()
	if v.IsException() {
		return fmt.Errorf("QuickJS 调用任务回调失败: %s", v.Error())
	}
	return nil
}

func init() {
	newRuntimeBackend = func(cfg jsengine.Config, opt Options) (runtimeBackend, error) {
		backend, err := newNativeBackend(cfg, opt)
		if err != nil {
			return nil, err
		}
		return backend, nil
	}
}
