package dice

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
)

const (
	// onebotSentIDTTL is how long a message id returned by a send action keeps
	// identifying the message as one this Core sent. Reports of one's own
	// messages normally follow within seconds; history recovery can look further
	// back, so the memory is generous but bounded by onebotSentIDCapacity.
	onebotSentIDTTL      = 24 * time.Hour
	onebotSentIDCapacity = 8192
	// onebotEchoHeldCapacity bounds the reports waiting at once; beyond it a
	// report is judged immediately on what is known.
	onebotEchoHeldCapacity = 64
)

// onebotSentLedger tells Core's own sends apart from messages typed by hand in
// another client of the same account. It lives in the runtime, so every action
// that leaves through this runtime is seen whichever way it was issued
// (outbound effects, forward effects, plugin callApi/callApiRaw, enqueueApi):
// the message id a send action returns is remembered, and the account's report
// of that id is then known to be Core's.
//
// The provider may report a message before the send action's response reaches
// Core. A report of an unknown id is therefore held while a send action for the
// same conversation (or one whose target could not be read) is still in
// flight, and judged when the last such action answers, or after holdTimeout.
// Nothing waits on another conversation's sends.
type onebotSentLedger struct {
	mu          sync.Mutex
	ids         map[string]time.Time
	order       []onebotSentEntry
	inflight    map[string]int
	wild        int
	held        []*onebotHeldEcho
	now         func() time.Time
	holdTimeout time.Duration
	// release judges a held report. It runs without the ledger lock and must not
	// block.
	release func(held *onebotHeldEcho, origin adapterapi.SelfMessageOrigin)
}

type onebotSentEntry struct {
	id string
	at time.Time
}

type onebotHeldEcho struct {
	id      string
	key     string
	message adapterapi.InboundMessage
	ctx     context.Context
	timer   *time.Timer
}

func newOnebotSentLedger(release func(*onebotHeldEcho, adapterapi.SelfMessageOrigin)) *onebotSentLedger {
	return &onebotSentLedger{
		ids: make(map[string]time.Time), inflight: make(map[string]int),
		now: time.Now, holdTimeout: emitter.EchoTimeOut + 2*time.Second, release: release,
	}
}

// onebotConversationKey names a conversation the same way for a send action's
// target and for a report's conversation; "" means it could not be read.
func onebotConversationKey(group, guild, channel, user string) string {
	switch {
	case group != "":
		return "g:" + group
	case guild != "" && channel != "":
		return "c:" + guild + "-" + channel
	case user != "":
		return "p:" + user
	}
	return ""
}

// known reports whether id was returned by a send action of this Core.
func (l *onebotSentLedger) known(id string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.knownLocked(id)
}

func (l *onebotSentLedger) knownLocked(id string) bool {
	at, ok := l.ids[id]
	return ok && l.now().Sub(at) < onebotSentIDTTL
}

func (l *onebotSentLedger) rememberLocked(id string) {
	now := l.now()
	l.ids[id] = now
	l.order = append(l.order, onebotSentEntry{id: id, at: now})
	for len(l.order) > 0 && (len(l.order) > onebotSentIDCapacity || now.Sub(l.order[0].at) >= onebotSentIDTTL) {
		oldest := l.order[0]
		l.order = l.order[1:]
		if at, ok := l.ids[oldest.id]; ok && at.Equal(oldest.at) {
			delete(l.ids, oldest.id)
		}
	}
	if len(l.order) == 0 {
		l.order = nil
	}
}

// begin records a send action in flight towards key.
func (l *onebotSentLedger) begin(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if key == "" {
		l.wild++
		return
	}
	l.inflight[key]++
}

// finish records the end of a send action together with the message id it
// returned ("" when none) and judges the reports it settles.
func (l *onebotSentLedger) finish(key, id string) {
	l.mu.Lock()
	if key == "" {
		l.wild--
	} else if l.inflight[key]--; l.inflight[key] <= 0 {
		delete(l.inflight, key)
	}
	if id != "" {
		l.rememberLocked(id)
	}
	var settled []*onebotHeldEcho
	var origins []adapterapi.SelfMessageOrigin
	kept := l.held[:0]
	for _, held := range l.held {
		switch {
		case l.knownLocked(held.id):
			settled, origins = append(settled, held), append(origins, adapterapi.SelfMessageIssuedByCore)
		case !l.mayStillArriveLocked(held.key):
			settled, origins = append(settled, held), append(origins, adapterapi.SelfMessageUnattributed)
		default:
			kept = append(kept, held)
		}
	}
	clear(l.held[len(kept):])
	l.held = kept
	l.mu.Unlock()
	for i, held := range settled {
		held.timer.Stop()
		l.release(held, origins[i])
	}
}

// mayStillArriveLocked reports whether a send action still in flight could be
// the source of a report for the conversation key.
func (l *onebotSentLedger) mayStillArriveLocked(key string) bool {
	if l.wild > 0 {
		return true
	}
	if key == "" {
		return len(l.inflight) > 0
	}
	return l.inflight[key] > 0
}

// classify judges a report of an own message. When the id is not known yet but
// a send action that could have produced it is in flight, the report is held
// and release is called later; held reports true then.
func (l *onebotSentLedger) classify(ctx context.Context, id, key string, message adapterapi.InboundMessage) (origin adapterapi.SelfMessageOrigin, held bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.knownLocked(id) {
		return adapterapi.SelfMessageIssuedByCore, false
	}
	if !l.mayStillArriveLocked(key) || len(l.held) >= onebotEchoHeldCapacity {
		return adapterapi.SelfMessageUnattributed, false
	}
	entry := &onebotHeldEcho{id: id, key: key, message: message, ctx: ctx}
	entry.timer = time.AfterFunc(l.holdTimeout, func() { l.expire(entry) })
	l.held = append(l.held, entry)
	return 0, true
}

func (l *onebotSentLedger) expire(entry *onebotHeldEcho) {
	l.mu.Lock()
	origin := adapterapi.SelfMessageUnattributed
	if l.knownLocked(entry.id) {
		origin = adapterapi.SelfMessageIssuedByCore
	}
	found := false
	for i, held := range l.held {
		if held == entry {
			l.held = append(l.held[:i], l.held[i+1:]...)
			found = true
			break
		}
	}
	l.mu.Unlock()
	if found {
		l.release(entry, origin)
	}
}

// discard drops every held report (runtime shutdown); nothing is delivered.
func (l *onebotSentLedger) discard() {
	l.mu.Lock()
	held := l.held
	l.held = nil
	l.mu.Unlock()
	for _, entry := range held {
		entry.timer.Stop()
	}
}

// BeginAction implements emitter.ActionObserver.
func (l *onebotSentLedger) BeginAction(action string, frame []byte) func(response []byte) {
	if !onebotActionSendsMessage(action) {
		return nil
	}
	key := onebotActionConversationKey(frame)
	l.begin(key)
	return func(response []byte) { l.finish(key, onebotSendResponseMessageID(response)) }
}

// onebotActionSendsMessage recognises the standard OneBot actions that create
// a message and answer with its id: send_msg, send_private_msg, send_group_msg,
// send_guild_channel_msg, and the forward variants. Asynchronous variants and
// vendor-specific actions carry no id Core could match.
func onebotActionSendsMessage(action string) bool {
	action = strings.ToLower(strings.TrimSpace(action))
	return strings.HasPrefix(action, "send_") && (strings.HasSuffix(action, "_msg") || action == "send_msg" || strings.Contains(action, "forward")) &&
		!strings.HasSuffix(action, "_async")
}

// onebotActionConversationKey reads the conversation a send action targets.
func onebotActionConversationKey(frame []byte) string {
	var request struct {
		Params struct {
			MessageType string          `json:"message_type"`
			GroupID     json.RawMessage `json:"group_id"`
			UserID      json.RawMessage `json:"user_id"`
			GuildID     json.RawMessage `json:"guild_id"`
			ChannelID   json.RawMessage `json:"channel_id"`
		} `json:"params"`
	}
	if json.Unmarshal(frame, &request) != nil {
		return ""
	}
	p := request.Params
	group, _ := onebotInboundID(p.GroupID)
	user, _ := onebotInboundID(p.UserID)
	guild, _ := onebotInboundID(p.GuildID)
	channel, _ := onebotInboundID(p.ChannelID)
	switch p.MessageType {
	case "private":
		group = ""
	case "group":
		user = ""
	}
	return onebotConversationKey(group, guild, channel, user)
}

// onebotSendResponseMessageID reads the id a successful send action returned.
func onebotSendResponseMessageID(response []byte) string {
	if len(response) == 0 {
		return ""
	}
	var envelope onebotResponseEnvelope
	if json.Unmarshal(response, &envelope) != nil || len(bytes.TrimSpace(envelope.Data)) == 0 {
		return ""
	}
	if envelope.RetCode != nil && *envelope.RetCode != 0 || envelope.RetCodeCamel != nil && *envelope.RetCodeCamel != 0 ||
		strings.EqualFold(envelope.Status, "failed") {
		return ""
	}
	var data struct {
		MessageID json.RawMessage `json:"message_id"`
	}
	if json.Unmarshal(envelope.Data, &data) != nil {
		return ""
	}
	id, _ := onebotInboundID(data.MessageID)
	if id == "0" {
		return ""
	}
	return id
}

// sentLedger returns the runtime's ledger, creating it on first use.
func (r *onebotRuntime) sentLedger() *onebotSentLedger {
	r.sentOnce.Do(func() { r.sent = newOnebotSentLedger(r.releaseHeldEcho) })
	return r.sent
}

// releaseHeldEcho delivers a held report once it has been judged. Delivery is
// asynchronous: it may be triggered from the goroutine of an unrelated send.
func (r *onebotRuntime) releaseHeldEcho(held *onebotHeldEcho, origin adapterapi.SelfMessageOrigin) {
	message := held.message
	message.SelfOrigin = origin
	go r.admitCallback(func() {
		ctx := held.ctx
		if ctx == nil || ctx.Err() != nil {
			ctx = context.Background()
		}
		if err := r.deliverOnebotInbound(ctx, message); err != nil {
			// Backpressure and the like are retried the way a live event is:
			// the raw event goes back to the run loop and is judged afresh.
			if isRetryableInboundError(err) && message.AdapterEvent != nil {
				event := onebotRuntimeEvent{kind: "inbound", raw: []byte(message.AdapterEvent.RawJSON)}
				if rehandoffOnebotInbound(&event) && r.enqueue(event) {
					r.inboundRetries.Add(1)
					return
				}
			}
			r.inboundRejected.Add(1)
		}
	})
}
