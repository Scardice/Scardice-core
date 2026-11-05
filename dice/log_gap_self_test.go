package dice

import "testing"

// selfLogPosition drives the sequence accounting the way the callbacks do: a
// group's users' messages go through detectLogGap, the account's own reports
// through detectSelfLogGap, and each Core group send counts when it is sent.
type selfLogPosition struct {
	t       *testing.T
	runtime *GroupRuntimeResources
	state   GroupLogState
	stored  *storedSeq
}

func newSelfLogPosition(t *testing.T, lastSeq int64) *selfLogPosition {
	t.Helper()
	p := &selfLogPosition{
		t: t, runtime: newLogGapRuntime(),
		state:  GroupLogState{ID: 7, Name: "run", On: true, BaselineSeq: lastSeq - 1},
		stored: &storedSeq{value: lastSeq - 1},
	}
	if span, _ := detectLogGap(p.runtime, p.state, seqMessage(lastSeq), p.stored.read); span.missing != 0 {
		t.Fatalf("seeding the position reported a gap: %+v", span)
	}
	return p
}

func (p *selfLogPosition) coreSends() { noteLogGapSelfSent(p.runtime) }

func (p *selfLogPosition) user(seq int64) logGapSpan {
	span, _ := detectLogGap(p.runtime, p.state, seqMessage(seq), p.stored.read)
	return span
}

func (p *selfLogPosition) report(seq int64, issuedByCore bool) logGapSpan {
	return detectSelfLogGap(p.runtime, p.state, seq, seq, issuedByCore, p.stored.read)
}

func (p *selfLogPosition) want(span logGapSpan, from, to, missing int64) {
	p.t.Helper()
	if span.fromSeq != from || span.toSeq != to || span.missing != missing {
		p.t.Fatalf("gap = %+v, want %d..%d missing %d", span, from, to, missing)
	}
}

func (p *selfLogPosition) wantNone(span logGapSpan) {
	p.t.Helper()
	if span.missing != 0 {
		p.t.Fatalf("phantom gap: %+v", span)
	}
}

func (p *selfLogPosition) selfSent() int64 {
	p.runtime.logSequence.mu.Lock()
	defer p.runtime.logSequence.mu.Unlock()
	return p.runtime.logSequence.selfSent
}

// The report of a Core send arrives before the next message of anyone: the
// send was already counted when it left, so the report must not deduct it again.
func TestSelfLogGapEarlyReportOfACoreSendIsNotCountedTwice(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.coreSends()
	p.wantNone(p.report(11, true))
	if p.selfSent() != 0 {
		t.Fatalf("selfSent = %d after its send was reported, want 0", p.selfSent())
	}
	p.wantNone(p.user(12))
	p.want(p.user(14), 12, 14, 1)
}

// The report arrives after the next message: that message already deducted the
// send, and the report changes nothing.
func TestSelfLogGapLateReportOfACoreSendChangesNothing(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.coreSends()
	p.wantNone(p.user(12))
	p.wantNone(p.report(11, true))
	if p.selfSent() != 0 {
		t.Fatalf("selfSent = %d, want 0", p.selfSent())
	}
	// A genuinely missing message is still found afterwards.
	p.want(p.user(14), 12, 14, 1)
}

// With reportSelfMessage off no report ever comes: accounting is the old one.
func TestSelfLogGapWithoutReportsKeepsTheOldAccounting(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.coreSends()
	p.coreSends()
	p.wantNone(p.user(13))
	p.coreSends()
	p.want(p.user(16), 13, 16, 1)
}

// Reports of two Core sends may arrive in the opposite order.
func TestSelfLogGapOutOfOrderReportsOfCoreSendsAreCountedOnce(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.coreSends() // 11
	p.coreSends() // 12
	p.wantNone(p.report(12, true))
	p.wantNone(p.report(11, true))
	if p.selfSent() != 0 {
		t.Fatalf("selfSent = %d, want 0", p.selfSent())
	}
	p.wantNone(p.user(13))
	p.want(p.user(15), 13, 15, 1)
}

// A hand-typed message was never counted as a Core send.
func TestSelfLogGapHandTypedMessageIsPositionedNotDeducted(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.wantNone(p.report(11, false))
	p.wantNone(p.user(12))

	// Two numbers below it belong to nobody known: a real gap.
	q := newSelfLogPosition(t, 10)
	q.want(q.report(13, false), 10, 13, 2)
}

// A Core send in the middle of a real gap does not hide the missing message.
func TestSelfLogGapReportDoesNotHideARealGap(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.coreSends() // seq 12, while 11 is somebody's message nobody recorded
	p.want(p.report(12, true), 10, 12, 1)
	p.wantNone(p.user(13))
}

// Hand-typed messages next to Core sends still balance.
func TestSelfLogGapMixedOwnMessagesBalance(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.coreSends()                   // 11 sent by Core
	p.wantNone(p.report(12, false)) // 12 typed by hand; 11 hides below it
	if p.selfSent() != 0 {
		t.Fatalf("selfSent = %d, want 0", p.selfSent())
	}
	p.wantNone(p.report(11, true))
	p.wantNone(p.user(13))
}

// A send Core never counted (a plugin's callApi) reported while nothing is
// counted does not eat into the next count.
func TestSelfLogGapUncountedCoreSendReportCreatesNoPhantomGap(t *testing.T) {
	p := newSelfLogPosition(t, 10)
	p.wantNone(p.report(11, true))
	p.coreSends() // 12
	p.wantNone(p.user(13))
}

func TestSelfLogGapReportOnAnotherLogOrBelowItsBaselineChangesNothing(t *testing.T) {
	p := newSelfLogPosition(t, 100)
	p.wantNone(p.report(50, false))
	p.wantNone(p.report(100, true))
	p.wantNone(p.user(101))

	fresh := GroupLogState{ID: 8, Name: "new", On: true}
	span := detectSelfLogGap(p.runtime, fresh, 900, 900, false, p.stored.read)
	p.wantNone(span)
	p.wantNone(detectSelfLogGap(p.runtime, fresh, 901, 901, false, p.stored.read))
}

func TestSelfLogGapRebuildsFromTheStoredLogAfterARestart(t *testing.T) {
	runtime := newLogGapRuntime()
	state := GroupLogState{ID: 7, Name: "run", On: true, BaselineSeq: 90}
	stored := &storedSeq{value: 105}
	span := detectSelfLogGap(runtime, state, 108, 108, false, stored.read)
	if span.fromSeq != 105 || span.toSeq != 108 || span.missing != 2 {
		t.Fatalf("gap after restart = %+v, want 105..108 missing 2", span)
	}
	if stored.calls != 1 {
		t.Fatalf("stored sequence read %d times, want once", stored.calls)
	}
}

func TestSelfLogGapIgnoresReportsWithoutASequenceOrARuntime(t *testing.T) {
	stored := &storedSeq{}
	state := GroupLogState{ID: 7, Name: "run", On: true}
	if span := detectSelfLogGap(newLogGapRuntime(), state, 0, "x", true, stored.read); span.missing != 0 || stored.calls != 0 {
		t.Fatalf("report without a sequence changed state: %+v reads=%d", span, stored.calls)
	}
	if span := detectSelfLogGap(nil, state, 5, "x", true, stored.read); span.missing != 0 {
		t.Fatalf("report without a runtime: %+v", span)
	}
}
