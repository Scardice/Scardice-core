package dice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
)

// historyProviderFake answers get_group_msg_history the way LLBot was observed
// to: message_seq is the END of the page, the page holds up to count messages
// ending at it, oldest first, and an anchor that does not exist yields nothing.
type historyProviderFake struct {
	*onebotOutboundFake
	mu        sync.Mutex
	seqs      []int64 // sequence numbers that exist, ascending
	untimed   map[int64]bool
	failWith  error
	pageCalls []emitterTypes.GetGroupMsgHistoryReq
}

func (f *historyProviderFake) Raw(_ context.Context, action emitter.Action, params any) ([]byte, error) {
	if action != emitter.ACTION_GET_GROUP_MSG_HISTORY {
		return nil, errors.New("unexpected action " + action)
	}
	request, ok := params.(emitterTypes.GetGroupMsgHistoryReq)
	if !ok {
		return nil, fmt.Errorf("unexpected params %T", params)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pageCalls = append(f.pageCalls, request)
	if f.failWith != nil {
		return nil, f.failWith
	}
	end, found := slices.BinarySearch(f.seqs, request.MessageSeq)
	var items []string
	if found {
		for _, seq := range f.seqs[max(0, end-request.Count+1) : end+1] {
			timeField := fmt.Sprintf(`,"time":%d`, 1793116000+seq)
			if f.untimed[seq] {
				timeField = ""
			}
			items = append(items, fmt.Sprintf(`{"post_type":"message","message_type":"group","group_id":%d,"user_id":1001,"message_id":%d,"message_seq":%d%s,"sender":{"nickname":"A","role":"member"},"message":[{"type":"text","data":{"text":"m%d"}}]}`,
				request.GroupID, 9000+seq, seq, timeField, seq))
		}
	}
	return []byte(`{"status":"ok","retcode":0,"data":{"messages":[` + strings.Join(items, ",") + `]}}`), nil
}

func (f *historyProviderFake) anchors() []int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]int64, len(f.pageCalls))
	for i, call := range f.pageCalls {
		out[i] = call.MessageSeq
	}
	return out
}

func consecutive(from, to int64) []int64 {
	var out []int64
	for seq := from; seq <= to; seq++ {
		out = append(out, seq)
	}
	return out
}

func sequencesOf(result adapterapi.QueryResult) []int64 {
	out := make([]int64, len(result.History))
	for i, message := range result.History {
		out[i] = message.Sequence
	}
	return out
}

func historyQuery(t *testing.T, fake *historyProviderFake, after, before int64, limit int) (adapterapi.QueryResult, error) {
	t.Helper()
	request := adapterapi.QueryRequest{
		EndpointID: "endpoint-1", Kind: adapterapi.QueryKindGroupHistory, Group: "QQ-Group:2002",
		AfterSequence: after, BeforeSequence: before, Limit: limit,
	}
	result, err := (&onebotRuntime{outbound: fake}).Query(context.Background(), request)
	if err == nil {
		if validateErr := result.Validate(request); validateErr != nil {
			t.Fatalf("the answer breaks its own contract: %v", validateErr)
		}
	}
	return result, err
}

func TestOnebotGroupHistoryPagesBackFromTheNewEndOfTheGap(t *testing.T) {
	fake := &historyProviderFake{onebotOutboundFake: &onebotOutboundFake{}, seqs: consecutive(1, 500)}
	result, err := historyQuery(t, fake, 100, 450, adapterapi.MaxHistoryQueryMessages)
	if err != nil {
		t.Fatal(err)
	}
	if want := consecutive(101, 449); !slices.Equal(sequencesOf(result), want) {
		t.Fatalf("got %d messages %v..., want 101..449", len(result.History), sequencesOf(result)[:3])
	}
	if anchors := fake.anchors(); len(anchors) < 2 || anchors[0] != 450 {
		t.Fatalf("anchors = %v: the first page must end at the message that revealed the gap, and it takes several pages", anchors)
	}
	for _, call := range fake.pageCalls {
		if call.Count > 200 {
			t.Fatalf("a page asked for %d messages; the provider's own limit is far lower than the window", call.Count)
		}
		if _, exists := slices.BinarySearch(fake.seqs, call.MessageSeq); !exists {
			t.Fatalf("a page was anchored at %d, which does not exist, so the provider could return nothing", call.MessageSeq)
		}
	}
}

func TestOnebotGroupHistoryKeepsTheNewestWhenThereAreMoreThanTheLimit(t *testing.T) {
	fake := &historyProviderFake{onebotOutboundFake: &onebotOutboundFake{}, seqs: consecutive(1, 451)}
	result, err := historyQuery(t, fake, 0, 451, 50)
	if err != nil {
		t.Fatal(err)
	}
	if want := consecutive(401, 450); !slices.Equal(sequencesOf(result), want) {
		t.Fatalf("got %v, want the newest fifty 401..450", sequencesOf(result))
	}
}

func TestOnebotGroupHistoryFollowsRealMessagesWhenNumbersAreMissing(t *testing.T) {
	// Recalled messages leave holes. Every other number exists here.
	var seqs []int64
	for seq := int64(2); seq <= 400; seq += 2 {
		seqs = append(seqs, seq)
	}
	fake := &historyProviderFake{onebotOutboundFake: &onebotOutboundFake{}, seqs: seqs}
	result, err := historyQuery(t, fake, 100, 300, adapterapi.MaxHistoryQueryMessages)
	if err != nil {
		t.Fatal(err)
	}
	var want []int64
	for seq := int64(102); seq <= 298; seq += 2 {
		want = append(want, seq)
	}
	if !slices.Equal(sequencesOf(result), want) {
		t.Fatalf("holes lost messages: got %v", sequencesOf(result))
	}
}

func TestOnebotGroupHistoryStopsWhereTheProvidersHistoryStarts(t *testing.T) {
	fake := &historyProviderFake{onebotOutboundFake: &onebotOutboundFake{}, seqs: consecutive(3, 10)}
	result, err := historyQuery(t, fake, 0, 10, 100)
	if err != nil {
		t.Fatal(err)
	}
	if want := consecutive(3, 9); !slices.Equal(sequencesOf(result), want) {
		t.Fatalf("got %v, want 3..9", sequencesOf(result))
	}
	if calls := len(fake.anchors()); calls > 3 {
		t.Fatalf("%d provider calls for seven messages: the loop does not notice the start of history", calls)
	}
}

func TestOnebotGroupHistorySkipsEntriesItCannotPlaceButKeepsTheRest(t *testing.T) {
	fake := &historyProviderFake{onebotOutboundFake: &onebotOutboundFake{}, seqs: consecutive(1, 20), untimed: map[int64]bool{7: true}}
	result, err := historyQuery(t, fake, 0, 20, 100)
	if err != nil {
		t.Fatal(err)
	}
	want := slices.DeleteFunc(consecutive(1, 19), func(seq int64) bool { return seq == 7 })
	if !slices.Equal(sequencesOf(result), want) {
		t.Fatalf("got %v, want everything except the untimed 7", sequencesOf(result))
	}
}

func TestOnebotGroupHistoryFailuresAreErrorsNotGuesses(t *testing.T) {
	failing := &historyProviderFake{onebotOutboundFake: &onebotOutboundFake{}, seqs: consecutive(1, 20), failWith: errors.New("provider down")}
	if result, err := historyQuery(t, failing, 0, 20, 10); err == nil {
		t.Fatalf("a failed provider call produced %d messages", len(result.History))
	}
	if _, err := (&onebotRuntime{}).Query(context.Background(), adapterapi.QueryRequest{
		EndpointID: "endpoint-1", Kind: adapterapi.QueryKindGroupHistory, Group: "QQ-Group:2002", AfterSequence: 0, BeforeSequence: 10, Limit: 5,
	}); err == nil {
		t.Fatal("a runtime without a provider connection answered")
	}
	notQQ := adapterapi.QueryRequest{EndpointID: "endpoint-1", Kind: adapterapi.QueryKindGroupHistory, Group: "Discord:1", AfterSequence: 0, BeforeSequence: 10, Limit: 5}
	if _, err := (&onebotRuntime{outbound: failing}).Query(context.Background(), notQQ); !errors.Is(err, adapterapi.ErrInvalidContract) {
		t.Fatalf("a non QQ group was not refused: %v", err)
	}
}
