package adapterapi

import (
	"errors"
	"testing"
)

func historyRequest() QueryRequest {
	return QueryRequest{
		EndpointID: "endpoint-1", Kind: QueryKindGroupHistory, Group: "QQ-Group:2002",
		AfterSequence: 100, BeforeSequence: 110, Limit: 50,
	}
}

func historyMessage(sequence int64) InboundMessage {
	message := groupMessage()
	message.Conversation = "QQ-Group:2002"
	message.Sequence = sequence
	return message
}

func TestGroupHistoryQueryNeedsAGroupAndABoundedWindow(t *testing.T) {
	if err := historyRequest().Validate(); err != nil {
		t.Fatalf("valid history query rejected: %v", err)
	}
	invalid := map[string]func(*QueryRequest){
		"no group":             func(r *QueryRequest) { r.Group = "" },
		"a member as well":     func(r *QueryRequest) { r.Member = "QQ:3003" },
		"negative start":       func(r *QueryRequest) { r.AfterSequence = -1 },
		"empty window":         func(r *QueryRequest) { r.BeforeSequence = r.AfterSequence + 1 },
		"inverted window":      func(r *QueryRequest) { r.BeforeSequence = r.AfterSequence },
		"no limit":             func(r *QueryRequest) { r.Limit = 0 },
		"limit over the bound": func(r *QueryRequest) { r.Limit = MaxHistoryQueryMessages + 1 },
	}
	for name, mutate := range invalid {
		request := historyRequest()
		mutate(&request)
		if err := request.Validate(); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	// The window belongs to history queries only.
	role := QueryRequest{EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003", Limit: 5}
	if err := role.Validate(); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("a member role query carrying a history window was accepted: %v", err)
	}
}

func TestGroupHistoryAnswerStaysInsideTheAskedWindow(t *testing.T) {
	request := historyRequest()
	good := QueryResult{History: []InboundMessage{historyMessage(101), historyMessage(105), historyMessage(109)}}
	if err := good.Validate(request); err != nil {
		t.Fatalf("valid answer rejected: %v", err)
	}
	if err := (QueryResult{}).Validate(request); err != nil {
		t.Fatalf("an empty window is a valid answer: %v", err)
	}

	wrongGroup := historyMessage(105)
	wrongGroup.Conversation = "QQ-Group:9"
	live := historyMessage(105)
	live.History = InboundHistoryRecordOnly
	direct := historyMessage(105)
	direct.ConversationKind = ConversationKindDirect
	tooMany := QueryResult{}
	for sequence := int64(101); sequence < 101+51; sequence++ {
		tooMany.History = append(tooMany.History, historyMessage(sequence))
	}
	small := request
	small.Limit = 2

	cases := map[string]struct {
		result  QueryResult
		request QueryRequest
	}{
		"at the lower bound":   {QueryResult{History: []InboundMessage{historyMessage(100)}}, request},
		"at the upper bound":   {QueryResult{History: []InboundMessage{historyMessage(110)}}, request},
		"outside the window":   {QueryResult{History: []InboundMessage{historyMessage(300)}}, request},
		"no sequence":          {QueryResult{History: []InboundMessage{historyMessage(0)}}, request},
		"descending":           {QueryResult{History: []InboundMessage{historyMessage(105), historyMessage(104)}}, request},
		"repeated":             {QueryResult{History: []InboundMessage{historyMessage(105), historyMessage(105)}}, request},
		"another group":        {QueryResult{History: []InboundMessage{wrongGroup}}, request},
		"already marked":       {QueryResult{History: []InboundMessage{live}}, request},
		"a direct message":     {QueryResult{History: []InboundMessage{direct}}, request},
		"more than the limit":  {QueryResult{History: good.History}, small},
		"over the bound":       {tooMany, request},
		"a role in the answer": {QueryResult{Role: "admin", History: good.History}, request},
	}
	for name, tc := range cases {
		if err := tc.result.Validate(tc.request); !errors.Is(err, ErrInvalidContract) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}

	roleRequest := QueryRequest{EndpointID: "endpoint-1", Kind: QueryKindMemberRole, Group: "QQ-Group:2002", Member: "QQ:3003"}
	if err := (QueryResult{Role: "admin", History: good.History}).Validate(roleRequest); !errors.Is(err, ErrInvalidContract) {
		t.Errorf("a role answer carrying history was accepted: %v", err)
	}
}
