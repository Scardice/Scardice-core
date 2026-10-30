package dice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"Scardice-core/adapterapi"
	emitter "Scardice-core/dice/imsdk/onebot"
	"Scardice-core/dice/imsdk/onebot/schema"
	emitterTypes "Scardice-core/dice/imsdk/onebot/types"
)

type onebotOutboundFake struct {
	personID              int64
	groupID               int64
	personMessageID       int64
	groupMessageID        int64
	personMessage         schema.MessageChain
	groupMessage          schema.MessageChain
	deleted               int64
	deleteCh              chan int64
	cardGroup, cardMember int64
	card                  string
	quitGroup             int64
	rawAction             emitter.Action
	rawParams             any
	rawResponse           []byte
	rawErr                error
	sendResponseNil       bool
	calls                 int
}

func (f *onebotOutboundFake) SendPvtMsg(_ context.Context, id int64, msg schema.MessageChain) (*emitterTypes.SendMsgRes, error) {
	f.calls++
	f.personID, f.personMessage = id, msg
	if f.sendResponseNil {
		//nolint:nilnil // Inject the SDK's empty-success response to verify ambiguous delivery handling.
		return nil, nil
	}
	messageID := f.personMessageID
	if messageID == 0 {
		messageID = 123
	}
	return &emitterTypes.SendMsgRes{MessageId: messageID}, nil
}
func (f *onebotOutboundFake) SendGrMsg(_ context.Context, id int64, msg schema.MessageChain) (*emitterTypes.SendMsgRes, error) {
	f.calls++
	f.groupID, f.groupMessage = id, msg
	if f.sendResponseNil {
		//nolint:nilnil // Inject the SDK's empty-success response to verify ambiguous delivery handling.
		return nil, nil
	}
	messageID := f.groupMessageID
	if messageID == 0 {
		messageID = 456
	}
	return &emitterTypes.SendMsgRes{MessageId: messageID}, nil
}
func (f *onebotOutboundFake) DelMsg(_ context.Context, id int64) error {
	f.calls++
	f.deleted = id
	if f.deleteCh != nil {
		f.deleteCh <- id
	}
	return nil
}
func (f *onebotOutboundFake) SetGroupCard(_ context.Context, group, member int64, card string) error {
	f.calls++
	f.cardGroup, f.cardMember, f.card = group, member, card
	return nil
}
func (f *onebotOutboundFake) QuitGroup(_ context.Context, group int64) error {
	f.calls++
	f.quitGroup = group
	return nil
}
func (f *onebotOutboundFake) Raw(_ context.Context, action emitter.Action, params any) ([]byte, error) {
	f.calls++
	f.rawAction, f.rawParams = action, params
	return f.rawResponse, f.rawErr
}

type blockingRecallOnebotOutbound struct {
	*onebotOutboundFake
	started chan int64
	unblock chan struct{}
}

func (f *blockingRecallOnebotOutbound) DelMsg(ctx context.Context, id int64) error {
	select {
	case f.started <- id:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-f.unblock:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type onebotTemporaryError struct{}

func (onebotTemporaryError) Error() string   { return "temporary provider failure" }
func (onebotTemporaryError) Timeout() bool   { return false }
func (onebotTemporaryError) Temporary() bool { return true }

func outboundEffectForTest(t *testing.T, payload adapterapi.EffectPayload, caps adapterapi.CapabilitySet, action adapterapi.ActionKind) adapterapi.OutboundEffect {
	t.Helper()
	lane, err := adapterapi.NewLaneMetadata("endpoint-1", payload.Target, []byte("index-root"), 1)
	if err != nil {
		t.Fatal(err)
	}
	kind := adapterapi.EffectKindAction
	risk := adapterapi.EffectRiskNormal
	retry := adapterapi.EffectRetryProviderIdempotent
	switch payload.Kind {
	case adapterapi.EffectPayloadPersonText, adapterapi.EffectPayloadGroupText, adapterapi.EffectPayloadSegments, adapterapi.EffectPayloadFile:
		kind, retry = adapterapi.EffectKindMessage, adapterapi.EffectRetryNonIdempotent
	case adapterapi.EffectPayloadSetGroupCard, adapterapi.EffectPayloadQuit, adapterapi.EffectPayloadBan, adapterapi.EffectPayloadKick:
		risk, retry = adapterapi.EffectRiskHigh, adapterapi.EffectRetryNonIdempotent
	case adapterapi.EffectPayloadAnswerRequest:
		retry = adapterapi.EffectRetryNonIdempotent
	case adapterapi.EffectPayloadInvalid, adapterapi.EffectPayloadEdit, adapterapi.EffectPayloadRecall, adapterapi.EffectPayloadGroupInfoRefresh:
	}
	return adapterapi.OutboundEffect{
		Version: adapterapi.EffectVersionOne, ID: "effect-1", EndpointID: "endpoint-1", OperationID: "operation-1",
		CorrelationID: "correlation-1", CausationID: "causation-1", Lane: lane, Deadline: time.Now().Add(time.Minute),
		Risk: risk, RetryClass: retry, RequiredCapabilities: caps,
		RequiredAction: action, Kind: kind, Payload: payload,
	}
}

func outboundMessageEffectForTest(t *testing.T, payload adapterapi.EffectPayload, caps adapterapi.CapabilitySet) adapterapi.OutboundEffect {
	effect := outboundEffectForTest(t, payload, caps, adapterapi.ActionKindSendMessage)
	effect.Kind = adapterapi.EffectKindMessage
	effect.RetryClass = adapterapi.EffectRetryNonIdempotent
	return effect
}

func TestOnebotRuntimeExecuteSendsPersonSegmentsAndReturnsProviderID(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSegments, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "QQ:42"}, Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindText, Text: "hello"}, {Kind: adapterapi.SegmentKindMention, Text: "QQ:7"}}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "123" {
		t.Fatalf("result = %#v", result)
	}
	if fake.personID != 42 || len(fake.personMessage) != 2 {
		t.Fatalf("person send = %#v", fake)
	}
}
func TestOnebotRuntimeExecuteSendsGroupText(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "456" {
		t.Fatalf("result = %#v", result)
	}
	if fake.groupID != 9 || len(fake.groupMessage) != 1 {
		t.Fatalf("group send = %#v", fake)
	}
}
func TestOnebotRuntimeExecuteExpandsSealImageFromDataPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(filepath.Join("data", "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("data", "images", "1000059382.png"), []byte("image-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "检定结果\n[图:data/images/1000059382.png]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("result = %#v", result)
	}
	if len(fake.groupMessage) != 2 || fake.groupMessage[0].Type != "text" || fake.groupMessage[1].Type != "image" {
		t.Fatalf("group message = %#v", fake.groupMessage)
	}
	var image struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(fake.groupMessage[1].Data, &image); err != nil {
		t.Fatal(err)
	}
	if image.File != "base64://aW1hZ2UtYnl0ZXM=" {
		t.Fatalf("image file = %q", image.File)
	}
}
func TestOnebotRuntimeExecuteExpandsCQLocalImageFromDataPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.MkdirAll(filepath.Join("data", "images"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join("data", "images", "cq.png"), []byte("cq-image"), 0o644); err != nil {
		t.Fatal(err)
	}

	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "[CQ:image,file=data/images/cq.png,cache=0]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || len(fake.groupMessage) != 1 || fake.groupMessage[0].Type != "image" {
		t.Fatalf("result = %#v, group message = %#v", result, fake.groupMessage)
	}
	var image struct {
		File  string `json:"file"`
		Cache string `json:"cache"`
	}
	if err := json.Unmarshal(fake.groupMessage[0].Data, &image); err != nil {
		t.Fatal(err)
	}
	if image.File != "base64://Y3EtaW1hZ2U=" || image.Cache != "0" {
		t.Fatalf("image data = %#v", image)
	}
}

func TestOnebotDescriptorRuntimeUsesSharedAssetURLForLargeLocalImage(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data", "default")
	imageDir := filepath.Join(dir, "data", "images")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(imageDir, "large.png"), make([]byte, onebotAssetInlineThreshold+1), 0o644); err != nil {
		t.Fatal(err)
	}

	descriptor := OnebotDescriptor{}
	validated, err := descriptor.ValidateConfig(context.Background(), json.RawMessage(`{"mode":"client","url":"ws://127.0.0.1:6700"}`))
	if err != nil {
		t.Fatal(err)
	}
	created, err := descriptor.NewRuntime(adapterapi.RuntimeInit{
		EndpointID:           "endpoint-1",
		Generation:           1,
		DesiredVersion:       1,
		Config:               validated,
		ResourceRoot:         dataDir,
		ResourceAccessToken:  "asset-token",
		ResourceServeAddress: "0.0.0.0:4567",
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime := created.(*onebotRuntime)
	fake := &onebotOutboundFake{}
	runtime.outbound = fake
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "[图:data/images/large.png]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || len(fake.groupMessage) != 1 || fake.groupMessage[0].Type != "image" {
		t.Fatalf("result=%#v group message=%#v", result, fake.groupMessage)
	}
	var image struct {
		File string `json:"file"`
	}
	if err := json.Unmarshal(fake.groupMessage[0].Data, &image); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(image.File, ":4567/assets-img/asset-token/images/large.png") {
		t.Fatalf("image file=%q", image.File)
	}
}

func TestOnebotRuntimeExecuteExpandsCQCodes(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text: "前缀" +
			"[CQ:at,qq=7]" +
			"[CQ:face,id=14]" +
			"[CQ:image,file=https://example.com/a.png?x=1&amp;y=2,cache=0]" +
			"[CQ:record,file=base64://dm9pY2U=]" +
			"[CQ:reply,id=42]" +
			"[CQ:poke,qq=8]" +
			"[CQ:json,data={&#91;&quot;ok&quot;&#93;:true}]" +
			"[CQ:Vendor.X,id=1]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("result = %#v", result)
	}
	wantTypes := []string{"text", "at", "face", "image", "record", "reply", "poke", "json", "Vendor.X"}
	if len(fake.groupMessage) != len(wantTypes) {
		t.Fatalf("group message = %#v", fake.groupMessage)
	}
	for index, want := range wantTypes {
		if fake.groupMessage[index].Type != want {
			t.Fatalf("segment %d type = %q, want %q", index, fake.groupMessage[index].Type, want)
		}
	}
	var image struct {
		File  string `json:"file"`
		Cache string `json:"cache"`
	}
	if err := json.Unmarshal(fake.groupMessage[3].Data, &image); err != nil {
		t.Fatal(err)
	}
	if image.File != "https://example.com/a.png?x=1&y=2" || image.Cache != "0" {
		t.Fatalf("image data = %#v", image)
	}
}

func TestOnebotRuntimeExecutePreservesCQResourceFileAndURL(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "[CQ:image,file=uploaded.image,url=https://example.com/a.png?x=1&amp;y=2,cache=0]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || len(fake.groupMessage) != 1 || fake.groupMessage[0].Type != "image" {
		t.Fatalf("result=%#v group message=%#v", result, fake.groupMessage)
	}
	var image struct {
		File  string `json:"file"`
		URL   string `json:"url"`
		Cache string `json:"cache"`
	}
	if err := json.Unmarshal(fake.groupMessage[0].Data, &image); err != nil {
		t.Fatal(err)
	}
	if image.File != "uploaded.image" || image.URL != "https://example.com/a.png?x=1&y=2" || image.Cache != "0" {
		t.Fatalf("image data=%#v", image)
	}
}

func TestOnebotRuntimeExecutePreservesResourceCodeWithMissingReference(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "[CQ:image]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || len(fake.groupMessage) != 1 || fake.groupMessage[0].Type != "text" {
		t.Fatalf("result=%#v group message=%#v", result, fake.groupMessage)
	}
	var text struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(fake.groupMessage[0].Data, &text); err != nil {
		t.Fatal(err)
	}
	if text.Text != "[CQ:image]" {
		t.Fatalf("text=%q", text.Text)
	}
}

func TestOnebotRuntimeExecuteExpandsAllSealResourceAliases(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text: "[图:https://example.com/a.png]" +
			"[img:https://example.com/b.png]" +
			"[文本:https://example.com/a.txt]" +
			"[text:https://example.com/b.txt]" +
			"[语音:https://example.com/a.wav]" +
			"[voice:https://example.com/b.wav]" +
			"[视频:https://example.com/a.mp4]" +
			"[video:https://example.com/b.mp4]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("result = %#v", result)
	}
	wantTypes := []string{"image", "image", "image", "image", "record", "record", "video", "video"}
	if len(fake.groupMessage) != len(wantTypes) {
		t.Fatalf("group message = %#v", fake.groupMessage)
	}
	for index, want := range wantTypes {
		if fake.groupMessage[index].Type != want {
			t.Fatalf("segment %d type = %q, want %q", index, fake.groupMessage[index].Type, want)
		}
	}
}

func TestOnebotRuntimeExecuteExpandsCodesInsideSegmentText(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadSegments,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Segments: []adapterapi.MessageSegment{
			{Kind: adapterapi.SegmentKindText, Text: "前[图:https://example.com/a.png]"},
			{Kind: adapterapi.SegmentKindMention, Text: "QQ:7"},
			{Kind: adapterapi.SegmentKindText, Text: "[CQ:face,id=14]后"},
		},
	}, adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("result=%#v", result)
	}
	wantTypes := []string{"text", "image", "at", "face", "text"}
	if len(fake.groupMessage) != len(wantTypes) {
		t.Fatalf("group message=%#v", fake.groupMessage)
	}
	for index, want := range wantTypes {
		if fake.groupMessage[index].Type != want {
			t.Fatalf("segment %d type=%q, want %q", index, fake.groupMessage[index].Type, want)
		}
	}
}
func TestOnebotRuntimeExecuteRecallCodeUsesExplicitIDWithoutSendingMessage(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "[CQ:recall,id=77]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || fake.deleted != 77 || fake.groupMessage != nil || fake.calls != 1 {
		t.Fatalf("result=%#v fake=%#v", result, fake)
	}
}

func TestOnebotRuntimeExecuteRecallCodeUsesSentMessageIDByDefault(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "hello[CQ:recall]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "456" || fake.deleted != 456 || fake.calls != 2 {
		t.Fatalf("result=%#v fake=%#v", result, fake)
	}
	if len(fake.groupMessage) != 1 || fake.groupMessage[0].Type != "text" {
		t.Fatalf("group message=%#v", fake.groupMessage)
	}
}

func TestOnebotRuntimeExecuteAcceptsNegativeProviderMessageID(t *testing.T) {
	fake := &onebotOutboundFake{groupMessageID: -456}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "hello[CQ:recall]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "-456" || fake.deleted != -456 || fake.calls != 2 {
		t.Fatalf("result=%#v fake=%#v", result, fake)
	}
}

func TestOnebotRuntimeExecuteDelayedRecallCodeDoesNotBlock(t *testing.T) {
	fake := &onebotOutboundFake{deleteCh: make(chan int64, 1)}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "[CQ:recall,id=88,delay=200]",
	}, adapterapi.CapabilityOutbound)

	started := time.Now()
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("result=%#v", result)
	}
	if elapsed := time.Since(started); elapsed >= 100*time.Millisecond {
		t.Fatalf("delayed recall blocked for %v", elapsed)
	}
	select {
	case messageID := <-fake.deleteCh:
		if messageID != 88 {
			t.Fatalf("recalled message ID=%d", messageID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delayed recall")
	}
}

func TestOnebotRuntimeExecuteDelayedRecallAcceptsNegativeMessageID(t *testing.T) {
	fake := &onebotOutboundFake{deleteCh: make(chan int64, 1)}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "[CQ:recall,id=-88,delay=10]",
	}, adapterapi.CapabilityOutbound)

	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded {
		t.Fatalf("result=%#v", result)
	}
	select {
	case messageID := <-fake.deleteCh:
		if messageID != -88 {
			t.Fatalf("recalled message ID=%d", messageID)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for delayed recall")
	}
}

func TestOnebotRuntimeDelayedRecallQueueIsBounded(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	runtime.outbound = fake
	defer runtime.cancelOnebotMessageRecalls()

	for index := range maxOnebotPendingRecalls {
		if err := runtime.scheduleOnebotMessageRecall(fake, int64(index+1), time.Hour); err != nil {
			t.Fatalf("schedule %d: %v", index, err)
		}
	}
	if err := runtime.scheduleOnebotMessageRecall(fake, 999, time.Hour); !errors.Is(err, ErrOnebotRecallQueueFull) {
		t.Fatalf("overflow error=%v", err)
	}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{
		Kind:   adapterapi.EffectPayloadGroupText,
		Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"},
		Text:   "hello[CQ:recall,delay=3600000]",
	}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome == adapterapi.EffectSucceeded || fake.calls != 0 {
		t.Fatalf("result=%#v calls=%d", result, fake.calls)
	}
	if runtime.recallRejected.Load() != 2 {
		t.Fatalf("rejected recalls=%d", runtime.recallRejected.Load())
	}
}

func TestOnebotRuntimeDelayedRecallBoundIncludesProviderCalls(t *testing.T) {
	unblock := make(chan struct{})
	fake := &blockingRecallOnebotOutbound{
		onebotOutboundFake: &onebotOutboundFake{},
		started:            make(chan int64, maxOnebotPendingRecalls),
		unblock:            unblock,
	}
	runtime := newOnebotRuntime(OnebotConfig{}, nil)
	defer runtime.cancelOnebotMessageRecalls()
	defer close(unblock)

	for index := range maxOnebotPendingRecalls {
		if err := runtime.scheduleOnebotMessageRecall(fake, int64(index+1), time.Millisecond); err != nil {
			t.Fatalf("schedule %d: %v", index, err)
		}
	}
	for range maxOnebotPendingRecalls {
		select {
		case <-fake.started:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for delayed recall provider call")
		}
	}
	if err := runtime.scheduleOnebotMessageRecall(fake, 999, time.Hour); !errors.Is(err, ErrOnebotRecallQueueFull) {
		t.Fatalf("overflow error while provider calls are active=%v", err)
	}
}

func TestOnebotRuntimeShutdownCancelsPendingDelayedRecalls(t *testing.T) {
	tests := []struct {
		name     string
		shutdown func(*onebotRuntime) error
	}{
		{
			name: "stop",
			shutdown: func(runtime *onebotRuntime) error {
				return runtime.Stop(context.Background())
			},
		},
		{
			name: "run cleanup",
			shutdown: func(runtime *onebotRuntime) error {
				runtime.cleanup()
				return nil
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &onebotOutboundFake{deleteCh: make(chan int64, 1)}
			runtime := newOnebotRuntime(OnebotConfig{}, nil)
			if err := runtime.scheduleOnebotMessageRecall(fake, 77, time.Hour); err != nil {
				t.Fatal(err)
			}
			if err := test.shutdown(runtime); err != nil {
				t.Fatal(err)
			}

			select {
			case messageID := <-fake.deleteCh:
				t.Fatalf("shutdown allowed delayed recall for message %d", messageID)
			case <-time.After(20 * time.Millisecond):
			}
			deadline := time.After(time.Second)
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for {
				runtime.recallMu.Lock()
				pending := runtime.recallPending
				runtime.recallMu.Unlock()
				if pending == 0 {
					break
				}
				select {
				case <-deadline:
					t.Fatalf("pending delayed recall reservations=%d after shutdown", pending)
				case <-ticker.C:
				}
			}
			if err := runtime.scheduleOnebotMessageRecall(fake, 88, time.Hour); !errors.Is(err, ErrOnebotRuntimeStopped) {
				t.Fatalf("schedule after shutdown error=%v", err)
			}
		})
	}
}

func TestOnebotRuntimeExecuteAcceptsInboundGroupConversationID(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ:group:9"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || fake.groupID != 9 {
		t.Fatalf("result=%#v fake=%#v", result, fake)
	}
}

func TestOnebotRuntimeExecuteRejectsBareGroupConversationIDBeforeIO(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "9"}, Text: "hello"}, adapterapi.CapabilityOutbound)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
		t.Fatalf("result=%#v calls=%d", result, fake.calls)
	}
}
func TestOnebotRuntimeExecuteRejectsBarePersonAndMemberIDsBeforeIO(t *testing.T) {
	t.Run("person", func(t *testing.T) {
		fake := &onebotOutboundFake{}
		effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadPersonText, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "42"}, Text: "hello"}, adapterapi.CapabilityOutbound)
		result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
		if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
			t.Fatalf("result=%#v calls=%d", result, fake.calls)
		}
	})
	t.Run("member", func(t *testing.T) {
		fake := &onebotOutboundFake{}
		effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadKick, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ:group:9", Member: "8"}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindKick)
		result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
		if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
			t.Fatalf("result=%#v calls=%d", result, fake.calls)
		}
	})
}

func TestOnebotRuntimeExecuteRejectsInvalidMentionsBeforeIO(t *testing.T) {
	for _, mention := range []string{"7", " QQ:7 "} {
		t.Run(mention, func(t *testing.T) {
			fake := &onebotOutboundFake{}
			effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSegments, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetPerson, Conversation: "QQ:42"}, Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindMention, Text: mention}}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages)
			result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
			if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
				t.Fatalf("result=%#v calls=%d", result, fake.calls)
			}
		})
	}
}

func TestOnebotRuntimeExecuteSendsGroupSegments(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundMessageEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSegments, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, Segments: []adapterapi.MessageSegment{{Kind: adapterapi.SegmentKindText, Text: "hello"}}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityRichMessages)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectSucceeded || result.ProviderID != "456" || fake.groupID != 9 || len(fake.groupMessage) != 1 {
		t.Fatalf("result=%#v fake=%#v", result, fake)
	}
}

func TestOnebotRuntimeExecuteMapsActionsToTypedAndRawEmitterCalls(t *testing.T) {
	tests := []struct {
		name    string
		payload adapterapi.EffectPayload

		action adapterapi.ActionKind
		caps   adapterapi.CapabilitySet
		check  func(*testing.T, *onebotOutboundFake)
	}{
		{"recall", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadRecall, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "-77"}, adapterapi.ActionKindRecallMessage, adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) {
			if f.deleted != -77 {
				t.Fatalf("deleted = %d", f.deleted)
			}
		}},
		{"card", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadSetGroupCard, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"}, Card: "new"}, adapterapi.ActionKindSetGroupCard, adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) {
			if f.cardGroup != 9 || f.cardMember != 8 || f.card != "new" {
				t.Fatalf("card = %#v", f)
			}
		}},
		{"quit", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadQuit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}}, adapterapi.ActionKindQuit, adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) {
			if f.quitGroup != 9 {
				t.Fatalf("quit = %d", f.quitGroup)
			}
		}},
		{"edit", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadEdit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "77", Text: "edited"}, adapterapi.ActionKindEditMessage, adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) {
			if f.rawAction != "set_msg" {
				t.Fatalf("raw action = %q", f.rawAction)
			}
		}},
		{"ban", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadBan, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"}, DurationSeconds: 30, Reason: "rule"}, adapterapi.ActionKindBan, adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) {
			if f.rawAction != "set_group_ban" {
				t.Fatalf("raw action = %q", f.rawAction)
			}
		}},
		{"kick", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadKick, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9", Member: "QQ:8"}, Reason: "rule"}, adapterapi.ActionKindKick, adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) {
			if f.rawAction != "set_group_kick" {
				t.Fatalf("raw action = %q", f.rawAction)
			}
		}},
		{"group info", adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupInfoRefresh, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}}, adapterapi.ActionKindGroupInfoRefresh, adapterapi.CapabilityOutbound | adapterapi.CapabilityActions, func(t *testing.T, f *onebotOutboundFake) {
			request, ok := f.rawParams.(emitterTypes.GetGroupInfoReq)
			if f.rawAction != emitter.ACTION_GET_GROUP_INFO || !ok || request.GroupId != 9 || !request.NoCache {
				t.Fatalf("group info request = action:%q params:%#v", f.rawAction, f.rawParams)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &onebotOutboundFake{rawResponse: []byte(`{"status":"ok","retcode":0,"data":{"group_id":9,"group_name":"Group","member_count":1,"max_member_count":500}}`)}
			runtime := &onebotRuntime{outbound: fake}
			effect := outboundEffectForTest(t, tt.payload, tt.caps, tt.action)
			if err := effect.Validate(); err != nil {
				t.Fatalf("fixture invalid: %v", err)
			}
			result := runtime.Execute(context.Background(), effect)
			if result.Outcome != adapterapi.EffectSucceeded {
				t.Fatalf("result = %#v", result)
			}
			tt.check(t, fake)
		})
	}
}

func TestOnebotRuntimeExecuteRejectsFileAndArtifactBeforeProviderIO(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadFile, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, File: adapterapi.ArtifactInput{ID: "artifact-1", Filename: "safe.txt"}}, adapterapi.CapabilityOutbound|adapterapi.CapabilityArtifacts, adapterapi.ActionKindSendFile)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 || !strings.Contains(result.Code, "artifact") {
		t.Fatalf("result=%#v calls=%d", result, fake.calls)
	}
}

func TestOnebotRuntimeExecuteRedactsProviderErrors(t *testing.T) {
	fake := &onebotOutboundFake{rawResponse: []byte(`{"status":"failed","retcode":1403,"token":"secret-token","body":"raw-provider-body"}`), rawErr: errors.New("Authorization: Bearer secret-token raw-provider-body")}
	runtime := &onebotRuntime{outbound: fake}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadEdit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "77", Text: "edited"}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage)
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectRetryable || strings.Contains(result.Message, "secret-token") || strings.Contains(result.Message, "raw-provider-body") || strings.Contains(result.Message, "Authorization") {
		t.Fatalf("result leaked provider details: %#v", result)
	}
}
func TestOnebotRuntimeExecuteClassifiesExplicitTemporaryProviderErrorsAsRetryable(t *testing.T) {
	fake := &onebotOutboundFake{rawErr: onebotTemporaryError{}}
	effect := outboundEffectForTest(t, adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadEdit, Target: adapterapi.EffectTarget{Kind: adapterapi.TargetGroup, Conversation: "QQ-Group:9"}, MessageID: "77", Text: "edited"}, adapterapi.CapabilityOutbound|adapterapi.CapabilityActions, adapterapi.ActionKindEditMessage)
	result := (&onebotRuntime{outbound: fake}).Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectRetryable || result.Code != "onebot_provider_transient" {
		t.Fatalf("result=%#v", result)
	}
}

func TestOnebotRuntimeExecuteValidatesBeforeProviderIO(t *testing.T) {
	fake := &onebotOutboundFake{}
	runtime := &onebotRuntime{outbound: fake}
	effect := adapterapi.OutboundEffect{Version: adapterapi.EffectVersionOne, ID: "effect-1", Payload: adapterapi.EffectPayload{Kind: adapterapi.EffectPayloadGroupText}}
	result := runtime.Execute(context.Background(), effect)
	if result.Outcome != adapterapi.EffectUnsupported || fake.calls != 0 {
		t.Fatalf("result=%#v calls=%d", result, fake.calls)
	}
}

func TestOnebotDescriptorAdvertisesImplementedActionsOnly(t *testing.T) {
	validated, err := (OnebotDescriptor{}).ValidateConfig(context.Background(), []byte(`{"mode":"client","url":"ws://bot.example"}`))
	if err != nil {
		t.Fatal(err)
	}
	actions := (OnebotDescriptor{}).SupportedActions(validated)
	for _, action := range []adapterapi.ActionKind{adapterapi.ActionKindSendMessage, adapterapi.ActionKindRecallMessage, adapterapi.ActionKindEditMessage, adapterapi.ActionKindSetGroupCard, adapterapi.ActionKindQuit, adapterapi.ActionKindBan, adapterapi.ActionKindKick, adapterapi.ActionKindGroupInfoRefresh} {
		if !actions.Has(action) {
			t.Fatalf("missing advertised action %v", action)
		}
	}
	if actions.Has(adapterapi.ActionKindSendFile) {
		t.Fatal("file action must remain unsupported without artifact reader")
	}
}

type onebotRejectedActionTestError struct {
	detail string
}

func (err onebotRejectedActionTestError) Error() string { return err.detail }
func (onebotRejectedActionTestError) IsActionRejected() {}
