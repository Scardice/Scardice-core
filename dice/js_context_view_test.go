package dice

import (
	"reflect"
	"strings"
	"testing"

	"Scardice-core/message"
)

func TestJSMessageViewCopiesNestedValues(t *testing.T) {
	rawID := map[string]any{"nested": []any{map[string]any{"id": "before"}}}
	msg := &Message{
		Message: "hello",
		RawID:   rawID,
		Sender:  SenderBase{UserID: "user-1", Nickname: "Alice"},
		Segment: []message.IMessageElement{&message.DefaultElement{RawType: "custom", Data: []byte(`{"ok":true}`)}},
	}
	view := NewJSMessageView(msg)
	if view == nil {
		t.Fatal("expected message view")
	}
	if len(view.Segment) != 1 {
		t.Fatalf("segment length = %d, want 1", len(view.Segment))
	}
	view.Segment[0]["data"].([]any)[0] = uint64('x')
	if msg.Segment[0].(*message.DefaultElement).Data[0] != '{' {
		t.Fatal("message view aliases segment data")
	}
	view.RawID.(map[string]any)["nested"].([]any)[0].(map[string]any)["id"] = "after"
	if rawID["nested"].([]any)[0].(map[string]any)["id"] != "before" {
		t.Fatal("message view aliases nested raw id")
	}
	view.Sender.Nickname = "Changed"
	if msg.Sender.Nickname != "Alice" {
		t.Fatal("message view aliases sender")
	}
}

func TestJSGroupAndPlayerViewsCopyMapsAndSlices(t *testing.T) {
	group := &GroupInfo{
		GroupID:         "group-1",
		GroupName:       "Group",
		HelpPackages:    []string{"help"},
		DiceIDActiveMap: new(SyncMap[string, bool]),
		BotList:         new(SyncMap[string, bool]),
		PlayerGroups:    new(SyncMap[string, []string]),
	}
	group.DiceIDActiveMap.Store("dice", true)
	group.BotList.Store("bot", true)
	group.PlayerGroups.Store("team", []string{"one", "two"})
	player := &GroupPlayerInfo{Name: "Alice", UserID: "user-1", AutoSetNameTemplate: "{name}"}

	groupView := NewJSGroupView(group)
	playerView := NewJSPlayerView(player)
	groupView.DiceIDActive["dice"] = false
	groupView.BotList["bot"] = false
	groupView.PlayerGroups["team"][0] = "changed"
	groupView.HelpPackages[0] = "changed"
	playerView.Name = "Changed"
	if active, _ := group.DiceIDActiveMap.Load("dice"); !active {
		t.Fatal("group view aliases active map")
	}
	if bot, _ := group.BotList.Load("bot"); !bot {
		t.Fatal("group view aliases bot map")
	}
	team, _ := group.PlayerGroups.Load("team")
	if team[0] != "one" {
		t.Fatal("group view aliases nested slice")
	}
	if player.Name != "Alice" {
		t.Fatal("player view aliases player")
	}
}

func TestJSContextOverlayWhitelistAndTypedDiff(t *testing.T) {
	ctx := &MsgContext{
		MessageType:     "group",
		IsPrivate:       false,
		IsCurGroupBotOn: true,
		CommandHideFlag: "",
		PrivilegeLevel:  40,
		DelegateText:    "old",
	}
	overlay := NewJSContextOverlay(ctx)
	if err := overlay.Set("isPrivate", true); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Set("isCurGroupBotOn", false); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Set("commandHideFlag", "hidden"); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Set("privilegeLevel", 60); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Set("delegateText", "new"); err != nil {
		t.Fatal(err)
	}
	if err := overlay.Set("group", nil); err == nil {
		t.Fatal("expected excluded group write to be rejected")
	}
	if err := overlay.Set("messageType", "private"); err == nil {
		t.Fatal("expected excluded messageType write to be rejected")
	}
	want := JSContextDiff{
		IsPrivate:       boolPtr(true),
		IsCurGroupBotOn:  boolPtr(false),
		CommandHideFlag:  stringPtr("hidden"),
		PrivilegeLevel:   intPtr(60),
		DelegateText:     stringPtr("new"),
	}
	if got := overlay.Diff(); !reflect.DeepEqual(got, want) {
		t.Fatalf("diff = %#v, want %#v", got, want)
	}
	if ctx.IsPrivate || !ctx.IsCurGroupBotOn || ctx.PrivilegeLevel != 40 || ctx.DelegateText != "old" {
		t.Fatal("overlay mutated authoritative context")
	}
}

func TestJSContextOverlayDirectWritableFieldsAreCaptured(t *testing.T) {
	overlay := NewJSContextOverlay(&MsgContext{IsPrivate: false, PrivilegeLevel: 10})
	overlay.IsPrivate = true
	overlay.PrivilegeLevel = 20
	diff := overlay.Diff()
	if diff.IsPrivate == nil || !*diff.IsPrivate || diff.PrivilegeLevel == nil || *diff.PrivilegeLevel != 20 {
		t.Fatalf("direct writable fields were not captured: %#v", diff)
	}
	if got := overlay.View(); !got.IsPrivate || got.PrivilegeLevel != 20 {
		t.Fatalf("view did not include direct writable fields: %#v", got)
	}
}

func TestJSContextViewsNilSafeAndExcludeAuthorityPointers(t *testing.T) {
	if got := NewJSMessageView(nil); got != nil {
		t.Fatal("nil message should produce nil view")
	}
	if got := NewJSGroupView(nil); got != nil {
		t.Fatal("nil group should produce nil view")
	}
	if got := NewJSPlayerView(nil); got != nil {
		t.Fatal("nil player should produce nil view")
	}
	if got := NewJSEndPointView(nil); got != nil {
		t.Fatal("nil endpoint should produce nil view")
	}
	if got := NewJSContextView(nil); got == nil {
		t.Fatal("nil context should still produce an empty view")
	}
	if got := NewJSCallbackContext(nil, nil); got == nil || got.Message != nil {
		t.Fatal("nil callback inputs should be safe")
	}

	for _, typ := range []reflect.Type{
		reflect.TypeOf(JSMessageView{}), reflect.TypeOf(JSSenderView{}),
		reflect.TypeOf(JSGroupView{}), reflect.TypeOf(JSPlayerView{}),
		reflect.TypeOf(JSEndPointView{}), reflect.TypeOf(JSContextView{}),
	} {
		assertNoAuthorityPointerTypes(t, typ)
	}
}

func assertNoAuthorityPointerTypes(t *testing.T, typ reflect.Type) {
	t.Helper()
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		if field.PkgPath != "" || field.Type.Kind() != reflect.Pointer {
			continue
		}
		if strings.HasPrefix(field.Type.Elem().Name(), "JS") {
			continue
		}
		if field.Type.Elem().Kind() != reflect.Bool && field.Type.Elem().Kind() != reflect.Int && field.Type.Elem().Kind() != reflect.String {
			t.Fatalf("%s.%s exposes pointer type %s", typ.Name(), field.Name, field.Type)
		}
	}
}

func boolPtr(v bool) *bool {
	return &v
}

func stringPtr(v string) *string {
	return &v
}

func intPtr(v int) *int {
	return &v
}
func TestJSMessageViewCopiesNestedStructValues(t *testing.T) {
	type nestedDetails struct {
		Code string `jsbind:"code"`
	}
	type nestedRawID struct {
		Label  string        `jsbind:"label"`
		Detail nestedDetails `jsbind:"detail"`
	}
	rawID := nestedRawID{Label: "message-1", Detail: nestedDetails{Code: "ok"}}
	view := NewJSMessageView(&Message{RawID: rawID})
	copied, ok := view.RawID.(map[string]any)
	if !ok {
		t.Fatalf("raw ID = %#v, want copied map", view.RawID)
	}
	if copied["label"] != "message-1" {
		t.Fatalf("copied label = %#v, want message-1", copied["label"])
	}
	detail, ok := copied["detail"].(map[string]any)
	if !ok || detail["code"] != "ok" {
		t.Fatalf("copied detail = %#v, want map with code", copied["detail"])
	}
	detail["code"] = "changed"
	if rawID.Detail.Code != "ok" {
		t.Fatal("nested struct clone aliases source")
	}
}
func TestJSMessageViewTerminatesCyclicRawID(t *testing.T) {
	rawID := map[string]any{}
	rawID["self"] = rawID
	view := NewJSMessageView(&Message{RawID: rawID})
	copied, ok := view.RawID.(map[string]any)
	if !ok {
		t.Fatalf("raw ID = %#v, want copied map", view.RawID)
	}
	if value, ok := copied["self"]; !ok || value != nil {
		t.Fatalf("copied cycle = %#v, want nil cycle terminator", copied["self"])
	}
}
