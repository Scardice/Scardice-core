package dice

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// The JS*View types are request-local copies. They intentionally contain no
// Dice, session, adapter, database, lock, channel, or provider references.
// Mutating one of these values cannot mutate the callback's authoritative
// objects.
type JSSenderView struct {
	Nickname string `jsbind:"nickname" json:"nickname"`
	UserID   string `jsbind:"userId" json:"userId"`
	IsRobot  bool   `jsbind:"isRobot" json:"isRobot"`
}

type JSSegmentView map[string]any

type JSMessageView struct {
	Time        int64           `jsbind:"time" json:"time"`
	MessageType string          `jsbind:"messageType" json:"messageType"`
	GroupID     string          `jsbind:"groupId" json:"groupId"`
	GuildID     string          `jsbind:"guildId" json:"guildId"`
	ChannelID   string          `jsbind:"channelId" json:"channelId"`
	Sender      JSSenderView    `jsbind:"sender" json:"sender"`
	Message     string          `jsbind:"message" json:"message"`
	RawID       any             `jsbind:"rawId" json:"rawId"`
	Platform    string          `jsbind:"platform" json:"platform"`
	GroupName   string          `json:"groupName"`
	Seq         int64           `jsbind:"seq" json:"seq"`
	Segment     []JSSegmentView `jsbind:"segment" json:"segment"`
}

type JSGroupView struct {
	Active                bool                `jsbind:"active" json:"active"`
	GroupID               string              `jsbind:"groupId" json:"groupId"`
	GuildID               string              `jsbind:"guildId" json:"guildId"`
	ChannelID             string              `jsbind:"channelId" json:"channelId"`
	GroupName             string              `jsbind:"groupName" json:"groupName"`
	CocRuleIndex          int                 `jsbind:"cocRuleIndex" json:"cocRuleIndex"`
	DiceIDActive          map[string]bool     `json:"diceIdActive,omitempty"`
	DiceIDExists          map[string]bool     `json:"diceIdExists,omitempty"`
	BotList               map[string]bool     `json:"botList,omitempty"`
	InactivatedExtensions map[string]bool     `json:"inactivatedExtensions,omitempty"`
	ActivatedExtensions   []string            `json:"activatedExtensions,omitempty"`
	HelpPackages          []string            `json:"helpPackages,omitempty"`
	PlayerGroups          map[string][]string `json:"playerGroups,omitempty"`
}

type JSPlayerView struct {
	Name                string `jsbind:"name" json:"name"`
	UserID              string `jsbind:"userId" json:"userId"`
	InGroup             bool   `json:"inGroup"`
	LastCommandTime     int64  `jsbind:"lastCommandTime" json:"lastCommandTime"`
	AutoSetNameTemplate string `jsbind:"autoSetNameTemplate" json:"autoSetNameTemplate"`
	DiceSideNum         int    `json:"diceSideNum"`
	GroupID             string `json:"groupId"`
}

type JSEndPointView struct {
	ID                  string        `jsbind:"id" json:"id"`
	Nickname            string        `jsbind:"nickname" json:"nickname"`
	State               EndpointState `jsbind:"state" json:"state"`
	UserID              string        `jsbind:"userId" json:"userId"`
	GroupNum            int64         `jsbind:"groupNum" json:"groupNum"`
	CmdExecutedNum      int64         `jsbind:"cmdExecutedNum" json:"cmdExecutedNum"`
	CmdExecutedLastTime int64         `jsbind:"cmdExecutedLastTime" json:"cmdExecutedLastTime"`
	OnlineTotalTime     int64         `jsbind:"onlineTotalTime" json:"onlineTotalTime"`
	Platform            string        `jsbind:"platform" json:"platform"`
	RelWorkDir          string        `json:"relWorkDir"`
	Enable              bool          `jsbind:"enable" json:"enable"`
	ProtocolType        string        `json:"protocolType"`
	IsPublic            bool          `json:"isPublic"`
}

type JSContextView struct {
	MessageType     string          `json:"messageType"`
	Group           *JSGroupView    `jsbind:"group" json:"group"`
	Player          *JSPlayerView   `jsbind:"player" json:"player"`
	EndPoint        *JSEndPointView `jsbind:"endPoint" json:"endPoint"`
	IsCurGroupBotOn bool            `jsbind:"isCurGroupBotOn" json:"isCurGroupBotOn"`
	IsPrivate       bool            `jsbind:"isPrivate" json:"isPrivate"`
	CommandHideFlag string          `jsbind:"commandHideFlag" json:"commandHideFlag"`
	PrivilegeLevel  int             `jsbind:"privilegeLevel" json:"privilegeLevel"`
	DelegateText    string          `jsbind:"delegateText" json:"delegateText"`
}

type JSCallbackContext struct {
	Context JSContextView  `json:"context"`
	Message *JSMessageView `json:"message"`
}

func NewJSSenderView(sender SenderBase) JSSenderView {
	return JSSenderView{Nickname: sender.Nickname, UserID: sender.UserID, IsRobot: sender.IsRobot}
}

func NewJSMessageView(msg *Message) *JSMessageView {
	if msg == nil {
		return nil
	}
	view := &JSMessageView{
		Time: msg.Time, MessageType: msg.MessageType, GroupID: msg.GroupID,
		GuildID: msg.GuildID, ChannelID: msg.ChannelID, Sender: NewJSSenderView(msg.Sender),
		Message: msg.Message, RawID: cloneJSValue(msg.RawID), Platform: msg.Platform,
		GroupName: msg.GroupName, Seq: msg.Seq,
	}
	if len(msg.Segment) != 0 {
		view.Segment = make([]JSSegmentView, 0, len(msg.Segment))
		for _, segment := range msg.Segment {
			if copied, ok := cloneJSStruct(segment); ok {
				view.Segment = append(view.Segment, JSSegmentView(copied))
			}
		}
	}
	return view
}

func NewJSGroupView(group *GroupInfo) *JSGroupView {
	if group == nil {
		return nil
	}
	view := &JSGroupView{
		Active: group.Active, GroupID: group.GroupID, GuildID: group.GuildID,
		ChannelID: group.ChannelID, GroupName: group.GroupName, CocRuleIndex: group.CocRuleIndex,
		InactivatedExtensions: cloneStringSet(group.InactivatedExtSet),
		HelpPackages:          append([]string(nil), group.HelpPackages...),
	}
	for _, extension := range group.GetActivatedExtListRaw() {
		if extension != nil && extension.Name != "" {
			view.ActivatedExtensions = append(view.ActivatedExtensions, extension.Name)
		}
	}
	if group.DiceIDActiveMap != nil {
		view.DiceIDActive = map[string]bool{}
		group.DiceIDActiveMap.Range(func(key string, value bool) bool { view.DiceIDActive[key] = value; return true })
	}
	if group.DiceIDExistsMap != nil {
		view.DiceIDExists = map[string]bool{}
		group.DiceIDExistsMap.Range(func(key string, value bool) bool { view.DiceIDExists[key] = value; return true })
	}
	if group.BotList != nil {
		view.BotList = map[string]bool{}
		group.BotList.Range(func(key string, value bool) bool { view.BotList[key] = value; return true })
	}
	if group.PlayerGroups != nil {
		view.PlayerGroups = map[string][]string{}
		group.PlayerGroups.Range(func(key string, value []string) bool {
			view.PlayerGroups[key] = append([]string(nil), value...)
			return true
		})
	}
	return view
}

func NewJSPlayerView(player *GroupPlayerInfo) *JSPlayerView {
	if player == nil {
		return nil
	}
	return &JSPlayerView{
		Name: player.Name, UserID: player.UserID, InGroup: player.InGroup,
		LastCommandTime: player.LastCommandTime, AutoSetNameTemplate: player.AutoSetNameTemplate,
		DiceSideNum: player.DiceSideNum, GroupID: player.GroupID,
	}
}

func NewJSEndPointView(endpoint *EndPointInfo) *JSEndPointView {
	if endpoint == nil {
		return nil
	}
	base := endpoint.EndPointInfoBase
	return &JSEndPointView{
		ID: base.ID, Nickname: base.Nickname, State: base.State, UserID: base.UserID,
		GroupNum: base.GroupNum, CmdExecutedNum: base.CmdExecutedNum,
		CmdExecutedLastTime: base.CmdExecutedLastTime, OnlineTotalTime: base.OnlineTotalTime,
		Platform: base.Platform, RelWorkDir: base.RelWorkDir, Enable: base.Enable,
		ProtocolType: base.ProtocolType, IsPublic: base.IsPublic,
	}
}

func NewJSContextView(ctx *MsgContext) *JSContextView {
	view := &JSContextView{}
	if ctx == nil {
		return view
	}
	view.MessageType = ctx.MessageType
	view.Group = NewJSGroupView(ctx.Group)
	view.Player = NewJSPlayerView(ctx.Player)
	view.EndPoint = NewJSEndPointView(ctx.EndPoint)
	view.IsCurGroupBotOn = ctx.IsCurGroupBotOn
	view.IsPrivate = ctx.IsPrivate
	view.CommandHideFlag = ctx.CommandHideFlag
	view.PrivilegeLevel = ctx.PrivilegeLevel
	view.DelegateText = ctx.DelegateText
	return view
}

func NewJSCallbackContext(ctx *MsgContext, msg *Message) *JSCallbackContext {
	return &JSCallbackContext{Context: *NewJSContextView(ctx), Message: NewJSMessageView(msg)}
}

func cloneStringSet(values StringSet) map[string]bool {
	if values == nil {
		return nil
	}
	result := make(map[string]bool, len(values))
	for key := range values {
		result[key] = true
	}
	return result
}

// cloneJSValue keeps only JSON-like values and always allocates fresh maps and
// slices. Unsupported values (including pointers to runtime objects) are not
// exposed to the callback facade.
func cloneJSValue(value any) any {
	if value == nil {
		return nil
	}
	state := &jsCloneState{active: make(map[jsCloneReference]struct{})}
	return cloneJSReflectValueWithState(reflect.ValueOf(value), 0, state)
}

const maxJSCloneDepth = 16

type jsCloneReference struct {
	kind  reflect.Kind
	type_ reflect.Type
	ptr   uintptr
	len   int
	cap   int
}

type jsCloneState struct {
	active map[jsCloneReference]struct{}
}

func cloneJSReflectValueWithState(value reflect.Value, depth int, state *jsCloneState) any {
	if !value.IsValid() || depth > maxJSCloneDepth {
		return nil
	}
	switch value.Kind() {
	case reflect.Interface:
		if value.IsNil() {
			return nil
		}
		return cloneJSReflectValueWithState(value.Elem(), depth+1, state)
	case reflect.Pointer, reflect.Invalid, reflect.Uintptr, reflect.Complex64, reflect.Complex128,
		reflect.Chan, reflect.Func, reflect.UnsafePointer:
		return nil
	case reflect.Map:
		if value.IsNil() || value.Type().Key().Kind() != reflect.String {
			return nil
		}
		reference := jsCloneReference{kind: value.Kind(), type_: value.Type(), ptr: value.Pointer()}
		if !state.enter(reference) {
			return nil
		}
		defer state.leave(reference)
		result := make(map[string]any, value.Len())
		keys := value.MapKeys()
		sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
		for _, key := range keys {
			result[key.String()] = cloneJSReflectValueWithState(value.MapIndex(key), depth+1, state)
		}
		return result
	case reflect.Slice:
		if value.IsNil() {
			return nil
		}
		if value.Type() == reflect.TypeOf([]byte(nil)) {
			result := make([]byte, value.Len())
			reflect.Copy(reflect.ValueOf(result), value)
			return result
		}
		reference := jsCloneReference{
			kind: value.Kind(), type_: value.Type(), ptr: value.Pointer(),
			len: value.Len(), cap: value.Cap(),
		}
		if !state.enter(reference) {
			return nil
		}
		defer state.leave(reference)
		result := make([]any, value.Len())
		for index := range value.Len() {
			result[index] = cloneJSReflectValueWithState(value.Index(index), depth+1, state)
		}
		return result
	case reflect.Array:
		result := make([]any, value.Len())
		for index := range value.Len() {
			result[index] = cloneJSReflectValueWithState(value.Index(index), depth+1, state)
		}
		return result
	case reflect.Struct:
		result, _ := cloneJSReflectStruct(value, depth, state)
		return result
	case reflect.String:
		return value.String()
	case reflect.Bool:
		return value.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return value.Int()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return value.Uint()
	case reflect.Float32, reflect.Float64:
		return value.Float()
	}
	return nil
}

func (state *jsCloneState) enter(reference jsCloneReference) bool {
	if _, exists := state.active[reference]; exists {
		return false
	}
	state.active[reference] = struct{}{}
	return true
}

func (state *jsCloneState) leave(reference jsCloneReference) {
	delete(state.active, reference)
}
func cloneJSStruct(value any) (map[string]any, bool) {
	reflected := reflect.ValueOf(value)
	depth := 0
	for reflected.IsValid() && (reflected.Kind() == reflect.Pointer || reflected.Kind() == reflect.Interface) {
		if reflected.IsNil() || depth > maxJSCloneDepth {
			return nil, false
		}
		reflected = reflected.Elem()
		depth++
	}
	if !reflected.IsValid() || reflected.Kind() != reflect.Struct {
		return nil, false
	}
	state := &jsCloneState{active: make(map[jsCloneReference]struct{})}
	return cloneJSReflectStruct(reflected, depth, state)
}

func cloneJSReflectStruct(value reflect.Value, depth int, state *jsCloneState) (map[string]any, bool) {
	if !value.IsValid() || value.Kind() != reflect.Struct || depth > maxJSCloneDepth {
		return nil, false
	}
	result := make(map[string]any)
	typeOfValue := value.Type()
	for index := range value.NumField() {
		field := typeOfValue.Field(index)
		if field.PkgPath != "" || field.Name == "Stream" {
			continue
		}
		name := field.Name
		if tag := field.Tag.Get("jsbind"); tag != "" && tag != "-" {
			name = strings.Split(tag, ",")[0]
		}
		if name == "" || name == "-" {
			continue
		}
		result[name] = cloneJSReflectValueWithState(value.Field(index), depth+1, state)
	}
	return result, true
}

var (
	ErrJSContextMutationRejected = errors.New("js context mutation rejected")
	ErrJSContextFieldNotWritable = errors.New("js context field is not writable")
	ErrJSContextValueType        = errors.New("js context mutation has invalid type")
)

// JSContextDiff is the only state that a callback may request to write back.
// Nil means unchanged, so setting a field to its zero value remains observable.
type JSContextDiff struct {
	IsPrivate       *bool   `json:"isPrivate,omitempty"`
	IsCurGroupBotOn *bool   `json:"isCurGroupBotOn,omitempty"`
	CommandHideFlag *string `json:"commandHideFlag,omitempty"`
	PrivilegeLevel  *int    `json:"privilegeLevel,omitempty"`
	DelegateText    *string `json:"delegateText,omitempty"`
}

func (d JSContextDiff) Empty() bool {
	return d.IsPrivate == nil && d.IsCurGroupBotOn == nil && d.CommandHideFlag == nil && d.PrivilegeLevel == nil && d.DelegateText == nil
}

type JSContextOverlay struct {
	base JSContextView

	// These are the only exported writable fields. A JS binding can safely
	// bind the overlay and assign them directly; Diff observes those changes.
	IsPrivate       bool   `jsbind:"isPrivate" json:"isPrivate"`
	IsCurGroupBotOn bool   `jsbind:"isCurGroupBotOn" json:"isCurGroupBotOn"`
	CommandHideFlag string `jsbind:"commandHideFlag" json:"commandHideFlag"`
	PrivilegeLevel  int    `jsbind:"privilegeLevel" json:"privilegeLevel"`
	DelegateText    string `jsbind:"delegateText" json:"delegateText"`
}

func NewJSContextOverlay(ctx *MsgContext) *JSContextOverlay {
	base := *NewJSContextView(ctx)
	return &JSContextOverlay{
		base: base, IsPrivate: base.IsPrivate, IsCurGroupBotOn: base.IsCurGroupBotOn,
		CommandHideFlag: base.CommandHideFlag, PrivilegeLevel: base.PrivilegeLevel,
		DelegateText: base.DelegateText,
	}
}

func (o *JSContextOverlay) View() JSContextView {
	if o == nil {
		return JSContextView{}
	}
	view := o.base
	view.IsPrivate = o.IsPrivate
	view.IsCurGroupBotOn = o.IsCurGroupBotOn
	view.CommandHideFlag = o.CommandHideFlag
	view.PrivilegeLevel = o.PrivilegeLevel
	view.DelegateText = o.DelegateText
	return view
}

func (o *JSContextOverlay) Diff() JSContextDiff {
	if o == nil {
		return JSContextDiff{}
	}
	diff := JSContextDiff{}
	if o.IsPrivate != o.base.IsPrivate {
		diff.IsPrivate = &o.IsPrivate
	}
	if o.IsCurGroupBotOn != o.base.IsCurGroupBotOn {
		diff.IsCurGroupBotOn = &o.IsCurGroupBotOn
	}
	if o.CommandHideFlag != o.base.CommandHideFlag {
		diff.CommandHideFlag = &o.CommandHideFlag
	}
	if o.PrivilegeLevel != o.base.PrivilegeLevel {
		diff.PrivilegeLevel = &o.PrivilegeLevel
	}
	if o.DelegateText != o.base.DelegateText {
		diff.DelegateText = &o.DelegateText
	}
	return diff
}
func (o *JSContextOverlay) Set(field string, value any) error {
	if o == nil {
		return ErrJSContextMutationRejected
	}
	switch field {
	case "isPrivate":
		v, ok := value.(bool)
		if !ok {
			return fmt.Errorf("%w: %s", ErrJSContextValueType, field)
		}
		o.IsPrivate = v
	case "isCurGroupBotOn":
		v, ok := value.(bool)
		if !ok {
			return fmt.Errorf("%w: %s", ErrJSContextValueType, field)
		}
		o.IsCurGroupBotOn = v
	case "commandHideFlag":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("%w: %s", ErrJSContextValueType, field)
		}
		o.CommandHideFlag = v
	case "privilegeLevel":
		v, ok := contextInt(value)
		if !ok {
			return fmt.Errorf("%w: %s", ErrJSContextValueType, field)
		}
		o.PrivilegeLevel = v
	case "delegateText":
		v, ok := value.(string)
		if !ok {
			return fmt.Errorf("%w: %s", ErrJSContextValueType, field)
		}
		o.DelegateText = v
	default:
		return fmt.Errorf("%w: %s", ErrJSContextFieldNotWritable, field)
	}
	return nil
}

func contextInt(value any) (int, bool) {
	reflected := reflect.ValueOf(value)
	if !reflected.IsValid() {
		return 0, false
	}
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		converted := reflected.Int()
		maxInt := int64(^uint(0) >> 1)
		if converted < -maxInt-1 || converted > maxInt {
			return 0, false
		}
		return int(converted), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		converted := reflected.Uint()
		maxInt := uint64(^uint(0) >> 1)
		if converted > maxInt {
			return 0, false
		}
		return int(converted), true
	case reflect.Float32, reflect.Float64:
		converted := reflected.Float()
		integer := int(converted)
		return integer, float64(integer) == converted
	default:
		return 0, false
	}
}

// DiffEntries presents the diff in a stable whitelist order for collectors and
// logs. Values contain only primitive types.
type JSContextMutation struct {
	Field string `json:"field"`
	Value any    `json:"value"`
}

func (o *JSContextOverlay) DiffEntries() []JSContextMutation {
	if o == nil {
		return nil
	}
	diff := o.Diff()
	entries := make([]JSContextMutation, 0, 5)
	if diff.IsPrivate != nil {
		entries = append(entries, JSContextMutation{Field: "isPrivate", Value: *diff.IsPrivate})
	}
	if diff.IsCurGroupBotOn != nil {
		entries = append(entries, JSContextMutation{Field: "isCurGroupBotOn", Value: *diff.IsCurGroupBotOn})
	}
	if diff.CommandHideFlag != nil {
		entries = append(entries, JSContextMutation{Field: "commandHideFlag", Value: *diff.CommandHideFlag})
	}
	if diff.PrivilegeLevel != nil {
		entries = append(entries, JSContextMutation{Field: "privilegeLevel", Value: *diff.PrivilegeLevel})
	}
	if diff.DelegateText != nil {
		entries = append(entries, JSContextMutation{Field: "delegateText", Value: *diff.DelegateText})
	}
	return entries
}
