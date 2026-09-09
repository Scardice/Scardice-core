package configstate

import (
	"Scardice-core/eventstore"
)

const (
	ConfigAggregateType             = "dice-config"
	ConfigEventSchemaVersion uint16 = 1
	ConfigProjectionName            = "dice-config"
	ConfigProjectionVersion         = "v1"
)

type State struct {
	Version       uint64           `json:"version"`
	DiceID        string           `json:"diceId"`
	ConfigVersion int              `json:"configVersion"`
	Base          BaseConfig       `json:"base"`
	Rate          RateConfig       `json:"rate"`
	Quit          QuitConfig       `json:"quit"`
	Extension     ExtensionConfig  `json:"extension"`
	Ban           BanConfig        `json:"ban"`
	JS            JSConfig         `json:"js"`
	StoryLog      StoryLogConfig   `json:"storyLog"`
	Mail          MailConfig       `json:"mail"`
	News          NewsConfig       `json:"news"`
	PublicDice    PublicDiceConfig `json:"publicDice"`
	Censor        CensorConfig     `json:"censor"`
	Store         StoreConfig      `json:"store"`
	Advanced      AdvancedConfig   `json:"advanced"`
	Outer         OuterConfig      `json:"outer"`
}
type Aggregate = State
type ConfigState = State

func (s State) Clone() State {
	out := s
	out.Base = cloneBaseConfig(s.Base)
	out.Censor = cloneCensorConfig(s.Censor)
	out.Store = cloneStoreConfig(s.Store)
	out.Outer = cloneOuterConfig(s.Outer)
	return out
}
func ConfigStream(diceID string) eventstore.StreamID {
	if !validID(diceID) {
		return eventstore.StreamID{AggregateType: ConfigAggregateType}
	}
	return eventstore.StreamID{AggregateType: ConfigAggregateType, AggregateID: diceID}
}

type CommandKind string

const (
	CommandImportBaseline CommandKind = "import_baseline"
	CommandPatch          CommandKind = "patch"
	ImportBaseline                    = CommandImportBaseline
	Patch                             = CommandPatch
)

type Baseline struct {
	DiceID        string
	ConfigVersion int
	Base          BaseConfig
	Rate          RateConfig
	Quit          QuitConfig
	Extension     ExtensionConfig
	Ban           BanConfig
	JS            JSConfig
	StoryLog      StoryLogConfig
	Mail          MailConfig
	News          NewsConfig
	PublicDice    PublicDiceConfig
	Censor        CensorConfig
	Store         StoreConfig
	Advanced      AdvancedConfig
	CommandPrefix []string
	DiceMasters   []string
}
type ConfigPatch struct {
	Base             *BaseConfig
	Rate             *RateConfig
	Quit             *QuitConfig
	Extension        *ExtensionConfig
	Ban              *BanConfig
	JS               *JSConfig
	StoryLog         *StoryLogConfig
	Mail             *MailConfig
	News             *NewsConfig
	PublicDice       *PublicDiceConfig
	Censor           *CensorConfig
	Store            *StoreConfig
	Advanced         *AdvancedConfig
	Outer            *OuterConfig
	CommandPrefix    []string
	DiceMasters      []string
	SetCommandPrefix bool
	SetDiceMasters   bool
}
type Command struct {
	Kind               CommandKind
	Type               CommandKind
	Baseline           *Baseline
	Patch              *ConfigPatch
	ExpectedVersion    uint64
	ExpectedVersionSet bool
}
type Decision struct {
	Events []TypedEvent
	Replay bool
}
type ConfigCommand = Command
type ConfigDecision = Decision

func defaultBaseline(b Baseline) Baseline {
	if b.ConfigVersion == 0 {
		b.ConfigVersion = 1
	}
	if b.Rate.PersonalReplenishRate == "" {
		b.Rate.PersonalReplenishRate = "@every 3s"
	}
	if b.Rate.GroupReplenishRate == "" {
		b.Rate.GroupReplenishRate = "@every 3s"
	}
	if b.Rate.PersonalBurst == 0 {
		b.Rate.PersonalBurst = 3
	}
	if b.Rate.GroupBurst == 0 {
		b.Rate.GroupBurst = 3
	}
	if b.Rate.SpamSameCommandWindowSec == 0 {
		b.Rate.SpamSameCommandWindowSec = 30
	}
	if b.Rate.SpamRecoveryMultiplierMax == 0 {
		b.Rate.SpamRecoveryMultiplierMax = 5
	}
	if b.Quit.QuitInactiveBatchSize == 0 {
		b.Quit.QuitInactiveBatchSize = 10
	}
	if b.Quit.QuitInactiveThreshold == "" {
		b.Quit.QuitInactiveThreshold = "0s"
	}
	if b.Extension.MaxExecuteTime == 0 {
		b.Extension.MaxExecuteTime = 12
	}
	if b.Extension.MaxCocCardGen == 0 {
		b.Extension.MaxCocCardGen = 5
	}
	if b.JS.JsEngine == "" {
		b.JS.JsEngine = "goja"
	}
	if b.Advanced.CustomReplyCooldown == 0 {
		b.Advanced.CustomReplyCooldown = 5
	}
	if b.StoryLog.LogSizeNoticeCount == 0 {
		b.StoryLog.LogSizeNoticeCount = 500
	}
	if len(b.CommandPrefix) == 0 {
		b.CommandPrefix = []string{"!", ".", "。", "/"}
	}
	b.DiceMasters = normalizeSlices(b.DiceMasters, true)
	return b
}
func decide(state State, command Command) (Decision, error) {
	if command.ExpectedVersionSet && command.ExpectedVersion != state.Version {
		return Decision{}, ErrStaleVersion
	}
	kind := command.Kind
	if kind == "" {
		kind = command.Type
	}
	if kind == CommandImportBaseline {
		if state.Version != 0 || command.Baseline == nil {
			return Decision{}, ErrInvalidCommand
		}
		b := defaultBaseline(*command.Baseline)
		if !validID(b.DiceID) {
			return Decision{}, ErrInvalidCommand
		}
		events := []TypedEvent{BaseChangedV1{DiceID: b.DiceID, ConfigVersion: b.ConfigVersion, BaseConfig: b.Base}, RateChangedV1{b.Rate}, QuitChangedV1{b.Quit}, ExtensionChangedV1{b.Extension}, BanChangedV1{b.Ban}, JSChangedV1{b.JS}, StoryLogChangedV1{b.StoryLog}, MailChangedV1{b.Mail}, NewsChangedV1{b.News}, PublicDiceChangedV1{b.PublicDice}, CensorChangedV1{b.Censor}, StoreChangedV1{b.Store}, AdvancedChangedV1{b.Advanced}, OuterChangedV1{OuterConfig{CommandPrefix: b.CommandPrefix, DiceMasters: b.DiceMasters}}}
		for _, e := range events {
			if err := validateEvent(e); err != nil {
				return Decision{}, err
			}
		}
		return Decision{Events: events}, nil
	}
	if kind != CommandPatch || state.Version == 0 || command.Patch == nil {
		return Decision{}, ErrInvalidCommand
	}
	p := command.Patch
	events := make([]TypedEvent, 0, 14)
	add := func(e TypedEvent, same bool) error {
		if same {
			return nil
		}
		if err := validateEvent(e); err != nil {
			return err
		}
		events = append(events, e)
		return nil
	}
	if p.Base != nil {
		if err := add(BaseChangedV1{DiceID: state.DiceID, ConfigVersion: state.ConfigVersion, BaseConfig: *p.Base}, equalBase(state.Base, *p.Base)); err != nil {
			return Decision{}, err
		}
	}
	if p.Rate != nil {
		if err := add(RateChangedV1{*p.Rate}, state.Rate == *p.Rate); err != nil {
			return Decision{}, err
		}
	}
	if p.Quit != nil {
		if err := add(QuitChangedV1{*p.Quit}, state.Quit == *p.Quit); err != nil {
			return Decision{}, err
		}
	}
	if p.Extension != nil {
		if err := add(ExtensionChangedV1{*p.Extension}, state.Extension == *p.Extension); err != nil {
			return Decision{}, err
		}
	}
	if p.Ban != nil {
		if err := add(BanChangedV1{*p.Ban}, state.Ban == *p.Ban); err != nil {
			return Decision{}, err
		}
	}
	if p.JS != nil {
		if err := add(JSChangedV1{*p.JS}, state.JS == *p.JS); err != nil {
			return Decision{}, err
		}
	}
	if p.StoryLog != nil {
		if err := add(StoryLogChangedV1{*p.StoryLog}, state.StoryLog == *p.StoryLog); err != nil {
			return Decision{}, err
		}
	}
	if p.Mail != nil {
		if err := add(MailChangedV1{*p.Mail}, state.Mail == *p.Mail); err != nil {
			return Decision{}, err
		}
	}
	if p.News != nil {
		if err := add(NewsChangedV1{*p.News}, state.News == *p.News); err != nil {
			return Decision{}, err
		}
	}
	if p.PublicDice != nil {
		if err := add(PublicDiceChangedV1{*p.PublicDice}, state.PublicDice == *p.PublicDice); err != nil {
			return Decision{}, err
		}
	}
	if p.Censor != nil {
		if err := add(CensorChangedV1{*p.Censor}, equalCensor(state.Censor, *p.Censor)); err != nil {
			return Decision{}, err
		}
	}
	if p.Store != nil {
		if err := add(StoreChangedV1{*p.Store}, equalStore(state.Store, *p.Store)); err != nil {
			return Decision{}, err
		}
	}
	if p.Advanced != nil {
		if err := add(AdvancedChangedV1{*p.Advanced}, state.Advanced == *p.Advanced); err != nil {
			return Decision{}, err
		}
	}
	if p.SetCommandPrefix || p.SetDiceMasters {
		outer := state.Outer
		if p.SetCommandPrefix {
			outer.CommandPrefix = append([]string(nil), p.CommandPrefix...)
		}
		if p.SetDiceMasters {
			outer.DiceMasters = normalizeSlices(p.DiceMasters, true)
		}
		if err := add(OuterChangedV1{outer}, equalOuter(state.Outer, outer)); err != nil {
			return Decision{}, err
		}
	}
	return Decision{Events: events, Replay: len(events) == 0}, nil
}
func Decide(state State, command Command) (Decision, error) {
	if command.Patch != nil {
		patch := *command.Patch
		if patch.Outer != nil {
			outer := patch.Outer
			patch.SetCommandPrefix = true
			patch.CommandPrefix = append([]string(nil), outer.CommandPrefix...)
			patch.SetDiceMasters = true
			patch.DiceMasters = append([]string(nil), outer.DiceMasters...)
		}
		command.Patch = &patch
	}
	return decide(state, command)
}
func equalBase(a, b BaseConfig) bool {
	idsA := append([]string(nil), a.NoticeIDs...)
	idsB := append([]string(nil), b.NoticeIDs...)
	a.NoticeIDs = nil
	b.NoticeIDs = nil
	return baseScalarsEqual(a, b) && sliceEqual(idsA, idsB)
}
func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func equalCensor(a, b CensorConfig) bool {
	return a.Enable == b.Enable && a.Mode == b.Mode && a.CaseSensitive == b.CaseSensitive && a.MatchPinyin == b.MatchPinyin && a.FilterRegex == b.FilterRegex && mapEqual(a.Thresholds, b.Thresholds) && u8MapEqual(a.Handlers, b.Handlers) && mapEqual(a.Scores, b.Scores)
}
func mapEqual(a, b map[string]int) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func u8MapEqual(a, b map[string]uint8) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func equalStore(a, b StoreConfig) bool {
	return sliceSetEqual(a.BackendURLs, b.BackendURLs) && sliceSetEqual(a.DisabledBackendURLs, b.DisabledBackendURLs)
}
func sliceSetEqual(a, b []string) bool {
	aa := normalizeSlices(a, true)
	bb := normalizeSlices(b, true)
	return sliceEqual(aa, bb)
}
func equalOuter(a, b OuterConfig) bool {
	return sliceEqual(a.CommandPrefix, b.CommandPrefix) && sliceSetEqual(a.DiceMasters, b.DiceMasters)
}

func Reduce(state State, event TypedEvent) (State, error) {
	if isNilEvent(event) {
		return State{}, ErrInvalidEvent
	}
	if err := validateEvent(event); err != nil {
		return State{}, err
	}
	next := state.Clone()
	if next.Version == ^uint64(0) {
		return State{}, ErrInvalidState
	}
	if err := event.configApply(&next); err != nil {
		return State{}, err
	}
	next.Version++
	return next, nil
}
func Replay(events []TypedEvent) (State, error) {
	var state State
	for _, event := range events {
		var err error
		state, err = Reduce(state, event)
		if err != nil {
			return State{}, err
		}
	}
	return state, nil
}
func ApplyEnvelope(state State, e eventstore.Envelope) (State, error) {
	if e.Stream.AggregateType != ConfigAggregateType || e.SchemaVersion != ConfigEventSchemaVersion || e.StreamVersion != state.Version+1 {
		return State{}, ErrInvalidState
	}
	typed, err := DecodeTypedEvent(EventType(e.EventType), e.Payload)
	if err != nil {
		return State{}, err
	}
	next, err := Reduce(state, typed)
	if err != nil {
		return State{}, err
	}
	if ConfigStream(next.DiceID) != e.Stream {
		return State{}, ErrInvalidState
	}
	return next, nil
}
func ReplayEnvelopes(events []eventstore.Envelope) (State, error) {
	var state State
	for _, e := range events {
		var err error
		state, err = ApplyEnvelope(state, e)
		if err != nil {
			return State{}, err
		}
	}
	return state, nil
}
func ValidateState(s State) error {
	if err := validateStateIdentity(s); err != nil {
		return err
	}
	if s.Version == 0 {
		return nil
	}
	validation := []error{
		(BaseChangedV1{DiceID: s.DiceID, ConfigVersion: s.ConfigVersion, BaseConfig: s.Base}).configValidate(),
		(RateChangedV1{RateConfig: s.Rate}).configValidate(),
		(QuitChangedV1{QuitConfig: s.Quit}).configValidate(),
		(ExtensionChangedV1{ExtensionConfig: s.Extension}).configValidate(),
		(BanChangedV1{BanConfig: s.Ban}).configValidate(),
		(JSChangedV1{JSConfig: s.JS}).configValidate(),
		(StoryLogChangedV1{StoryLogConfig: s.StoryLog}).configValidate(),
		(MailChangedV1{MailConfig: s.Mail}).configValidate(),
		(NewsChangedV1{NewsConfig: s.News}).configValidate(),
		(PublicDiceChangedV1{PublicDiceConfig: s.PublicDice}).configValidate(),
		(CensorChangedV1{CensorConfig: s.Censor}).configValidate(),
		(StoreChangedV1{StoreConfig: s.Store}).configValidate(),
		(AdvancedChangedV1{AdvancedConfig: s.Advanced}).configValidate(),
		(OuterChangedV1{OuterConfig: s.Outer}).configValidate(),
	}
	for _, err := range validation {
		if err != nil {
			return ErrInvalidState
		}
	}
	return nil
}
func validateStateIdentity(s State) error {
	if s.Version == 0 {
		return nil
	}
	if !validID(s.DiceID) || s.ConfigVersion <= 0 {
		return ErrInvalidState
	}
	return nil
}
func baseScalarsEqual(a, b BaseConfig) bool {
	return a.CommandCompatibleMode == b.CommandCompatibleMode && a.OnlyLogCommandInGroup == b.OnlyLogCommandInGroup && a.OnlyLogCommandInPrivate == b.OnlyLogCommandInPrivate && a.VersionCode == b.VersionCode && a.MessageDelayRangeStart == b.MessageDelayRangeStart && a.MessageDelayRangeEnd == b.MessageDelayRangeEnd && a.WorkInQQChannel == b.WorkInQQChannel && a.QQChannelAutoOn == b.QQChannelAutoOn && a.QQChannelLogMessage == b.QQChannelLogMessage && a.QQEnablePoke == b.QQEnablePoke && a.TextCmdTrustOnly == b.TextCmdTrustOnly && a.IgnoreUnaddressedBotCmd == b.IgnoreUnaddressedBotCmd && a.UILogLimit == b.UILogLimit && a.FriendAddComment == b.FriendAddComment && a.CustomReplyConfigEnable == b.CustomReplyConfigEnable && a.AutoReloginEnable == b.AutoReloginEnable && a.RefuseGroupInvite == b.RefuseGroupInvite && a.BotExtFreeSwitch == b.BotExtFreeSwitch && a.BotExitWithoutAt == b.BotExitWithoutAt && a.TrustOnlyMode == b.TrustOnlyMode && a.AliveNoticeEnable == b.AliveNoticeEnable && a.AliveNoticeValue == b.AliveNoticeValue && a.ReplyDebugMode == b.ReplyDebugMode && a.PlayerNameWrapEnable == b.PlayerNameWrapEnable && a.DiceRandomMode == b.DiceRandomMode && a.VMVersionForReply == b.VMVersionForReply && a.VMVersionForDeck == b.VMVersionForDeck && a.VMVersionForCustomText == b.VMVersionForCustomText && a.VMVersionForMsg == b.VMVersionForMsg
}

// configstate comparisons normalize set-like fields at the command boundary.
