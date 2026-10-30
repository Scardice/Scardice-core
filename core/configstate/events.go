package configstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"

	"Scardice-core/eventstore"
)

type EventType string

const (
	EventConfigBaseChanged       EventType = "dice_config.base_changed"
	EventConfigRateChanged       EventType = "dice_config.rate_changed"
	EventConfigQuitChanged       EventType = "dice_config.quit_changed"
	EventConfigExtensionChanged  EventType = "dice_config.extension_changed"
	EventConfigBanChanged        EventType = "dice_config.ban_changed"
	EventConfigJSChanged         EventType = "dice_config.js_changed"
	EventConfigStoryLogChanged   EventType = "dice_config.story_log_changed"
	EventConfigMailChanged       EventType = "dice_config.mail_changed"
	EventConfigNewsChanged       EventType = "dice_config.news_changed"
	EventConfigPublicDiceChanged EventType = "dice_config.public_dice_changed"
	EventConfigCensorChanged     EventType = "dice_config.censor_changed"
	EventConfigStoreChanged      EventType = "dice_config.store_changed"
	EventConfigAdvancedChanged   EventType = "dice_config.advanced_changed"
	EventConfigOuterChanged      EventType = "dice_config.outer_changed"
)
const (
	ConfigBaseChanged       = EventConfigBaseChanged
	ConfigRateChanged       = EventConfigRateChanged
	ConfigQuitChanged       = EventConfigQuitChanged
	ConfigExtensionChanged  = EventConfigExtensionChanged
	ConfigBanChanged        = EventConfigBanChanged
	ConfigJSChanged         = EventConfigJSChanged
	ConfigStoryLogChanged   = EventConfigStoryLogChanged
	ConfigMailChanged       = EventConfigMailChanged
	ConfigNewsChanged       = EventConfigNewsChanged
	ConfigPublicDiceChanged = EventConfigPublicDiceChanged
	ConfigCensorChanged     = EventConfigCensorChanged
	ConfigStoreChanged      = EventConfigStoreChanged
	ConfigAdvancedChanged   = EventConfigAdvancedChanged
	ConfigOuterChanged      = EventConfigOuterChanged
)

func (e EventType) Valid() bool {
	switch e {
	case EventConfigBaseChanged, EventConfigRateChanged, EventConfigQuitChanged, EventConfigExtensionChanged, EventConfigBanChanged, EventConfigJSChanged, EventConfigStoryLogChanged, EventConfigMailChanged, EventConfigNewsChanged, EventConfigPublicDiceChanged, EventConfigCensorChanged, EventConfigStoreChanged, EventConfigAdvancedChanged, EventConfigOuterChanged:
		return true
	}
	return false
}

var (
	ErrInvalidEvent          = errors.New("configstate: invalid event")
	ErrUnsupportedSchema     = errors.New("configstate: unsupported event schema")
	ErrInvalidState          = errors.New("configstate: invalid state")
	ErrInvalidIdentity       = errors.New("configstate: invalid identity")
	ErrInvalidCommand        = errors.New("configstate: invalid command")
	ErrStaleVersion          = errors.New("configstate: stale expected version")
	ErrRepositoryUnavailable = errors.New("configstate: repository unavailable")
)

type TypedEvent interface {
	EventType() EventType
	configApply(*State) error
	configValidate() error
}

type BaseConfig struct {
	CommandCompatibleMode   bool     `json:"commandCompatibleMode"`
	NoticeIDs               []string `json:"noticeIds,omitempty"`
	OnlyLogCommandInGroup   bool     `json:"onlyLogCommandInGroup"`
	OnlyLogCommandInPrivate bool     `json:"onlyLogCommandInPrivate"`
	VersionCode             int      `json:"versionCode"`
	MessageDelayRangeStart  float64  `json:"messageDelayRangeStart"`
	MessageDelayRangeEnd    float64  `json:"messageDelayRangeEnd"`
	WorkInQQChannel         bool     `json:"workInQQChannel"`
	QQChannelAutoOn         bool     `json:"qqChannelAutoOn"`
	QQChannelLogMessage     bool     `json:"qqChannelLogMessage"`
	QQEnablePoke            bool     `json:"qqEnablePoke"`
	TextCmdTrustOnly        bool     `json:"textCmdTrustOnly"`
	IgnoreUnaddressedBotCmd bool     `json:"ignoreUnaddressedBotCmd"`
	UILogLimit              int64    `json:"uiLogLimit"`
	FriendAddComment        string   `json:"friendAddComment,omitempty"`
	CustomReplyConfigEnable bool     `json:"customReplyConfigEnable"`
	AutoReloginEnable       bool     `json:"autoReloginEnable"`
	RefuseGroupInvite       bool     `json:"refuseGroupInvite"`
	BotExtFreeSwitch        bool     `json:"botExtFreeSwitch"`
	BotExitWithoutAt        bool     `json:"botExitWithoutAt"`
	TrustOnlyMode           bool     `json:"trustOnlyMode"`
	AliveNoticeEnable       bool     `json:"aliveNoticeEnable"`
	AliveNoticeValue        string   `json:"aliveNoticeValue,omitempty"`
	ReplyDebugMode          bool     `json:"replyDebugMode"`
	PlayerNameWrapEnable    bool     `json:"playerNameWrapEnable"`
	DiceRandomMode          string   `json:"diceRandomMode,omitempty"`
	VMVersionForReply       string   `json:"vmVersionForReply,omitempty"`
	VMVersionForDeck        string   `json:"vmVersionForDeck,omitempty"`
	VMVersionForCustomText  string   `json:"vmVersionForCustomText,omitempty"`
	VMVersionForMsg         string   `json:"vmVersionForMsg,omitempty"`
}
type RateConfig struct {
	RateLimitEnabled          bool   `json:"rateLimitEnabled"`
	PersonalReplenishRate     string `json:"personalReplenishRate,omitempty"`
	GroupReplenishRate        string `json:"groupReplenishRate,omitempty"`
	PersonalBurst             int64  `json:"personalBurst"`
	GroupBurst                int64  `json:"groupBurst"`
	SpamSameCommandWindowSec  int64  `json:"spamSameCommandWindowSec"`
	SpamRecoveryMultiplierMax int64  `json:"spamRecoveryMultiplierMax"`
}
type QuitConfig struct {
	QuitInactiveThreshold         string `json:"quitInactiveThreshold,omitempty"`
	QuitInactiveNoticeSummaryMode bool   `json:"quitInactiveNoticeSummaryMode"`
	QuitInactiveBatchSize         int64  `json:"quitInactiveBatchSize"`
	QuitInactiveBatchWait         int64  `json:"quitInactiveBatchWait"`
}
type ExtensionConfig struct {
	DefaultCocRuleIndex int64 `json:"defaultCocRuleIndex"`
	MaxExecuteTime      int64 `json:"maxExecuteTime"`
	MaxCocCardGen       int64 `json:"maxCocCardGen"`
	CocCardMergeForward bool  `json:"cocCardMergeForward"`
}
type BanConfig struct {
	RefuseReply                 bool    `json:"refuseReply"`
	RefuseInvite                bool    `json:"refuseInvite"`
	QuitLastPlace               bool    `json:"quitLastPlace"`
	QuitPlaceImmediately        bool    `json:"quitPlaceImmediately"`
	QuitIfAdmin                 bool    `json:"quitIfAdmin"`
	QuitIfAdminSilentIfNotAdmin bool    `json:"quitIfAdminSilentIfNotAdmin"`
	ThresholdWarn               int64   `json:"thresholdWarn"`
	ThresholdBan                int64   `json:"thresholdBan"`
	AutoBanMinutes              int64   `json:"autoBanMinutes"`
	ScoreReducePerMinute        int64   `json:"scoreReducePerMinute"`
	ScoreGroupMuted             int64   `json:"scoreGroupMuted"`
	ScoreGroupKicked            int64   `json:"scoreGroupKicked"`
	ScoreTooManyCommand         int64   `json:"scoreTooManyCommand"`
	BanNotifyIntervalMinutes    int64   `json:"banNotifyIntervalMinutes"`
	JointScorePercentOfGroup    float64 `json:"jointScorePercentOfGroup"`
	JointScorePercentOfInviter  float64 `json:"jointScorePercentOfInviter"`
}
type JSConfig struct {
	JsEnable                       bool                       `json:"jsEnable"`
	JsEngine                       string                     `json:"jsEngine,omitempty"`
	JsRuntimeOptions               map[string]json.RawMessage `json:"jsRuntimeOptions,omitempty"`
	JsRuntimeRoutes                map[string]string          `json:"jsRuntimeRoutes,omitempty"`
	DisabledJsScripts              map[string]bool            `json:"disabledJsScripts,omitempty"`
	QuickJSMemoryLimitMiB          uint64                     `json:"quickJSMemoryLimitMiB"`
	QuickJSGCThresholdMiB          uint64                     `json:"quickJSGCThresholdMiB"`
	QuickJSMaxStackSizeKiB         uint64                     `json:"quickJSMaxStackSizeKiB"`
	QuickJSExecuteTimeoutSeconds   uint64                     `json:"quickJSExecuteTimeoutSeconds"`
	QuickJSMaxFetchConcurrent      uint64                     `json:"quickJSMaxFetchConcurrent"`
	QuickJSMaxFetchResponseMiB     uint64                     `json:"quickJSMaxFetchResponseMiB"`
	QuickJSMaxWebSocketConnections uint64                     `json:"quickJSMaxWebSocketConnections"`
	QuickJSMaxWebSocketMessageMiB  uint64                     `json:"quickJSMaxWebSocketMessageMiB"`
	QuickJSMaxFilesystemReadMiB    uint64                     `json:"quickJSMaxFilesystemReadMiB"`
	QuickJSMaxFilesystemWriteMiB   uint64                     `json:"quickJSMaxFilesystemWriteMiB"`
	QuickJSMaxPBKDF2Iterations     uint64                     `json:"quickJSMaxPBKDF2Iterations"`
	QuickJSMaxPBKDF2OutputBytes    uint64                     `json:"quickJSMaxPBKDF2OutputBytes"`
}
type StoryLogConfig struct {
	LogSizeNoticeEnable bool `json:"logSizeNoticeEnable"`
	LogSizeNoticeCount  int  `json:"logSizeNoticeCount"`
}
type MailConfig struct {
	MailEnable      bool   `json:"mailEnable"`
	MailFrom        string `json:"mailFrom,omitempty"`
	MailPasswordRef string `json:"mailPasswordRef,omitempty"`
	MailSMTP        string `json:"mailSmtp,omitempty"`
}
type NewsConfig struct {
	NewsMark string `json:"newsMark,omitempty"`
}
type PublicDiceConfig struct {
	Enable      bool     `json:"enable"`
	ID          string   `json:"id,omitempty"`
	Name        string   `json:"name,omitempty"`
	Brief       string   `json:"brief,omitempty"`
	Note        string   `json:"note,omitempty"`
	Avatar      string   `json:"avatar,omitempty"`
	EndpointIDs []string `json:"endpointIds,omitempty"`
}
type CensorConfig struct {
	Enable        bool             `json:"enable"`
	Mode          int              `json:"mode"`
	Thresholds    map[string]int   `json:"thresholds,omitempty"`
	Handlers      map[string]uint8 `json:"handlers,omitempty"`
	Scores        map[string]int   `json:"scores,omitempty"`
	CaseSensitive bool             `json:"caseSensitive"`
	MatchPinyin   bool             `json:"matchPinyin"`
	FilterRegex   string           `json:"filterRegex,omitempty"`
}
type StoreConfig struct {
	BackendURLs         []string `json:"backendUrls,omitempty"`
	DisabledBackendURLs []string `json:"disabledBackendUrls,omitempty"`
}
type AdvancedConfig struct {
	Show                              bool    `json:"show"`
	Enable                            bool    `json:"enable"`
	StoryLogBackendURL                string  `json:"storyLogBackendUrl,omitempty"`
	StoryLogAPIVersion                string  `json:"storyLogApiVersion,omitempty"`
	StoryLogBackendTokenRef           string  `json:"storyLogBackendTokenRef,omitempty"`
	CustomReplyCooldown               float64 `json:"customReplyCooldown"`
	ExposeDangerousSealInst           bool    `json:"exposeDangerousSealInst"`
	AllowFilesystemUnrestrictedAccess bool    `json:"allowFilesystemUnrestrictedAccess"`
}
type OuterConfig struct {
	CommandPrefix []string `json:"commandPrefix,omitempty"`
	DiceMasters   []string `json:"diceMasters,omitempty"`
}

// Each event carries exactly one persisted configuration group.
type BaseChangedV1 struct {
	DiceID        string `json:"diceId"`
	ConfigVersion int    `json:"configVersion"`
	BaseConfig
}
type RateChangedV1 struct{ RateConfig }
type QuitChangedV1 struct{ QuitConfig }
type ExtensionChangedV1 struct{ ExtensionConfig }
type BanChangedV1 struct{ BanConfig }
type JSChangedV1 struct{ JSConfig }
type StoryLogChangedV1 struct{ StoryLogConfig }
type MailChangedV1 struct{ MailConfig }
type NewsChangedV1 struct{ NewsConfig }
type PublicDiceChangedV1 struct{ PublicDiceConfig }
type CensorChangedV1 struct{ CensorConfig }
type StoreChangedV1 struct{ StoreConfig }
type AdvancedChangedV1 struct{ AdvancedConfig }
type OuterChangedV1 struct{ OuterConfig }

func (BaseChangedV1) EventType() EventType       { return EventConfigBaseChanged }
func (RateChangedV1) EventType() EventType       { return EventConfigRateChanged }
func (QuitChangedV1) EventType() EventType       { return EventConfigQuitChanged }
func (ExtensionChangedV1) EventType() EventType  { return EventConfigExtensionChanged }
func (BanChangedV1) EventType() EventType        { return EventConfigBanChanged }
func (JSChangedV1) EventType() EventType         { return EventConfigJSChanged }
func (StoryLogChangedV1) EventType() EventType   { return EventConfigStoryLogChanged }
func (MailChangedV1) EventType() EventType       { return EventConfigMailChanged }
func (NewsChangedV1) EventType() EventType       { return EventConfigNewsChanged }
func (PublicDiceChangedV1) EventType() EventType { return EventConfigPublicDiceChanged }
func (CensorChangedV1) EventType() EventType     { return EventConfigCensorChanged }
func (StoreChangedV1) EventType() EventType      { return EventConfigStoreChanged }
func (AdvancedChangedV1) EventType() EventType   { return EventConfigAdvancedChanged }
func (OuterChangedV1) EventType() EventType      { return EventConfigOuterChanged }
func (e BaseChangedV1) configApply(s *State) error {
	if s.Version == 0 {
		if !validID(e.DiceID) {
			return ErrInvalidIdentity
		}
		s.DiceID = e.DiceID
	} else if s.DiceID != e.DiceID {
		return ErrInvalidState
	}
	s.ConfigVersion = e.ConfigVersion
	s.Base = cloneBaseConfig(e.BaseConfig)
	return nil
}
func (e RateChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Rate = e.RateConfig })
}
func (e QuitChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Quit = e.QuitConfig })
}
func (e ExtensionChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Extension = e.ExtensionConfig })
}
func (e BanChangedV1) configApply(s *State) error { return setGroup(s, func() { s.Ban = e.BanConfig }) }
func (e JSChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.JS = cloneJSConfig(e.JSConfig) })
}
func (e StoryLogChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.StoryLog = e.StoryLogConfig })
}
func (e MailChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Mail = e.MailConfig })
}
func (e NewsChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.News = e.NewsConfig })
}
func (e PublicDiceChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.PublicDice = clonePublicDiceConfig(e.PublicDiceConfig) })
}
func (e CensorChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Censor = cloneCensorConfig(e.CensorConfig) })
}
func (e StoreChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Store = cloneStoreConfig(e.StoreConfig) })
}
func (e AdvancedChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Advanced = e.AdvancedConfig })
}
func (e OuterChangedV1) configApply(s *State) error {
	return setGroup(s, func() { s.Outer = cloneOuterConfig(e.OuterConfig) })
}
func setGroup(s *State, apply func()) error {
	if s.Version == 0 || s.DiceID == "" {
		return ErrInvalidState
	}
	apply()
	return nil
}
func cloneBaseConfig(value BaseConfig) BaseConfig {
	value.NoticeIDs = append([]string(nil), value.NoticeIDs...)
	return value
}
func cloneCensorConfig(value CensorConfig) CensorConfig {
	value.Thresholds = normalizeMaps(value.Thresholds)
	value.Handlers = normalizeU8Maps(value.Handlers)
	value.Scores = normalizeMaps(value.Scores)
	return value
}
func cloneStoreConfig(value StoreConfig) StoreConfig {
	value.BackendURLs = normalizeSlices(value.BackendURLs, true)
	value.DisabledBackendURLs = normalizeSlices(value.DisabledBackendURLs, true)
	return value
}
func cloneOuterConfig(value OuterConfig) OuterConfig {
	value.CommandPrefix = normalizeSlices(value.CommandPrefix, false)
	value.DiceMasters = normalizeSlices(value.DiceMasters, true)
	return value
}
func validID(v string) bool { return strings.TrimSpace(v) != "" && len(v) <= 255 }
func validReference(v string) bool {
	return (strings.HasPrefix(v, "vault:") || strings.HasPrefix(v, "sha256:")) && len(v) <= 255
}
func validateEvent(e TypedEvent) error {
	if isNilEvent(e) {
		return ErrInvalidEvent
	}
	return e.configValidate()
}
func (e BaseChangedV1) configValidate() error {
	if !validID(e.DiceID) || e.ConfigVersion <= 0 || e.MessageDelayRangeStart < 0 || e.MessageDelayRangeEnd < e.MessageDelayRangeStart || !finite(e.MessageDelayRangeStart) || !finite(e.MessageDelayRangeEnd) || e.UILogLimit < 0 {
		return ErrInvalidCommand
	}
	return nil
}
func (e RateChangedV1) configValidate() error {
	if e.PersonalBurst <= 0 || e.GroupBurst <= 0 || e.SpamSameCommandWindowSec <= 0 || e.SpamRecoveryMultiplierMax <= 0 {
		return ErrInvalidCommand
	}
	return nil
}
func (e QuitChangedV1) configValidate() error {
	if e.QuitInactiveBatchSize <= 0 || e.QuitInactiveBatchWait < 0 {
		return ErrInvalidCommand
	}
	return nil
}
func (e ExtensionChangedV1) configValidate() error {
	if e.MaxExecuteTime <= 0 || e.MaxCocCardGen <= 0 {
		return ErrInvalidCommand
	}
	return nil
}
func (e BanChangedV1) configValidate() error {
	if e.ThresholdWarn < 0 || e.ThresholdBan < 0 || e.AutoBanMinutes < 0 || e.ScoreReducePerMinute < 0 || e.BanNotifyIntervalMinutes < 0 || !finite(e.JointScorePercentOfGroup) || e.JointScorePercentOfGroup < 0 || e.JointScorePercentOfGroup > 1 || !finite(e.JointScorePercentOfInviter) || e.JointScorePercentOfInviter < 0 || e.JointScorePercentOfInviter > 1 {
		return ErrInvalidCommand
	}
	return nil
}
func (e JSChangedV1) configValidate() error {
	if e.JsEngine != "" && !validID(e.JsEngine) {
		return ErrInvalidCommand
	}
	for extensionID, runtimeID := range e.JsRuntimeRoutes {
		if !validID(extensionID) || strings.TrimSpace(extensionID) != extensionID ||
			!validID(runtimeID) || strings.TrimSpace(runtimeID) != runtimeID {
			return ErrInvalidCommand
		}
	}
	return nil
}
func (e StoryLogChangedV1) configValidate() error {
	if e.LogSizeNoticeCount <= 0 {
		return ErrInvalidCommand
	}
	return nil
}
func (e MailChangedV1) configValidate() error {
	if e.MailPasswordRef != "" && !validReference(e.MailPasswordRef) {
		return ErrInvalidCommand
	}
	return nil
}
func (e NewsChangedV1) configValidate() error       { return nil }
func (e PublicDiceChangedV1) configValidate() error { return nil }
func (e CensorChangedV1) configValidate() error {
	if e.Mode < 0 || e.Mode > 2 {
		return ErrInvalidCommand
	}
	if e.FilterRegex != "" {
		if _, err := regexp.Compile(e.FilterRegex); err != nil {
			return ErrInvalidCommand
		}
	}
	return nil
}
func (e StoreChangedV1) configValidate() error { return nil }
func (e AdvancedChangedV1) configValidate() error {
	if e.CustomReplyCooldown <= 0 || !finite(e.CustomReplyCooldown) {
		return ErrInvalidCommand
	}
	if e.StoryLogBackendTokenRef != "" && !validReference(e.StoryLogBackendTokenRef) {
		return ErrInvalidCommand
	}
	return nil
}
func (e OuterChangedV1) configValidate() error {
	if len(e.CommandPrefix) == 0 {
		return ErrInvalidCommand
	}
	for _, v := range e.CommandPrefix {
		if strings.TrimSpace(v) == "" {
			return ErrInvalidCommand
		}
	}
	for _, v := range e.DiceMasters {
		if !validID(v) {
			return ErrInvalidCommand
		}
	}
	return nil
}
func finite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
func containsJSONNull(value any) bool {
	switch v := value.(type) {
	case nil:
		return true
	case map[string]any:
		for _, child := range v {
			if containsJSONNull(child) {
				return true
			}
		}
	case []any:
		for _, child := range v {
			if containsJSONNull(child) {
				return true
			}
		}
	}
	return false
}
func containsConfigEventJSONNull(value any, typ EventType) bool {
	if typ != EventConfigJSChanged {
		return containsJSONNull(value)
	}
	fields, ok := value.(map[string]any)
	if !ok {
		return containsJSONNull(value)
	}
	for key, field := range fields {
		if strings.EqualFold(key, "jsRuntimeOptions") {
			providers, ok := field.(map[string]any)
			if !ok {
				return true
			}
			for _, payload := range providers {
				if payload == nil {
					return true
				}
			}
			continue
		}
		if containsJSONNull(field) {
			return true
		}
	}
	return false
}
func containsConfigProjectionJSONNull(value any) bool {
	fields, ok := value.(map[string]any)
	if !ok {
		return containsJSONNull(value)
	}
	for key, field := range fields {
		if strings.EqualFold(key, "js") {
			if containsConfigEventJSONNull(field, EventConfigJSChanged) {
				return true
			}
			continue
		}
		if containsJSONNull(field) {
			return true
		}
	}
	return false
}

func DecodeTypedEvent(typ EventType, payload []byte) (TypedEvent, error) {
	if len(payload) > eventstore.MaxEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "config event payload", Limit: eventstore.MaxEventPayloadBytes, Actual: len(payload)}
	}
	var raw any
	if json.Unmarshal(payload, &raw) != nil {
		return nil, ErrInvalidEvent
	}
	if _, ok := raw.(map[string]any); !ok || containsConfigEventJSONNull(raw, typ) {
		return nil, ErrInvalidEvent
	}
	var event TypedEvent
	switch typ {
	case EventConfigBaseChanged:
		event = &BaseChangedV1{}
	case EventConfigRateChanged:
		event = &RateChangedV1{}
	case EventConfigQuitChanged:
		event = &QuitChangedV1{}
	case EventConfigExtensionChanged:
		event = &ExtensionChangedV1{}
	case EventConfigBanChanged:
		event = &BanChangedV1{}
	case EventConfigJSChanged:
		event = &JSChangedV1{}
	case EventConfigStoryLogChanged:
		event = &StoryLogChangedV1{}
	case EventConfigMailChanged:
		event = &MailChangedV1{}
	case EventConfigNewsChanged:
		event = &NewsChangedV1{}
	case EventConfigPublicDiceChanged:
		event = &PublicDiceChangedV1{}
	case EventConfigCensorChanged:
		event = &CensorChangedV1{}
	case EventConfigStoreChanged:
		event = &StoreChangedV1{}
	case EventConfigAdvancedChanged:
		event = &AdvancedChangedV1{}
	case EventConfigOuterChanged:
		event = &OuterChangedV1{}
	default:
		return nil, ErrInvalidEvent
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.DisallowUnknownFields()
	if err := dec.Decode(event); err != nil {
		return nil, ErrInvalidEvent
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrInvalidEvent
	}
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	return event, nil
}
func normalizeSlices(s []string, sortValues bool) []string {
	out := append([]string(nil), s...)
	if sortValues {
		sort.Strings(out)
	}
	return out
}
func normalizeMaps(in map[string]int) map[string]int {
	if in == nil {
		return nil
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func normalizeU8Maps(in map[string]uint8) map[string]uint8 {
	if in == nil {
		return nil
	}
	out := make(map[string]uint8, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
func cloneEvent(e TypedEvent) TypedEvent {
	switch v := e.(type) {
	case BaseChangedV1:
		v.NoticeIDs = normalizeSlices(v.NoticeIDs, false)
		return v
	case OuterChangedV1:
		v.CommandPrefix = normalizeSlices(v.CommandPrefix, false)
		v.DiceMasters = normalizeSlices(v.DiceMasters, true)
		return v
	case CensorChangedV1:
		v.Thresholds = normalizeMaps(v.Thresholds)
		v.Handlers = normalizeU8Maps(v.Handlers)
		v.Scores = normalizeMaps(v.Scores)
		return v
	case StoreChangedV1:
		v.BackendURLs = normalizeSlices(v.BackendURLs, true)
		v.DisabledBackendURLs = normalizeSlices(v.DisabledBackendURLs, true)
		return v
	}
	return e
}
func MarshalTypedEvent(event TypedEvent) ([]byte, error) {
	if event == nil {
		return nil, ErrInvalidEvent
	}
	event = cloneEvent(event)
	if err := validateEvent(event); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return nil, err
	}
	if len(payload) > eventstore.MaxEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "config event payload", Limit: eventstore.MaxEventPayloadBytes, Actual: len(payload)}
	}
	return payload, nil
}
func isNilEvent(e TypedEvent) bool {
	if e == nil {
		return true
	}
	v := reflect.ValueOf(e)
	return (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) && v.IsNil()
}

// Constructors keep event allocation explicit at command boundaries and mirror
// the other core aggregate packages.
func NewBaseChangedV1(diceID string, version int, value BaseConfig) BaseChangedV1 {
	return BaseChangedV1{DiceID: diceID, ConfigVersion: version, BaseConfig: cloneBaseConfig(value)}
}
func NewRateChangedV1(value RateConfig) RateChangedV1 { return RateChangedV1{RateConfig: value} }
func NewQuitChangedV1(value QuitConfig) QuitChangedV1 { return QuitChangedV1{QuitConfig: value} }
func NewExtensionChangedV1(value ExtensionConfig) ExtensionChangedV1 {
	return ExtensionChangedV1{ExtensionConfig: value}
}
func NewBanChangedV1(value BanConfig) BanChangedV1 { return BanChangedV1{BanConfig: value} }
func NewJSChangedV1(value JSConfig) JSChangedV1    { return JSChangedV1{JSConfig: cloneJSConfig(value)} }
func NewStoryLogChangedV1(value StoryLogConfig) StoryLogChangedV1 {
	return StoryLogChangedV1{StoryLogConfig: value}
}
func NewMailChangedV1(value MailConfig) MailChangedV1 { return MailChangedV1{MailConfig: value} }
func NewNewsChangedV1(value NewsConfig) NewsChangedV1 { return NewsChangedV1{NewsConfig: value} }
func NewPublicDiceChangedV1(value PublicDiceConfig) PublicDiceChangedV1 {
	return PublicDiceChangedV1{PublicDiceConfig: clonePublicDiceConfig(value)}
}
func NewCensorChangedV1(value CensorConfig) CensorChangedV1 {
	return CensorChangedV1{CensorConfig: cloneCensorConfig(value)}
}
func NewStoreChangedV1(value StoreConfig) StoreChangedV1 {
	return StoreChangedV1{StoreConfig: cloneStoreConfig(value)}
}
func NewAdvancedChangedV1(value AdvancedConfig) AdvancedChangedV1 {
	return AdvancedChangedV1{AdvancedConfig: value}
}
func NewOuterChangedV1(value OuterConfig) OuterChangedV1 {
	return OuterChangedV1{OuterConfig: cloneOuterConfig(value)}
}

type ConfigBaseChangedV1 = BaseChangedV1
type ConfigRateChangedV1 = RateChangedV1
type ConfigQuitChangedV1 = QuitChangedV1
type ConfigExtensionChangedV1 = ExtensionChangedV1
type ConfigBanChangedV1 = BanChangedV1
type ConfigJSChangedV1 = JSChangedV1
type ConfigStoryLogChangedV1 = StoryLogChangedV1
type ConfigMailChangedV1 = MailChangedV1
type ConfigNewsChangedV1 = NewsChangedV1
type ConfigPublicDiceChangedV1 = PublicDiceChangedV1
type ConfigCensorChangedV1 = CensorChangedV1
type ConfigStoreChangedV1 = StoreChangedV1
type ConfigAdvancedChangedV1 = AdvancedChangedV1
type ConfigOuterChangedV1 = OuterChangedV1

func MarshalTypedEvents(events []TypedEvent) ([]byte, error) {
	encoded := make([]json.RawMessage, 0, len(events))
	for _, event := range events {
		payload, err := MarshalTypedEvent(event)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, payload)
	}
	payload, err := json.Marshal(encoded)
	if err != nil {
		return nil, err
	}
	if len(payload) > eventstore.MaxEventPayloadBytes {
		return nil, &eventstore.OversizeError{Bound: "config event payload", Limit: eventstore.MaxEventPayloadBytes, Actual: len(payload)}
	}
	return payload, nil
}
