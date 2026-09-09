package dice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/eventstore"
)

// DurableCommitConfigSnapshot translates the legacy in-memory config shape to
// one optimistic event-store patch. mailPasswordRef is nil when the request
// did not address the secret; a non-nil value is either empty or a reference.
func (d *Dice) DurableCommitConfigSnapshot(ctx context.Context, config Config, commandPrefix, diceMasters []string, mailPasswordRef *string) error {
	store, diceID, err := d.durableStoreAndID()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := configstate.ReadProjected(ctx, store, diceID)
	if err != nil {
		return fmt.Errorf("dice: read config projection: %w", err)
	}
	patch, err := durableConfigPatch(state, config, commandPrefix, diceMasters, mailPasswordRef)
	if err != nil {
		return err
	}
	repo := configstate.NewRepository(store)
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, configstate.Command{
		Kind:               configstate.CommandPatch,
		Patch:              &patch,
		ExpectedVersion:    state.Version,
		ExpectedVersionSet: true,
	})
	return err
}

// DurableLegacyAdvancedView returns the advanced group without exposing the
// event-store projection object.
func (d *Dice) DurableLegacyAdvancedView(ctx context.Context) (AdvancedConfig, error) {
	_, advanced, _, err := d.DurableLegacyConfigView(ctx)
	return advanced, err
}

// DurableCommitAdvancedSnapshot persists advanced settings while retaining the
// existing token reference unless the request explicitly changes it.
func (d *Dice) DurableCommitAdvancedSnapshot(ctx context.Context, advanced AdvancedConfig, tokenRef *string) error {
	store, diceID, err := d.durableStoreAndID()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := configstate.ReadProjected(ctx, store, diceID)
	if err != nil {
		return fmt.Errorf("dice: read config projection: %w", err)
	}
	ref := state.Advanced.StoryLogBackendTokenRef
	if tokenRef != nil {
		if *tokenRef != "" && !durableConfigSecretReference(*tokenRef) {
			return errors.New("dice: advanced token must be a vault: or sha256: reference")
		}
		ref = *tokenRef
	}
	group := configstate.AdvancedConfig{
		Show:                              advanced.Show,
		Enable:                            advanced.Enable,
		StoryLogBackendURL:                advanced.StoryLogBackendUrl,
		StoryLogAPIVersion:                advanced.StoryLogApiVersion,
		StoryLogBackendTokenRef:           ref,
		CustomReplyCooldown:               advanced.CustomReplyCooldown,
		ExposeDangerousSealInst:           advanced.ExposeDangerousSealInst,
		AllowFilesystemUnrestrictedAccess: advanced.AllowFilesystemUnrestrictedAccess,
	}
	repo := configstate.NewRepository(store)
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, configstate.Command{
		Kind:               configstate.CommandPatch,
		Patch:              &configstate.ConfigPatch{Advanced: &group},
		ExpectedVersion:    state.Version,
		ExpectedVersionSet: true,
	})
	return err
}

// DurableSetExtensionDefaults changes one extension's default command policy
// through the extension aggregate instead of the legacy Config slice.
func (d *Dice) DurableSetExtensionDefaults(ctx context.Context, extensionID string, autoActive bool, disabledCommands []string) error {
	repo, diceID, err := d.durableExtensionRepository()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	state, err := repo.Load(ctx, diceID)
	if err != nil {
		return err
	}
	if _, ok := state.Extensions[extensionID]; !ok {
		return extensionstate.ErrUnknownExtension
	}
	_, err = repo.DecideAndAppend(ctx, state, state.Version, eventstore.Metadata{}, extensionstate.Command{
		Kind:             extensionstate.CommandSetDefaults,
		ExtensionID:      extensionID,
		AutoActive:       autoActive,
		DisabledCommands: append([]string(nil), disabledCommands...),
	})
	return err
}

func durableConfigSecretReference(value string) bool {
	return strings.HasPrefix(value, "vault:") || strings.HasPrefix(value, "sha256:")
}

func durableConfigPatch(state configstate.State, config Config, commandPrefix, diceMasters []string, mailPasswordRef *string) (configstate.ConfigPatch, error) {
	configVersion := config.ConfigVersion
	if configVersion <= 0 {
		configVersion = state.ConfigVersion
	}
	if configVersion <= 0 {
		configVersion = 1
	}
	mailRef := state.Mail.MailPasswordRef
	if mailPasswordRef != nil {
		if *mailPasswordRef != "" && !durableConfigSecretReference(*mailPasswordRef) {
			return configstate.ConfigPatch{}, errors.New("dice: mail password must be a vault: or sha256: reference")
		}
		mailRef = strings.TrimSpace(*mailPasswordRef)
	}

	base := configstate.BaseConfig{
		CommandCompatibleMode:   config.CommandCompatibleMode,
		NoticeIDs:               append([]string(nil), config.NoticeIDs...),
		OnlyLogCommandInGroup:   config.OnlyLogCommandInGroup,
		OnlyLogCommandInPrivate: config.OnlyLogCommandInPrivate,
		VersionCode:             config.VersionCode,
		MessageDelayRangeStart:  config.MessageDelayRangeStart,
		MessageDelayRangeEnd:    config.MessageDelayRangeEnd,
		WorkInQQChannel:         config.WorkInQQChannel,
		QQChannelAutoOn:         config.QQChannelAutoOn,
		QQChannelLogMessage:     config.QQChannelLogMessage,
		QQEnablePoke:            config.QQEnablePoke,
		TextCmdTrustOnly:        config.TextCmdTrustOnly,
		IgnoreUnaddressedBotCmd: config.IgnoreUnaddressedBotCmd,
		UILogLimit:              config.UILogLimit,
		FriendAddComment:        config.FriendAddComment,
		CustomReplyConfigEnable: config.CustomReplyConfigEnable,
		AutoReloginEnable:       config.AutoReloginEnable,
		RefuseGroupInvite:       config.RefuseGroupInvite,
		BotExtFreeSwitch:        config.BotExtFreeSwitch,
		BotExitWithoutAt:        config.BotExitWithoutAt,
		TrustOnlyMode:           config.TrustOnlyMode,
		AliveNoticeEnable:       config.AliveNoticeEnable,
		AliveNoticeValue:        config.AliveNoticeValue,
		ReplyDebugMode:          config.ReplyDebugMode,
		PlayerNameWrapEnable:    config.PlayerNameWrapEnable,
		DiceRandomMode:          config.DiceRandomMode,
		VMVersionForReply:       config.VMVersionForReply,
		VMVersionForDeck:        config.VMVersionForDeck,
		VMVersionForCustomText:  config.VMVersionForCustomText,
		VMVersionForMsg:         config.VMVersionForMsg,
	}
	rateConfig := configstate.RateConfig{
		RateLimitEnabled:          config.RateLimitEnabled,
		PersonalReplenishRate:     config.PersonalReplenishRateStr,
		GroupReplenishRate:        config.GroupReplenishRateStr,
		PersonalBurst:             config.PersonalBurst,
		GroupBurst:                config.GroupBurst,
		SpamSameCommandWindowSec:  config.SpamSameCommandWindowSec,
		SpamRecoveryMultiplierMax: config.SpamRecoveryMultiplierMax,
	}
	quitConfig := configstate.QuitConfig{
		QuitInactiveThreshold:         config.QuitInactiveThreshold.String(),
		QuitInactiveNoticeSummaryMode: config.QuitInactiveNoticeSummaryMode,
		QuitInactiveBatchSize:         config.QuitInactiveBatchSize,
		QuitInactiveBatchWait:         config.QuitInactiveBatchWait,
	}
	extensionConfig := configstate.ExtensionConfig{
		DefaultCocRuleIndex: config.DefaultCocRuleIndex,
		MaxExecuteTime:      config.MaxExecuteTime,
		MaxCocCardGen:       config.MaxCocCardGen,
		CocCardMergeForward: config.CocCardMergeForward,
	}
	banConfig := configstate.BanConfig{}
	if config.BanList != nil {
		banConfig = configstate.BanConfig{
			RefuseReply:                 config.BanList.BanBehaviorRefuseReply,
			RefuseInvite:                config.BanList.BanBehaviorRefuseInvite,
			QuitLastPlace:               config.BanList.BanBehaviorQuitLastPlace,
			QuitPlaceImmediately:        config.BanList.BanBehaviorQuitPlaceImmediately,
			QuitIfAdmin:                 config.BanList.BanBehaviorQuitIfAdmin,
			QuitIfAdminSilentIfNotAdmin: config.BanList.BanBehaviorQuitIfAdminSilentIfNotAdmin,
			ThresholdWarn:               config.BanList.ThresholdWarn,
			ThresholdBan:                config.BanList.ThresholdBan,
			AutoBanMinutes:              config.BanList.AutoBanMinutes,
			ScoreReducePerMinute:        config.BanList.ScoreReducePerMinute,
			ScoreGroupMuted:             config.BanList.ScoreGroupMuted,
			ScoreGroupKicked:            config.BanList.ScoreGroupKicked,
			ScoreTooManyCommand:         config.BanList.ScoreTooManyCommand,
			BanNotifyIntervalMinutes:    config.BanList.BanNotifyIntervalMinutes,
			JointScorePercentOfGroup:    config.BanList.JointScorePercentOfGroup,
			JointScorePercentOfInviter:  config.BanList.JointScorePercentOfInviter,
		}
	}
	jsConfig := configstate.JSConfig{
		JsEnable:                       config.JsEnable,
		JsEngine:                       config.JsEngine,
		QuickJSMemoryLimitMiB:          config.QuickJSMemoryLimitMiB,
		QuickJSGCThresholdMiB:          config.QuickJSGCThresholdMiB,
		QuickJSMaxStackSizeKiB:         config.QuickJSMaxStackSizeKiB,
		QuickJSExecuteTimeoutSeconds:   config.QuickJSExecuteTimeoutSeconds,
		QuickJSMaxFetchConcurrent:      config.QuickJSMaxFetchConcurrent,
		QuickJSMaxFetchResponseMiB:     config.QuickJSMaxFetchResponseMiB,
		QuickJSMaxWebSocketConnections: config.QuickJSMaxWebSocketConnections,
		QuickJSMaxWebSocketMessageMiB:  config.QuickJSMaxWebSocketMessageMiB,
		QuickJSMaxFilesystemReadMiB:    config.QuickJSMaxFilesystemReadMiB,
		QuickJSMaxFilesystemWriteMiB:   config.QuickJSMaxFilesystemWriteMiB,
		QuickJSMaxPBKDF2Iterations:     config.QuickJSMaxPBKDF2Iterations,
		QuickJSMaxPBKDF2OutputBytes:    config.QuickJSMaxPBKDF2OutputBytes,
	}
	storyLogConfig := configstate.StoryLogConfig{LogSizeNoticeEnable: config.LogSizeNoticeEnable, LogSizeNoticeCount: config.LogSizeNoticeCount}
	mailConfig := configstate.MailConfig{MailEnable: config.MailEnable, MailFrom: config.MailFrom, MailPasswordRef: mailRef, MailSMTP: config.MailSMTP}
	newsConfig := configstate.NewsConfig{NewsMark: config.NewsMark}
	publicDiceConfig := configstate.PublicDiceConfig{Enable: config.PublicDiceConfig.Enable, ID: config.PublicDiceConfig.ID, Name: config.PublicDiceConfig.Name, Brief: config.PublicDiceConfig.Brief, Note: config.PublicDiceConfig.Note, Avatar: config.PublicDiceConfig.Avatar}
	censorConfig := configstate.CensorConfig{Enable: config.EnableCensor, Mode: int(config.CensorMode), CaseSensitive: config.CensorCaseSensitive, MatchPinyin: config.CensorMatchPinyin, FilterRegex: config.CensorFilterRegexStr, Thresholds: map[string]int{}, Handlers: map[string]uint8{}, Scores: map[string]int{}}
	for level, value := range config.CensorThresholds {
		censorConfig.Thresholds[strconv.Itoa(int(level))] = value
	}
	for level, value := range config.CensorHandlers {
		censorConfig.Handlers[strconv.Itoa(int(level))] = value
	}
	for level, value := range config.CensorScores {
		censorConfig.Scores[strconv.Itoa(int(level))] = value
	}
	storeConfig := configstate.StoreConfig{BackendURLs: append([]string(nil), config.BackendUrls...), DisabledBackendURLs: append([]string(nil), config.DisabledBackendUrls...)}
	outerConfig := configstate.OuterConfig{CommandPrefix: append([]string(nil), commandPrefix...), DiceMasters: append([]string(nil), diceMasters...)}
	return configstate.ConfigPatch{
		Base:             &base,
		Rate:             &rateConfig,
		Quit:             &quitConfig,
		Extension:        &extensionConfig,
		Ban:              &banConfig,
		JS:               &jsConfig,
		StoryLog:         &storyLogConfig,
		Mail:             &mailConfig,
		News:             &newsConfig,
		PublicDice:       &publicDiceConfig,
		Censor:           &censorConfig,
		Store:            &storeConfig,
		Outer:            &outerConfig,
		SetCommandPrefix: true,
		SetDiceMasters:   true,
	}, nil
}
