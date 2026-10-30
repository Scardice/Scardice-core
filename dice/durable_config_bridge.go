package dice

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"Scardice-core/core/configstate"
	"Scardice-core/core/extensionstate"
	"Scardice-core/core/managerstate"
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
	preparedAppend, err := repo.PrepareDecision(state, state.Version, eventstore.Metadata{}, configstate.Command{
		Kind:               configstate.CommandPatch,
		Patch:              &patch,
		ExpectedVersion:    state.Version,
		ExpectedVersionSet: true,
	})
	if err != nil || len(preparedAppend.Events) == 0 {
		return err
	}
	_, err = store.Commit(ctx, eventstore.UnitOfWork{Streams: []eventstore.StreamAppend{preparedAppend}})
	return err
}

type DurableManagerConfigPatch struct {
	ServeAddress   *string
	TrayTooltip    *string
	UIPasswordHash *string
	DiceRandomMode *string
}

type DurableExtensionDefault struct {
	ExtensionID      string
	AutoActive       bool
	DisabledCommands []string
}

type DurableConfigRequest struct {
	Config                   Config
	CommandPrefix            []string
	DiceMasters              []string
	MailPasswordRef          *string
	PersistDiceConfig        bool
	Manager                  *DurableManagerConfigPatch
	ExtensionDefaults        []DurableExtensionDefault
	PersistExtensionDefaults bool
}

// DurableCommitConfigRequest prepares only the owners addressed by the
// request, then commits all of their aggregate decisions in one UnitOfWork.
func (d *Dice) DurableCommitConfigRequest(ctx context.Context, request DurableConfigRequest) error {
	store, diceID, err := d.durableStoreAndID()
	if err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}

	work := eventstore.UnitOfWork{Streams: make([]eventstore.StreamAppend, 0, 3)}
	if request.PersistDiceConfig {
		state, readErr := configstate.ReadProjected(ctx, store, diceID)
		if readErr != nil {
			return fmt.Errorf("dice: read config projection: %w", readErr)
		}
		patch, patchErr := durableConfigPatch(state, request.Config, request.CommandPrefix, request.DiceMasters, request.MailPasswordRef)
		if patchErr != nil {
			return patchErr
		}
		preparedAppend, prepareErr := configstate.NewRepository(store).PrepareDecision(state, state.Version, eventstore.Metadata{}, configstate.Command{
			Kind:               configstate.CommandPatch,
			Patch:              &patch,
			ExpectedVersion:    state.Version,
			ExpectedVersionSet: true,
		})
		if prepareErr != nil {
			return prepareErr
		}
		if len(preparedAppend.Events) != 0 {
			work.Streams = append(work.Streams, preparedAppend)
		}
	}

	if request.PersistExtensionDefaults {
		repository, extensionDiceID, repoErr := d.durableExtensionRepository()
		if repoErr != nil {
			return repoErr
		}
		state, loadErr := repository.Load(ctx, extensionDiceID)
		if loadErr != nil {
			return loadErr
		}
		commands := make([]extensionstate.Command, 0, len(request.ExtensionDefaults)+len(state.DefaultCommands))
		desiredDefaults := make(map[string]struct{}, len(request.ExtensionDefaults))
		for _, defaults := range request.ExtensionDefaults {
			desiredDefaults[defaults.ExtensionID] = struct{}{}
			commands = append(commands, extensionstate.Command{
				Kind:             extensionstate.CommandSetDefaults,
				ExtensionID:      defaults.ExtensionID,
				AutoActive:       defaults.AutoActive,
				DisabledCommands: append([]string(nil), defaults.DisabledCommands...),
			})
		}
		removedDefaults := make([]string, 0, len(state.DefaultCommands))
		for extensionID := range state.DefaultCommands {
			if _, desired := desiredDefaults[extensionID]; !desired {
				removedDefaults = append(removedDefaults, extensionID)
			}
		}
		sort.Strings(removedDefaults)
		for _, extensionID := range removedDefaults {
			commands = append(commands, extensionstate.Command{
				Kind:        extensionstate.CommandClearDefaults,
				ExtensionID: extensionID,
			})
		}
		preparedAppend, prepareErr := repository.PrepareCommands(state, state.Version, eventstore.Metadata{}, commands)
		if prepareErr != nil {
			return prepareErr
		}
		if len(preparedAppend.Events) != 0 {
			work.Streams = append(work.Streams, preparedAppend)
		}
	}

	var manager *DiceManager
	var managerPrepared *managerstate.PreparedSave
	var managerPublic managerstate.PublicConfig
	var managerAuth managerstate.Auth
	managerLocked := false
	if durableManagerPatchRequested(request.Manager) {
		manager = d.Parent
		if manager == nil {
			return errors.New("dice: manager is unavailable for durable config update")
		}
		manager.managerStateMu.Lock()
		managerLocked = true
		defer func() {
			if managerLocked {
				manager.managerStateMu.Unlock()
			}
		}()
		if manager.durableStore == nil || manager.managerState.Version == 0 {
			return errors.New("dice: event-sourced manager state is unavailable")
		}
		managerPublic, managerAuth = manager.eventSourcedManagerSnapshot()
		if request.Manager.ServeAddress != nil {
			managerPublic.ServeAddress = *request.Manager.ServeAddress
		}
		if request.Manager.TrayTooltip != nil {
			managerPublic.TrayTooltip = NormalizeTrayTooltipPrefix(*request.Manager.TrayTooltip)
		}
		if request.Manager.DiceRandomMode != nil {
			managerPublic.DiceRandomMode = *request.Manager.DiceRandomMode
		}
		if request.Manager.UIPasswordHash != nil {
			managerAuth.UIPasswordHash = *request.Manager.UIPasswordHash
			managerAuth.AccessTokens = nil
		}
		repository, repoErr := managerstate.NewRepository(store)
		if repoErr != nil {
			return repoErr
		}
		prepared, prepareErr := repository.PrepareSave(ctx, manager.managerState, managerPublic, managerAuth)
		if prepareErr != nil {
			return prepareErr
		}
		managerPrepared = &prepared
		work.Streams = append(work.Streams, prepared.Stream)
		work.SecretUpdates = append(work.SecretUpdates, prepared.Secret)
	}

	if len(work.Streams) == 0 && managerPrepared == nil {
		return nil
	}
	commitAndPublish := func() error {
		if len(work.Streams) > 0 {
			if _, err := store.Commit(ctx, work); err != nil {
				return err
			}
		}
		if managerPrepared != nil {
			manager.managerState = managerPrepared.State
			if request.Manager.UIPasswordHash != nil {
				manager.applyEventSourcedManager(managerPublic, managerAuth)
			} else {
				manager.applyEventSourcedManagerPublic(managerPublic)
			}
		}
		return nil
	}
	if managerPrepared != nil && request.Manager.DiceRandomMode != nil {
		return manager.setDiceRandomModeWithCommit(DiceRandomMode(*request.Manager.DiceRandomMode), commitAndPublish)
	}
	return commitAndPublish()
}

func durableManagerPatchRequested(patch *DurableManagerConfigPatch) bool {
	return patch != nil &&
		(patch.ServeAddress != nil || patch.TrayTooltip != nil ||
			patch.UIPasswordHash != nil || patch.DiceRandomMode != nil)
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
		JsRuntimeOptions:               cloneJSRuntimeOptions(config.JsRuntimeOptions),
		JsRuntimeRoutes:                cloneJSRuntimeRoutes(config.JsRuntimeRoutes),
		DisabledJsScripts:              cloneDisabledJsScripts(config.DisabledJsScripts),
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
	publicDiceConfig := configstate.PublicDiceConfig{
		Enable: config.Enable, ID: config.ID, Name: config.PublicDiceConfig.Name,
		Brief: config.Brief, Note: config.Note, Avatar: config.Avatar,
		EndpointIDs: append([]string(nil), config.EndpointIDs...),
	}
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

// LegacyConfigBaseline converts one stopped legacy Dice configuration into
// the explicit event-sourced baseline used by the hard-cut importer.
func LegacyConfigBaseline(diceID string, config Config, advanced AdvancedConfig, commandPrefix, diceMasters []string, mailPasswordRef, storyLogTokenRef string) (configstate.Baseline, error) {
	patch, err := durableConfigPatch(configstate.State{}, config, commandPrefix, diceMasters, &mailPasswordRef)
	if err != nil {
		return configstate.Baseline{}, err
	}
	patch.Advanced = &configstate.AdvancedConfig{
		Show:                              advanced.Show,
		Enable:                            advanced.Enable,
		StoryLogBackendURL:                advanced.StoryLogBackendUrl,
		StoryLogAPIVersion:                advanced.StoryLogApiVersion,
		StoryLogBackendTokenRef:           storyLogTokenRef,
		CustomReplyCooldown:               advanced.CustomReplyCooldown,
		ExposeDangerousSealInst:           advanced.ExposeDangerousSealInst,
		AllowFilesystemUnrestrictedAccess: advanced.AllowFilesystemUnrestrictedAccess,
	}
	return baselineFromConfigPatch(diceID, config.ConfigVersion, patch, commandPrefix, diceMasters), nil
}

// LegacyExtensionBaseline preserves the extension defaults serialized in
// serve.yaml without loading scripts or executing callbacks.
func LegacyExtensionBaseline(config Config) extensionstate.Baseline {
	baseline := extensionstate.Baseline{}
	for _, item := range config.ExtDefaultSettings {
		if item == nil || strings.TrimSpace(item.Name) == "" {
			continue
		}
		disabled := make([]string, 0, len(item.DisabledCommand))
		for command, value := range item.DisabledCommand {
			if value {
				disabled = append(disabled, command)
			}
		}
		sort.Strings(disabled)
		baseline.Extensions = append(baseline.Extensions, extensionstate.ExtensionIdentity{
			ID: item.Name, Name: item.Name, Version: "legacy", Source: "legacy",
		})
		baseline.Defaults = append(baseline.Defaults, extensionstate.DefaultCommandUpdate{
			ExtensionID: item.Name, AutoActive: item.AutoActive, DisabledCommands: disabled,
		})
		if item.AutoActive {
			baseline.Enable = append(baseline.Enable, item.Name)
		} else {
			baseline.Disable = append(baseline.Disable, item.Name)
		}
	}
	return baseline
}
