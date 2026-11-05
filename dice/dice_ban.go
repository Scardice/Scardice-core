package dice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"Scardice-core/core/configstate"
	"Scardice-core/core/execution"
	"Scardice-core/eventstore"
)

type BanRankType int

const (
	BanRankBanned  BanRankType = -30
	BanRankWarn    BanRankType = -10
	BanRankNormal  BanRankType = 0
	BanRankTrusted BanRankType = 30
)

type BanListInfoItem struct {
	ID      string      `jsbind:"id"      json:"ID"`
	Name    string      `jsbind:"name"    json:"name"`
	Score   int64       `jsbind:"score"   json:"score"`   // 怒气值
	Rank    BanRankType `jsbind:"rank"    json:"rank"`    // 0 没事 -10警告 -30禁止 30信任
	Times   []int64     `jsbind:"times"   json:"times"`   // 事发时间
	Reasons []string    `jsbind:"reasons" json:"reasons"` // 拉黑原因
	Places  []string    `jsbind:"places"  json:"places"`  // 发生地点
	BanTime int64       `jsbind:"banTime" json:"banTime"` // 上黑名单时间

	BanUpdatedAt      int64  `json:"-"` // 排序依据，不过可能和bantime重复？
	UpdatedAt         int64  `json:"-"` // 数据更新时间
	EventStoreVersion uint64 `yaml:"-" json:"-"`
}

var BanRankText = map[BanRankType]string{
	BanRankTrusted: "信任",
	BanRankBanned:  "禁止",
	BanRankWarn:    "警告",
	BanRankNormal:  "常规",
}

func (i *BanListInfoItem) toText(_ *Dice) string {
	prefix := BanRankText[i.Rank]
	if i.Rank == -10 || i.Rank == -30 {
		return fmt.Sprintf("[%s] <%s>(%s) 原因: %s", prefix, i.Name, i.ID, strings.Join(i.Reasons, ","))
	}
	if i.Rank == 30 {
		return fmt.Sprintf("[%s] <%s> <%s> 原因: %s", prefix, i.Name, i.ID, strings.Join(i.Reasons, ","))
	}
	return ""
}

type banListRuntime struct {
	noticeMu sync.Mutex
	noticeAt map[blacklistedUserNoticeKey]time.Time
	cronID   cron.EntryID
}

type BanListInfo struct {
	source                                 configViewSource
	Parent                                 *Dice   `json:"-"                                      yaml:"-"`
	BanBehaviorRefuseReply                 bool    `json:"banBehaviorRefuseReply"                 yaml:"banBehaviorRefuseReply"`                 // 拉黑行为: 拒绝回复
	BanBehaviorRefuseInvite                bool    `json:"banBehaviorRefuseInvite"                yaml:"banBehaviorRefuseInvite"`                // 拉黑行为: 拒绝邀请
	BanBehaviorQuitLastPlace               bool    `json:"banBehaviorQuitLastPlace"               yaml:"banBehaviorQuitLastPlace"`               // 拉黑行为: 退出事发群
	BanBehaviorQuitPlaceImmediately        bool    `json:"banBehaviorQuitPlaceImmediately"        yaml:"banBehaviorQuitPlaceImmediately"`        // 拉黑行为: 使用时立即退出群
	BanBehaviorQuitIfAdmin                 bool    `json:"banBehaviorQuitIfAdmin"                 yaml:"banBehaviorQuitIfAdmin"`                 // 拉黑行为: 邀请者以上权限使用时立即退群，否则发出警告信息
	BanBehaviorQuitIfAdminSilentIfNotAdmin bool    `json:"banBehaviorQuitIfAdminSilentIfNotAdmin" yaml:"banBehaviorQuitIfAdminSilentIfNotAdmin"` // 邀请者以上权限使用时立即退群，否则仅拒绝回复
	ThresholdWarn                          int64   `json:"thresholdWarn"                          yaml:"thresholdWarn"`                          // 警告阈值
	ThresholdBan                           int64   `json:"thresholdBan"                           yaml:"thresholdBan"`                           // 错误阈值
	AutoBanMinutes                         int64   `json:"autoBanMinutes"                         yaml:"autoBanMinutes"`                         // 自动禁止时长
	ScoreReducePerMinute                   int64   `json:"scoreReducePerMinute"                   yaml:"scoreReducePerMinute"`
	ScoreGroupMuted                        int64   `json:"scoreGroupMuted"                        yaml:"scoreGroupMuted"`
	ScoreGroupKicked                       int64   `json:"scoreGroupKicked"                       yaml:"scoreGroupKicked"`
	ScoreTooManyCommand                    int64   `json:"scoreTooManyCommand"                    yaml:"scoreTooManyCommand"`
	BanNotifyIntervalMinutes               int64   `json:"banNotifyIntervalMinutes"               yaml:"banNotifyIntervalMinutes"`
	JointScorePercentOfGroup               float64 `json:"jointScorePercentOfGroup"               yaml:"jointScorePercentOfGroup"`
	JointScorePercentOfInviter             float64 `json:"jointScorePercentOfInviter"             yaml:"jointScorePercentOfInviter"`

	runtime *banListRuntime `json:"-" yaml:"-"`
}

func (i *BanListInfo) Init() {
	// 此为配置装载前的默认设置
	i.BanBehaviorRefuseReply = true
	i.BanBehaviorRefuseInvite = true
	i.BanBehaviorQuitLastPlace = false
	i.ThresholdWarn = 100
	i.ThresholdBan = 200
	i.AutoBanMinutes = 60 * 12 // 12小时

	i.ScoreReducePerMinute = 1
	i.ScoreGroupMuted = 100
	i.ScoreGroupKicked = 200
	i.ScoreTooManyCommand = 100
	i.BanNotifyIntervalMinutes = int64(defaultBlacklistedUserNoticeCooldown / time.Minute)

	i.JointScorePercentOfGroup = 0.5
	i.JointScorePercentOfInviter = 0.3
	if i.runtime == nil {
		i.runtime = &banListRuntime{noticeAt: map[blacklistedUserNoticeKey]time.Time{}}
	}
}

func (i *BanListInfo) cloneReadView(owner *Dice) *BanListInfo {
	if i == nil {
		return nil
	}
	cloned := *i
	cloned.Parent = owner
	if cloned.runtime == nil {
		cloned.runtime = &banListRuntime{noticeAt: map[blacklistedUserNoticeKey]time.Time{}}
	}
	return &cloned
}

func banListSettingsFromState(parent *Dice, state configstate.State) BanListInfo {
	return BanListInfo{
		Parent:                                 parent,
		BanBehaviorRefuseReply:                 state.Ban.RefuseReply,
		BanBehaviorRefuseInvite:                state.Ban.RefuseInvite,
		BanBehaviorQuitLastPlace:               state.Ban.QuitLastPlace,
		BanBehaviorQuitPlaceImmediately:        state.Ban.QuitPlaceImmediately,
		BanBehaviorQuitIfAdmin:                 state.Ban.QuitIfAdmin,
		BanBehaviorQuitIfAdminSilentIfNotAdmin: state.Ban.QuitIfAdminSilentIfNotAdmin,
		ThresholdWarn:                          state.Ban.ThresholdWarn,
		ThresholdBan:                           state.Ban.ThresholdBan,
		AutoBanMinutes:                         state.Ban.AutoBanMinutes,
		ScoreReducePerMinute:                   state.Ban.ScoreReducePerMinute,
		ScoreGroupMuted:                        state.Ban.ScoreGroupMuted,
		ScoreGroupKicked:                       state.Ban.ScoreGroupKicked,
		ScoreTooManyCommand:                    state.Ban.ScoreTooManyCommand,
		BanNotifyIntervalMinutes:               state.Ban.BanNotifyIntervalMinutes,
		JointScorePercentOfGroup:               state.Ban.JointScorePercentOfGroup,
		JointScorePercentOfInviter:             state.Ban.JointScorePercentOfInviter,
	}
}

func (i *BanListInfo) settingsForTransaction(
	ctx context.Context,
	transaction *DurableCallbackTransaction,
) (BanListInfo, error) {
	if i == nil || i.Parent == nil || transaction == nil {
		return BanListInfo{}, execution.ErrDomainTxUnavailable
	}
	participant, _, err := i.Parent.configOwner(ctx, transaction.Domain())
	if err != nil {
		return BanListInfo{}, err
	}
	return banListSettingsFromState(i.Parent, participant.state), nil
}

func (i *BanListInfo) settingsForContext(ctx *MsgContext) (BanListInfo, error) {
	if i == nil || i.Parent == nil {
		return BanListInfo{}, execution.ErrDomainTxUnavailable
	}
	if ctx != nil && ctx.callbackTransaction != nil {
		if ctx.Dice != nil && ctx.Dice != i.Parent {
			return BanListInfo{}, errors.New("ban list message context belongs to another dice")
		}
		return i.settingsForTransaction(ctx.domainContext(), ctx.callbackTransaction)
	}
	return *i, nil
}

func (i *BanListInfo) Loads() {
	if err := i.LoadsWithError(); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单读取校验失败: %v", err)
	}
}

func (i *BanListInfo) LoadsWithError() error {
	if i == nil || i.Parent == nil || i.Parent.DurableStore == nil {
		return nil
	}
	repository, err := newModerationBanRepository(i.Parent)
	if err != nil {
		return err
	}
	_, err = repository.load(context.Background())
	return err
}

func (i *BanListInfo) AfterLoads() {
	if i == nil {
		return
	}
	if i.runtime == nil {
		i.runtime = &banListRuntime{noticeAt: map[blacklistedUserNoticeKey]time.Time{}}
	}
	d := i.Parent
	if d == nil || d.Parent == nil || d.Parent.Cron == nil {
		return
	}
	i.runtime.noticeMu.Lock()
	if i.runtime.cronID != 0 {
		i.runtime.noticeMu.Unlock()
		return
	}
	entryID, err := d.Parent.Cron.AddFunc("@every 1m", func() {
		view := d.currentConfigView()
		if view == nil || view.config.BanList == nil {
			return
		}
		current := view.config.BanList
		current.cleanupBlacklistedUserNotices(time.Now())
		_, decayErr := current.decayEventSourced(d, time.Now().Unix())
		if decayErr != nil && d.Logger != nil {
			d.Logger.Errorf("黑白名单衰减失败: %v", decayErr)
		}
	})
	if err == nil {
		i.runtime.cronID = entryID
	}
	i.runtime.noticeMu.Unlock()
}

func (i *BanListInfo) decayEventSourced(d *Dice, now int64) (bool, error) {
	if i == nil || d == nil || d.DurableStore == nil {
		return false, nil
	}
	repository, err := newModerationBanRepository(d)
	if err != nil {
		return false, err
	}
	items, err := repository.load(context.Background())
	if err != nil {
		return false, err
	}
	subjects := make([]string, 0, len(items))
	for id, item := range items {
		if item != nil && (item.Rank == BanRankNormal || item.Rank == BanRankWarn) {
			subjects = append(subjects, id)
		}
	}
	if len(subjects) == 0 {
		return false, nil
	}
	changed := false
	request := struct {
		At       int64    `json:"at"`
		Subjects []string `json:"subjects"`
	}{now, subjects}
	err = d.withFreshDomainExecution(context.Background(), "moderation-decay", request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		if validateErr := i.validateConfigSource(context.Background(), transaction); validateErr != nil {
			return validateErr
		}
		settings, settingsErr := i.settingsForTransaction(context.Background(), transaction)
		if settingsErr != nil {
			return settingsErr
		}
		if settings.ScoreReducePerMinute == 0 {
			return nil
		}
		for _, subjectID := range subjects {
			item, exists, readErr := d.ModerationItemForDomain(context.Background(), transaction.Domain(), subjectID)
			if readErr != nil {
				return readErr
			}
			if !exists || (item.Rank != BanRankNormal && item.Rank != BanRankWarn) {
				continue
			}
			nextScore := item.Score - settings.ScoreReducePerMinute
			if nextScore <= 0 {
				if deleteErr := d.ContributeModerationDelete(context.Background(), transaction.Domain(), metadata, subjectID); deleteErr != nil {
					return deleteErr
				}
			} else {
				if updateErr := d.ContributeModerationMutation(context.Background(), transaction.Domain(), metadata, subjectID, func(current *BanListInfoItem, exists bool) error {
					if !exists || (current.Rank != BanRankNormal && current.Rank != BanRankWarn) {
						return nil
					}
					current.Score -= settings.ScoreReducePerMinute
					current.UpdatedAt = now
					return nil
				}); updateErr != nil {
					return updateErr
				}
			}
			changed = true
		}
		return nil
	})
	return changed && err == nil, err
}

func (i *BanListInfo) validateConfigSource(ctx context.Context, transaction *DurableCallbackTransaction) error {
	if i == nil || i.Parent == nil || transaction == nil {
		return execution.ErrDomainTxUnavailable
	}
	participant, _, err := i.Parent.configOwner(ctx, transaction.Domain())
	if err != nil {
		return err
	}
	if !configSourceMatchesParticipant(i.source, participant) {
		return ErrConfigViewChanged
	}
	return nil
}

func (i *BanListInfo) runMutation(
	ctx context.Context,
	message *MsgContext,
	operation string,
	request any,
	run func(context.Context, *DurableCallbackTransaction, eventstore.Metadata) error,
) error {
	if i == nil || i.Parent == nil {
		return errors.New("ban list parent is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if message != nil && message.Dice != nil && message.Dice != i.Parent {
		return errors.New("ban list message context belongs to another dice")
	}
	runValidated := func(callCtx context.Context, transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		if err := i.validateConfigSource(callCtx, transaction); err != nil {
			return err
		}
		return run(callCtx, transaction, metadata)
	}
	if message != nil && message.callbackTransaction != nil {
		return runValidated(message.domainContext(), message.callbackTransaction, message.callbackMetadata)
	}
	return i.Parent.withFreshDomainExecution(ctx, operation, request, func(transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		return runValidated(ctx, transaction, metadata)
	})
}

// AddScoreBase
// 这一份ctx有endpoint就行
func (i *BanListInfo) AddScoreBase(uid string, score int64, place string, reason string, ctx *MsgContext) *BanListInfoItem {
	item, err := i.AddScoreBaseWithError(uid, score, place, reason, ctx)
	if err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单保存失败: %v", err)
	}
	return item
}

func (i *BanListInfo) AddScoreBaseWithError(uid string, score int64, place string, reason string, ctx *MsgContext) (*BanListInfoItem, error) {
	if i == nil || i.Parent == nil || uid == "" {
		return nil, errors.New("ban list, parent, and ID are required")
	}
	d := i.Parent
	name := ""
	if d.Parent != nil {
		name = d.Parent.TryGetUserName(uid)
		if strings.Contains(uid, "-Group:") {
			name = d.Parent.TryGetGroupName(uid)
		}
	}
	now := time.Now().Unix()
	var (
		updatedItem  *BanListInfoItem
		removeFriend bool
	)
	request := struct {
		SubjectID string `json:"subjectId"`
		Score     int64  `json:"score"`
		Place     string `json:"place"`
		Reason    string `json:"reason"`
		At        int64  `json:"at"`
	}{uid, score, place, reason, now}
	err := i.runMutation(context.Background(), ctx, "moderation-score", request, func(callCtx context.Context, transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		settings, settingsErr := i.settingsForTransaction(callCtx, transaction)
		if settingsErr != nil {
			return settingsErr
		}
		err := d.ContributeModerationMutation(callCtx, transaction.Domain(), metadata, uid, func(item *BanListInfoItem, _ bool) error {
			item.Score += score
			item.Name = name
			item.Places = append(item.Places, place)
			item.Reasons = append(item.Reasons, reason)
			item.Times = append(item.Times, now)
			oldRank := item.Rank
			switch item.Rank {
			case BanRankTrusted, BanRankBanned:
			case BanRankNormal, BanRankWarn:
				if item.Score < settings.ThresholdWarn {
					item.Rank = BanRankNormal
				}
				if item.Score >= settings.ThresholdWarn {
					item.Rank = BanRankWarn
				}
				if item.Score >= settings.ThresholdBan {
					item.Rank = BanRankBanned
					item.BanTime = now
					removeFriend = ctx != nil && ctx.EndPoint != nil && ctx.EndPoint.Platform == "QQ"
				}
				if oldRank != item.Rank {
					item.BanUpdatedAt = now
				}
			}
			item.UpdatedAt = now
			updatedItem = cloneBanListItem(item)
			return nil
		})
		if err != nil {
			return err
		}
		if removeFriend {
			if err = transaction.AfterCommit(func() {
				if adapter, ok := ctx.EndPoint.Adapter.(interface {
					DeleteFriend(ctx *MsgContext, id string)
				}); ok {
					adapter.DeleteFriend(ctx, uid)
				} else if d.Logger != nil {
					d.Logger.Warn("当前 QQ 适配器不支持删除好友")
				}
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return updatedItem, err
}

func (i *BanListInfo) addJointScoreWithError(score int64, place string, reason string, ctx *MsgContext) (string, BanRankType, error) {
	settings, err := i.settingsForContext(ctx)
	if err != nil {
		return "", BanRankNormal, err
	}
	if settings.JointScorePercentOfGroup > 0 {
		groupScore := settings.JointScorePercentOfGroup * float64(score)
		if _, err := i.AddScoreBaseWithError(place, int64(groupScore), place, reason, ctx); err != nil {
			return "", BanRankNormal, err
		}
	}
	if settings.JointScorePercentOfInviter > 0 && ctx != nil && ctx.Group != nil && ctx.Group.GroupID() == place {
		inviterID := ctx.Group.InviteUserID()
		if inviterID != "" {
			rank, rankErr := i.noticeRankForContext(ctx, inviterID)
			if rankErr != nil {
				return "", BanRankNormal, rankErr
			}
			inviterScore := settings.JointScorePercentOfInviter * float64(score)
			if _, err := i.AddScoreBaseWithError(inviterID, int64(inviterScore), place, reason, ctx); err != nil {
				return "", BanRankNormal, err
			}
			return inviterID, rank, nil
		}
	}
	return "", BanRankNormal, nil
}
func (i *BanListInfo) noticeRankForContext(ctx *MsgContext, uid string) (BanRankType, error) {
	item, ok, err := i.GetByIDForContext(ctx, uid)
	if err != nil {
		return BanRankNormal, err
	}
	if ok {
		return item.Rank, nil
	}
	return BanRankNormal, nil
}

func (i *BanListInfo) NoticeCheckPrepare(uid string) BanRankType {
	return i.NoticeCheckPrepareForContext(nil, uid)
}

func (i *BanListInfo) NoticeCheckPrepareForContext(ctx *MsgContext, uid string) BanRankType {
	rank, err := i.noticeRankForContext(ctx, uid)
	if err != nil {
		if ctx != nil {
			ctx.setExecutionError(err)
		}
		if i != nil && i.Parent != nil && i.Parent.Logger != nil {
			i.Parent.Logger.Errorf("黑白名单读取失败: %v", err)
		}
		return BanRankNormal
	}
	return rank
}

func (i *BanListInfo) NoticeCheck(uid string, place string, oldRank BanRankType, ctx *MsgContext) BanRankType {
	log := i.Parent.Logger
	item, ok, err := i.GetByIDForContext(ctx, uid)
	if err != nil {
		if ctx != nil {
			ctx.setExecutionError(err)
		}
		return 0
	}
	if !ok {
		return 0
	}
	settings, settingsErr := i.settingsForContext(ctx)
	if settingsErr != nil {
		if ctx != nil {
			ctx.setExecutionError(settingsErr)
		}
		if log != nil {
			log.Errorf("读取黑名单设置失败: %v", settingsErr)
		}
		return 0
	}

	curRank := item.Rank
	if oldRank == curRank || (curRank != BanRankWarn && curRank != BanRankBanned) {
		return 0
	}

	txt := fmt.Sprintf("黑名单等级提升: %v", item.toText(i.Parent))
	log.Info(txt)

	// If user is banned and we should quit immediately, do it first before sending notifications
	if curRank == BanRankBanned && settings.BanBehaviorQuitLastPlace && ctx != nil {
		var isWhiteGroup bool
		d := ctx.Dice
		value, exists, readErr := i.GetByIDForContext(ctx, place)
		if readErr != nil {
			ctx.setExecutionError(readErr)
			if log != nil {
				log.Errorf("读取事发群信任状态失败: %v", readErr)
			}
			return 0
		}
		if exists && value.Rank == BanRankTrusted {
			isWhiteGroup = true
		}

		if !isWhiteGroup {
			// Quit group immediately before sending other notifications to avoid spam
			ReplyGroupRaw(ctx,
				&Message{GroupID: place},
				DiceFormatTmpl(ctx, "核心:黑名单惩罚_退群"),
				"")
			if d.OutboundBridge == nil && ctx.EndPoint != nil && ctx.EndPoint.Adapter != nil && !isPureOnebotEndpoint(ctx.EndPoint) {
				time.Sleep(1 * time.Second)
			}
			if err := QuitGroup(ctx, place); err != nil {
				ctx.setExecutionError(err)
				d.Logger.Errorf("黑名单触发退群请求提交失败: group=%s error=%v", place, err)
			}
			return 0
		}
		d.Logger.Infof("群<%s>触发\"退出事发群\"的拉黑惩罚，但该群是信任群所以未退群", place)
	}

	if ctx != nil {
		// 做出通知
		ctx.Notice(txt, NoticeTypeBan)

		if ctx.Player == nil {
			diceID, playerName := "", ""
			if ctx.Dice != nil {
				diceID = ctx.Dice.BaseConfig.Name
			}
			if i.Parent != nil && i.Parent.Parent != nil {
				playerName = i.Parent.Parent.TryGetUserName(uid)
			}
			ctx.Player = newDetachedGroupPlayerInfo(diceID, place, uid, playerName)
		}

		VarSetValueStr(ctx, "$t黑名单事件", txt)

		// 发给当事人
		ReplyPersonRaw(ctx,
			&Message{Sender: SenderBase{UserID: uid}},
			DiceFormatTmpl(ctx, "核心:黑名单触发_当事人"),
			"")

		// 发给当事群
		time.Sleep(1 * time.Second)
		ReplyGroupRaw(ctx,
			&Message{GroupID: place},
			DiceFormatTmpl(ctx, "核心:黑名单触发_所在群"),
			"")

		// 发给邀请者
		time.Sleep(1 * time.Second)
		if ctx.Group != nil && ctx.Group.GroupID() == place {
			inviterID := ctx.Group.InviteUserID()
			if inviterID != "" {
				VarSetValueStr(ctx, "$t事发群名", ctx.Group.GroupName())
				VarSetValueStr(ctx, "$t事发群号", ctx.Group.GroupID())
				text := DiceFormatTmpl(ctx, "核心:黑名单触发_邀请人")
				ReplyPersonRaw(ctx, &Message{Sender: SenderBase{UserID: inviterID}}, text, "")
			}
		}
	}

	return 0
}

func (i *BanListInfo) addScoreWithJointAndNotice(
	uid string,
	score int64,
	place, reason, jointReason string,
	ctx *MsgContext,
) error {
	rank, err := i.noticeRankForContext(ctx, uid)
	if err != nil {
		return err
	}
	if _, err := i.AddScoreBaseWithError(uid, score, place, reason, ctx); err != nil {
		return err
	}
	inviterID, inviterRank, err := i.addJointScoreWithError(score, place, jointReason, ctx)
	if err != nil {
		return err
	}
	i.NoticeCheck(uid, place, rank, ctx)
	if inviterID != "" && inviterID != uid {
		i.NoticeCheck(inviterID, place, inviterRank, ctx)
	}
	if ctx != nil {
		if err = ctx.getExecutionError(); err != nil {
			return err
		}
	}
	return nil
}

// AddScoreByGroupMuted 群组禁言
func (i *BanListInfo) AddScoreByGroupMuted(uid string, place string, ctx *MsgContext) {
	if err := i.AddScoreByGroupMutedForContext(uid, place, ctx); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单禁言评分失败: %v", err)
	}
}

func (i *BanListInfo) AddScoreByGroupMutedForContext(uid string, place string, ctx *MsgContext) error {
	settings, err := i.settingsForContext(ctx)
	if err != nil {
		return err
	}
	return i.addScoreWithJointAndNotice(uid, settings.ScoreGroupMuted, place, "禁言骰子", "连带责任:禁言骰子", ctx)
}

// AddScoreByGroupKicked 群组踢出
func (i *BanListInfo) AddScoreByGroupKicked(uid string, place string, ctx *MsgContext) {
	if err := i.AddScoreByGroupKickedForContext(uid, place, ctx); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单踢出评分失败: %v", err)
	}
}

func (i *BanListInfo) AddScoreByGroupKickedForContext(uid string, place string, ctx *MsgContext) error {
	settings, err := i.settingsForContext(ctx)
	if err != nil {
		return err
	}
	return i.addScoreWithJointAndNotice(uid, settings.ScoreGroupKicked, place, "踢出骰子", "连带责任:踢出骰子", ctx)
}

// AddScoreByCommandSpam 指令刷屏
func (i *BanListInfo) AddScoreByCommandSpam(uid string, place string, ctx *MsgContext) {
	if err := i.AddScoreByCommandSpamForContext(uid, place, ctx); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单刷屏评分失败: %v", err)
	}
}

func (i *BanListInfo) AddScoreByCommandSpamForContext(uid string, place string, ctx *MsgContext) error {
	settings, err := i.settingsForContext(ctx)
	if err != nil {
		return err
	}
	return i.addScoreWithJointAndNotice(uid, settings.ScoreTooManyCommand, place, "指令刷屏", "连带责任:指令刷屏", ctx)
}

// AddScoreByCensor 敏感词审查
func (i *BanListInfo) AddScoreByCensor(uid string, score int64, place string, level string, ctx *MsgContext) {
	if err := i.AddScoreByCensorForContext(uid, score, place, level, ctx); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单敏感词评分失败: %v", err)
	}
}

func (i *BanListInfo) AddScoreByCensorForContext(uid string, score int64, place string, level string, ctx *MsgContext) error {
	return i.addScoreWithJointAndNotice(
		uid, score, place, "触发<"+level+">敏感词", "连带责任:触发<"+level+">敏感词", ctx,
	)
}

func (i *BanListInfo) GetByID(uid string) (*BanListInfoItem, bool) {
	if i == nil || i.Parent == nil || uid == "" {
		return nil, false
	}
	repository, err := newModerationBanRepository(i.Parent)
	if err != nil {
		return nil, false
	}
	item, exists, err := repository.loadItem(context.Background(), uid)
	if err != nil {
		if i.Parent.Logger != nil {
			i.Parent.Logger.Errorf("黑白名单读取失败: %v", err)
		}
		return nil, false
	}
	return item, exists
}

func (i *BanListInfo) GetByIDForContext(ctx *MsgContext, uid string) (*BanListInfoItem, bool, error) {
	if i == nil || i.Parent == nil || uid == "" {
		return nil, false, nil
	}
	if ctx != nil && ctx.Dice != nil && ctx.Dice != i.Parent {
		return nil, false, errors.New("ban list message context belongs to another dice")
	}
	if ctx != nil && ctx.callbackTransaction != nil {
		return i.Parent.ModerationItemForDomain(ctx.domainContext(), ctx.callbackTransaction.Domain(), uid)
	}
	repository, err := newModerationBanRepository(i.Parent)
	if err != nil {
		return nil, false, err
	}
	return repository.loadItem(context.Background(), uid)
}

func (i *BanListInfo) SetTrustByID(uid string, place string, reason string) {
	if err := i.SetTrustByIDWithError(uid, place, reason); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单保存失败: %v", err)
	}
}

func (i *BanListInfo) SetTrustByIDWithError(uid string, place string, reason string) error {
	return i.SetTrustByIDForContext(nil, uid, place, reason)
}

func (i *BanListInfo) SetTrustByIDForContext(ctx *MsgContext, uid string, place string, reason string) error {
	if i == nil || i.Parent == nil || uid == "" {
		return errors.New("ban list, parent, and ID are required")
	}
	d := i.Parent
	name := ""
	if d.Parent != nil {
		name = d.Parent.TryGetUserName(uid)
		if strings.Contains(uid, "-Group:") {
			name = d.Parent.TryGetGroupName(uid)
		}
	}
	now := time.Now().Unix()
	request := struct {
		SubjectID string `json:"subjectId"`
		Place     string `json:"place"`
		Reason    string `json:"reason"`
		At        int64  `json:"at"`
	}{uid, place, reason, now}
	return i.runMutation(context.Background(), ctx, "moderation-trust", request, func(callCtx context.Context, transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		return d.ContributeModerationMutation(callCtx, transaction.Domain(), metadata, uid, func(item *BanListInfoItem, _ bool) error {
			item.Rank = BanRankTrusted
			item.Name = name
			item.Places = append(item.Places, place)
			item.Reasons = append(item.Reasons, reason)
			item.Times = append(item.Times, now)
			item.BanUpdatedAt = now
			item.UpdatedAt = now
			return nil
		})
	})
}

func (i *BanListInfo) SetRankByID(d *Dice, uid string, rank BanRankType, name string, place string, reason string) error {
	return i.SetRankByIDForContext(nil, d, uid, rank, name, place, reason)
}

func (i *BanListInfo) SetRankByIDForContext(ctx *MsgContext, d *Dice, uid string, rank BanRankType, name string, place string, reason string) error {
	if i == nil || uid == "" {
		return errors.New("ban list and ID are required")
	}
	if d == nil {
		d = i.Parent
	}
	if d == nil || d != i.Parent {
		return errors.New("ban list parent does not match dice")
	}
	switch rank {
	case BanRankBanned, BanRankWarn, BanRankTrusted, BanRankNormal:
	default:
		return fmt.Errorf("invalid ban rank %d", rank)
	}
	now := time.Now().Unix()
	fallbackName := ""
	if name == "" && d.Parent != nil {
		if strings.Contains(uid, "-Group:") {
			fallbackName = d.Parent.TryGetGroupName(uid)
		} else {
			fallbackName = d.Parent.TryGetUserName(uid)
		}
	}
	request := struct {
		SubjectID string      `json:"subjectId"`
		Rank      BanRankType `json:"rank"`
		Name      string      `json:"name"`
		Place     string      `json:"place"`
		Reason    string      `json:"reason"`
		At        int64       `json:"at"`
	}{uid, rank, name, place, reason, now}
	return i.runMutation(context.Background(), ctx, "moderation-rank", request, func(callCtx context.Context, transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		settings, settingsErr := i.settingsForTransaction(callCtx, transaction)
		if settingsErr != nil {
			return settingsErr
		}
		return d.ContributeModerationMutation(callCtx, transaction.Domain(), metadata, uid, func(item *BanListInfoItem, exists bool) error {
			if name != "" {
				item.Name = name
			} else if !exists {
				item.Name = fallbackName
			}
			switch rank {
			case BanRankBanned:
				item.Rank = rank
				item.Score = settings.ThresholdBan
				item.BanTime = now
			case BanRankWarn:
				item.Rank = rank
				item.Score = settings.ThresholdWarn
				item.BanTime = 0
			case BanRankTrusted:
				item.Rank = rank
			case BanRankNormal:
				item.Rank = rank
				item.Score = 0
				item.BanTime = 0
			}
			if place != "" || reason != "" {
				item.Reasons = append(item.Reasons, reason)
				item.Places = append(item.Places, place)
				item.Times = append(item.Times, now)
			}
			item.BanUpdatedAt = now
			item.UpdatedAt = now
			return nil
		})
	})
}

func (i *BanListInfo) ImportItems(d *Dice, items []*BanListInfoItem) error {
	if i == nil {
		return errors.New("ban list is unavailable")
	}
	if d == nil {
		d = i.Parent
	}
	if d == nil || d != i.Parent {
		return errors.New("ban list parent does not match dice")
	}
	now := time.Now().Unix()
	imported := make([]*BanListInfoItem, len(items))
	for index, item := range items {
		if item == nil || item.ID == "" {
			return errors.New("ban list item ID is required")
		}
		imported[index] = cloneBanListItem(item)
		imported[index].EventStoreVersion = 0
		imported[index].UpdatedAt = now
		if imported[index].BanUpdatedAt == 0 {
			imported[index].BanUpdatedAt = now
		}
	}
	return i.runMutation(context.Background(), nil, "moderation-import", imported, func(callCtx context.Context, transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		for _, importedItem := range imported {
			copyItem := cloneBanListItem(importedItem)
			if err := d.ContributeModerationMutation(callCtx, transaction.Domain(), metadata, copyItem.ID, func(item *BanListInfoItem, _ bool) error {
				*item = *copyItem
				item.Times = append([]int64(nil), copyItem.Times...)
				item.Reasons = append([]string(nil), copyItem.Reasons...)
				item.Places = append([]string(nil), copyItem.Places...)
				return nil
			}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (d *Dice) GetBanListWithError(ctx context.Context) ([]*BanListInfoItem, error) {
	if d == nil {
		return []*BanListInfoItem{}, nil
	}
	repository, err := newModerationBanRepository(d)
	if err != nil {
		return nil, err
	}
	items, err := repository.load(ctx)
	if err != nil {
		return nil, err
	}
	list := make([]*BanListInfoItem, 0, len(items))
	for _, item := range items {
		list = append(list, cloneBanListItem(item))
	}
	sortBanListItems(list)
	return list, nil
}

func (d *Dice) GetBanList() []*BanListInfoItem {
	list, err := d.GetBanListWithError(context.Background())
	if err != nil {
		if d != nil && d.Logger != nil {
			d.Logger.Errorf("黑白名单读取失败: %v", err)
		}
		return []*BanListInfoItem{}
	}
	return list
}

func (i *BanListInfo) DeleteByID(d *Dice, id string) {
	if err := i.DeleteByIDWithError(d, id); err != nil && d != nil && d.Logger != nil {
		d.Logger.Errorf("黑白名单删除失败: %v", err)
	}
}

func (i *BanListInfo) DeleteByIDWithError(d *Dice, id string) error {
	return i.DeleteByIDForContext(nil, d, id)
}

func (i *BanListInfo) DeleteByIDForContext(ctx *MsgContext, d *Dice, id string) error {
	if i == nil || id == "" {
		return nil
	}
	if d == nil {
		d = i.Parent
	}
	if d == nil || d != i.Parent {
		return errors.New("ban list parent does not match dice")
	}
	callCtx := context.Background()
	if ctx != nil {
		callCtx = ctx.domainContext()
	}
	return i.runMutation(callCtx, ctx, "moderation-delete", struct {
		SubjectID string `json:"subjectId"`
	}{id}, func(domainCtx context.Context, transaction *DurableCallbackTransaction, metadata eventstore.Metadata) error {
		return d.ContributeModerationDelete(domainCtx, transaction.Domain(), metadata, id)
	})
}
