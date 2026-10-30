package dice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/robfig/cron/v3"

	"Scardice-core/dice/service"
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

type BanListInfo struct {
	Parent                                 *Dice                              `json:"-"                                      yaml:"-"`
	Map                                    *SyncMap[string, *BanListInfoItem] `json:"-"                                      yaml:"-"`
	BanBehaviorRefuseReply                 bool                               `json:"banBehaviorRefuseReply"                 yaml:"banBehaviorRefuseReply"`                 // 拉黑行为: 拒绝回复
	BanBehaviorRefuseInvite                bool                               `json:"banBehaviorRefuseInvite"                yaml:"banBehaviorRefuseInvite"`                // 拉黑行为: 拒绝邀请
	BanBehaviorQuitLastPlace               bool                               `json:"banBehaviorQuitLastPlace"               yaml:"banBehaviorQuitLastPlace"`               // 拉黑行为: 退出事发群
	BanBehaviorQuitPlaceImmediately        bool                               `json:"banBehaviorQuitPlaceImmediately"        yaml:"banBehaviorQuitPlaceImmediately"`        // 拉黑行为: 使用时立即退出群
	BanBehaviorQuitIfAdmin                 bool                               `json:"banBehaviorQuitIfAdmin"                 yaml:"banBehaviorQuitIfAdmin"`                 // 拉黑行为: 邀请者以上权限使用时立即退群，否则发出警告信息
	BanBehaviorQuitIfAdminSilentIfNotAdmin bool                               `json:"banBehaviorQuitIfAdminSilentIfNotAdmin" yaml:"banBehaviorQuitIfAdminSilentIfNotAdmin"` // 拉黑行为: 邀请者以上权限使用时立即退群，否则仅拒绝回复
	ThresholdWarn                          int64                              `json:"thresholdWarn"                          yaml:"thresholdWarn"`                          // 警告阈值
	ThresholdBan                           int64                              `json:"thresholdBan"                           yaml:"thresholdBan"`                           // 错误阈值
	AutoBanMinutes                         int64                              `json:"autoBanMinutes"                         yaml:"autoBanMinutes"`                         // 自动禁止时长

	ScoreReducePerMinute     int64 `json:"scoreReducePerMinute" yaml:"scoreReducePerMinute"`         // 每分钟下降
	ScoreGroupMuted          int64 `json:"scoreGroupMuted"      yaml:"scoreGroupMuted"`              // 群组禁言
	ScoreGroupKicked         int64 `json:"scoreGroupKicked"     yaml:"scoreGroupKicked"`             // 群组踢出
	ScoreTooManyCommand      int64 `json:"scoreTooManyCommand"  yaml:"scoreTooManyCommand"`          // 刷指令
	BanNotifyIntervalMinutes int64 `json:"banNotifyIntervalMinutes" yaml:"banNotifyIntervalMinutes"` // 同一用户同一群内通报间隔；0 为默认 20 分钟，负数表示每次通报

	JointScorePercentOfGroup   float64 `json:"jointScorePercentOfGroup"   yaml:"jointScorePercentOfGroup"`   // 群组连带责任
	JointScorePercentOfInviter float64 `json:"jointScorePercentOfInviter" yaml:"jointScorePercentOfInviter"` // 邀请人连带责任

	banNoticeMu sync.Mutex                             `json:"-" yaml:"-"`
	banNoticeAt map[blacklistedUserNoticeKey]time.Time `json:"-" yaml:"-"`
	// SyncMap protects map operations; itemsMu protects mutable item values.
	itemsMu            sync.RWMutex `json:"-" yaml:"-"`
	persistenceMu      sync.Mutex   `json:"-" yaml:"-"`
	persistenceLoadErr error        `json:"-" yaml:"-"`
	cronID             cron.EntryID `json:"-" yaml:"-"`
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
	i.Map = new(SyncMap[string, *BanListInfoItem])
	i.banNoticeAt = map[blacklistedUserNoticeKey]time.Time{}
}

func (i *BanListInfo) Loads() {
	if err := i.LoadsWithError(); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单加载失败: %v", err)
	}
}

func (i *BanListInfo) LoadsWithError() error {
	if i == nil || i.Parent == nil || i.Parent.DurableStore == nil {
		return nil
	}
	repository, err := newModerationBanRepository(i.Parent)
	if err == nil {
		var loaded map[string]*BanListInfoItem
		loaded, err = repository.load(context.Background())
		if err == nil {
			i.itemsMu.Lock()
			if i.Map == nil {
				i.Map = new(SyncMap[string, *BanListInfoItem])
			}
			i.Map.Range(func(id string, _ *BanListInfoItem) bool {
				i.Map.Delete(id)
				return true
			})
			for id, item := range loaded {
				i.Map.Store(id, item)
			}
			i.itemsMu.Unlock()
		}
	}
	i.persistenceMu.Lock()
	i.persistenceLoadErr = err
	i.persistenceMu.Unlock()
	return err
}

func (i *BanListInfo) AfterLoads() {
	d := i.Parent
	if d == nil || d.Parent == nil || d.Parent.Cron == nil {
		return
	}
	i.cronID, _ = d.Parent.Cron.AddFunc("@every 1m", func() {
		i.cleanupBlacklistedUserNotices(time.Now())
		if d.DBOperator == nil && d.DurableStore == nil {
			return
		}
		now := time.Now().Unix()
		if d.DurableStore != nil {
			_, err := i.decayEventSourced(d, now)
			if err != nil && d.Logger != nil {
				d.Logger.Errorf("黑白名单衰减失败: %v", err)
			}
			return
		}
		changed, _, err := i.decayScoresWithDelete(now, func(id string) error {
			return service.BanItemDel(d.DBOperator, id)
		})
		if err != nil && d.Logger != nil {
			d.Logger.Errorf("黑白名单衰减失败: %v", err)
		}
		if changed {
			if err = i.SaveChangedWithError(d); err != nil && d.Logger != nil {
				d.Logger.Errorf("黑白名单保存失败: %v", err)
			}
		}
	})
}

func (i *BanListInfo) decayScores(now int64) (bool, []string) {
	changed, toDelete, _ := i.decayScoresWithDelete(now, nil)
	return changed, toDelete
}

func (i *BanListInfo) decayScoresWithDelete(now int64, deleteItem func(string) error) (bool, []string, error) {
	if i == nil {
		return false, nil, nil
	}
	i.itemsMu.Lock()
	defer i.itemsMu.Unlock()
	if i.Map == nil {
		return false, nil, nil
	}
	var (
		toDelete []string
		changed  bool
		saveErr  error
	)
	i.Map.Range(func(id string, item *BanListInfoItem) bool {
		if item == nil || (item.Rank != BanRankNormal && item.Rank != BanRankWarn) {
			return true
		}
		previousScore, previousUpdatedAt := item.Score, item.UpdatedAt
		item.Score -= i.ScoreReducePerMinute
		scoreChanged := item.Score != previousScore
		if scoreChanged {
			item.UpdatedAt = now
		}
		if item.Score > 0 {
			changed = changed || scoreChanged
			return true
		}
		if deleteItem != nil {
			if err := deleteItem(id); err != nil {
				item.Score, item.UpdatedAt = previousScore, previousUpdatedAt
				saveErr = errors.Join(saveErr, err)
				return true
			}
		}
		toDelete = append(toDelete, id)
		i.Map.Delete(id)
		changed = true
		return true
	})
	return changed, toDelete, saveErr
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
	if err := i.PersistenceError(); err != nil {
		return nil, err
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

	i.itemsMu.Lock()
	if i.Map == nil {
		i.Map = new(SyncMap[string, *BanListInfoItem])
	}
	item, _ := i.Map.Load(uid)
	if item == nil {
		item = &BanListInfoItem{ID: uid}
	} else {
		item = cloneBanListItem(item)
	}
	item.Score += score
	item.Name = name
	item.Places = append(item.Places, place)
	item.Reasons = append(item.Reasons, reason)
	item.Times = append(item.Times, now)
	oldRank := item.Rank
	removeFriend := false

	switch item.Rank {
	case BanRankTrusted, BanRankBanned: /* no-op */
	case BanRankNormal, BanRankWarn:
		if item.Score < i.ThresholdWarn {
			item.Rank = BanRankNormal
		}
		if item.Score >= i.ThresholdWarn {
			item.Rank = BanRankWarn
		}
		if item.Score >= i.ThresholdBan {
			item.Rank = BanRankBanned
			item.BanTime = now
			removeFriend = ctx != nil && ctx.EndPoint != nil && ctx.EndPoint.Platform == "QQ"
		}
		if oldRank != item.Rank {
			item.BanUpdatedAt = now
		}
	}
	item.UpdatedAt = now

	if d.DurableStore != nil {
		repository, err := newModerationBanRepository(d)
		if err == nil {
			err = repository.save(context.Background(), item)
		}
		if err != nil {
			i.itemsMu.Unlock()
			return nil, err
		}
	} else if d.DBOperator != nil {
		if err := persistSQLBanListItem(d, item); err != nil {
			i.itemsMu.Unlock()
			return nil, err
		}
		item.UpdatedAt = 0
	}
	i.Map.Store(uid, item)
	updatedItem := cloneBanListItem(item)
	i.itemsMu.Unlock()

	if removeFriend {
		if adapter, ok := ctx.EndPoint.Adapter.(interface {
			DeleteFriend(ctx *MsgContext, id string)
		}); ok {
			adapter.DeleteFriend(ctx, uid)
		} else if d.Logger != nil {
			d.Logger.Warn("当前 QQ 适配器不支持删除好友")
		}
	}
	if ctx != nil {
		// 警告: XXX 因为等行为，进入警告列表
		// 黑名单: XXX 因为等行为，进入黑名单。将作出以下惩罚：拒绝回复、拒绝邀请、退出事发群
		// TODO
		//nolint:forbidigo // that is a todo
		fmt.Println("TODO Alert")
	}
	return updatedItem, nil
}

// 返回连带责任人
func (i *BanListInfo) addJointScore(_ string, score int64, place string, reason string, ctx *MsgContext) (string, BanRankType) {
	d := i.Parent
	if i.JointScorePercentOfGroup > 0 {
		score := i.JointScorePercentOfGroup * float64(score)
		i.AddScoreBase(place, int64(score), place, reason, ctx)
	}
	if i.JointScorePercentOfInviter > 0 {
		groupInfo, ok := d.ImSession.ServiceAtNew.Load(place)
		if ok && groupInfo.InviteUserID != "" {
			rank := i.NoticeCheckPrepare(groupInfo.InviteUserID)
			score := i.JointScorePercentOfInviter * float64(score)
			i.AddScoreBase(groupInfo.InviteUserID, int64(score), place, reason, ctx)

			// text := fmt.Sprintf("提醒: 你邀请的骰子在群组<%s>中被禁言/踢出/指令刷屏了", groupInfo.GroupName)
			// ReplyPersonRaw(ctx, &Message{Sender: SenderBase{UserId: groupInfo.InviteUserId}}, text, "")
			return groupInfo.InviteUserID, rank
		}
	}
	return "", BanRankNormal
}

func (i *BanListInfo) NoticeCheckPrepare(uid string) BanRankType {
	item, ok := i.GetByID(uid)
	if ok {
		return item.Rank
	}
	return BanRankNormal
}

func (i *BanListInfo) NoticeCheck(uid string, place string, oldRank BanRankType, ctx *MsgContext) BanRankType {
	log := i.Parent.Logger
	item, ok := i.GetByID(uid)
	if !ok {
		return 0
	}

	curRank := item.Rank
	if oldRank == curRank || (curRank != BanRankWarn && curRank != BanRankBanned) {
		return 0
	}

	txt := fmt.Sprintf("黑名单等级提升: %v", item.toText(i.Parent))
	log.Info(txt)

	// If user is banned and we should quit immediately, do it first before sending notifications
	if curRank == BanRankBanned && i.BanBehaviorQuitLastPlace && ctx != nil {
		var isWhiteGroup bool
		d := ctx.Dice
		value, exists := (&d.Config).BanList.GetByID(place)
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
			ctx.Player = &GroupPlayerInfo{} // 为了能存 $t 变量，God bless this design
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
		groupInfo, ok := i.Parent.ImSession.ServiceAtNew.Load(place)
		if ok && groupInfo.InviteUserID != "" {
			VarSetValueStr(ctx, "$t事发群名", groupInfo.GroupName)
			VarSetValueStr(ctx, "$t事发群号", groupInfo.GroupID)
			text := DiceFormatTmpl(ctx, "核心:黑名单触发_邀请人")
			ReplyPersonRaw(ctx, &Message{Sender: SenderBase{UserID: groupInfo.InviteUserID}}, text, "")
		}
	}

	return 0
}

// AddScoreByGroupMuted 群组禁言
func (i *BanListInfo) AddScoreByGroupMuted(uid string, place string, ctx *MsgContext) {
	rank := i.NoticeCheckPrepare(uid)

	i.AddScoreBase(uid, i.ScoreGroupMuted, place, "禁言骰子", ctx)
	inviterID, inviterRank := i.addJointScore(uid, i.ScoreGroupMuted, place, "连带责任:禁言骰子", ctx)

	i.NoticeCheck(uid, place, rank, ctx)
	if inviterID != "" && inviterID != uid {
		// 如果连带责任人与操作者不是同一人，进行单独计算
		i.NoticeCheck(inviterID, place, inviterRank, ctx)
	}
}

// AddScoreByGroupKicked 群组踢出
func (i *BanListInfo) AddScoreByGroupKicked(uid string, place string, ctx *MsgContext) {
	rank := i.NoticeCheckPrepare(uid)

	i.AddScoreBase(uid, i.ScoreGroupKicked, place, "踢出骰子", ctx)
	inviterID, inviterRank := i.addJointScore(uid, i.ScoreGroupKicked, place, "连带责任:踢出骰子", ctx)

	i.NoticeCheck(uid, place, rank, ctx)
	if inviterID != "" && inviterID != uid {
		// 如果连带责任人与操作者不是同一人，进行单独计算
		i.NoticeCheck(inviterID, place, inviterRank, ctx)
	}
}

// AddScoreByCommandSpam 指令刷屏
func (i *BanListInfo) AddScoreByCommandSpam(uid string, place string, ctx *MsgContext) {
	rank := i.NoticeCheckPrepare(uid)

	i.AddScoreBase(uid, i.ScoreTooManyCommand, place, "指令刷屏", ctx)
	inviterID, inviterRank := i.addJointScore(uid, i.ScoreTooManyCommand, place, "连带责任:指令刷屏", ctx)

	i.NoticeCheck(uid, place, rank, ctx)
	if inviterID != "" && inviterID != uid {
		// 如果连带责任人与操作者不是同一人，进行单独计算
		i.NoticeCheck(inviterID, place, inviterRank, ctx)
	}
}

// AddScoreByCensor 敏感词审查
func (i *BanListInfo) AddScoreByCensor(uid string, score int64, place string, level string, ctx *MsgContext) {
	rank := i.NoticeCheckPrepare(uid)

	i.AddScoreBase(uid, score, place, "触发<"+level+">敏感词", ctx)
	inviterID, inviterRank := i.addJointScore(uid, score, place, "连带责任:触发<"+level+">敏感词", ctx)

	i.NoticeCheck(uid, place, rank, ctx)
	if inviterID != "" && inviterID != uid {
		// 如果连带责任人与操作者不是同一人，进行单独计算
		i.NoticeCheck(inviterID, place, inviterRank, ctx)
	}
}

func (i *BanListInfo) GetByID(uid string) (*BanListInfoItem, bool) {
	if i == nil || uid == "" {
		return nil, false
	}
	i.itemsMu.RLock()
	defer i.itemsMu.RUnlock()
	if i.Map == nil {
		return nil, false
	}
	item, ok := i.Map.Load(uid)
	if !ok || item == nil {
		return nil, false
	}
	return cloneBanListItem(item), true
}

func (i *BanListInfo) SetTrustByID(uid string, place string, reason string) {
	if err := i.SetTrustByIDWithError(uid, place, reason); err != nil && i != nil && i.Parent != nil && i.Parent.Logger != nil {
		i.Parent.Logger.Errorf("黑白名单保存失败: %v", err)
	}
}

func (i *BanListInfo) SetTrustByIDWithError(uid string, place string, reason string) error {
	if i == nil || uid == "" {
		return nil
	}
	if err := i.PersistenceError(); err != nil {
		return err
	}
	d := i.Parent
	var name string
	if d != nil && d.Parent != nil {
		name = d.Parent.TryGetUserName(uid)
		if strings.Contains(uid, "-Group:") {
			name = d.Parent.TryGetGroupName(uid)
		}
	}
	now := time.Now().Unix()

	i.itemsMu.Lock()
	if i.Map == nil {
		i.Map = new(SyncMap[string, *BanListInfoItem])
	}
	item, _ := i.Map.Load(uid)
	if item == nil {
		item = &BanListInfoItem{ID: uid}
	} else {
		item = cloneBanListItem(item)
	}
	item.Rank = BanRankTrusted
	item.Name = name
	item.Places = append(item.Places, place)
	item.Reasons = append(item.Reasons, reason)
	item.Times = append(item.Times, now)
	item.BanUpdatedAt = now
	item.UpdatedAt = now
	if d != nil && d.DurableStore != nil {
		repository, err := newModerationBanRepository(d)
		if err == nil {
			err = repository.save(context.Background(), item)
		}
		if err != nil {
			i.itemsMu.Unlock()
			return err
		}
	} else if d != nil && d.DBOperator != nil {
		if err := persistSQLBanListItem(d, item); err != nil {
			i.itemsMu.Unlock()
			return err
		}
		item.UpdatedAt = 0
	}
	i.Map.Store(uid, item)
	i.itemsMu.Unlock()
	return nil
}

func (i *BanListInfo) SetRankByID(d *Dice, uid string, rank BanRankType, name string, place string, reason string) error {
	if i == nil || uid == "" {
		return errors.New("ban list and ID are required")
	}
	if d == nil {
		d = i.Parent
	}
	if err := i.PersistenceError(); err != nil {
		return err
	}
	switch rank {
	case BanRankBanned, BanRankWarn, BanRankTrusted, BanRankNormal:
	default:
		return fmt.Errorf("invalid ban rank %d", rank)
	}

	now := time.Now().Unix()
	fallbackName := ""
	if name == "" && d != nil && d.Parent != nil {
		if strings.Contains(uid, "-Group:") {
			fallbackName = d.Parent.TryGetGroupName(uid)
		} else {
			fallbackName = d.Parent.TryGetUserName(uid)
		}
	}
	i.itemsMu.Lock()
	if i.Map == nil {
		i.Map = new(SyncMap[string, *BanListInfoItem])
	}
	item, exists := i.Map.Load(uid)
	if item == nil {
		exists = false
		item = &BanListInfoItem{ID: uid}
	} else {
		item = cloneBanListItem(item)
	}
	if name != "" {
		item.Name = name
	} else if !exists {
		item.Name = fallbackName
	}
	switch rank {
	case BanRankBanned:
		item.Rank = rank
		item.Score = i.ThresholdBan
		item.BanTime = now
	case BanRankWarn:
		item.Rank = rank
		item.Score = i.ThresholdWarn
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
	if d != nil && d.DurableStore != nil {
		repository, err := newModerationBanRepository(d)
		if err == nil {
			err = repository.save(context.Background(), item)
		}
		if err != nil {
			i.itemsMu.Unlock()
			return err
		}
	} else if d != nil && d.DBOperator != nil {
		if err := persistSQLBanListItem(d, item); err != nil {
			i.itemsMu.Unlock()
			return err
		}
		item.UpdatedAt = 0
	}
	i.Map.Store(uid, item)
	i.itemsMu.Unlock()
	return nil
}

func (i *BanListInfo) ImportItems(d *Dice, items []*BanListInfoItem) error {
	if i == nil {
		return errors.New("ban list is unavailable")
	}
	if d == nil {
		d = i.Parent
	}
	if err := i.PersistenceError(); err != nil {
		return err
	}
	now := time.Now().Unix()
	imported := make([]*BanListInfoItem, len(items))
	for index, item := range items {
		if item == nil || item.ID == "" {
			return errors.New("ban list item ID is required")
		}
		imported[index] = cloneBanListItem(item)
		imported[index].UpdatedAt = now
		if imported[index].BanUpdatedAt == 0 {
			imported[index].BanUpdatedAt = now
		}
	}

	var repository *moderationBanRepository
	if d != nil && d.DurableStore != nil {
		var err error
		repository, err = newModerationBanRepository(d)
		if err != nil {
			return err
		}
	}
	i.itemsMu.Lock()
	if i.Map == nil {
		i.Map = new(SyncMap[string, *BanListInfoItem])
	}
	for _, item := range imported {
		if repository != nil {
			item.EventStoreVersion = 0
			if current, ok := i.Map.Load(item.ID); ok && current != nil {
				item.EventStoreVersion = current.EventStoreVersion
			}
			if err := repository.save(context.Background(), item); err != nil {
				i.itemsMu.Unlock()
				return err
			}
		} else if d != nil && d.DBOperator != nil {
			if err := persistSQLBanListItem(d, item); err != nil {
				i.itemsMu.Unlock()
				return err
			}
			item.UpdatedAt = 0
		}
		i.Map.Store(item.ID, item)
	}
	i.itemsMu.Unlock()
	return nil
}

func (d *Dice) GetBanList() []*BanListInfoItem {
	if d == nil || d.Config.BanList == nil {
		return []*BanListInfoItem{}
	}
	if d.DurableStore != nil || d.DBOperator == nil {
		return d.Config.BanList.snapshot()
	}
	var list []*BanListInfoItem
	_ = service.BanItemList(d.DBOperator, func(id string, banUpdatedAt int64, data []byte) {
		var item BanListInfoItem
		if err := json.Unmarshal(data, &item); err != nil {
			item = BanListInfoItem{}
		}
		item.ID = id
		item.BanUpdatedAt = banUpdatedAt
		list = append(list, &item)
	})
	return list
}

func persistSQLBanListItem(d *Dice, item *BanListInfoItem) error {
	if d == nil || d.DBOperator == nil || item == nil || item.ID == "" {
		return errors.New("ban list SQL persistence is unavailable")
	}
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return service.BanItemSave(d.DBOperator, item.ID, item.UpdatedAt, item.BanUpdatedAt, data)
}

func (i *BanListInfo) SaveChanged(d *Dice) {
	if err := i.SaveChangedWithError(d); err != nil && d != nil && d.Logger != nil {
		d.Logger.Errorf("黑白名单保存失败: %v", err)
	}
}

func (i *BanListInfo) SaveChangedWithError(d *Dice) error {
	if i == nil {
		return nil
	}
	if d == nil {
		d = i.Parent
	}
	if d == nil {
		return nil
	}
	if d.DurableStore != nil {
		return i.PersistenceError()
	}
	if d.DBOperator == nil {
		return nil
	}
	i.itemsMu.Lock()
	defer i.itemsMu.Unlock()
	if i.Map == nil {
		return nil
	}
	var saveErr error
	i.Map.Range(func(id string, item *BanListInfoItem) bool {
		if item == nil || item.UpdatedAt == 0 {
			return true
		}
		data, err := json.Marshal(item)
		if err == nil {
			err = service.BanItemSave(d.DBOperator, id, item.UpdatedAt, item.BanUpdatedAt, data)
		}
		if err != nil {
			saveErr = errors.Join(saveErr, err)
			return true
		}
		item.UpdatedAt = 0
		return true
	})
	return saveErr
}

func (i *BanListInfo) DeleteByID(d *Dice, id string) {
	if err := i.DeleteByIDWithError(d, id); err != nil && d != nil && d.Logger != nil {
		d.Logger.Errorf("黑白名单删除失败: %v", err)
	}
}

func (i *BanListInfo) DeleteByIDWithError(d *Dice, id string) error {
	if i == nil || id == "" {
		return nil
	}
	if d == nil {
		d = i.Parent
	}
	if err := i.PersistenceError(); err != nil && d != nil && d.DurableStore != nil {
		return err
	}
	if d != nil && d.DurableStore != nil {
		repository, err := newModerationBanRepository(d)
		if err != nil {
			return err
		}
		i.itemsMu.Lock()
		defer i.itemsMu.Unlock()
		item := &BanListInfoItem{ID: id}
		if i.Map != nil {
			if current, ok := i.Map.Load(id); ok && current != nil {
				item = cloneBanListItem(current)
			}
		}
		if err = repository.delete(context.Background(), item); err != nil {
			return err
		}
		if i.Map != nil {
			i.Map.Delete(id)
		}
		return nil
	}
	if d != nil && d.DBOperator != nil {
		i.itemsMu.Lock()
		defer i.itemsMu.Unlock()
		if err := service.BanItemDel(d.DBOperator, id); err != nil {
			return err
		}
		if i.Map != nil {
			i.Map.Delete(id)
		}
		return nil
	}
	i.itemsMu.Lock()
	if i.Map != nil {
		i.Map.Delete(id)
	}
	i.itemsMu.Unlock()
	return nil
}
