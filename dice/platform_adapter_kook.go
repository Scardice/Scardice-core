package dice

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lonelyevil/kook"
	"github.com/lonelyevil/kook/log_adapter/plog"
	kooklog "github.com/phuslu/log"
	"github.com/yuin/goldmark"
	"go.uber.org/zap"

	"Scardice-core/logger"
	"Scardice-core/message"
)

// ConsoleWriterShutUp Kook go的作者要求必须使用他们自己的logger用于构造Intent Session，并且该logger不可缺省，因此这里重新实现一个不干活的logger以保证控制台log的干净整洁
type ConsoleWriterShutUp struct {
	*kooklog.ConsoleWriter
}

func (c *ConsoleWriterShutUp) Close() (err error)                       { return nil }
func (c *ConsoleWriterShutUp) WriteEntry(_ *kooklog.Entry) (int, error) { return 0, nil }

// kook go的鉴权目前并不好用，这里重写一遍
const (
	RolePermissionAdmin                  kook.RolePermission = 1 << iota
	RolePermissionManageGuild            kook.RolePermission = 1 << 1
	RolePermissionViewAuditLog           kook.RolePermission = 1 << 2
	RolePermissionCreateInvite           kook.RolePermission = 1 << 3
	RolePermissionManageInvite           kook.RolePermission = 1 << 4
	RolePermissionManageChannel          kook.RolePermission = 1 << 5
	RolePermissionKickUser               kook.RolePermission = 1 << 6
	RolePermissionBanUser                kook.RolePermission = 1 << 7
	RolePermissionManageGuildEmoji       kook.RolePermission = 1 << 8
	RolePermissionChangeNickname         kook.RolePermission = 1 << 9
	RolePermissionManageRolePermission   kook.RolePermission = 1 << 10
	RolePermissionViewChannel            kook.RolePermission = 1 << 11
	RolePermissionSendMessage            kook.RolePermission = 1 << 12
	RolePermissionManageMessage          kook.RolePermission = 1 << 13
	RolePermissionUploadFile             kook.RolePermission = 1 << 14
	RolePermissionConnectVoice           kook.RolePermission = 1 << 15
	RolePermissionManageVoice            kook.RolePermission = 1 << 16
	RolePermissionMentionEveryone        kook.RolePermission = 1 << 17
	RolePermissionCreateReaction         kook.RolePermission = 1 << 18
	RolePermissionFollowReaction         kook.RolePermission = 1 << 19
	RolePermissionInvitedToVoice         kook.RolePermission = 1 << 20
	RolePermissionForceManualVoice       kook.RolePermission = 1 << 21
	RolePermissionFreeVoice              kook.RolePermission = 1 << 22
	RolePermissionVoice                  kook.RolePermission = 1 << 23
	RolePermissionManageUserVoiceReceive kook.RolePermission = 1 << 24
	RolePermissionManageUserVoiceCreate  kook.RolePermission = 1 << 25
	RolePermissionManageNickname         kook.RolePermission = 1 << 26
	RolePermissionPlayMusic              kook.RolePermission = 1 << 27
)

// RolePermissionAll 有两种情况会使一个用户拥有一个服务器内的所有权限，第一种是作为服务器创建者的用户，即Owner，第二种是被授予了Admin权限的用户
// 但是尽管他们可以bypass所有的权限检查，但是他们自身并不一定拥有所有的权限，这导致检查时会出现问题，因此这里创建一个permissionAll权限，
// 并把Admin和Owner当作拥有该权限的用户进行处理
const (
	RolePermissionAll = RolePermissionAdmin |
		RolePermissionManageGuild |
		RolePermissionViewAuditLog |
		RolePermissionCreateInvite |
		RolePermissionManageInvite |
		RolePermissionManageChannel |
		RolePermissionKickUser |
		RolePermissionBanUser |
		RolePermissionManageGuildEmoji |
		RolePermissionChangeNickname |
		RolePermissionManageRolePermission |
		RolePermissionViewChannel |
		RolePermissionSendMessage |
		RolePermissionManageMessage |
		RolePermissionUploadFile |
		RolePermissionConnectVoice |
		RolePermissionManageVoice |
		RolePermissionMentionEveryone |
		RolePermissionCreateReaction |
		RolePermissionFollowReaction |
		RolePermissionInvitedToVoice |
		RolePermissionForceManualVoice |
		RolePermissionFreeVoice |
		RolePermissionVoice |
		RolePermissionManageUserVoiceReceive |
		RolePermissionManageUserVoiceCreate |
		RolePermissionManageNickname |
		RolePermissionPlayMusic
)

type CardMessage struct {
	Type    string        `json:"type"`
	Modules []interface{} `json:"modules"`
	Theme   string        `json:"theme"`
	Size    string        `json:"size"`
}

type CardMessageModuleText struct {
	Type string `json:"type"`
	Text struct {
		Content string `json:"content"`
		Type    string `json:"type"`
	} `json:"text"`
}

type CardMessageModuleImage struct {
	Type     string `json:"type"`
	Elements []struct {
		Type string `json:"type"`
		Src  string `json:"src"`
	} `json:"elements"`
}

type CardMessageModuleFile struct {
	Type  string `json:"type"`
	Title string `json:"title"`
	Src   string `json:"src"`
	// Size  string `json:"size"`
}

const (
	// 管理员/服务器信息缓存用于避免每条 KOOK 消息都同步调用 UserView/GuildView。
	// 权限变更最多延迟一个 TTL，换取回复路径不再被 REST 往返阻塞。
	kookAdminCacheTTL        = 2 * time.Minute
	kookGuildCacheTTL        = 5 * time.Minute
	kookAdminErrorCacheTTL   = 15 * time.Second
	kookGuildErrorCacheTTL   = 15 * time.Second
	kookAdminCacheMaxEntries = 4096
	kookGuildCacheMaxEntries = 1024
)

type kookAdminCacheEntry struct {
	admin     bool
	expiresAt time.Time
}

type kookGuildCacheEntry struct {
	guild     *kook.Guild
	expiresAt time.Time
}

// PlatformAdapterKook 与 PlatformAdapterDiscord 基本相同的实现，因此不详细写注释了，可以去参考隔壁的实现
type PlatformAdapterKook struct {
	Token         string        `json:"-"     yaml:"token"`
	EndPoint      *EndPointInfo `json:"-"     yaml:"-"`
	IntentSession *kook.Session `json:"-"     yaml:"-"`

	sessionMu sync.Mutex
	// serving 防止并发 Serve 启动两套连接；会话被清空/禁用时复位。
	serving bool

	adminCacheMu sync.Mutex
	adminCache   map[string]kookAdminCacheEntry
	guildCacheMu sync.Mutex
	guildCache   map[string]kookGuildCacheEntry

	// resumeStateMu 串行化 resume 文件的写入/删除，避免用户禁用后
	// 后台定时保存又把旧状态写回去。
	resumeStateMu sync.Mutex

	// handlerMu 跨 Session 串行化 handler。禁用后立即启用会创建新 Session，
	// 仅靠 Session 内部的锁无法阻止旧会话的迟到命令并发修改数据。
	handlerMu sync.Mutex
}

// getSession 返回当前会话快照。会话可能在发送/重连过程中被启用、禁用或替换，
// 所有访问都必须经过这里，避免读到半更新的指针。
func (pa *PlatformAdapterKook) getSession() *kook.Session {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	return pa.IntentSession
}

// endpointSnapshot 在同一把锁内读取发送所需的端点状态/身份，
// 避免禁用、重登时读到半更新的 Enable/State/Nickname/UserID。
func (pa *PlatformAdapterKook) endpointSnapshot() (bool, EndpointState, string, string) {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	if pa.EndPoint == nil {
		return false, StateDisconnected, "", ""
	}
	return pa.EndPoint.Enable, pa.EndPoint.State, pa.EndPoint.UserID, pa.EndPoint.Nickname
}

func (pa *PlatformAdapterKook) setSession(session *kook.Session) {
	pa.sessionMu.Lock()
	pa.IntentSession = session
	pa.sessionMu.Unlock()
	pa.clearPermissionCaches()
}

func (pa *PlatformAdapterKook) clearPermissionCaches() {
	pa.adminCacheMu.Lock()
	pa.adminCache = nil
	pa.adminCacheMu.Unlock()
	pa.guildCacheMu.Lock()
	pa.guildCache = nil
	pa.guildCacheMu.Unlock()
}

const kookResumeStateFileName = "kook_resume.json"

type kookResumeFile struct {
	Gateway   string `json:"gateway"`
	SessionID string `json:"session_id"`
	SN        int64  `json:"sn"`
	TokenHash string `json:"token_hash"`
	SavedAt   int64  `json:"saved_at"`
}

func (pa *PlatformAdapterKook) kookTokenHash() string {
	// 与 kook.New 写入 Identify.Token 的格式保持一致。
	sum := sha256.Sum256([]byte("Bot " + pa.Token))
	return fmt.Sprintf("%x", sum[:])
}

func kookSessionTokenHash(session *kook.Session) string {
	if session == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(session.Identify.Token))
	return fmt.Sprintf("%x", sum[:])
}

func (pa *PlatformAdapterKook) resumeStatePath() string {
	if pa.EndPoint == nil || strings.TrimSpace(pa.EndPoint.RelWorkDir) == "" {
		return ""
	}
	return filepath.Join(pa.EndPoint.RelWorkDir, kookResumeStateFileName)
}

// restoreKookResumeState 在首次 Open 前恢复上次进程留下的 session/sn。
// 网关/session 过期时 resume 会失败，SDK 会自动转新 session。
func (pa *PlatformAdapterKook) restoreKookResumeState(session *kook.Session) {
	pa.resumeStateMu.Lock()
	defer pa.resumeStateMu.Unlock()
	path := pa.resumeStatePath()
	if path == "" {
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var state kookResumeFile
	if err := json.Unmarshal(data, &state); err != nil {
		return
	}
	// token 变化后旧 gateway/session 可能属于另一个机器人，不能恢复。
	if state.TokenHash == "" || state.TokenHash != pa.kookTokenHash() {
		return
	}
	session.RestoreResumeState(kook.ResumeState{
		// 不恢复文件里的旧网关地址：可能已过期，且旧格式文件可能带 token。
		// Open 会通过 REST 重新获取当前 gateway，再附加 resume 参数。
		Gateway:   "",
		SessionID: strings.TrimSpace(state.SessionID),
		SN:        state.SN,
	})
}

// sanitizeKookGatewayURL 去掉 gateway URL 中的查询参数。KOOK 返回的 gateway
// 地址带 token=，直接写入 resume 文件会泄露凭据；这里只保留 scheme/host/path，
// 恢复时再通过 REST 重新获取带 token 的新地址。
func sanitizeKookGatewayURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	u.RawQuery = ""
	u.Fragment = ""
	u.User = nil
	return u.String()
}

// writeKookResumeFileNoSync 原子替换 resume 文件，但不做 fsync。
// 这个快照在每个 sn 前进后同步写入，逐事件刷盘会明显拖慢事件处理；
// 进程崩溃时页缓存仍在，最坏情况只是断电时回退几秒进度，
// 重复事件由 resume 重放承担。
func writeKookResumeFileNoSync(path string, data []byte) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmp, err := os.CreateTemp(dir, "."+base+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

func (pa *PlatformAdapterKook) saveKookResumeState(session *kook.Session) {
	if session == nil {
		return
	}
	pa.resumeStateMu.Lock()
	defer pa.resumeStateMu.Unlock()
	if !pa.isCurrentSession(session) || session.IsClosed() {
		return
	}
	state := session.ResumeState()
	if state.SessionID == "" {
		return
	}
	path := pa.resumeStatePath()
	if path == "" {
		return
	}
	payload, err := json.Marshal(kookResumeFile{
		// gateway 只保存去掉查询参数的主机/路径，恢复时重新获取带 token 的地址。
		Gateway:   sanitizeKookGatewayURL(state.Gateway),
		SessionID: state.SessionID,
		SN:        state.SN,
		TokenHash: kookSessionTokenHash(session),
		SavedAt:   time.Now().Unix(),
	})
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	_ = writeKookResumeFileNoSync(path, payload)
}

func (pa *PlatformAdapterKook) clearKookResumeState() {
	pa.resumeStateMu.Lock()
	defer pa.resumeStateMu.Unlock()
	path := pa.resumeStatePath()
	if path != "" {
		_ = os.Remove(path)
	}
}

// persistKookResumeState 定期保存 sn；进程异常退出时最多丢 5 秒的进度，
// 重启后 resume 会从较早的 sn 开始补发，重复事件由 sn 去重吸收。
func (pa *PlatformAdapterKook) persistKookResumeState(session *kook.Session) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !pa.isCurrentSession(session) || session.IsClosed() {
			return
		}
		pa.saveKookResumeState(session)
	}
}

// clearSessionIf 只在当前会话仍是 session 时清空，返回是否由本次调用清空。
// 这是防止旧 Serve/DoRelogin 协程误清掉新会话的关键。
func (pa *PlatformAdapterKook) clearSessionIf(session *kook.Session) bool {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	if pa.IntentSession != session {
		return false
	}
	pa.IntentSession = nil
	pa.serving = false
	return true
}

func (pa *PlatformAdapterKook) isCurrentSession(session *kook.Session) bool {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	return session != nil && pa.IntentSession == session
}

// isServingSession 同时确认会话仍是当前会话且没有被禁用/重登取消。
func (pa *PlatformAdapterKook) isServingSession(session *kook.Session) bool {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	return session != nil && pa.serving && pa.IntentSession == session
}

// setSessionStateIfCurrent 把“确认仍是当前会话”和“写端点状态”放在同一把锁里，
// 避免旧 Serve/fatal 协程在新会话接管后把状态改回离线/失败。
func (pa *PlatformAdapterKook) setSessionStateIfCurrent(session *kook.Session, enable bool, state EndpointState) bool {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	if session == nil || pa.IntentSession != session {
		return false
	}
	if pa.EndPoint != nil {
		pa.EndPoint.Enable = enable
		pa.EndPoint.State = state
	}
	return true
}

func (pa *PlatformAdapterKook) setEndpointState(enable bool, state EndpointState) {
	pa.sessionMu.Lock()
	if pa.EndPoint != nil {
		pa.EndPoint.Enable = enable
		pa.EndPoint.State = state
	}
	pa.sessionMu.Unlock()
}

func (pa *PlatformAdapterKook) setEndpointStateIfIdle(enable bool, state EndpointState) bool {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	if pa.IntentSession != nil {
		return false
	}
	if pa.EndPoint != nil {
		pa.EndPoint.Enable = enable
		pa.EndPoint.State = state
	}
	return true
}

// clearSessionAndSetState 原子地清空当前会话并写入最终状态，返回是否由本次调用完成。
func (pa *PlatformAdapterKook) clearSessionAndSetState(session *kook.Session, enable bool, state EndpointState) bool {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	if session == nil || pa.IntentSession != session {
		return false
	}
	pa.IntentSession = nil
	pa.serving = false
	if pa.EndPoint != nil {
		pa.EndPoint.Enable = enable
		pa.EndPoint.State = state
	}
	pa.clearPermissionCaches()
	return true
}

// applyIdentityIfCurrent 防止旧会话在 UserMe 返回后覆盖新会话的身份字段。
func (pa *PlatformAdapterKook) applyIdentityIfCurrent(session *kook.Session, self *kook.User) bool {
	pa.sessionMu.Lock()
	defer pa.sessionMu.Unlock()
	if session == nil || pa.IntentSession != session || self == nil || pa.EndPoint == nil {
		return false
	}
	pa.EndPoint.Nickname = self.Nickname
	pa.EndPoint.UserID = FormatDiceIDKook(self.ID)
	return true
}

func (pa *PlatformAdapterKook) saveState() {
	if pa.EndPoint == nil || pa.EndPoint.Session == nil || pa.EndPoint.Session.Parent == nil {
		return
	}
	d := pa.EndPoint.Session.Parent
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
}

const kookUserMeMaxAttempts = 3

// fetchKookSelf 对 UserMe 做有限重试：REST 短暂抖动不应该直接禁用端点。
// 每次重试前后都检查会话所有权，用户禁用/重登时立即退出。
func (pa *PlatformAdapterKook) fetchKookSelf(s *kook.Session, log *zap.SugaredLogger) (*kook.User, error) {
	var lastErr error
	for attempt := 0; attempt < kookUserMeMaxAttempts; attempt++ {
		if !pa.isCurrentSession(s) {
			return nil, errors.New("KOOK 会话已被替换")
		}
		self, err := s.UserMe()
		if err == nil && self != nil {
			return self, nil
		}
		lastErr = err
		if lastErr == nil {
			lastErr = errors.New("UserMe 返回空账号")
		}
		if attempt+1 < kookUserMeMaxAttempts {
			log.Warnf("获取KOOK账号信息失败，准备重试(%d/%d): %v", attempt+1, kookUserMeMaxAttempts, lastErr)
			time.Sleep(time.Second)
		}
	}
	return nil, lastErr
}

func (pa *PlatformAdapterKook) cachedGuildAdmin(key string) (bool, bool) {
	pa.adminCacheMu.Lock()
	defer pa.adminCacheMu.Unlock()
	entry, ok := pa.adminCache[key]
	if !ok || time.Now().After(entry.expiresAt) {
		if ok {
			delete(pa.adminCache, key)
		}
		return false, false
	}
	return entry.admin, true
}

func (pa *PlatformAdapterKook) storeGuildAdmin(key string, admin bool) {
	pa.storeGuildAdminTTL(key, admin, kookAdminCacheTTL)
}

func (pa *PlatformAdapterKook) storeGuildAdminTTL(key string, admin bool, ttl time.Duration) {
	pa.adminCacheMu.Lock()
	defer pa.adminCacheMu.Unlock()
	if pa.adminCache == nil {
		pa.adminCache = make(map[string]kookAdminCacheEntry, kookAdminCacheMaxEntries)
	}
	if len(pa.adminCache) >= kookAdminCacheMaxEntries {
		now := time.Now()
		for cacheKey, entry := range pa.adminCache {
			if now.After(entry.expiresAt) {
				delete(pa.adminCache, cacheKey)
			}
		}
		if len(pa.adminCache) >= kookAdminCacheMaxEntries {
			// 仍然满员说明活跃用户极多；整体重置比每条消息做 LRU 更简单。
			pa.adminCache = make(map[string]kookAdminCacheEntry, kookAdminCacheMaxEntries)
		}
	}
	pa.adminCache[key] = kookAdminCacheEntry{
		admin:     admin,
		expiresAt: time.Now().Add(ttl),
	}
}

func (pa *PlatformAdapterKook) cachedGuild(session *kook.Session, guildID string) *kook.Guild {
	now := time.Now()
	pa.guildCacheMu.Lock()
	entry, ok := pa.guildCache[guildID]
	pa.guildCacheMu.Unlock()
	if ok && now.Before(entry.expiresAt) {
		// guild == nil 表示 15 秒内的负缓存，避免 REST 故障时每条消息重复请求。
		return entry.guild
	}
	guild, err := session.GuildView(guildID)
	pa.guildCacheMu.Lock()
	if pa.guildCache == nil {
		pa.guildCache = make(map[string]kookGuildCacheEntry, kookGuildCacheMaxEntries)
	}
	if len(pa.guildCache) >= kookGuildCacheMaxEntries {
		for cacheKey, cacheEntry := range pa.guildCache {
			if now.After(cacheEntry.expiresAt) {
				delete(pa.guildCache, cacheKey)
			}
		}
		if len(pa.guildCache) >= kookGuildCacheMaxEntries {
			pa.guildCache = make(map[string]kookGuildCacheEntry, kookGuildCacheMaxEntries)
		}
	}
	if err != nil || guild == nil {
		pa.guildCache[guildID] = kookGuildCacheEntry{expiresAt: now.Add(kookGuildErrorCacheTTL)}
		pa.guildCacheMu.Unlock()
		return nil
	}
	pa.guildCache[guildID] = kookGuildCacheEntry{guild: guild, expiresAt: now.Add(kookGuildCacheTTL)}
	pa.guildCacheMu.Unlock()
	return guild
}

// handleKookFatal 由 SDK 在后台重连遇到不可恢复的认证错误时调用。
func (pa *PlatformAdapterKook) handleKookFatal(session *kook.Session, err error) {
	log := zap.S().Named(logger.LogKeyAdapter)
	log.Errorf("KOOK 连接不可恢复，已停止自动重连: %v", err)
	if !pa.clearSessionAndSetState(session, false, StateConnectionFailed) {
		// 会话已被新连接替换；旧 session 仍需关闭，避免残留连接。
		if session != nil {
			_ = session.Close()
		}
		return
	}
	pa.saveState()
	_ = session.Close()
	pa.clearKookResumeState()
}

// recoverKookEvent 隔离事件处理中的 panic，避免 SDK 回调协程把整个进程带崩。
func (pa *PlatformAdapterKook) recoverKookEvent(log *zap.SugaredLogger, eventName string) {
	if r := recover(); r != nil {
		log.Errorf("KOOK %s 事件处理异常: %v 堆栈: %v", eventName, r, string(debug.Stack()))
	}
}

func (pa *PlatformAdapterKook) GetGroupInfoAsync(groupID string) {
	// 极罕见情况下，未连接成功或被禁用的Endpoint也会去call GetGroupInfoAsync，并且由于IntentSession并未被实例化而抛出nil错误，因此这里做一个检查
	session := pa.getSession()
	if session == nil {
		return
	}
	logger := pa.EndPoint.Session.Parent.Logger
	dm := pa.EndPoint.Session.Parent.Parent
	go pa.updateChannelNum()
	channel, err := session.ChannelView(ExtractKookChannelID(groupID))
	if err != nil {
		logger.Errorf("获取Kook频道信息#%s时出错:%s", groupID, err.Error())
		return
	}
	dm.GroupNameCache.Store(groupID, &GroupNameCacheItem{
		Name: channel.Name,
		time: time.Now().Unix(),
	})
	groupInfo, ok := pa.EndPoint.Session.ServiceAtNew.Load(groupID)
	if ok {
		if channel.Name != groupInfo.GroupName {
			groupInfo.GroupName = channel.Name
			groupInfo.MarkDirty(pa.EndPoint.Session.Parent)
		}
	}
}

func (pa *PlatformAdapterKook) updateChannelNum() {
	session := pa.getSession()
	if session == nil {
		return
	}
	page := new(kook.PageSetting)
	guilds, _, _ := session.GuildList(page)
	groupNum := 0
	// guilds是bot加入的服务器list，channels是每个服务器里的频道（有权限访问的）
	for _, guild := range guilds {
		groupNum += len(guild.Channels)
	}
	pa.EndPoint.GroupNum = int64(groupNum)
}

func (pa *PlatformAdapterKook) updateGameStatus() {
	logger := pa.EndPoint.Session.Parent.Logger
	session := pa.getSession()
	if session == nil {
		return
	}
	// 注释掉的部分是遗留代码，用于在kook中注册一个叫做Scardice的GameStatus，只需要执行一次因此注释掉
	// gameupdate := new(kook.GameUpdate)
	// gameupdate.ID = int64(768222)
	// gameupdate.Icon = "https://img.kookapp.cn/assets/2022-12/DfYli1buyO0e80c0.png"
	// gameupdate.Name = "Scardice"
	// _, _ = pa.IntentSession.GameUpdate(gameupdate)
	err := session.GameActivity(int64(768222))
	if err != nil {
		logger.Errorf("更新游戏状态时出错:%s", err.Error())
		return
	}
}

func (pa *PlatformAdapterKook) Serve() int {
	log := zap.S().Named(logger.LogKeyAdapter)

	pa.sessionMu.Lock()
	if pa.serving || pa.IntentSession != nil {
		pa.sessionMu.Unlock()
		log.Info("KOOK serve already running, skip duplicate Serve")
		return 0
	}
	pa.serving = true
	pa.sessionMu.Unlock()

	// 不喜欢太安静的控制台可以把ConsoleWriterShutUp换成kooklog.ConsoleWriter
	l := kooklog.Logger{
		Level:  kooklog.TraceLevel,
		Writer: &ConsoleWriterShutUp{},
	}
	s := kook.New(pa.Token, plog.NewLogger(&l))
	// 与当前/旧 Session 共用一把 handler 锁，禁用→启用期间旧命令不会和新命令并发。
	s.SetHandlerLock(&pa.handlerMu)
	pa.restoreKookResumeState(s)
	s.AddHandler(func(ctx *kook.KmarkdownMessageContext) {
		defer pa.recoverKookEvent(log, "KMarkdown")
		if ctx.Extra.Author.Bot {
			return
		}
		if ctx.Common.Type == kook.MessageTypeKMarkdown || ctx.Common.Type == kook.MessageTypeImage {
			msg := pa.toStdMessage(ctx)
			if msg == nil {
				return
			}
			pa.EndPoint.Session.Execute(pa.EndPoint, msg, false)
			return
		}
	})
	s.AddHandler(func(ctx *kook.ImageMessageContext) {
		defer pa.recoverKookEvent(log, "Image")
		if ctx.Extra.Author.Bot {
			return
		}
		msg := new(Message)
		msg.Time = ctx.Common.MsgTimestamp
		msg.RawID = ctx.Common.MsgID
		msg.Platform = "KOOK"
		send := new(SenderBase)
		send.UserID = FormatDiceIDKook(ctx.Common.AuthorID)
		send.Nickname = ctx.Extra.Author.Nickname
		if ctx.Common.ChannelType == "PERSON" {
			msg.MessageType = "private"
		} else {
			msg.MessageType = "group"
			msg.GroupID = FormatDiceIDKookChannel(ctx.Common.TargetID)
			msg.GuildID = FormatDiceIDKookGuild(ctx.Extra.GuildID)
			// if pa.checkIfGuildAdmin(ctx) {
			//	send.GroupRole = "admin"
			// }
		}
		msg.Message = fmt.Sprintf("[CQ:image,file=someimage,url=%s]", ctx.Common.Content)
		msg.Sender = *send
		pa.EndPoint.Session.Execute(pa.EndPoint, msg, false)
	})
	s.AddHandler(func(ctx *kook.MessageDeleteContext) {
		defer pa.recoverKookEvent(log, "MessageDelete")
		msg := new(Message)
		msg.Time = ctx.Common.MsgTimestamp
		msg.RawID = ctx.Extra.MsgID
		msg.GroupID = FormatDiceIDKookChannel(ctx.Extra.ChannelID)
		msg.Sender.UserID = FormatDiceIDKook(ctx.Common.AuthorID)
		msg.Sender.Nickname = "系统"
		if ctx.Common.ChannelType == "PERSON" {
			msg.MessageType = "private"
		} else {
			msg.MessageType = "group"
		}
		mctx := &MsgContext{Session: pa.EndPoint.Session, EndPoint: pa.EndPoint, Dice: pa.EndPoint.Session.Parent, MessageType: msg.MessageType}
		// pa.EndPoint.Session.Parent.Logger.Infof("删除信息#%s(%s)", msg.RawId, msg.GroupId)
		pa.EndPoint.Session.OnMessageDeleted(mctx, msg)
	})

	s.AddHandler(func(ctx *kook.BotJoinContext) {
		defer pa.recoverKookEvent(log, "BotJoin")
		msg := new(Message)
		msg.Time = ctx.Common.MsgTimestamp
		msg.RawID = ctx.Common.MsgID
		msg.Platform = "KOOK"

		guild, err := s.GuildView(ctx.Extra.GuildID)
		if err != nil {
			log.Errorf("无法获取服务器信息，跳过入群致辞")
			return
		}

		msg.GuildID = FormatDiceIDKookGuild(ctx.Extra.GuildID)
		// WelcomeChannel 是发送“xxx加入群组”消息的频道，DefaultChannel 是加入后第一个看到的频道
		// 这两个可能都为空
		if guild.WelcomeChannelID != "" {
			msg.GroupID = FormatDiceIDKookChannel(guild.WelcomeChannelID)
		} else if guild.DefaultChannelID != "" {
			msg.GroupID = FormatDiceIDKookChannel(guild.DefaultChannelID)
		}

		// 如果获取不到默认频道的话，入群致辞和 OnGuildJoined 基本上没什么意义
		if msg.GroupID == "" {
			return
		}

		msg.Sender.UserID = FormatDiceIDKook(ctx.Common.AuthorID)
		msg.Sender.Nickname = "系统"
		if ctx.Common.ChannelType == "PERSON" {
			msg.MessageType = "private"
		} else {
			msg.MessageType = "group"
		}

		mctx := &MsgContext{Session: pa.EndPoint.Session, EndPoint: pa.EndPoint, Dice: pa.EndPoint.Session.Parent, MessageType: msg.MessageType}
		pa.GetGroupInfoAsync(msg.GroupID)
		go func() {
			defer func() {
				if r := recover(); r != nil {
					log.Errorf("入群致辞异常: %v 堆栈: %v", r, string(debug.Stack()))
				}
			}()

			// 稍作等待后发送入群致词
			time.Sleep(1 * time.Second)

			mctx.Player = &GroupPlayerInfo{}
			log.Infof("发送入群致辞，群: <%s>(%s)", guild.Name, msg.GuildID)
			text := DiceFormatTmpl(mctx, "核心:骰子进群")
			ReplyGroup(mctx, msg, text)
		}()

		// 此时 ServiceAtNew 中这个频道一般为空，照 im_session.go 中的方法处理
		// Pinenutn: 不清楚此处的逻辑，修改为Exists检查
		// channel, ok := mctx.Session.ServiceAtNew.Load(msg.GroupID)
		ok := mctx.Session.ServiceAtNew.Exists(msg.GroupID)
		if !ok {
			channel := SetBotOnAtGroup(mctx, msg.GroupID)
			channel.Active = true
			_, _, selfID, _ := pa.endpointSnapshot()
			channel.DiceIDExistsMap.Store(selfID, true)
			now := time.Now().Unix()
			channel.UpdatedAtTime = now
			channel.EnteredTime = now
			mctx.Session.ServiceAtNew.Store(msg.GroupID, channel)
		}

		if groupInfo, ok := mctx.Session.ServiceAtNew.Load(msg.GroupID); ok {
			groupInfo.TriggerExtHook(mctx.Dice, func(ext *ExtInfo) func() {
				if ext.OnGuildJoined == nil {
					return nil
				}
				return func() { ext.OnGuildJoined(mctx, msg) }
			})
		}
	})

	s.AddHandler(func(ctx *kook.MessageUpdateContext) {
		defer pa.recoverKookEvent(log, "MessageUpdate")
		msg := new(Message)
		msg.Time = ctx.Extra.UpdatedAt.ToTime().Unix() // secs
		msg.RawID = ctx.Extra.MsgID
		msg.Message = ctx.Extra.Content
		msg.Platform = "KOOK"
		if ctx.Common.ChannelType == "PERSON" {
			msg.MessageType = "private"
		} else {
			msg.MessageType = "group"
		}
		msg.GroupID = FormatDiceIDKookChannel(ctx.Extra.ChannelID)
		msg.GuildID = FormatDiceIDKookGuild(ctx.Common.TargetID)

		mctx := &MsgContext{
			Session:     pa.EndPoint.Session,
			EndPoint:    pa.EndPoint,
			Dice:        pa.EndPoint.Session.Parent,
			MessageType: msg.MessageType,
			Player:      &GroupPlayerInfo{},
		}
		pa.EndPoint.Session.OnMessageEdit(mctx, msg)
	})

	// 先取账号身份，再 Open。KOOK 的 REST UserMe 不依赖 WebSocket；
	// 这样 Open 刚开始推送事件时，EndPoint.UserID 已经是可用的，
	// 不会出现“能回复但自我 @ 识别使用空 UserID”的窗口。
	pa.setSession(s)
	if !pa.isServingSession(s) {
		// 启动期间被禁用/重登：不要继续拉连接或覆盖端点状态。
		_ = s.Close()
		return 0
	}
	go pa.persistKookResumeState(s)
	// 每处理完一个 sn 就同步保存 resume 快照，避免进程退出后从旧快照
	// 重放已经执行过的命令。5 秒 ticker 仍保留作为兜底。
	s.SetSnPersistHandler(func() {
		pa.saveKookResumeState(s)
	})
	s.SetFatalHandler(func(fatalErr error) {
		pa.handleKookFatal(s, fatalErr)
	})
	s.SetReconnectHandler(func() {
		if pa.setSessionStateIfCurrent(s, true, StateConnected) {
			pa.saveKookResumeState(s)
			pa.saveState()
		}
	})
	self, err := pa.fetchKookSelf(s, log)
	if err != nil || self == nil {
		log.Errorf("获取KOOK账号信息失败:%v", err)
		if !pa.clearSessionAndSetState(s, false, StateConnectionFailed) {
			// 用户已禁用，或新的 Serve 已经接管；旧协程不能覆盖新状态。
			_ = s.Close()
			return 0
		}
		pa.saveState()
		_ = s.Close()
		// 保留 resume 文件：UserMe 失败可能是瞬时 REST 故障，
		// 下次启用时仍可尝试 resume；真正过期时 SDK 会转新 session。
		return 1
	}
	if !pa.applyIdentityIfCurrent(s, self) {
		// UserMe 期间用户禁用/重登，旧会话直接退出。
		_ = s.Close()
		return 0
	}

	// 身份就绪后再置为已连接，避免 Open() 刚启动时服务端推送的首条事件
	// 因发送守卫看到 State/Enable 未就绪而被静默丢弃。
	if !pa.setSessionStateIfCurrent(s, true, StateConnected) {
		_ = s.Close()
		return 0
	}
	if !pa.isServingSession(s) {
		_ = s.Close()
		return 0
	}
	err = s.Open()
	if err != nil && !errors.Is(err, kook.ErrWSAlreadyOpen) {
		if errors.Is(err, kook.ErrSessionClosed) || s.IsClosed() {
			// 用户禁用/新会话接管，不能覆盖新状态，也不要复活旧连接。
			return 0
		}
		if kook.IsPermanentAuthError(err) {
			log.Errorf("与KOOK服务建立连接时出错:%s", err.Error())
			pa.clearKookResumeState()
			if !pa.clearSessionAndSetState(s, false, StateConnectionFailed) {
				_ = s.Close()
				return 0
			}
			pa.saveState()
			_ = s.Close()
			return 1
		}
		// 网络抖动等瞬时错误：保留 session_id/sn，交给 SDK 后台 resume，
		// 不能在这里 Close 掉刚由 Open 保留下来的恢复状态。
		log.Warnf("与KOOK服务连接遇到瞬时错误，保留会话并后台重连: %v", err)
		if !pa.isServingSession(s) {
			_ = s.Close()
			return 0
		}
		pa.setSessionStateIfCurrent(s, true, StateConnecting)
		if s.IsOpen() {
			// 后台 resume 可能在 Open 返回错误后已经成功，避免把状态降回连接中。
			pa.setSessionStateIfCurrent(s, true, StateConnected)
		}
		pa.saveKookResumeState(s)
		s.ReconnectAsync()
		pa.saveState()
		return 0
	}
	pa.saveKookResumeState(s)
	if !pa.setSessionStateIfCurrent(s, true, StateConnected) {
		// 连接建立期间被禁用/替换，避免旧协程继续改状态。
		_ = s.Close()
		return 0
	}
	go pa.updateGameStatus()
	_, _, selfID, selfName := pa.endpointSnapshot()
	log.Infof("KOOK 连接成功，账号<%s>(%s)", selfName, selfID)
	pa.saveState()
	return 0
}

func (pa *PlatformAdapterKook) DoRelogin() bool {
	log := zap.S().Named(logger.LogKeyAdapter)
	log.Infof("正在重新登录KOOK服务……")
	session := pa.getSession()
	if session != nil {
		if !pa.clearSessionAndSetState(session, false, StateDisconnected) {
			// 新会话已经接管；不要覆盖它的状态，也不要再启动第三个会话。
			_ = session.Close()
			return false
		}
		_ = session.Close()
		pa.clearKookResumeState()
	} else {
		if !pa.setEndpointStateIfIdle(false, StateDisconnected) {
			// 检查期间已有新会话启动，本次重登不应覆盖它。
			pa.saveState()
			return false
		}
		pa.sessionMu.Lock()
		pa.serving = false
		pa.sessionMu.Unlock()
		pa.clearKookResumeState()
	}
	pa.saveState()
	return pa.Serve() == 0
}

func (pa *PlatformAdapterKook) SetEnable(enable bool) {
	log := zap.S().Named(logger.LogKeyAdapter)
	if enable {
		log.Infof("正在启用KOOK服务……")
		session := pa.getSession()
		if session == nil {
			pa.Serve()
			return
		}
		// 与 Serve 相同：先置已连接状态，避免 Open 启动期的首条事件回复被丢弃。
		if !pa.setSessionStateIfCurrent(session, true, StateConnected) {
			_ = session.Close()
			return
		}
		if !pa.isServingSession(session) {
			_ = session.Close()
			return
		}
		err := session.Open()
		if err != nil && !errors.Is(err, kook.ErrWSAlreadyOpen) {
			if errors.Is(err, kook.ErrSessionClosed) || session.IsClosed() {
				return
			}
			if kook.IsPermanentAuthError(err) {
				log.Errorf("与KOOK服务进行连接时出错:%s", err)
				pa.clearKookResumeState()
				if pa.clearSessionAndSetState(session, false, StateConnectionFailed) {
					pa.saveState()
				}
				_ = session.Close()
				return
			}
			log.Warnf("与KOOK服务连接遇到瞬时错误，保留会话并后台重连: %v", err)
			if !pa.isServingSession(session) {
				_ = session.Close()
				return
			}
			pa.setSessionStateIfCurrent(session, true, StateConnecting)
			if session.IsOpen() {
				pa.setSessionStateIfCurrent(session, true, StateConnected)
			}
			pa.saveKookResumeState(session)
			session.ReconnectAsync()
			pa.saveState()
			return
		}
		if !pa.setSessionStateIfCurrent(session, true, StateConnected) {
			_ = session.Close()
			return
		}
		pa.updateGameStatus()
		_, _, selfID, selfName := pa.endpointSnapshot()
		log.Infof("KOOK 连接成功，账号<%s>(%s)", selfName, selfID)
	} else {
		session := pa.getSession()
		if session == nil {
			if pa.setEndpointStateIfIdle(false, StateDisconnected) {
				pa.sessionMu.Lock()
				pa.serving = false
				pa.sessionMu.Unlock()
				pa.clearKookResumeState()
				pa.saveState()
				return
			}
			// 检查期间有新会话启动，继续走正常停止流程。
			session = pa.getSession()
			if session == nil {
				pa.saveState()
				return
			}
		}
		if !pa.clearSessionAndSetState(session, false, StateDisconnected) {
			_ = session.Close()
			return
		}
		_ = session.Close()
		pa.clearKookResumeState()
	}
	pa.saveState()
}

func (pa *PlatformAdapterKook) SendSegmentToGroup(ctx *MsgContext, groupID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterKook) SendSegmentToPerson(ctx *MsgContext, userID string, msg []message.IMessageElement, flag string) {
}

func (pa *PlatformAdapterKook) SendToPerson(ctx *MsgContext, userID string, text string, flag string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	session := pa.getSession()
	enable, state, selfID, selfName := pa.endpointSnapshot()
	if !enable || session == nil || state != StateConnected {
		return
	}
	channel, err := session.UserChatCreate(ExtractKookUserID(userID))
	if err != nil {
		log.Errorf("创建Kook用户#%s的私聊频道时出错:%s", userID, err)
		return
	}
	resp, err := pa.SendToChannelRaw(channel.Code, text, true)
	if err != nil {
		return
	}
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "KOOK",
		MessageType: "private",
		Message:     text,
		Sender: SenderBase{
			UserID:   selfID,
			Nickname: selfName,
		},
		RawID: resp.MsgID,
	}, flag)
}

func (pa *PlatformAdapterKook) SendToGroup(ctx *MsgContext, groupID string, text string, flag string) {
	session := pa.getSession()
	enable, state, selfID, selfName := pa.endpointSnapshot()
	if !enable || session == nil || state != StateConnected {
		return
	}
	resp, err := pa.SendToChannelRaw(ExtractKookChannelID(groupID), text, false)
	if err != nil {
		return
	}
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "KOOK",
		MessageType: "group",
		Message:     text,
		GroupID:     groupID,
		Sender: SenderBase{
			UserID:   selfID,
			Nickname: selfName,
		},
		RawID: resp.MsgID,
	}, flag)
}

func (pa *PlatformAdapterKook) SendFileToPerson(ctx *MsgContext, userID string, path string, flag string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	session := pa.getSession()
	enable, state, selfID, selfName := pa.endpointSnapshot()
	if !enable || session == nil || state != StateConnected {
		return
	}
	channel, err := session.UserChatCreate(ExtractKookUserID(userID))
	if err != nil {
		log.Errorf("创建Kook用户#%s的私聊频道时出错:%s", userID, err)
		return
	}
	resp, err := pa.SendFileToChannelRaw(channel.Code, path, true)
	if err != nil {
		return
	}
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "KOOK",
		MessageType: "private",
		Segment: []message.IMessageElement{
			&message.FileElement{
				File: path,
			},
		},
		Sender: SenderBase{
			UserID:   selfID,
			Nickname: selfName,
		},
		RawID: resp.MsgID,
	}, flag)
}

func (pa *PlatformAdapterKook) SendFileToGroup(ctx *MsgContext, groupID string, path string, flag string) {
	session := pa.getSession()
	enable, state, selfID, selfName := pa.endpointSnapshot()
	if !enable || session == nil || state != StateConnected {
		return
	}
	resp, err := pa.SendFileToChannelRaw(ExtractKookChannelID(groupID), path, false)
	if err != nil {
		return
	}
	pa.EndPoint.Session.OnMessageSend(ctx, &Message{
		Platform:    "KOOK",
		MessageType: "group",
		Segment: []message.IMessageElement{
			&message.FileElement{
				File: path,
			},
		},
		GroupID: groupID,
		Sender: SenderBase{
			UserID:   selfID,
			Nickname: selfName,
		},
		RawID: resp.MsgID,
	}, flag)
}

func (pa *PlatformAdapterKook) MemberBan(_ string, _ string, _ int64) {}

func (pa *PlatformAdapterKook) MemberKick(_ string, _ string) {}

func (pa *PlatformAdapterKook) EditMessage(ctx *MsgContext, msgID, message string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	session := pa.getSession()
	if session == nil {
		return
	}
	req := kook.MessageUpdate{
		MessageUpdateBase: kook.MessageUpdateBase{
			MsgID:   msgID,
			Content: message,
		},
	}
	if err := session.MessageUpdate(&req); err != nil {
		log.Errorf("更新KOOK消息失败: %v", err)
	}
}

func (pa *PlatformAdapterKook) RecallMessage(ctx *MsgContext, msgID string) {
	// TODO: not tested
	session := pa.getSession()
	enable, state, _, _ := pa.endpointSnapshot()
	if !enable || session == nil || state != StateConnected {
		return
	}
	_ = session.MessageDelete(msgID)
}

func (pa *PlatformAdapterKook) SendFileToChannelRaw(id string, path string, private bool) (*kook.MessageResp, error) {
	log := zap.S().Named(logger.LogKeyAdapter)
	bot := pa.getSession()
	if bot == nil {
		return nil, fmt.Errorf("KOOK 会话未建立")
	}
	e, err := message.FilepathToFileElement(path)
	if err != nil {
		log.Errorf("向Kook频道#%s发送文件[path=%s]时出错:%s", id, path, err)
		return nil, err
	}

	streamToByte := func(stream io.Reader) []byte {
		buf := new(bytes.Buffer)
		_, errRead := buf.ReadFrom(stream)
		if errRead != nil {
			return nil
		}
		return buf.Bytes()
	}
	assert, err := bot.AssetCreate(e.File, streamToByte(e.Stream))
	if err != nil {
		log.Errorf("Kook创建asserts时出错:%s", err)
		return nil, err
	}

	card := CardMessage{
		Type:  "card",
		Theme: "primary",
		Size:  "lg",
	}
	cardModule := CardMessageModuleFile{
		Type:  "file",
		Title: e.File,
		Src:   assert,
	}
	card.Modules = append(card.Modules, cardModule)
	cardArray := []CardMessage{card}
	sendText, err := json.Marshal(cardArray)
	if err != nil {
		log.Errorf("Kook创建card时出错:%s", err)
		return nil, err
	}
	msgb := kook.MessageCreateBase{
		Content: "",
		Type:    kook.MessageTypeCard,
	}
	msgb.Content = string(sendText)
	resp, err := pa.MessageCreateRaw(msgb, id, private)
	if err != nil {
		log.Errorf("向Kook频道#%s发送文件[path=%s]时出错:%s", id, path, err)
	}
	return resp, err
}

func (pa *PlatformAdapterKook) SendToChannelRaw(id string, text string, private bool) (*kook.MessageResp, error) {
	log := zap.S().Named(logger.LogKeyAdapter)
	bot := pa.getSession()
	if bot == nil {
		return nil, fmt.Errorf("KOOK 会话未建立")
	}
	elem := message.ConvertStringMessage(text)
	// var err error
	streamToByte := func(stream io.Reader) []byte {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(stream)
		if err != nil {
			return nil
		}
		return buf.Bytes()
	}
	msgb := kook.MessageCreateBase{
		Content: "",
		Type:    kook.MessageTypeCard,
	}
	card := CardMessage{
		Type:  "card",
		Theme: "primary",
		Size:  "lg",
	}
	for _, element := range elem {
		switch e := element.(type) {
		case *message.TextElement:
			// goldmark.DefaultParser().Parse(txt.NewReader([]byte(e.Content)))
			// msgb.Content += antiMarkdownFormat(e.Content)
			cardModule := CardMessageModuleText{
				Type: "section",
				Text: struct {
					Content string `json:"content"`
					Type    string `json:"type"`
				}{Content: e.Content, Type: "plain-text"},
			}
			card.Modules = append(card.Modules, cardModule)
		case *message.ImageElement:
			assert, err := bot.AssetCreate(e.File.File, streamToByte(e.File.Stream))
			if err != nil {
				log.Errorf("Kook创建asserts时出错:%s", err)
				break
			}
			cardModule := CardMessageModuleImage{
				Type: "container",
			}
			cardModule.Elements = append(cardModule.Elements, struct {
				Type string `json:"type"`
				Src  string `json:"src"`
			}{"image", assert})
			card.Modules = append(card.Modules, cardModule)
		// Disabled due to Security Concerns
		// case *message.FileElement:
		//	assert, err := bot.AssetCreate(e.File, streamToByte(e.Stream))
		//	if err != nil {
		//		pa.EndPoint.Session.Parent.Logger.Errorf("Kook创建asserts时出错:%s", err)
		//		break
		//	}
		//	cardModule := CardMessageModuleFile{
		//		Type:  "file",
		//		Title: e.File,
		//		Src:   assert,
		//	}
		//	card.Modules = append(card.Modules, cardModule)
		case *message.AtElement:
			cardModule := CardMessageModuleText{
				Type: "section",
				Text: struct {
					Content string `json:"content"`
					Type    string `json:"type"`
				}{Content: "(met)" + e.Target + "(met)", Type: "kmarkdown"},
			}
			card.Modules = append(card.Modules, cardModule)
			// msgb.Content = msgb.Content + fmt.Sprintf("(met)%s(met)", e.ReplySeq)
		case *message.TTSElement:
			// msgb.Content += antiMarkdownFormat(e.Content)
		case *message.ReplyElement:
			msgb.Quote = e.ReplySeq
		}
	}
	cardArray := []CardMessage{card}
	sendText, err := json.Marshal(cardArray)
	if err != nil {
		log.Errorf("Kook创建card时出错:%s", err)
		return nil, err
	}
	msgb.Content = string(sendText)
	// pa.EndPoint.Session.Parent.Logger.Infof("Kook发送消息:%s", msgb.Content)
	resp, err := pa.MessageCreateRaw(msgb, id, private)
	if err != nil {
		log.Errorf("向Kook频道#%s发送消息时出错:%s", id, err)
	}
	return resp, err
}

func antiMarkdownFormat(text string) string {
	text = strings.ReplaceAll(text, "\\", "\\\\")
	// text = strings.ReplaceAll(text, "_", "\\_")
	text = strings.ReplaceAll(text, "~", "\\~")
	// text = strings.ReplaceAll(text, "|", "\\|")
	// text = strings.ReplaceAll(text, ">", "\\>")
	// text = strings.ReplaceAll(text, "<", "\\<")
	text = strings.ReplaceAll(text, "`", "\\`")
	// text = strings.ReplaceAll(text, "#", "\\#")
	// text = strings.ReplaceAll(text, "+", "\\+")
	// text = strings.ReplaceAll(text, "-", "\\-")
	// text = strings.ReplaceAll(text, "=", "\\=")
	// text = strings.ReplaceAll(text, "{", "\\{")
	// text = strings.ReplaceAll(text, "}", "\\}")
	// text = strings.ReplaceAll(text, ".", "\\.")
	text = strings.ReplaceAll(text, "!", "\\!")
	text = strings.ReplaceAll(text, "(", "\\(")
	text = strings.ReplaceAll(text, ")", "\\)")
	text = strings.ReplaceAll(text, "[", "\\[")
	text = strings.ReplaceAll(text, "]", "\\]")
	text = strings.ReplaceAll(text, "*", "\\*")
	// text = strings.ReplaceAll(text, ":", "\\:")
	// text = strings.ReplaceAll(text, "\"", "\\\"")
	// text = strings.ReplaceAll(text, "'", "\\'")
	// text = strings.ReplaceAll(text, "/", "\\/")
	// text = strings.ReplaceAll(text, "@", "\\@")
	// text = strings.ReplaceAll(text, "%", "\\%")
	// text = strings.ReplaceAll(text, ",", "\\,")
	// text = strings.ReplaceAll(text, " ", "\\ ")
	return text
}

func (pa *PlatformAdapterKook) MessageCreateRaw(base kook.MessageCreateBase, id string, isPrivate bool) (*kook.MessageResp, error) {
	bot := pa.getSession()
	if bot == nil {
		return nil, fmt.Errorf("KOOK 会话未建立")
	}
	if isPrivate {
		resp, err := bot.DirectMessageCreate(&kook.DirectMessageCreate{ChatCode: id, MessageCreateBase: base})
		return resp, err
	}
	base.TargetID = id
	resp, err := bot.MessageCreate(&kook.MessageCreate{MessageCreateBase: base})
	// pa.EndPoint.Session.Parent.Logger.Infof("Kook发送消息返回:%s", ret)
	return resp, err
}

func FormatDiceIDKook(diceKook string) string {
	return fmt.Sprintf("KOOK:%s", diceKook)
}

func FormatDiceIDKookGuild(diceKook string) string {
	return fmt.Sprintf("KOOK-Guild:%s", diceKook)
}

func FormatDiceIDKookChannel(diceKook string) string {
	return fmt.Sprintf("KOOK-CH-Group:%s", diceKook)
}

func ExtractKookUserID(id string) string {
	if strings.HasPrefix(id, "KOOK:") {
		return id[len("KOOK:"):]
	}
	return id
}

func ExtractKookChannelID(id string) string {
	if strings.HasPrefix(id, "KOOK-CH-Group:") {
		return id[len("KOOK-CH-Group:"):]
	}
	return id
}

func ExtractKookGuildID(id string) string {
	if strings.HasPrefix(id, "KOOK-Guild:") {
		return id[len("KOOK-Guild:"):]
	}
	return id
}

func (pa *PlatformAdapterKook) QuitGroup(_ *MsgContext, groupID string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	session := pa.getSession()
	if session == nil {
		return
	}
	channel, err := session.ChannelView(ExtractKookChannelID(groupID))
	if err != nil {
		log.Errorf("获取Kook频道信息#%s时出错:%s", groupID, err.Error())
		return
	}
	err = session.GuildLeave(channel.GuildID)
	if err != nil {
		log.Errorf("退出Kook服务器#%s时出错:%s", channel.GuildID, err.Error())
		return
	}
}

func (pa *PlatformAdapterKook) SetGroupCardName(ctx *MsgContext, name string) {
	log := zap.S().Named(logger.LogKeyAdapter)
	session := pa.getSession()
	if session == nil {
		return
	}
	nick := &kook.GuildNickname{}
	nick.GuildID = ExtractKookGuildID(ctx.Group.GuildID)
	nick.Nickname = name
	nick.UserID = ExtractKookUserID(ctx.Player.UserID)
	err := session.GuildNickname(nick)
	if err != nil {
		log.Errorf("修改Kook用户#%s在服务器#%s(来源频道#%s)的昵称时出错:%s", ctx.Player.UserID, ctx.Group.GuildID, ctx.Group.GroupID, err.Error())
		return
	}
}

func trimHTML(src string) string {
	// 将HTML标签全转换成小写
	re := regexp.MustCompile(`\<[\S\s]+?\>`)
	src = re.ReplaceAllStringFunc(src, strings.ToLower)
	// 去除STYLE
	re = regexp.MustCompile(`\<style[\S\s]+?\</style\>`)
	src = re.ReplaceAllString(src, "")
	// 去除SCRIPT
	re = regexp.MustCompile(`\<script[\S\s]+?\</script\>`)
	src = re.ReplaceAllString(src, "")
	// 去除所有尖括号内的HTML代码，并换成换行符
	re = regexp.MustCompile(`\<[\S\s]+?\>`)
	src = re.ReplaceAllString(src, "\n")
	// 去除连续的换行符
	re = regexp.MustCompile(`\s{2,}`)
	src = re.ReplaceAllString(src, "\n")
	return strings.TrimSpace(src)
}

func (pa *PlatformAdapterKook) toStdMessage(ctx *kook.KmarkdownMessageContext) *Message {
	log := zap.S().Named(logger.LogKeyAdapter)
	msg := new(Message)
	msg.Time = ctx.Common.MsgTimestamp
	msg.RawID = ctx.Common.MsgID
	var buf bytes.Buffer
	if err := goldmark.Convert([]byte(ctx.Common.Content), &buf); err != nil {
		log.Errorf("Kook Markdown 解析错误:%s 内容:%s", err, ctx.Common.Content)
		return nil
	}
	msg.Message = trimHTML(buf.String())
	msg.Message = strings.ReplaceAll(msg.Message, `\[`, "[")
	msg.Message = strings.ReplaceAll(msg.Message, `\]`, "]")
	msg.Message = html.UnescapeString(msg.Message)
	msg.Platform = "KOOK"
	send := new(SenderBase)
	send.UserID = FormatDiceIDKook(ctx.Common.AuthorID)
	send.Nickname = ctx.Extra.Author.Nickname
	if ctx.Common.ChannelType == "PERSON" {
		msg.MessageType = "private"
	} else {
		msg.MessageType = "group"
		msg.GroupID = FormatDiceIDKookChannel(ctx.Common.TargetID)
		msg.GuildID = FormatDiceIDKookGuild(ctx.Extra.GuildID)
		if pa.checkIfGuildAdmin(ctx) {
			send.GroupRole = "admin"
		}
	}
	msg.Sender = *send
	return msg
}

func (pa *PlatformAdapterKook) checkIfGuildAdmin(ctx *kook.KmarkdownMessageContext) bool {
	// 每条消息都做 UserView + GuildView 会让回复被两次 REST 往返拖慢。
	// 管理员判断按 guild+user 做短 TTL 缓存，权限变化最多延迟 2 分钟生效。
	cacheKey := ctx.Extra.GuildID + "\x00" + ctx.Common.AuthorID
	if admin, ok := pa.cachedGuildAdmin(cacheKey); ok {
		return admin
	}
	session := pa.getSession()
	if session == nil {
		return false
	}
	user, err := session.UserView(ctx.Common.AuthorID, kook.UserViewWithGuildID(ctx.Extra.GuildID))
	if err != nil {
		// 短负缓存：REST 故障时避免每条消息都同步重试并拖住事件队列。
		pa.storeGuildAdminTTL(cacheKey, false, kookAdminErrorCacheTTL)
		return false
	}
	perm := pa.memberPermissions(&ctx.Extra.GuildID, &ctx.Common.TargetID, ctx.Common.AuthorID, user.Roles)
	admin := perm&int64(RolePermissionAdmin|RolePermissionBanUser|RolePermissionKickUser) > 0 || perm == int64(RolePermissionAll)
	pa.storeGuildAdmin(cacheKey, admin)
	return admin
}

func (pa *PlatformAdapterKook) memberPermissions(guildID *string, _ *string, userID string, roles []int64) (apermissions int64) {
	log := zap.S().Named(logger.LogKeyAdapter)
	session := pa.getSession()
	if session == nil {
		return 0
	}
	guild := pa.cachedGuild(session, *guildID)
	if guild == nil {
		log.Errorf("Kook GuildView 错误: guild=%s", *guildID)
		return 0
	}
	if userID == guild.MasterID {
		apermissions = int64(RolePermissionAll)
		return apermissions
	}
	for _, role := range roles {
		if strconv.FormatInt(role, 10) == guild.ID {
			apermissions |= role
			break
		}
	}

	for _, role := range guild.Roles {
		for _, roleID := range roles {
			if role.RoleID == roleID {
				apermissions |= int64(role.Permissions)
				break
			}
		}
	}

	if apermissions&int64(RolePermissionAdmin) == int64(RolePermissionAdmin) {
		apermissions |= int64(RolePermissionAll)
	}

	// 下面两部分用于判断频道权限覆写，由于该函数的目的并不是用于完整鉴权而是用于判断用户是否为管理员，而一般不考虑频道覆写中给予用户管理员的情况，
	// 因为这种操作并不合理也会产生安全性问题，同时在省略了这两段循环之后也可以提升性能
	// var denies, allows int64
	// Member overwrites can override role overrides, so do two passes
	// for _, overwrite := range channel.PermissionOverwrites {
	// 	for _, roleID := range roles {
	// 		if overwrite.Type == PermissionOverwriteTypeRole && roleID == overwrite.ID {
	// 			denies |= overwrite.Deny
	// 			allows |= overwrite.Allow
	// 			break
	// 		}
	// 	}
	// }
	// apermissions &= ^denies
	// apermissions |= allows
	// for _, overwrite := range channel.PermissionOverwrites {
	// 	if overwrite.Type == PermissionOverwriteTypeMember && overwrite.ID == userID {
	// 		apermissions &= ^overwrite.Deny
	// 		apermissions |= overwrite.Allow
	// 		break
	// 	}
	// }
	return apermissions
}
