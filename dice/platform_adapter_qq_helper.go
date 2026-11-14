package dice

import (
	"time"
)

func ServeQQ(d *Dice, ep *EndPointInfo) {
	defer CrashLog()
	if ep.Platform != "QQ" {
		return
	}

	switch ep.ProtocolType {
	case "walle-q":
		conn := ep.Adapter.(*PlatformAdapterWalleQ)
		serverWalleQ(d, ep, conn)

	case "red":
		conn := ep.Adapter.(*PlatformAdapterRed)
		serverRed(d, ep, conn)

	case "satori":
		conn := ep.Adapter.(*PlatformAdapterSatori)
		serverSatori(d, ep, conn)

	case "official":
		conn := ep.Adapter.(*PlatformAdapterOfficialQQ)
		serverOfficialQQ(d, ep, conn)
	case "onebot":
		fallthrough
	default: // onebot 作为默认情况
		conn := ep.Adapter.(*PlatformAdapterGocq)
		serverGocq(d, ep, conn)
	}
}

func serverGocq(d *Dice, ep *EndPointInfo, conn *PlatformAdapterGocq) {
	if conn.diceServing {
		return
	}
	conn.diceServing = true

	ep.Enable = true
	ep.State = 2 // 连接中
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)

	checkQuit := func() bool {
		if conn.GoCqhttpState == StateCodeInLoginDeviceLock {
			d.Logger.Infof("检测到设备锁流程，暂时不再连接")
			ep.State = 0
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			return true
		}
		if !conn.diceServing {
			// 退出连接
			d.Logger.Infof("检测到连接关闭，不再进行此onebot服务的重连: <%s>(%s)", ep.Nickname, ep.UserID)
			return true
		}
		if conn.GoCqhttpState == StateCodeLoginFailed {
			d.Logger.Infof("检测到登录失败，不再进行此onebot服务的重连: <%s>(%s)", ep.Nickname, ep.UserID)
			return true
		}
		if !ep.Enable {
			d.Logger.Infof("检测到账号被禁用，不再进行此onebot服务的重连: <%s>(%s)", ep.Nickname, ep.UserID)
			return true
		}
		return false
	}

	conn.reconnectTimes = 0
	for !checkQuit() {
		// 骰子开始连接
		d.Logger.Infof("开始连接 onebot 服务，帐号 <%s>(%s)，重试计数[%d/%d]", ep.Nickname, ep.UserID, conn.reconnectTimes, 5)
		ret := ep.Adapter.Serve()

		if ret == 0 {
			break
		}

		if checkQuit() {
			break
		}

		if conn.GoCqhttpState == StateCodeInLogin || conn.GoCqhttpState == StateCodeInLoginQrCode {
			time.Sleep(15 * time.Second)
			continue
		}

		conn.reconnectTimes++
		if conn.reconnectTimes > 5 {
			d.Logger.Infof("onebot 连接重试次数过多，先行中断: <%s>(%s)", ep.Nickname, ep.UserID)
			ep.State = StateDisconnected
			conn.GoCqhttpState = StateCodeLoginFailed
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			break
		}

		time.Sleep(15 * time.Second)
	}

	conn.diceServing = false
}

func serverWalleQ(d *Dice, ep *EndPointInfo, conn *PlatformAdapterWalleQ) {
	if conn.DiceServing {
		return
	}
	conn.DiceServing = true
	ep.Enable = true
	ep.State = 2 // 连接中
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)

	checkQuit := func() bool {
		if conn.WalleQState == StateCodeInLoginDeviceLock {
			d.Logger.Infof("检测到设备锁流程，暂时不再连接")
			ep.State = 0
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			return true
		} // 暂时去掉设备锁检查
		if !conn.DiceServing {
			// 退出连接
			d.Logger.Infof("检测到连接关闭，不再进行此onebot服务的重连: <%s>(%s)", ep.Nickname, ep.UserID)
			return true
		}
		return false
	}

	waitTimes := 0
	for !checkQuit() {
		// 骰子开始连接
		d.Logger.Infof("开始连接 onebot 服务，帐号 <%s>(%s)，重试计数[%d/%d]", ep.Nickname, ep.UserID, waitTimes, 5)
		ret := ep.Adapter.Serve()

		if ret == 0 {
			break
		}

		if checkQuit() {
			break
		}

		waitTimes++
		if waitTimes > 5 {
			d.Logger.Infof("onebot 连接重试次数过多，先行中断: <%s>(%s)", ep.Nickname, ep.UserID)
			conn.DiceServing = false
			// 重试预算耗尽后必须回置状态，避免 UI 永远停在“连接中”。
			ep.State = StateDisconnected
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			break
		}

		time.Sleep(15 * time.Second)
	}
}

func serverRed(d *Dice, ep *EndPointInfo, conn *PlatformAdapterRed) {
	if conn.DiceServing {
		return
	}
	conn.DiceServing = true

	ep.Enable = true
	ep.State = 2 // 连接中
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
	waitTimes := 0

	for {
		// 骰子开始连接
		d.Logger.Infof("开始连接 red 服务，帐号 <%s>(%s)，重试计数[%d/%d]", ep.Nickname, ep.UserID, waitTimes, 5)
		ret := ep.Adapter.Serve()

		if ret == 0 {
			break
		}

		waitTimes += 1
		if waitTimes > 5 {
			d.Logger.Infof("red 连接重试次数过多，先行中断: <%s>(%s)", ep.Nickname, ep.UserID)
			conn.DiceServing = false
			ep.State = StateDisconnected
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			break
		}

		time.Sleep(15 * time.Second)
	}
}

func serverSatori(d *Dice, ep *EndPointInfo, conn *PlatformAdapterSatori) {
	if conn.DiceServing {
		return
	}
	conn.DiceServing = true

	ep.Enable = true
	ep.State = 2 // 连接中
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
	waitTimes := 0

	for ep.State == 2 {
		// 骰子开始连接
		d.Logger.Infof("开始连接 satori 服务，帐号 <%s>(%s)，重试计数[%d/%d]", ep.Nickname, ep.UserID, waitTimes, 5)
		ret := ep.Adapter.Serve()

		if ret == 0 {
			break
		}

		waitTimes += 1
		if waitTimes > 5 {
			d.Logger.Infof("satori 连接重试次数过多，先行中断: <%s>(%s)", ep.Nickname, ep.UserID)
			conn.DiceServing = false
			ep.State = StateDisconnected
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			break
		}

		time.Sleep(15 * time.Second)
	}
}

// officialQQMaxConnectAttempts 是连续连接失败的终态上限。超过后必须把端点
// 明确置为失败并停止重试，否则错误的 AppID/白名单会让 UI 永远显示“连接中”。
// 设为 var 便于测试缩短等待。
var officialQQMaxConnectAttempts = 5

// officialQQServe 抽出 Serve 调用，便于测试注入“始终失败”的连接。
// 默认 nil，调用时回退到 defaultOfficialQQServe，避免与 Serve 形成初始化环。
var officialQQServe func(conn *PlatformAdapterOfficialQQ) int

func defaultOfficialQQServe(conn *PlatformAdapterOfficialQQ) int {
	return conn.Serve()
}

// officialQQInitialBackoff 是首次连接失败后的等待时间；测试可缩短。
var officialQQInitialBackoff = 15 * time.Second

// officialQQReadyTimeout 是 WebSocket 已提交后等待 READY 的上限。
// 超时按瞬时失败重启连接，避免端点永远停在“连接中”。测试可缩短。
var officialQQReadyTimeout = 60 * time.Second

// officialQQStart 启动 Serve 重试循环；测试可替换为不建真实连接的空实现。
var officialQQStart func(d *Dice, ep *EndPointInfo)

func defaultOfficialQQStart(d *Dice, ep *EndPointInfo) {
	go ServerOfficialQQ(d, ep)
}

func startOfficialQQ(d *Dice, ep *EndPointInfo) {
	start := officialQQStart
	if start == nil {
		start = defaultOfficialQQStart
	}
	start(d, ep)
}

func serverOfficialQQ(d *Dice, ep *EndPointInfo, conn *PlatformAdapterOfficialQQ) {
	// 用户可能在“SetEnable(true) → 后台 goroutine 真正启动”之间点禁用。
	// 异步启动必须尊重当下的 Enable=false，否则会把刚被禁用的端点重新连上。
	if enabled, _ := conn.endpointStateSnapshot(); !enabled {
		return
	}
	// Ctx 非空表示会话已经建立或正在运行，不能重复启动并覆盖端点状态。
	if conn.isSessionRunning() {
		return
	}
	if conn.isDiceServing() {
		return
	}

	epoch, stop := conn.beginServeLoop()
	if !conn.setDiceServingIfEpoch(true, epoch) {
		return
	}

	conn.setEndpointStateIfIdle(true, StateConnecting)
	d.LastUpdatedTime = time.Now().Unix()
	d.Save(false)
	waitTimes := 0
	backoff := officialQQInitialBackoff

	for {
		if !conn.serveLoopCurrent(epoch, stop) {
			// 用户已禁用/重登或新的 Serve 循环已接管；不要回写状态。
			conn.setDiceServingIfEpoch(false, epoch)
			return
		}
		// 骰子开始连接
		d.Logger.Infof("开始连接 official qq，帐号 <%s>(%s)，重试计数[%d/%d]", ep.Nickname, ep.UserID, waitTimes, officialQQMaxConnectAttempts)
		serve := officialQQServe
		if serve == nil {
			serve = defaultOfficialQQServe
		}
		ret := serve(conn)

		if ret == 0 {
			return
		}

		if !conn.serveLoopCurrent(epoch, stop) {
			conn.setDiceServingIfEpoch(false, epoch)
			return
		}
		// 永久失败（Webhook 配置非法、UIN 冲突、账号重复等）由 failConnect 置
		// Enable=false；用户禁用也会置 false。两种情况都停止重试，不改写用户状态。
		// Enable 由适配器的 sessionMu 保护，这里必须走加锁快照；直接读 ep.Enable
		// 会与 SetEnable/failConnect 并发构成数据竞争。
		if enabled, _ := conn.endpointStateSnapshot(); !enabled {
			conn.setDiceServingIfEpoch(false, epoch)
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			return
		}

		waitTimes++
		if waitTimes >= officialQQMaxConnectAttempts {
			// 连续失败达到上限：置失败态并停止，避免端点永远停在“连接中”。
			d.Logger.Infof("official qq 连接重试次数过多，先行中断: <%s>(%s)", ep.Nickname, ep.UserID)
			conn.setDiceServingIfEpoch(false, epoch)
			conn.setEndpointStateIfIdle(false, StateConnectionFailed)
			d.LastUpdatedTime = time.Now().Unix()
			d.Save(false)
			return
		}

		d.Logger.Warnf("official qq 连接失败，%s 后重试: 帐号 <%s>(%s)", backoff, ep.Nickname, ep.UserID)
		if !waitOfficialQQRetry(stop, backoff) {
			conn.setDiceServingIfEpoch(false, epoch)
			return
		}
		backoff *= 2
		if backoff > 5*time.Minute {
			backoff = 5 * time.Minute
		}
	}
}

// waitOfficialQQRetry 等待下一次重试，用户禁用/重登时立即返回 false。
func waitOfficialQQRetry(stop <-chan struct{}, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-stop:
		return false
	}
}
