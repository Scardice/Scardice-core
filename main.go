package main

// _ "net/http/pprof"
import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"Scardice-core/api"
	"Scardice-core/core/groupstate"
	"Scardice-core/core/messageflow"
	"Scardice-core/core/playerstate"
	"Scardice-core/core/privacypurge"
	"Scardice-core/dice"
	"Scardice-core/dice/service"
	"Scardice-core/endpoint"
	"Scardice-core/eventstore"
	"Scardice-core/logger"
	"Scardice-core/migrate/eventsourcing"
	"Scardice-core/projectionset"
	"Scardice-core/static"
	"Scardice-core/utils/crypto"
	"Scardice-core/utils/dboperator"
	"Scardice-core/utils/oschecker"
	"Scardice-core/utils/paniclog"

	"github.com/gofrs/flock"
	"github.com/jessevdk/go-flags"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

/*
*
二进制目录结构:
data/configs
data/extensions
data/logs
extensions/
*/

// LockFileName can be overridden via -ldflags "-X main.LockFileName=...".
var LockFileName = "Scardice-lock.lock"
var sealLock = flock.New(LockFileName)

const runtimeShutdownTimeout = 30 * time.Second

type cronStopper interface {
	Stop() context.Context
}

func waitCronStopped(ctx context.Context, scheduler cronStopper) error {
	if scheduler == nil {
		return nil
	}
	stopped := scheduler.Stop()
	select {
	case <-stopped.Done():
		return nil
	case <-ctx.Done():
		select {
		case <-stopped.Done():
			return nil
		default:
			return ctx.Err()
		}
	}
}

func cleanupCreate(diceManager *dice.DiceManager, extraCleanup func(context.Context, bool) error) func() {
	var cleanupOnce sync.Once
	return func() {
		log := logger.M()
		recovered := recover()
		if recovered != nil {
			showWindow()
			log.Errorf("异常: %v\n堆栈: %v", recovered, string(debug.Stack()))
			// 顺便修正一下上面这个，应该是木落忘了。
			if runtime.GOOS == "windows" {
				exec.Command("pause") // windows专属
			}
		}

		// sync.Once is also the join point: a deferred cleanup racing the signal
		// handler waits for the already-running operation instead of returning
		// into an outer database close.
		cleanupOnce.Do(func() {
			log.Info("程序即将退出，进行清理……")
			if !diceManager.CleanupFlag.CompareAndSwap(0, 1) {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), runtimeShutdownTimeout)
			defer cancel()
			runtimeQuiesced := true
			var shutdownErrs []error
			// JS、普通定时任务和事件 worker 共享一个总期限。任何仍可能访问
			// 事件库的资源超时后，后续清理只能停 supervisor，不能关闭数据库。
			for _, instance := range diceManager.Dice {
				if instance == nil {
					continue
				}
				if stopErr := instance.StopJSRuntime(ctx); stopErr != nil {
					runtimeQuiesced = false
					shutdownErrs = append(shutdownErrs, fmt.Errorf("stop JS runtime: %w", stopErr))
				}
				if instance.Cron != nil {
					if stopErr := waitCronStopped(ctx, instance.Cron); stopErr != nil {
						runtimeQuiesced = false
						shutdownErrs = append(shutdownErrs, fmt.Errorf("stop instance cron: %w", stopErr))
					}
				}
			}
			if diceManager.Cron != nil {
				if stopErr := waitCronStopped(ctx, diceManager.Cron); stopErr != nil {
					runtimeQuiesced = false
					shutdownErrs = append(shutdownErrs, fmt.Errorf("stop manager cron: %w", stopErr))
				}
			}
			if extraCleanup != nil {
				if cleanupErr := extraCleanup(ctx, runtimeQuiesced); cleanupErr != nil {
					shutdownErrs = append(shutdownErrs, cleanupErr)
				}
			}
			if shutdownErr := errors.Join(shutdownErrs...); shutdownErr != nil {
				log.Errorf("runtime shutdown did not fully quiesce before the shared deadline; process exit will force-stop remaining resources: %v", shutdownErr)
			}

			if unlockErr := sealLock.Unlock(); unlockErr != nil {
				log.Errorf("文件锁归还出现异常 %v", unlockErr)
			}
		})
	}
}

type eventStoreCloser interface {
	Close() error
}

func shutdownOwnedEventRuntime(
	ctx context.Context,
	runtimeQuiesced bool,
	workers *eventWorkerGroup,
	bootstrap *endpoint.Bootstrap,
	store eventStoreCloser,
) error {
	workersStopped := workers == nil
	return shutdownEventRuntime(
		ctx,
		func(ctx context.Context) error {
			if workers == nil {
				return nil
			}
			err := workers.Shutdown(ctx)
			workersStopped = err == nil
			return err
		},
		func(ctx context.Context) error {
			if !runtimeQuiesced || !workersStopped {
				if bootstrap != nil {
					return bootstrap.Supervisor.Shutdown(ctx)
				}
				return nil
			}
			if bootstrap != nil {
				return bootstrap.Shutdown(ctx)
			}
			if store != nil {
				return store.Close()
			}
			return nil
		},
	)
}

type pprofRecorder struct {
	dir     string
	cpuFile *os.File
}

func startPprofRecord(log *zap.SugaredLogger, bootTime int64) (*pprofRecorder, error) {
	dir := filepath.Join("./data/pprof", strconv.FormatInt(bootTime, 10))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	// 启用锁相关的采样
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

	cpuPath := filepath.Join(dir, "cpu.pprof")
	cpuFile, err := os.Create(cpuPath)
	if err != nil {
		return nil, err
	}
	if err := pprof.StartCPUProfile(cpuFile); err != nil {
		_ = cpuFile.Close()
		return nil, err
	}
	log.Infof("pprof 记录已启用，输出目录: %s", dir)

	return &pprofRecorder{
		dir:     dir,
		cpuFile: cpuFile,
	}, nil
}

func (r *pprofRecorder) stop(log *zap.SugaredLogger) {
	if r == nil {
		return
	}
	pprof.StopCPUProfile()
	if r.cpuFile != nil {
		_ = r.cpuFile.Close()
	}

	writeProfile := func(name string) {
		profile := pprof.Lookup(name)
		if profile == nil {
			return
		}
		path := filepath.Join(r.dir, name+".pprof")
		f, err := os.Create(path)
		if err != nil {
			log.Warnf("写入pprof失败(%s): %v", name, err)
			return
		}
		defer func() { _ = f.Close() }()
		if name == "heap" {
			runtime.GC()
		}
		if err := profile.WriteTo(f, 0); err != nil {
			log.Warnf("写入pprof失败(%s): %v", name, err)
		}
	}

	writeProfile("goroutine")
	writeProfile("heap")
	writeProfile("allocs")
	writeProfile("threadcreate")
	writeProfile("block")
	writeProfile("mutex")
}

func fixTimezone() {
	out, err := exec.Command("/system/bin/getprop", "persist.sys.timezone").Output()
	if err != nil {
		return
	}
	z, err := time.LoadLocation(strings.TrimSpace(string(out)))
	if err != nil {
		return
	}
	time.Local = z //nolint:reassign // old code
}

func main() {
	var opts struct {
		Version                bool   `description:"显示版本号"                                                           long:"version"`
		Install                bool   `description:"安装为系统服务"                                                         long:"install"          short:"i"`
		Uninstall              bool   `description:"删除系统服务"                                                          long:"uninstall"`
		ShowConsole            bool   `description:"Windows上显示控制台界面"                                                 long:"show-console"`
		HideUIWhenBoot         bool   `description:"启动时不弹出UI"                                                        long:"hide-ui"`
		ServiceUser            string `description:"用于启动服务的用户"                                                       long:"service-user"`
		ServiceName            string `description:"自定义服务名，默认为Scardice"                                              long:"service-name"`
		MultiInstanceOnWindows bool   `description:"允许在Windows上运行多个余烬"                                               long:"multi-instance"   short:"m"`
		Address                string `description:"将UI的http服务地址改为此值，例: 0.0.0.0:3211"                                long:"address"`
		DoUpdateWin            bool   `description:"windows自动升级用，不要在任何情况下主动调用"                                       long:"do-update-win"`
		DoUpdateOthers         bool   `description:"linux/mac自动升级用，不要在任何情况下主动调用"                                     long:"do-update-others"`
		Delay                  int64  `long:"delay"`
		JustForTest            bool   `long:"just-for-test"`
		DBCheck                bool   `description:"检查数据库是否有问题"                                                      long:"db-check"`
		ShowEnv                bool   `description:"显示环境变量"                                                          long:"show-env"`
		VacuumDB               bool   `description:"对数据库进行整理, 使其收缩到最小尺寸"                                             long:"vacuum"`
		UpdateTest             bool   `description:"更新测试"                                                            long:"update-test"`
		LogLevel               int8   `choice:"-1"                                                                   choice:"0"              choice:"1" choice:"2" choice:"3" choice:"4" choice:"5" default:"0" description:"设置日志等级"             long:"log-level"`
		ContainerMode          bool   `description:"容器模式，该模式下禁用内置客户端"                                                long:"container-mode"`
		PprofRecord            bool   `description:"启用pprof记录，写入data/pprof/<启动时间戳>"                                      long:"pprof-record"`
		ImportLegacy           bool   `description:"将已停止的 legacy YAML/SQLite/BuntDB 数据一次性导入事件库，成功后退出" long:"import-legacy"`
		VerifyEventStore       bool   `description:"启动时执行事件库全量清单哈希与密钥引用校验" long:"verify-event-store"`
		MutexProfileRate       int    `description:"对互斥锁竞用的采样速率，小于等于0=关闭，1=所有，其他N=N分之1采样率" long:"mutex-profile" default:"0"`
		BlockProfileRate       int    `description:"对阻塞事件的采样速率，小于等于0=关闭，1=所有，其他N=每N纳秒1次采样" long:"block-profile" default:"0"`
	}
	// 读取命令行传参
	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		return
	}
	// 防止输出
	if opts.Version {
		fmt.Fprintln(os.Stdout, dice.VERSION.String())
		return
	}
	if opts.ShowEnv {
		for i, e := range os.Environ() {
			fmt.Fprintln(os.Stdout, i, e)
		}
		return
	}

	// 在启动主要组件前开始采样（锁竞争与阻塞事件）
	runtime.SetMutexProfileFraction(opts.MutexProfileRate)
	runtime.SetBlockProfileRate(opts.BlockProfileRate)
	// 提前到最开始初始化所有日志
	uiWriter := logger.NewUIWriter()
	log := logger.InitLogger(zapcore.Level(opts.LogLevel), uiWriter).Named(logger.LogKeyMain)
	// 初始化PanicLog
	paniclog.InitPanicLog()

	// 3. 提示日志打印
	log.Info("运行日志开始记录，余烬出现故障时可查看 data/main.log 与 data/panic.log 获取更多信息")
	// 加载env相关
	err = godotenv.Load()
	if err != nil {
		log.Warn("未读取到.env参数，将使用进程环境变量；若未提供事件库配置，将自动初始化本地 SQLite。")
	}

	switch opts.MutexProfileRate {
	case 0:
		log.Info("关闭互斥锁分析采样")
	default:
		log.Infof("互斥锁采样率: 1/%d", opts.MutexProfileRate)
	}

	switch opts.BlockProfileRate {
	case 0:
		log.Info("关闭同步阻塞分析采样")
	default:
		log.Infof("阻塞采样率: 1 every %dns", opts.BlockProfileRate)
	}
	// 初始化文件加锁系统
	locked, err := sealLock.TryLock()
	// 如果有错误，或者未能取到锁
	if err != nil || !locked {
		// 打日志的时候防止打出nil
		if err == nil {
			err = errors.New("余烬正在运行中")
		}
		log.Errorf("获取锁文件失败，原因为: %v", err)
		showMsgBox("获取锁文件失败", "为避免数据损坏，拒绝继续启动。请检查是否启动多份余烬程序！")
		return
	}
	judge, osr := oschecker.OldVersionCheck()
	// 预留收集信息的接口，如果有需要可以考虑从这里拿数据。不从这里做提示的原因是Windows和Linux的展示方式不同。
	if judge {
		log.Info(fmt.Sprintf("您当前使用的系统为: %s", osr))
	}
	if opts.DBCheck {
		dboperator.DBCheck()
		return
	}
	if opts.VacuumDB {
		service.DBVacuum()
		return
	}

	if opts.Delay != 0 {
		log.Infof("延迟启动 %d 秒", opts.Delay)
		time.Sleep(time.Duration(opts.Delay) * time.Second)
	}

	if runtime.GOOS == "android" {
		fixTimezone()
	}

	_ = os.MkdirAll("./data", 0o755)

	// 提早初始化是为了读取ServiceName

	// Event-store metadata readiness is the first runtime gate. No legacy
	// loader, JavaScript, timer, pprof worker, Supervisor, or provider is
	// started before this lightweight read-only check succeeds.
	endpointDBConfig, endpointConfigErr := ensureEndpointDatabaseConfigWithAudit(os.Getenv, ".", func(event endpointBootstrapEvent) {
		if event.Created {
			log.Infof("自动创建%s：path=%s", event.Resource, event.Path)
			return
		}
		log.Infof("复用%s：path=%s", event.Resource, event.Path)
	})
	if endpointConfigErr != nil {
		log.Errorf("endpoint event database configuration failed: %v", endpointConfigErr)
		return
	}
	if endpointDBConfig.DSN == "" {
		log.Error("event-store configuration is required; refusing legacy runtime fallback")
		return
	}
	eventDB, openErr := eventstore.OpenDatabase(context.Background(), endpointDBConfig)
	if openErr != nil {
		log.Errorf("endpoint event database startup failed: %v", openErr)
		return
	}
	eventDatabaseHandedOff := false
	defer func() {
		if !eventDatabaseHandedOff {
			_ = eventDB.Close()
		}
	}()
	eventStore := eventstore.NewStore(eventDB, projectionset.StoreOptions()...)
	if opts.VerifyEventStore {
		if openErr = eventStore.ValidateReadiness(context.Background()); openErr != nil {
			log.Errorf("event-store exhaustive readiness validation failed: %v", openErr)
			return
		}
		log.Info("事件库全量完整性校验完成")
	} else {
		log.Info("事件库全量完整性校验默认关闭；可使用 --verify-event-store 显式执行")
	}
	if opts.ImportLegacy {
		readiness, readinessErr := eventStore.GetReadiness(context.Background())
		if readinessErr != nil {
			log.Errorf("read legacy import readiness failed: %v", readinessErr)
			return
		}
		persistentState, persistentStateErr := captureImportPersistentState(context.Background(), eventStore)
		if persistentStateErr != nil {
			log.Errorf("inspect active event database before legacy import failed: %v", persistentStateErr)
			return
		}
		if closeErr := eventStore.Close(); closeErr != nil {
			log.Errorf("close active event database before import failed: %v", closeErr)
			return
		}
		installationRoot, sourceRootErr := os.Getwd()
		if sourceRootErr != nil {
			log.Errorf("resolve legacy installation root failed: %v", sourceRootErr)
			return
		}
		sourceRoot, sourceRootErr := legacySourceRoot(installationRoot)
		if sourceRootErr != nil {
			log.Errorf("resolve legacy data root failed: %v", sourceRootErr)
			return
		}
		result, importErr := importLegacyInstallation(context.Background(), endpointDBConfig, readiness, persistentState, sourceRoot, time.Now())
		if importErr != nil {
			log.Errorf("legacy import failed: %v", importErr)
			return
		}
		for _, warning := range result.Warnings {
			log.Warnf("legacy import cleanup warning: %s", warning)
		}
		log.Infof("legacy import published: target=%s snapshot=%s records-batches=%d; restart Scardice normally", result.TargetIdentity, result.Snapshot.Root, result.Batches)
		return
	}
	legacyState := legacyStatePresent()
	startupReadiness, openErr := eventsourcing.ValidateStartupReadiness(context.Background(), eventStore, legacyState)
	if openErr != nil {
		log.Errorf("event-store startup gate rejected state: %v", openErr)
		return
	}

	// Legacy data is never loaded into the runtime. The importer is the only
	// allowed legacy reader; this process starts with an empty Core shell after
	// an import-ready target has been published.
	diceManager := &dice.DiceManager{}
	var pprofStop = func() {}
	var recErr error
	var endpointBootstrap *endpoint.Bootstrap
	eventWorkers := newEventWorkerGroup(context.Background())
	finishCleanUp := cleanupCreate(diceManager, func(ctx context.Context, runtimeQuiesced bool) error {
		pprofStop()
		api.RegisterEndpointBootstrap(nil)
		if shutdownErr := shutdownOwnedEventRuntime(ctx, runtimeQuiesced, eventWorkers, endpointBootstrap, eventStore); shutdownErr != nil {
			return fmt.Errorf("event runtime shutdown: %w", shutdownErr)
		}
		return nil
	})
	cleanUp := func() {
		eventWorkers.beginShutdown()
		finishCleanUp()
	}
	defer dice.CrashLog()
	defer cleanUp()
	// Before this point the database-only defer owns the handle. From here on,
	// cleanup owns the final close and only performs it after every database
	// user has quiesced.
	eventDatabaseHandedOff = true

	if opts.ContainerMode {
		log.Info("当前为容器模式，内置适配器与更新功能已被禁用")
		diceManager.ContainerMode = true
	}
	if err = diceManager.InitializeRuntime(); err != nil {
		log.Errorf("runtime initialization failed: %v", err)
		return
	}
	if err = diceManager.RestoreEventSourcedManager(context.Background(), eventStore); err != nil {
		log.Errorf("event-sourced manager restore failed: %v", err)
		return
	}
	if err = diceManager.RestoreEventSourcedDice(context.Background(), eventStore); err != nil {
		log.Errorf("event-sourced Dice restore failed: %v", err)
		return
	}

	if opts.Address != "" {
		log.Infof("由参数输入了服务地址: %s", opts.Address)
		diceManager.ServeAddress = opts.Address
	}

	if opts.Install {
		serviceName := opts.ServiceName
		if serviceName == "" {
			serviceName = diceManager.ServiceName
		}
		if serviceName == "" {
			serviceName = "Scardice"
		}
		if serviceName != diceManager.ServiceName {
			diceManager.ServiceName = serviceName
			diceManager.Save()
		}
		serviceInstall(true, serviceName, opts.ServiceUser)
		return
	}

	if opts.Uninstall {
		serviceName := diceManager.ServiceName
		serviceInstall(false, serviceName, "")
		return
	}

	if _, err1 := os.Stat("./auto_update.exe"); err1 == nil {
		// NOTE(lyjjl): 目前没有半自动更新需求，禁用对海豹更新程序的检查。
		// NOTE(lyjjl): 这里通过让 doNext 恒为 false 来短路后续更新流程；
		// 如果未来需要恢复，改回 doNext := true 并保留后面的哈希差异判断即可。
		doNext := false
		if filepath.Base(os.Args[0]) != "auto_update.exe" {
			a := crypto.Sha256Checksum("./auto_update.exe")
			b := crypto.Sha256Checksum(os.Args[0])
			doNext = doNext && a != b
		}
		if doNext {
			// 只有不同文件才进行校验
			// windows平台旧版本到1.4.0流程
			_ = os.WriteFile("./升级失败指引.txt", []byte("如果升级成功不用理会此文档，直接删除即可。\r\n\r\n如果升级后无法启动，或再次启动后恢复到旧版本，先不要紧张。\r\n你升级前的数据备份在backups目录。\r\n如果无法启动，请删除余烬目录中的\"update\"、\"auto_update.exe\"并手动进行升级。\n如果升级成功但在再次重启后回退版本，同上。\n\n如有其他问题可以加企鹅群询问：524364253 562897832"), 0o644)
			log.Warn("检测到 auto_update.exe，即将自动退出当前程序并进行升级")
			log.Warn("程序目录下会出现“升级日志.log”，这代表升级正在进行中，如果失败了请检查此文件。")

			err = errors.New("update disabled") // 更新功能已禁用，原调用: CheckUpdater(diceManager)
			if err != nil {
				log.Error("升级程序检查失败: ", err.Error())
			} else {
				_ = os.Remove("./auto_update.exe")
				// ui资源已经内置，删除旧的ui文件，这里有点风险，但是此时已经不考虑升级失败的情况
				_ = os.RemoveAll("./frontend")
				// UpdateByFile(diceManager, "./update/update.zip", true) // 更新功能已禁用
			}
			return
		}
	}

	if _, err2 := os.Stat("./auto_update"); err2 == nil {
		// NOTE(lyjjl): 目前没有半自动更新需求，禁用对海豹更新程序的检查。
		// NOTE(lyjjl): 这里通过让 doNext 恒为 false 来短路后续更新流程；
		// 如果未来需要恢复，改回 doNext := true 并保留后面的哈希差异判断即可。
		doNext := false
		if filepath.Base(os.Args[0]) != "auto_update" {
			a := crypto.Sha256Checksum("./auto_update")
			b := crypto.Sha256Checksum(os.Args[0])
			doNext = doNext && a != b
		}

		if doNext {
			err = errors.New("update disabled") // 更新功能已禁用，原调用: CheckUpdater(diceManager)
			if err != nil {
				log.Error("升级程序检查失败: ", err.Error())
			} else {
				_ = os.Remove("./auto_update")
				// ui资源已经内置，删除旧的ui文件，这里有点风险，但是此时已经不考虑升级失败的情况
				_ = os.RemoveAll("./frontend")
				// UpdateByFile(diceManager, "./update/update.tar.gz", true) // 更新功能已禁用
			}
			return
		}
	}

	removeUpdateFiles()

	if opts.UpdateTest {
		err = errors.New("update disabled") // 更新功能已禁用，原调用: CheckUpdater(diceManager)
		if err != nil {
			log.Error("升级程序检查失败: ", err.Error())
		}
	}

	// 先临时放这里，后面再整理一下升级模块
	diceManager.UpdateScardiceByFile = func(packName string) bool {
		err = errors.New("update disabled") // 更新功能已禁用，原调用: CheckUpdater(diceManager)
		if err != nil {
			log.Error("升级程序检查失败: ", err.Error())
			return false
		} else {
			// return UpdateByFile(diceManager, packName, false) // 更新功能已禁用
			return false
		}
	}

	cwd, _ := os.Getwd()
	log.Info(dice.APPNAME, dice.VERSION.String(), "当前工作路径: ", cwd)

	if strings.HasPrefix(cwd, os.TempDir()) {
		// C:\Users\XXX\AppData\Local\Temp
		// C:\Users\XXX\AppData\Local\Temp\BNZ.627d774316768935
		tempDirWarn()
		return
	}

	useBuiltinUI := false
	checkFrontendExists := func() bool {
		var stat os.FileInfo
		stat, err = os.Stat("./frontend_overwrite")
		return err == nil && stat.IsDir()
	}
	if !checkFrontendExists() {
		log.Info("未检测到外置的UI资源文件，将使用内置资源启动UI")
		useBuiltinUI = true
	} else {
		log.Info("检测到外置的UI资源文件，将使用frontend_overwrite文件夹内的资源启动UI")
	}

	// // 尝试进行升级
	// migrate.TryMigrateToV12()
	// // 尝试修正log_items表的message字段类型
	// if migrateErr := migrate.LogItemFixDatatype(); migrateErr != nil {
	//	log.Fatalf("修正log_items表时出错，%s", migrateErr.Error())
	//	return
	// }
	// // v131迁移历史设置项到自定义文案
	// if migrateErr := migrate.V131DeprecatedConfig2CustomText(); migrateErr != nil {
	//	log.Fatalf("迁移历史设置项时出错，%s", migrateErr.Error())
	//	return
	// }
	// // v141重命名刷屏警告字段
	// if migrateErr := migrate.V141DeprecatedConfigRename(); migrateErr != nil {
	//	log.Fatalf("迁移历史设置项时出错，%s", migrateErr.Error())
	//	return
	// }
	// // v144删除旧的帮助文档
	// if migrateErr := migrate.V144RemoveOldHelpdoc(); migrateErr != nil {
	//	log.Fatalf("移除旧帮助文档时出错，%v", migrateErr)
	// }
	// // v150升级
	// err = migrate.V150Upgrade()
	// if err != nil {
	//	// Fatalf将会退出程序...或许应该用Errorf一类的吗？
	//	log.Fatalf("您的146数据库可能存在问题，为保护数据，已经停止执行150升级命令。请尝试联系开发者，并提供你的日志。\n"+
	//		"数据已回滚，您可暂时使用旧版本等待进一步的修复和更新。您的报错内容为: %v", err)
	// }

	if !opts.ShowConsole || opts.MultiInstanceOnWindows {
		hideWindow()
	}

	go dice.TryGetBackendURL()

	pprofStop, recErr = startPprofRecordIfEnabled(opts.PprofRecord, log, diceManager.AppBootTime)
	if recErr != nil {
		log.Warnf("pprof 记录启动失败: %v", recErr)
	}

	// 提前接管退出信号，使启动阶段也能完成清理并落盘 pprof。
	go func() {
		interrupt := make(chan os.Signal, 1)
		signal.Notify(interrupt, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(interrupt)
		<-interrupt
		cleanUp()
		log.Info("程序即将退出，再见")
		os.Exit(0)
	}()

	// 初始化核心
	coreStartupStarted := time.Now()
	log.Info("开始初始化 Core 实例")
	diceManager.TryCreateDefault()
	startupDice := diceManager.DiceSnapshot()
	for _, instance := range startupDice {
		if instance == nil {
			continue
		}
		if attachErr := instance.AttachDurableStore(eventStore); attachErr != nil {
			log.Errorf("attach durable event store failed: %v", attachErr)
			return
		}
	}
	log.Infof("Core 实例准备完成: instances=%d elapsed=%s", len(startupDice), time.Since(coreStartupStarted).Round(time.Millisecond))
	if err = diceManager.PrepareEventSourcedState(context.Background()); err != nil {
		log.Errorf("event-sourced Core state initialization failed: %v", err)
		return
	}
	log.Infof("事件溯源配置恢复完成: elapsed=%s", time.Since(coreStartupStarted).Round(time.Millisecond))
	if err = diceManager.DeferStartupJSLoad(); err != nil {
		log.Errorf("defer production JavaScript startup failed: %v", err)
		return
	}
	var coreDice *dice.Dice
	if len(startupDice) > 0 {
		coreDice = startupDice[0]
	}
	if coreDice == nil {
		log.Errorf("event database requires an initialized Core instance")
		return
	}
	endpointBootstrap, openErr = endpoint.NewBootstrap(eventStore, nil, dice.NewAdapterDescriptors()...)
	if openErr != nil {
		log.Errorf("endpoint bootstrap construction failed: %v", openErr)
		return
	}
	resolver := newEventEndpointResolver(endpointBootstrap.Service, endpointBootstrap.Registry, eventStore)
	outboundService, outboundErr := messageflow.NewOutboundService(eventStore, resolver, eventStore, eventstore.UUIDGenerator{})
	if outboundErr != nil {
		log.Errorf("durable outbound service construction failed: %v", outboundErr)
		return
	}
	bridge := dice.NewDurableOutboundBridge(outboundService, resolver, eventstore.UUIDGenerator{})
	replay := inboundReplay{Supervisor: endpointBootstrap.Supervisor, GORMStore: eventStore}
	for _, instance := range startupDice {
		if instance == nil {
			continue
		}
		// Publish the final ports before InitDice starts runtime goroutines.
		instance.OutboundBridge = bridge
		instance.ProviderQuery = endpointBootstrap.Supervisor
		instance.ProviderCall = endpointBootstrap.Supervisor
		instance.InboundReplay = replay
	}
	log.Info("开始初始化 Core 扩展与持久化状态")
	diceManager.InitDice(uiWriter)
	if diceManager.CleanupFlag.Load() != 0 {
		return
	}
	log.Infof("Core 基础运行时初始化完成，JS 扩展等待端点与出站服务就绪: elapsed=%s", time.Since(coreStartupStarted).Round(time.Millisecond))
	if coreDice.ImSession == nil {
		log.Errorf("event database requires an initialized Core session")
		return
	}
	inboundService, inboundErr := messageflow.NewInboundService(eventStore, eventStore)
	if inboundErr != nil {
		log.Errorf("endpoint inbound service construction failed: %v", inboundErr)
		return
	}
	callbackHost := dice.NewDurableCallbackHost(coreDice)
	api.RegisterPrivacyPurgeService(privacypurge.NewService(eventStore, privacypurge.WithGroupCacheInvalidator(callbackHost.InvalidateGroup)))
	if startupReadiness.Mode == string(eventsourcing.ModeImport) && legacyState {
		installationRoot, repairErr := os.Getwd()
		if repairErr != nil {
			log.Errorf("resolve legacy endpoint metadata root failed: %v", repairErr)
			return
		}
		sourceRoot, repairErr := legacySourceRoot(installationRoot)
		if repairErr != nil {
			log.Errorf("resolve legacy endpoint metadata source failed: %v", repairErr)
			return
		}
		repaired, repairErr := eventsourcing.RepairLegacyEndpointMetadata(context.Background(), sourceRoot, endpointBootstrap.Service)
		if repairErr != nil {
			log.Errorf("repair imported endpoint metadata failed: %v", repairErr)
			return
		}
		if repaired > 0 {
			log.Infof("已补全早期导入遗漏的账号元数据: endpoints=%d", repaired)
		}
	}
	if openErr = endpointBootstrap.SetResourceRoot(coreDice.BaseConfig.DataDir); openErr != nil {
		log.Errorf("endpoint resource root setup failed: %v", openErr)
		return
	}
	assetImageToken := ""
	resourceServeAddress := ""
	if coreDice.Parent != nil {
		assetImageToken = coreDice.Parent.AssetImageToken
		resourceServeAddress = coreDice.Parent.ServeAddress
	}
	if openErr = endpointBootstrap.SetResourceAccessToken(assetImageToken); openErr != nil {
		log.Errorf("endpoint resource access setup failed: %v", openErr)
		return
	}
	if openErr = endpointBootstrap.SetResourceServeAddress(resourceServeAddress); openErr != nil {
		log.Errorf("endpoint resource address setup failed: %v", openErr)
		return
	}
	if openErr = endpointBootstrap.SetInboundSink(inboundService); openErr != nil {
		log.Errorf("endpoint inbound bridge setup failed: %v", openErr)
		return
	}
	if openErr = endpointBootstrap.SetAdapterEventSink(callbackHost); openErr != nil {
		log.Errorf("endpoint adapter event bridge setup failed: %v", openErr)
		return
	}
	if openErr = endpointBootstrap.SetCharacterSink(dice.NewCharacterService(coreDice)); openErr != nil {
		log.Errorf("endpoint character bridge setup failed: %v", openErr)
		return
	}
	if openErr = endpointBootstrap.SetIdentityObservationSink(dice.NewIdentityObservationSink(coreDice, endpointBootstrap.Service)); openErr != nil {
		log.Errorf("endpoint identity bridge setup failed: %v", openErr)
		return
	}
	if diceManager.CleanupFlag.Load() != 0 {
		return
	}
	api.RegisterEndpointBootstrap(endpointBootstrap)

	groupInfoObserver := dice.NewGroupInfoRefreshSuccessNotifier(coreDice, callbackHost)
	if diceManager.CleanupFlag.Load() != 0 {
		return
	}
	if _, openErr = endpointBootstrap.Startup(eventWorkers.ctx); openErr != nil {
		log.Errorf("endpoint bootstrap replay/reconcile failed: %v", openErr)
		return
	}
	callbackQueue := newEventQueueCoordinator(eventWorkers, eventCallbackIdleDelay, eventStore.InboxWorkSignal(), eventStore.HasInboxWork)
	effectQueue := newEventQueueCoordinator(eventWorkers, eventEffectIdleDelay, eventStore.OutboxWorkSignal(), eventStore.HasOutboxWork)
	if callbackErr := startEventWorkerPool(eventWorkers, eventCallbackWorkerCount, func(index int) (func(context.Context), error) {
		callbackService, err := messageflow.NewCallbackService(messageflow.CallbackConfig{
			Inbox: eventStore, Store: eventStore, BoundCodec: eventStore,
			Resolver: dice.NewDurableCallbackScopeResolver(coreDice),
			Group:    groupstate.NewRepository(eventStore), Player: playerstate.NewRepository(eventStore),
			Host: callbackHost, WorkerID: fmt.Sprintf("scardice-callback-%d", index),
		})
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context) {
			runEventCallbackProcessor(ctx, callbackService, callbackQueue.signal)
		}, nil
	}); callbackErr != nil {
		log.Errorf("durable callback worker pool construction failed: %v", callbackErr)
		return
	}
	if dispatcherErr := startEventWorkerPool(eventWorkers, eventEffectWorkerCount, func(index int) (func(context.Context), error) {
		dispatcher, err := endpoint.NewEffectDispatcher(eventStore, eventStore, endpointBootstrap.Supervisor, fmt.Sprintf("scardice-outbox-%d", index), endpoint.WithEffectResultNotifier(bridge), endpoint.WithEffectSuccessNotifier(groupInfoObserver))
		if err != nil {
			return nil, err
		}
		return func(ctx context.Context) {
			runEventEffectDispatcher(ctx, dispatcher, effectQueue.signal)
		}, nil
	}); dispatcherErr != nil {
		log.Errorf("outbound dispatcher worker pool construction failed: %v", dispatcherErr)
		return
	}
	if diceManager.CleanupFlag.Load() != 0 {
		return
	}
	// This is the one production publication point: endpoint reconciliation,
	// direct calls, durable enqueue, and their workers are ready before any
	// enabled plugin can evaluate top-level code.
	diceManager.IsReady = true
	diceManager.StartDeferredStartupJSLoad()
	log.Infof("Core 与端点运行时已就绪，JS 扩展开始后台加载: elapsed=%s", time.Since(coreStartupStarted).Round(time.Millisecond))
	go func() {
		// 每5分钟做一次新版本检查
		for {
			// go CheckVersion(diceManager) // 更新功能已禁用
			time.Sleep(5 * time.Minute)
		}
	}()
	go RebootRequestListen(diceManager)
	// go UpdateRequestListen(diceManager) // 更新功能已禁用
	// go UpdateCheckRequestListen(diceManager) // 更新功能已禁用

	if opts.Address != "" {
		log.Infof("由参数输入了服务地址: %s", opts.Address)
	}

	go uiServe(diceManager, opts.HideUIWhenBoot, useBuiltinUI)
	// OOM分析工具
	// err = nil
	// err = http.ListenAndServe(":9090", nil)
	// if err != nil {
	// 	fmt.Fprintf(os.Stdout, "ListenAndServe: %s", err)
	// }

	// darwin 的托盘菜单似乎需要在主线程启动才能工作，调整到这里
	trayInit(diceManager)
}

func removeUpdateFiles() {
	// 无论原因，只要走到这里全部删除
	_ = os.Remove("./auto_update_ok")
	_ = os.Remove("./auto_update.exe")
	_ = os.Remove("./auto_updat3.exe")
	_ = os.Remove("./auto_update_ok")
	_ = os.Remove("./auto_update")
	_ = os.Remove("./_delete_me.exe")
	_ = os.RemoveAll("./update")
}

func webUICORSConfig() middleware.CORSConfig {
	allowHeaders := []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, "token"}
	if api.WebUIOriginRateLimitBypassEnabled() {
		allowHeaders = append(allowHeaders, echo.HeaderAuthorization)
	}
	return middleware.CORSConfig{
		Skipper:      middleware.DefaultSkipper,
		AllowHeaders: allowHeaders,
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodPost, http.MethodDelete},
	}
}

func uiServe(dm *dice.DiceManager, hideUI bool, useBuiltin bool) {
	log := logger.M()
	log.Info("即将启动webui")
	// Echo instance
	e := echo.New()

	// 为UI添加日志，以echo方式输出
	e.Use(middleware.CORSWithConfig(webUICORSConfig()))

	e.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level: 5,
	}))
	mimePatch()
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		HSTSMaxAge:            3600,
		ContentSecurityPolicy: "default-src 'self' 'unsafe-inline'; img-src 'self' data: blob: *; media-src 'self' data: blob: *; style-src  'self' 'unsafe-inline' *; frame-src 'self' *;",
		// XFrameOptions:         "ALLOW-FROM https://captcha.go-cqhttp.org/",
	}))
	// X-Content-Type-Options: nosniff

	groupStatic := func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if c.Request().URL.Path == "/" {
				responseWriter := c.Response()
				responseWriter.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
				responseWriter.Header().Set("Pragma", "no-cache")
				responseWriter.Header().Set("Expires", "0")
			}
			return next(c)
		}
	}
	e.Use(groupStatic)
	if useBuiltin {
		frontend, _ := fs.Sub(static.Frontend, "frontend")
		e.StaticFS("/", frontend)
	} else {
		e.Static("/", "./frontend_overwrite")
	}

	api.Bind(e, dm)
	if dm.AssetImageToken != "" {
		registerAssetImageRoute(e, dm)
	}
	e.HideBanner = true // 关闭banner，原因是banner图案会改变终端光标位置

	httpServe(e, dm, hideUI)
}

// onebotAssetMaxSize 与 dice 包常量保持一致，用于 HTTP handler 拒绝超大文件。
const onebotAssetMaxSize = dice.OnebotAssetMaxSize

// registerAssetImageRoute 注册 /assets-img/:token/* 静态资源路由，供 OneBot 协议端拉取本地图片/语音等。
//   - token 鉴权（crypto/subtle.ConstantTimeCompare）
//   - EvalSymlinks 防符号链接穿越
//   - 10MB 硬上限防 OOM
func registerAssetImageRoute(e *echo.Echo, dm *dice.DiceManager) {
	expectedToken := dm.AssetImageToken
	absRootData, errData := filepath.EvalSymlinks(filepath.Join(".", "data"))

	e.GET("/assets-img/:token/*", func(c echo.Context) error {
		if errData != nil || absRootData == "" {
			return c.NoContent(http.StatusNotFound)
		}
		token := c.Param("token")
		if subtle.ConstantTimeCompare([]byte(token), []byte(expectedToken)) != 1 {
			return c.NoContent(http.StatusNotFound)
		}
		rel := filepath.Clean("/" + c.Param("*"))
		rel = strings.TrimPrefix(rel, "/")
		rel = filepath.FromSlash(rel)

		if strings.HasPrefix(rel, "..") {
			return c.NoContent(http.StatusNotFound)
		}

		absPath := filepath.Join(".", "data", rel)
		absFile, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			return c.NoContent(http.StatusNotFound)
		}
		if !strings.HasPrefix(absFile, absRootData+string(filepath.Separator)) {
			return c.NoContent(http.StatusNotFound)
		}
		fi, err := os.Stat(absFile)
		if err != nil || fi.IsDir() {
			return c.NoContent(http.StatusNotFound)
		}
		if fi.Size() > onebotAssetMaxSize {
			return c.NoContent(http.StatusRequestEntityTooLarge)
		}
		return c.File(absFile)
	})
}

//
// func checkCqHttpExists() bool {
//	if _, err := os.Stat("./go-cqhttp"); err == nil {
//		return true
//	}
//	return false
// }

func mimePatch() {
	builtinMimeTypesLower := map[string]string{
		".css":  "text/css; charset=utf-8",
		".gif":  "image/gif",
		".htm":  "text/html; charset=utf-8",
		".html": "text/html; charset=utf-8",
		".jpg":  "image/jpeg",
		".js":   "application/javascript",
		".wasm": "application/wasm",
		".pdf":  "application/pdf",
		".png":  "image/png",
		".svg":  "image/svg+xml",
		".xml":  "text/xml; charset=utf-8",
	}

	for k, v := range builtinMimeTypesLower {
		_ = mime.AddExtensionType(k, v)
	}
}
