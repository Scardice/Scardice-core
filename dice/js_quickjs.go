package dice

import (
	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/quickjs"
)

const (
	defaultQuickJSMemoryLimitMiB  uint64 = 256
	defaultQuickJSGCThresholdMiB  uint64 = 64
	defaultQuickJSMaxStackSizeKiB uint64 = 1024
	quickJSMiB                    uint64 = 1024 * 1024
	quickJSKiB                    uint64 = 1024
)

func (d *Dice) quickJSRuntimeLimits() quickjs.RuntimeLimits {
	memoryLimit := quickJSConfigLimitBytes(d.Config.QuickJSMemoryLimitMiB, quickJSMiB, defaultQuickJSMemoryLimitMiB*quickJSMiB)
	gcThreshold := quickJSConfigLimitBytes(d.Config.QuickJSGCThresholdMiB, quickJSMiB, defaultQuickJSGCThresholdMiB*quickJSMiB)
	if gcThreshold > uint64(1<<63-1) {
		gcThreshold = defaultQuickJSGCThresholdMiB * quickJSMiB
	}
	if gcThreshold >= memoryLimit {
		gcThreshold = memoryLimit / 4
	}
	return quickjs.RuntimeLimits{
		MemoryLimit:  memoryLimit,
		GCThreshold:  int64(gcThreshold),
		MaxStackSize: quickJSConfigLimitBytes(d.Config.QuickJSMaxStackSizeKiB, quickJSKiB, defaultQuickJSMaxStackSizeKiB*quickJSKiB),
	}
}

func quickJSConfigLimitBytes(value uint64, unit uint64, fallback uint64) uint64 {
	if value == 0 || value > ^uint64(0)/unit {
		return fallback
	}
	return value * unit
}

// jsInitQuickJS starts the experimental QuickJS runtime with the in-memory
// Node-compatible registry. Plugin source imports remain disabled.
func (d *Dice) jsInitQuickJS() {
	if d.ExtLoopManager == nil {
		d.ExtLoopManager = NewJsLoopManager()
	}
	d.jsClear()

	printer := &PrinterFunc{d: d, recorder: []string{}}
	environment, err := d.newQuickJSNodeEnvironment(printer)
	if err != nil {
		d.disableQuickJS(err)
		return
	}
	d.JsPrinter = printer

	loop, err := quickjs.New(
		quickjs.WithRuntimeLimits(d.quickJSRuntimeLimits()),
		quickjs.WithRegistry(environment.registry),
		quickjs.WithGlobals(environment.globals...),
		quickjs.WithLogger(quickJSNodeLogger{logger: d.Logger}),
	)
	if err != nil {
		d.disableQuickJS(err)
		return
	}
	versionID := d.ExtLoopManager.SetEngineLoop(loop)

	err = loop.Run(func(runtime jsengine.Runtime) error {
		if err := d.installJSHostAPI(runtime); err != nil {
			return err
		}
		if err := d.installJSExtHostAPI(runtime, runtime.Get("seal").Object(), versionID, nil); err != nil {
			return err
		}
		if err := d.installDangerousJSInstance(runtime, runtime.Get("seal").Object()); err != nil {
			return err
		}
		if err := runtime.Set("__dirname", ""); err != nil {
			return err
		}
		_, err := runtime.RunString("quickjs-bootstrap.js", `
			Object.freeze(seal);
			Object.freeze(seal.deck);
			Object.freeze(seal.coc);
			Object.freeze(seal.vars);
			Object.freeze(seal.ext);
			for (const name of [
				"seal", "process", "require", "Buffer", "Blob", "URL", "crypto",
				"AbortController", "structuredClone", "MessageChannel", "fetch", "WebSocket",
			]) {
				if (Object.prototype.hasOwnProperty.call(globalThis, name)) {
					Object.defineProperty(globalThis, name, { writable: false, configurable: false });
				}
			}
		`)
		return err
	})
	if err != nil {
		d.ExtLoopManager.SetEngineLoop(nil)
		d.disableQuickJS(err)
		return
	}
	if err := quickjs.Start(loop); err != nil {
		d.ExtLoopManager.SetEngineLoop(nil)
		d.disableQuickJS(err)
		return
	}

	(&d.Config).JsEnable = true
	if d.Logger != nil {
		d.Logger.Info("已加载 QuickJS-Go 实验 Host API；已启用 JS 插件加载")
	}
	d.MarkModified()
	d.Save(false)
}

func (d *Dice) disableQuickJS(err error) {
	(&d.Config).JsEnable = false
	if d.Logger != nil {
		d.Logger.Errorf("QuickJS-Go 实验 Host API 初始化失败: %v", err)
	}
}

func (d *Dice) isQuickJSExperiment() bool {
	engine, err := d.configuredJSEngine()
	return err == nil && engine == jsengine.EngineQuickJS
}
