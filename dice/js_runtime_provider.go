package dice

import (
	"context"
	"errors"
	"fmt"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/eventloop"
	"github.com/dop251/goja_nodejs/require"
	"gopkg.in/elazarl/goproxy.v1"

	"Scardice-core/static"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
	jsservices "Scardice-core/utils/jsengine/services"
	gojaservices "Scardice-core/utils/jsengine/services/goja"
)

// diceGojaProvider keeps the application-specific Goja service installation
// behind the provider boundary. JsInit only opens a provider and installs the
// engine-neutral Dice host API afterwards.
type diceGojaProvider struct {
	dice *Dice
}

func (p *diceGojaProvider) Descriptor() jsengine.Descriptor {
	return jsengine.Descriptor{
		ID:         jsengine.EngineGoja,
		Name:       "Goja",
		Version:    "builtin",
		Language:   "Go",
		Author:     "Scardice",
		Extensions: []string{".js", ".ts"},
		Capabilities: jsengine.CapabilityScript.With(
			jsengine.CapabilityCommonJS,
			jsengine.CapabilityHostObject,
			jsengine.CapabilityHostFunction,
			jsengine.CapabilityContextPropagation,
		),
		Builtin: true,
	}
}

func (p *diceGojaProvider) Open(ctx context.Context, _ jsengine.RuntimeOptions) (jsengine.Loop, error) {
	if p == nil || p.dice == nil {
		return nil, errors.New("goja Dice provider is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d := p.dice
	if pub, err := static.Scripts.ReadFile("scripts/seal_mod.public.pem"); err == nil && len(pub) > 0 {
		OfficialModPublicKey = string(pub)
	}

	registry := new(require.Registry)
	rawLoop := eventloop.NewEventLoop(
		eventloop.EnableConsole(false),
		eventloop.WithRegistry(registry),
		eventloop.WithDebugLog(true),
		eventloop.WithLogger(d.Logger),
	)
	engineLoop := gojaengine.WrapEventLoop(rawLoop)
	if err := gojaengine.InstallContextPropagation(engineLoop); err != nil {
		_ = engineLoop.Close()
		return nil, err
	}
	heapTracker := d.JSHeapTracker()
	heapRealm := heapTracker.attach(rawLoop.RunOnLoop, d.JSAllocSampler())
	opened := false
	defer func() {
		if !opened {
			heapTracker.detach(heapRealm)
		}
	}()
	jsengine.SetInvocationObserver(engineLoop, heapRealm)
	proxy := goproxy.NewProxyHttpServer()
	printer := &PrinterFunc{d: d, isRecord: false, recorder: []string{}}
	serviceRegistry := jsservices.NewRegistry()
	installer := gojaservices.NewInstaller(gojaservices.Options{
		Registry: registry,
		Loop:     rawLoop,
		Proxy:    proxy,
		Printer:  printer,
		Logger:   d.Logger,
		CryptoWarn: func(message string) {
			if script := jsContextScript(jsExecutionContextFor(engineLoop)); script != nil {
				message = fmt.Sprintf("插件=%q 文件=%q %s", script.Name, script.Filename, message)
			}
			printer.Warn(message)
		},
		NetworkAuthorize: func(target string) error {
			return jsNetworkAuthorizeWithContext(d, jsExecutionContextFor(engineLoop), target)
		},
		CurrentContext: func() any {
			return jsengine.CurrentContext(engineLoop)
		},
		ScheduleOnLoop: func(context any, run func(*goja.Runtime) error) error {
			if err := jsCompatibilitySchedulingAllowed(context); err != nil {
				return err
			}
			return jsengine.ScheduleWithContext(engineLoop, jsCompletionContext(context), func(runtime jsengine.Runtime) error {
				vm, ok := gojaengine.Raw(runtime)
				if !ok {
					return errors.New("goja runtime adapter unavailable")
				}
				return run(vm)
			})
		},
		Filesystem: gojaservices.FilesystemHooks{
			Require: func(rt *goja.Runtime, module *goja.Object) {
				jsFsRequire(rt, module, d, rawLoop, engineLoop)
			},
			Enable: func(rt *goja.Runtime) {
				jsFsEnable(rt, d, rawLoop, engineLoop)
			},
		},
	})
	if _, err := serviceRegistry.Install(installer); err != nil {
		_ = serviceRegistry.Close()
		_ = engineLoop.Close()
		return nil, err
	}

	var setupErr error
	rawLoop.Run(func(vm *goja.Runtime) {
		defer func() {
			if recovered := recover(); recovered != nil {
				setupErr = fmt.Errorf("goja runtime setup panic: %v", recovered)
			}
		}()
		vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
		vm.SetRandSource(DiceRandFloat64)
		setupErr = installer.Enable(vm)
		vm.SetAllocationTracker(heapRealm)
	})
	if setupErr != nil {
		_ = serviceRegistry.Close()
		_ = engineLoop.Close()
		return nil, setupErr
	}
	d.JsPrinter = printer
	startErr := make(chan error, 1)
	go func() {
		err := gojaengine.StartInForeground(engineLoop)
		if err != nil && d.Logger != nil {
			d.Logger.Errorf("JS事件循环启动失败: %v", err)
		}
		startErr <- err
	}()
	if err := gojaengine.WaitUntilStarted(engineLoop); err != nil {
		_ = serviceRegistry.Close()
		_ = engineLoop.Close()
		return nil, err
	}
	select {
	case err := <-startErr:
		if err != nil {
			_ = serviceRegistry.Close()
			_ = engineLoop.Close()
			return nil, err
		}
	default:
	}
	opened = true
	return ownJSRuntimeLoop(engineLoop, func() { heapTracker.detach(heapRealm) }, serviceRegistry), nil
}
