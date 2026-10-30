package dice

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"go.uber.org/zap"

	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

func TestCustomCocRuleUsesOwnerRealmAndRejectsReload(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "owner-thread"
		if stale {
			name = "stale-generation"
		}
		t.Run(name, func(t *testing.T) {
			loop := gojaengine.WrapEventLoop(startFsTestLoop(t))
			manager := NewJsLoopManager()
			generation := manager.SetLoop(loop)
			d := &Dice{ExtLoopManager: manager, Logger: zap.NewNop().Sugar()}
			plugin := &ExtInfo{Name: "rule-owner", JSLoopVersion: generation, IsJsExt: true, dice: d}
			var calls atomic.Int32
			if err := loop.Run(func(rt jsengine.Runtime) error {
				vm, _ := gojaengine.Raw(rt)
				vm.SetFieldNameMapper(gojaengine.FieldNameMapper())
				if err := d.installJSHostAPI(rt); err != nil {
					return err
				}
				return rt.Bind("ownerProbe", func() bool {
					calls.Add(1)
					return jsengine.InOwner(loop) && jsContextPlugin(jsExecutionContextFor(loop)) == plugin
				})
			}); err != nil {
				t.Fatal(err)
			}
			if err := jsengine.RunWithContext(loop, jsContextForPlugin(plugin), func(rt jsengine.Runtime) error {
				_, err := rt.RunString("rule.js", `var rule = seal.coc.newRule(); rule.index=20; rule.key="owned"; rule.check=function(){ if (!ownerProbe()) throw Error("wrong rule owner"); var ret=seal.coc.newRuleCheckResult(); ret.successRank=3; ret.criticalSuccessValue=9; return ret; }; if (!seal.coc.registerRule(rule)) throw Error("registration failed");`)
				return err
			}); err != nil {
				t.Fatal(err)
			}
			if stale {
				manager.SetLoop(nil)
			}
			var recovered any
			var rank int
			var critical int64
			func() {
				defer func() { recovered = recover() }()
				rank, critical = ResultCheck(&MsgContext{Dice: d}, 20, 10, 50, 0)
			}()
			if stale {
				err, ok := recovered.(error)
				if !ok || !errors.Is(err, errJSCallbackStaleGeneration) || calls.Load() != 0 {
					t.Fatalf("stale rule entered old runtime: calls=%d panic=%v", calls.Load(), recovered)
				}
			} else if recovered != nil || rank != 3 || critical != 9 {
				t.Fatalf("rule did not run in owner realm: result=(%d,%d) panic=%v", rank, critical, recovered)
			}
		})
	}
}

func TestCustomCocRegistrySnapshotsAndConcurrentRegistration(t *testing.T) {
	d := &Dice{}
	check := func(_ *MsgContext, _ int64, _ int64, _ int) CocRuleCheckRet {
		return CocRuleCheckRet{SuccessRank: 3, CriticalSuccessValue: 9}
	}
	source := &CocRuleInfo{Index: 20, Name: "registered", Check: check}
	if !d.CocExtraRulesAdd(source) {
		t.Fatal("registration failed")
	}
	source.Name = "mutated"
	source.Check = func(_ *MsgContext, _ int64, _ int64, _ int) CocRuleCheckRet { return CocRuleCheckRet{} }
	snapshot := d.CocExtraRulesSnapshot()
	if snapshot[0].Name != "registered" || snapshot[0].Check != nil {
		t.Fatal("registry leaked mutable rule or owner callback")
	}
	snapshot[0].Name = "changed snapshot"
	if current := d.CocExtraRulesSnapshot(); current[0].Name != "registered" {
		t.Fatal("snapshot mutation changed registered rule")
	}
	if rank, critical := ResultCheck(&MsgContext{Dice: d}, 20, 10, 50, 0); rank != 3 || critical != 9 {
		t.Fatalf("registration retained mutable callback: (%d,%d)", rank, critical)
	}
	var workers sync.WaitGroup
	for i := 21; i < 53; i++ {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			if !d.CocExtraRulesAdd(&CocRuleInfo{Index: index, Check: check}) {
				t.Errorf("register %d failed", index)
			}
			for range 10 {
				d.CocExtraRulesSnapshot()
				if rank, critical := ResultCheck(&MsgContext{Dice: d}, index, 10, 50, 0); rank != 3 || critical != 9 {
					t.Errorf("concurrent check %d = (%d,%d)", index, rank, critical)
				}
			}
		}(i)
	}
	workers.Wait()
	if d.CocExtraRulesAdd(&CocRuleInfo{Index: 20, Check: check}) {
		t.Fatal("duplicate registration replaced live rule")
	}
}
