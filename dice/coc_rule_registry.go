package dice

import (
	"fmt"
	"sort"

	"Scardice-core/utils/jsengine"
)

func (d *Dice) newJSCocRule() *CocRuleInfo {
	rule := &CocRuleInfo{jsBound: true}
	if d.ExtLoopManager == nil {
		return rule
	}
	manager := d.ExtLoopManager
	manager.loopLock.RLock()
	defer manager.loopLock.RUnlock()
	for generation, instance := range manager.instances {
		if jsengine.InOwner(instance.loop) {
			rule.jsGeneration, rule.jsLoop = generation, instance.loop
			break
		}
	}
	return rule
}
func (d *Dice) registerJSCocRule(rule *CocRuleInfo) bool {
	if rule == nil {
		return false
	}
	owner := d.newJSCocRule()
	if owner.jsLoop == nil || (rule.jsBound && rule.jsGeneration != owner.jsGeneration) {
		return false
	}
	registered := *rule
	registered.jsBound, registered.jsGeneration, registered.jsLoop = true, owner.jsGeneration, owner.jsLoop
	return d.CocExtraRulesAdd(&registered)
}

func (d *Dice) CocExtraRulesAdd(rule *CocRuleInfo) bool {
	if rule == nil || rule.Check == nil {
		return false
	}
	registered := *rule
	if rule.jsBound {
		manager := d.ExtLoopManager
		if manager == nil {
			return false
		}
		manager.loopLock.RLock()
		defer manager.loopLock.RUnlock()
		instance := manager.instances[rule.jsGeneration]
		if manager.stopped || instance == nil || instance.loop != rule.jsLoop || !jsengine.InOwner(rule.jsLoop) {
			return false
		}
		if realm := jsExecutionContextFor(rule.jsLoop); realm != nil {
			registered.jsRealm = *realm
			registered.jsRealm.Message = nil
		}
	}
	d.cocRulesMu.Lock()
	defer d.cocRulesMu.Unlock()
	if _, exists := d.cocExtraRules[rule.Index]; exists {
		return false
	}
	if d.cocExtraRules == nil {
		d.cocExtraRules = make(map[int]CocRuleInfo)
	}
	d.cocExtraRules[rule.Index] = registered
	return true
}

// TODO(局部重载/禁用与删除): CoC 规则带有 jsGeneration/jsLoop 归属，但只能整体清空。
// subTODO(局部重载): 按注册脚本摘除 CoC 规则（规则已记录所属 runtime，需要补脚本维度）。
func (d *Dice) clearCocExtraRules() {
	d.cocRulesMu.Lock()
	d.cocExtraRules = nil
	d.cocRulesMu.Unlock()
}

func (d *Dice) cocExtraRule(index int) (CocRuleInfo, bool) {
	d.cocRulesMu.RLock()
	rule, ok := d.cocExtraRules[index]
	d.cocRulesMu.RUnlock()
	return rule, ok
}

// CocExtraRulesSnapshot returns metadata, never owner-bound callback handles.
func (d *Dice) CocExtraRulesSnapshot() []CocRuleInfo {
	d.cocRulesMu.RLock()
	rules := make([]CocRuleInfo, 0, len(d.cocExtraRules))
	for _, rule := range d.cocExtraRules {
		rules = append(rules, CocRuleInfo{Index: rule.Index, Key: rule.Key, Name: rule.Name, Desc: rule.Desc})
	}
	d.cocRulesMu.RUnlock()
	sort.Slice(rules, func(i, j int) bool { return rules[i].Index < rules[j].Index })
	return rules
}

func (rule CocRuleInfo) check(ctx *MsgContext, d100, value int64, difficulty int) CocRuleCheckRet {
	if !rule.jsBound {
		return rule.Check(ctx, d100, value, difficulty)
	}
	realm := rule.jsRealm
	realm.Message = ctx
	ctx.messageJSExecution()
	var result CocRuleCheckRet
	manager := ctx.Dice.ExtLoopManager
	err := errJSCallbackStaleGeneration
	if manager != nil {
		err = manager.dispatchJSCallback(jsCallbackRequest{
			Generation: rule.jsGeneration, Realm: &realm, Kind: jsCallbackCommand,
			Callback: func() { result = rule.Check(ctx, d100, value, difficulty) },
		}, false)
	}
	if err != nil {
		ctx.recordJSExecutionError(err)
		panic(fmt.Errorf("custom CoC rule %d: %w", rule.Index, err))
	}
	return result
}
