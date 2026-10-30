package dice

import (
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"

	ds "github.com/sealdice/dicescript"
)

const maxReplyExprPrograms = 256

type replyExprProgram struct {
	function *ds.VMValue
	parseErr error

	compileMu sync.Mutex
	compiled  atomic.Bool
}

type replyExprProgramCache struct {
	mu       sync.RWMutex
	entries  map[string]*replyExprProgram
	order    []string
	capacity int
}

func newReplyExprProgramCache(capacity int) *replyExprProgramCache {
	if capacity < 1 {
		capacity = 1
	}
	return &replyExprProgramCache{
		entries:  make(map[string]*replyExprProgram, capacity),
		order:    make([]string, 0, capacity),
		capacity: capacity,
	}
}

var defaultReplyExprProgramCache = newReplyExprProgramCache(maxReplyExprPrograms)

func replyExprEvalCached(ctx *MsgContext, expression string, flags RollExtraFlags) (*VMResultV2m, string, error) {
	if flags.V1Only {
		return DiceExprEvalBase(ctx, expression, flags)
	}
	return defaultReplyExprProgramCache.eval(ctx, expression, flags)
}

func (c *replyExprProgramCache) eval(ctx *MsgContext, expression string, flags RollExtraFlags) (*VMResultV2m, string, error) {
	ctx.CreateVmIfNotExists()
	vm := ctx.vm
	vm.Ret = nil
	vm.Error = nil
	vm.RestInput = ""
	vm.Matched = ""
	vm.Config.DisableStmts = flags.DisableBlock
	vm.Config.IgnoreDiv0 = flags.IgnoreDiv0
	oldDiceMaxMode := vm.Config.DiceMaxMode
	vm.Config.DiceMaxMode = flags.BigFailDiceOn
	defer func() {
		vm.Config.DiceMaxMode = oldDiceMaxMode
	}()
	if vm.Config.DefaultDiceSideExpr == "" {
		vm.Config.DefaultDiceSideExpr = strconv.FormatInt(flags.DefaultDiceSideNum, 10)
	}

	expression = CompatibleReplace(ctx, expression)
	program, complete := c.loadOrCreate(expression, vm.Config)
	if !complete {
		return runPreparedReplyExpression(vm, expression)
	}
	if program.parseErr != nil {
		return nil, "", program.parseErr
	}
	result, err := program.invoke(vm)
	if err != nil {
		return nil, "", err
	}
	vm.Ret = result
	vm.RestInput = ""
	vm.Matched = expression
	return &VMResultV2m{VMValue: result, vm: vm}, "", nil
}

func (c *replyExprProgramCache) loadOrCreate(expression string, config ds.RollConfig) (*replyExprProgram, bool) {
	c.mu.RLock()
	program, ok := c.entries[expression]
	c.mu.RUnlock()
	if ok {
		return program, true
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if program, ok = c.entries[expression]; ok {
		return program, true
	}

	probe := ds.NewVM()
	probe.Config = config
	if err := probe.Parse(expression); err != nil {
		program = &replyExprProgram{parseErr: errors.New(err.Error())}
	} else {
		offset := probe.GetParsedOffset()
		if offset < 0 || offset > len(expression) {
			return nil, false
		}
		matched := strings.TrimRightFunc(expression[:offset], unicode.IsSpace)
		if len(matched) != len(expression) {
			return nil, false
		}
		program = &replyExprProgram{function: ds.NewFunctionValRaw(&ds.FunctionData{Expr: expression})}
	}

	if len(c.entries) >= c.capacity {
		oldest := c.order[0]
		delete(c.entries, oldest)
		copy(c.order, c.order[1:])
		c.order = c.order[:len(c.order)-1]
	}
	c.entries[expression] = program
	c.order = append(c.order, expression)
	return program, true
}

func (p *replyExprProgram) invoke(vm *ds.Context) (*ds.VMValue, error) {
	invoke := func() (*ds.VMValue, error) {
		vm.Error = nil
		// FuncInvokeRaw charges 100 operations for a nested invocation. This
		// cached wrapper replaces a top-level Run, so cancel that fixed charge.
		vm.NumOpCount = -100
		result := p.function.FuncInvokeRaw(vm, nil, true)
		if vm.Error != nil {
			return nil, vm.Error
		}
		if result == nil {
			return nil, errors.New("脚本执行结果为空")
		}
		return result, nil
	}

	if p.compiled.Load() {
		return invoke()
	}
	p.compileMu.Lock()
	defer p.compileMu.Unlock()
	if p.compiled.Load() {
		return invoke()
	}
	result, err := invoke()
	p.compiled.Store(true)
	return result, err
}

func runPreparedReplyExpression(vm *ds.Context, expression string) (*VMResultV2m, string, error) {
	if err := vm.Run(expression); err != nil {
		return nil, "", err
	}
	if vm.Ret == nil {
		return nil, "", errors.New("脚本执行结果为空")
	}
	return &VMResultV2m{VMValue: vm.Ret, vm: vm}, vm.GetDetailText(), nil
}

func (c *replyExprProgramCache) size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}
