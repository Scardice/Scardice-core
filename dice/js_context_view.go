package dice

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sync"

	ds "github.com/sealdice/dicescript"

	"Scardice-core/utils/jsengine/hostbridge"
)

var (
	ErrJSInvocationExpired       = errors.New("javascript invocation expired")
	ErrJSInvocationCrossRealm    = errors.New("javascript invocation belongs to another realm")
	ErrJSImmutableHostProperty   = errors.New("javascript host property is immutable")
	ErrJSUnsupportedHostProperty = errors.New("javascript host property is unsupported")
)

var jsInvocationRegistryInitMu sync.Mutex

type jsInvocationRegistryKey struct {
	source      *JsScriptInfo
	plugin      *ExtInfo
	generation  int64
	transaction *DurableCallbackTransaction
	binding     *jsPersistentBindingLifecycle
}

type jsEndpointIdentity struct{ id string }

type jsInvocationRegistry struct {
	dice        *Dice
	source      *JsScriptInfo
	plugin      *ExtInfo
	generation  int64
	message     *MsgContext
	binding     *jsPersistentBindingLifecycle
	transaction *DurableCallbackTransaction

	mu      sync.Mutex
	objects map[any]hostbridge.ControlledObject
	groups  map[*GroupInfo]*MsgContext
	players map[*GroupPlayerInfo]struct{}
}

func newJSInvocationRegistry(c *jsExecutionContext, source *JsScriptInfo, generation int64) *jsInvocationRegistry {
	plugin := jsContextPlugin(c)
	if source != nil {
		plugin = nil
	}
	registry := &jsInvocationRegistry{
		dice: c.Dice, source: source, plugin: plugin, generation: generation, message: c.Message, binding: c.binding,
		transaction: c.Transaction,
		objects:     make(map[any]hostbridge.ControlledObject),
		groups:      make(map[*GroupInfo]*MsgContext),
		players:     make(map[*GroupPlayerInfo]struct{}),
	}
	if registry.dice == nil && c.Message != nil {
		registry.dice = c.Message.Dice
	}
	registry.allowContext(c.Message)
	return registry
}

func (c *jsExecutionContext) invocationRegistry() *jsInvocationRegistry {
	if c == nil {
		return nil
	}
	if c.registry != nil {
		return c.registry
	}
	source := jsContextSource(c)
	generation := jsContextGeneration(c)
	if c.Message != nil {
		execution := c.Message.messageJSExecution()
		plugin := jsContextPlugin(c)
		if source != nil {
			plugin = nil
		}
		key := jsInvocationRegistryKey{
			source: source, plugin: plugin, generation: generation, transaction: c.Transaction, binding: c.binding,
		}
		execution.registryMu.Lock()
		if execution.registries == nil {
			execution.registries = make(map[jsInvocationRegistryKey]*jsInvocationRegistry)
		}
		registry := execution.registries[key]
		if registry == nil {
			registry = newJSInvocationRegistry(c, source, generation)
			execution.registries[key] = registry
		}
		c.registry = registry
		execution.registryMu.Unlock()
		return registry
	}
	jsInvocationRegistryInitMu.Lock()
	defer jsInvocationRegistryInitMu.Unlock()
	if c.registry == nil {
		c.registry = newJSInvocationRegistry(c, source, generation)
	}
	return c.registry
}

func jsContextGeneration(c *jsExecutionContext) int64 {
	if c == nil {
		return 0
	}
	if plugin := jsContextPlugin(c); plugin != nil && plugin.JSLoopVersion != 0 {
		return plugin.JSLoopVersion
	}
	if script := jsContextSource(c); script != nil {
		script.runtimeStateMu.RLock()
		generation := script.runtimeGeneration
		script.runtimeStateMu.RUnlock()
		return generation
	}
	return 0
}

func (c *jsExecutionContext) persistentInvocation() (*jsExecutionContext, error) {
	if c == nil {
		return nil, ErrJSInvocationExpired
	}
	if !c.persistentScope() {
		return c, nil
	}
	registry := c.invocationRegistry()
	if registry == nil || registry.dice == nil {
		return nil, ErrJSInvocationExpired
	}
	if registry.dice.ExtLoopManager == nil {
		return nil, ErrJSInvocationExpired
	}
	loop, err := registry.dice.ExtLoopManager.GetLoop(registry.generation)
	if err != nil {
		return nil, errors.Join(ErrJSInvocationExpired, err)
	}
	active := jsExecutionContextFor(loop)
	if active == nil {
		return nil, ErrJSInvocationExpired
	}
	if active.persistentScope() {
		if active.invocationRegistry() != registry {
			return nil, ErrJSInvocationExpired
		}
		delegated := registry.binding.activeInvocation()
		if delegated == nil || delegated == active {
			return active, nil
		}
		if err := delegated.ExecutionContext().Err(); err != nil {
			return nil, errors.Join(ErrJSInvocationExpired, err)
		}
		active = delegated
	}
	activeRegistry := active.invocationRegistry()
	if registry.source != nil && activeRegistry.source != registry.source {
		return nil, ErrJSInvocationCrossRealm
	}
	if registry.source == nil && registry.plugin != nil && activeRegistry.plugin != registry.plugin {
		return nil, ErrJSInvocationCrossRealm
	}
	if registry.binding != nil && activeRegistry.binding != registry.binding {
		return nil, ErrJSInvocationCrossRealm
	}
	if registry.generation != 0 && activeRegistry.generation != registry.generation {
		return nil, ErrJSInvocationCrossRealm
	}
	return active, nil
}

// HostWrap implements hostbridge.ControlledObjectScope. Persistent load-time
// binding scopes resolve the invocation currently entering the same generation;
// ordinary message/task scopes stay pinned to their originating root.
func (c *jsExecutionContext) HostWrap(value any) (hostbridge.ControlledObject, bool, error) {
	target, err := c.persistentInvocation()
	if err != nil {
		return nil, false, err
	}
	if target != c {
		return target.HostWrap(value)
	}
	if err := c.ExecutionContext().Err(); err != nil {
		return nil, false, errors.Join(ErrJSInvocationExpired, err)
	}
	return c.invocationRegistry().wrap(value)
}

func (r *jsInvocationRegistry) wrap(value any) (hostbridge.ControlledObject, bool, error) {
	if value == nil {
		return nil, false, nil
	}
	if controlled, ok := value.(hostbridge.ControlledObject); ok {
		return controlled, true, nil
	}
	switch typed := value.(type) {
	case *MsgContext:
		if typed == nil {
			return nil, false, nil
		}
		if err := r.authorizeContext(typed); err != nil {
			return nil, false, err
		}
		r.allowContext(typed)
		return r.object(typed, func() hostbridge.ControlledObject {
			return &jsControlledContext{registry: r, value: typed}
		}), true, nil
	case *GroupInfo:
		if typed == nil {
			return nil, false, nil
		}
		context, ok := r.groupContext(typed)
		if !ok {
			return nil, false, fmt.Errorf("%w: group facade changed", ErrJSInvocationCrossRealm)
		}
		return r.object(typed, func() hostbridge.ControlledObject {
			return &jsControlledGroup{registry: r, context: context, value: typed}
		}), true, nil
	case *GroupPlayerInfo:
		if typed == nil {
			return nil, false, nil
		}
		if !r.ownsPlayer(typed) {
			return nil, false, fmt.Errorf("%w: player facade changed", ErrJSInvocationCrossRealm)
		}
		return r.object(typed, func() hostbridge.ControlledObject {
			return &jsControlledPlayer{registry: r, value: typed}
		}), true, nil
	case *EndPointInfo:
		if typed == nil {
			return nil, false, nil
		}
		// Endpoint DTOs are detached projections rebuilt on every read, so the
		// endpoint ID is the identity: one invocation exposes one JavaScript
		// object per endpoint no matter which view reached the host boundary.
		var key any = typed
		if typed.ID != "" {
			key = jsEndpointIdentity{id: typed.ID}
		}
		return r.object(key, func() hostbridge.ControlledObject {
			return &jsControlledEndpoint{registry: r, value: typed}
		}), true, nil
	default:
		return nil, false, nil
	}
}

func (r *jsInvocationRegistry) object(key any, create func() hostbridge.ControlledObject) hostbridge.ControlledObject {
	r.mu.Lock()
	defer r.mu.Unlock()
	if object := r.objects[key]; object != nil {
		return object
	}
	object := create()
	r.objects[key] = object
	return object
}

func jsRootMessage(message *MsgContext) *MsgContext {
	for message != nil && message.executionParent != nil {
		message = message.executionParent
	}
	return message
}

func (r *jsInvocationRegistry) authorizeContext(message *MsgContext) error {
	if r == nil || message == nil {
		return ErrJSInvocationExpired
	}
	if r.message == nil {
		return fmt.Errorf("%w: root has no message authority", ErrJSInvocationCrossRealm)
	}
	if jsRootMessage(message) != jsRootMessage(r.message) {
		return fmt.Errorf("%w: message root changed", ErrJSInvocationCrossRealm)
	}
	if message.callbackTransaction != r.transaction {
		return fmt.Errorf("%w: transaction changed", ErrJSInvocationCrossRealm)
	}
	return nil
}

func (r *jsInvocationRegistry) allowContext(message *MsgContext) {
	if r == nil || message == nil {
		return
	}
	r.mu.Lock()
	if message.Group != nil {
		if _, exists := r.groups[message.Group]; !exists {
			r.groups[message.Group] = message
		}
	}
	if message.Player != nil {
		r.players[message.Player] = struct{}{}
	}
	r.mu.Unlock()
}

func (r *jsInvocationRegistry) groupContext(group *GroupInfo) (*MsgContext, bool) {
	if r == nil || group == nil {
		return nil, false
	}
	r.mu.Lock()
	context, ok := r.groups[group]
	r.mu.Unlock()
	return context, ok
}

func (r *jsInvocationRegistry) ownsPlayer(player *GroupPlayerInfo) bool {
	if r == nil || player == nil {
		return false
	}
	r.mu.Lock()
	_, ok := r.players[player]
	r.mu.Unlock()
	return ok
}

func (r *jsInvocationRegistry) authorizeMutation() error {
	if r == nil || r.dice == nil {
		return ErrJSInvocationExpired
	}
	if r.dice.ExtLoopManager == nil {
		return ErrJSInvocationExpired
	}
	loop, err := r.dice.ExtLoopManager.GetLoop(r.generation)
	if err != nil {
		return errors.Join(ErrJSInvocationExpired, err)
	}
	active := jsExecutionContextFor(loop)
	if active == nil || active.invocationRegistry() != r {
		return ErrJSInvocationExpired
	}
	if err := active.ExecutionContext().Err(); err != nil {
		return errors.Join(ErrJSInvocationExpired, err)
	}
	if r.message != nil {
		if err := r.message.checkExecution(); err != nil {
			return errors.Join(ErrJSInvocationExpired, err)
		}
	}
	if r.transaction != nil {
		domain := r.transaction.Domain()
		if domain == nil {
			return ErrJSInvocationExpired
		}
		if err := domain.CheckOpen(); err != nil {
			return errors.Join(ErrJSInvocationExpired, err)
		}
	}
	return nil
}

func (r *jsInvocationRegistry) unwrap(target reflect.Type, expected reflect.Type, value any) (any, error) {
	if target != expected {
		return nil, fmt.Errorf("%w: cannot unwrap %s as %s", ErrJSInvocationCrossRealm, expected, target)
	}
	if err := r.authorizeMutation(); err != nil {
		return nil, err
	}
	return value, nil
}

func controlledObject(r *jsInvocationRegistry, value any) (hostbridge.ControlledObject, error) {
	object, wrapped, err := r.wrap(value)
	if err != nil {
		return nil, err
	}
	if !wrapped {
		return nil, fmt.Errorf("%w: %T", ErrJSUnsupportedHostProperty, value)
	}
	return object, nil
}

type jsControlledContext struct {
	registry *jsInvocationRegistry
	value    *MsgContext
}

var jsContextHostKeys = []string{
	"commandHideFlag", "createVmIfNotExists", "delegateText", "endPoint", "eval", "evalFString",
	"extensionConfigSet", "extensionConfigValue", "extensionStorageGet", "extensionStorageSet",
	"genDefaultRollVmConfig", "group", "initSplitKey", "isCommandReplied", "isCurGroupBotOn",
	"isPrivate", "notice", "noticeCrossPlatform", "player", "privilegeLevel", "randIntn", "roll",
	"roll64", "setCommandReplied", "setSplitKey", "shallowCopy", "shuffle", "splitText", "translateSplit",
}

func (o *jsControlledContext) HostGet(name string) (any, bool, error) {
	if o == nil || o.value == nil || o.registry == nil {
		return nil, false, ErrJSInvocationExpired
	}
	ctx := o.value
	switch name {
	case "group":
		if ctx.Group == nil {
			return nil, true, nil
		}
		value := o.registry.object(ctx.Group, func() hostbridge.ControlledObject {
			return &jsControlledGroup{registry: o.registry, context: ctx, value: ctx.Group}
		})
		return value, true, nil
	case "player":
		if ctx.Player == nil {
			return nil, true, nil
		}
		value := o.registry.object(ctx.Player, func() hostbridge.ControlledObject {
			return &jsControlledPlayer{registry: o.registry, value: ctx.Player}
		})
		return value, true, nil
	case "endPoint":
		if ctx.EndPoint == nil {
			return nil, true, nil
		}
		value, err := controlledObject(o.registry, ctx.EndPoint)
		return value, true, err
	case "isCurGroupBotOn":
		return ctx.IsCurGroupBotOn, true, nil
	case "isPrivate":
		return ctx.IsPrivate, true, nil
	case "commandHideFlag":
		return ctx.CommandHideFlag, true, nil
	case "privilegeLevel":
		return ctx.PrivilegeLevel, true, nil
	case "delegateText":
		return ctx.DelegateText, true, nil
	case "roll":
		return ctx.Roll, true, nil
	case "roll64":
		return ctx.Roll64, true, nil
	case "randIntn":
		return ctx.RandIntn, true, nil
	case "shuffle":
		return ctx.Shuffle, true, nil
	case "isCommandReplied":
		return ctx.IsCommandReplied, true, nil
	case "setCommandReplied":
		return func(replied bool) error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			ctx.SetCommandReplied(replied)
			return nil
		}, true, nil
	case "setSplitKey":
		return func(key string) error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			ctx.SetSplitKey(key)
			return nil
		}, true, nil
	case "initSplitKey":
		return func() error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			ctx.InitSplitKey()
			return nil
		}, true, nil
	case "translateSplit":
		return func(text string) (string, error) {
			if err := o.registry.authorizeMutation(); err != nil {
				return "", err
			}
			return ctx.TranslateSplit(text), nil
		}, true, nil
	case "splitText":
		return func(text string) ([]string, error) {
			if err := o.registry.authorizeMutation(); err != nil {
				return nil, err
			}
			return ctx.SplitText(text), nil
		}, true, nil
	case "shallowCopy":
		return func() (*MsgContext, error) {
			if err := o.registry.authorizeMutation(); err != nil {
				return nil, err
			}
			return ctx.ShallowCopy(), nil
		}, true, nil
	case "notice":
		return func(text string, kinds ...NoticeType) error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			ctx.Notice(text, kinds...)
			return nil
		}, true, nil
	case "noticeCrossPlatform":
		return func(text string, kinds ...NoticeType) error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			ctx.NoticeCrossPlatform(text, kinds...)
			return nil
		}, true, nil
	case "extensionStorageSet":
		return func(extensionID, key, value string) error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			return ctx.ExtensionStorageSet(extensionID, key, value)
		}, true, nil
	case "extensionStorageGet":
		return func(extensionID, key string) (string, error) {
			if err := o.registry.authorizeMutation(); err != nil {
				return "", err
			}
			return ctx.ExtensionStorageGet(extensionID, key)
		}, true, nil
	case "extensionConfigSet":
		return func(extensionID, key string, value any) error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			return ctx.ExtensionConfigSet(extensionID, key, value)
		}, true, nil
	case "extensionConfigValue":
		return func(extensionID, key string) (any, bool, error) {
			if err := o.registry.authorizeMutation(); err != nil {
				return nil, false, err
			}
			return ctx.ExtensionConfigValue(extensionID, key)
		}, true, nil
	case "genDefaultRollVmConfig":
		return ctx.GenDefaultRollVmConfig, true, nil
	case "eval":
		return func(expression string, config *ds.RollConfig) (*VMResultV2, error) {
			if err := o.registry.authorizeMutation(); err != nil {
				return nil, err
			}
			return ctx.Eval(expression, config), nil
		}, true, nil
	case "evalFString":
		return func(expression string, config *ds.RollConfig) (*VMResultV2, error) {
			if err := o.registry.authorizeMutation(); err != nil {
				return nil, err
			}
			return ctx.EvalFString(expression, config), nil
		}, true, nil
	case "createVmIfNotExists":
		return func() error {
			if err := o.registry.authorizeMutation(); err != nil {
				return err
			}
			ctx.CreateVmIfNotExists()
			return nil
		}, true, nil
	default:
		return nil, false, nil
	}
}

func (o *jsControlledContext) HostSet(name string, value any) error {
	if o == nil || o.value == nil || o.registry == nil {
		return ErrJSInvocationExpired
	}
	if err := o.registry.authorizeMutation(); err != nil {
		return err
	}
	ctx := o.value
	switch name {
	case "isCurGroupBotOn":
		converted, ok := value.(bool)
		if !ok {
			return jsHostTypeError(name, "boolean", value)
		}
		ctx.IsCurGroupBotOn = converted
	case "isPrivate":
		converted, ok := value.(bool)
		if !ok {
			return jsHostTypeError(name, "boolean", value)
		}
		ctx.IsPrivate = converted
	case "commandHideFlag":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		ctx.CommandHideFlag = converted
	case "privilegeLevel":
		converted, ok := jsHostInt(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		ctx.PrivilegeLevel = converted
	case "delegateText":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		ctx.DelegateText = converted
	case "group", "player", "endPoint":
		return fmt.Errorf("%w: %s", ErrJSImmutableHostProperty, name)
	default:
		return fmt.Errorf("%w: %s", ErrJSUnsupportedHostProperty, name)
	}
	return nil
}

func (o *jsControlledContext) HostKeys() []string { return jsContextHostKeys }
func (o *jsControlledContext) HostUnwrap(target reflect.Type) (any, error) {
	return o.registry.unwrap(target, reflect.TypeFor[*MsgContext](), o.value)
}

type jsControlledGroup struct {
	registry *jsInvocationRegistry
	context  *MsgContext
	value    *GroupInfo
}

var jsGroupHostKeys = []string{
	"active", "channelId", "cocRuleIndex", "defaultHelpGroup", "diceId", "diceSideExpr", "diceSideNum",
	"enteredTime", "groupId", "groupName", "groupWelcomeMessage", "guildId", "helpPackages", "inviteUserId",
	"logCurName", "logOn", "recentDiceSendTime", "rollShaperMode", "showGroupWelcome", "system",
}

func (o *jsControlledGroup) HostGet(name string) (any, bool, error) {
	if o == nil || o.value == nil {
		return nil, false, ErrJSInvocationExpired
	}
	group := o.value
	switch name {
	case "active":
		return group.Active(), true, nil
	case "diceId":
		return group.DiceID(), true, nil
	case "groupId":
		return group.GroupID(), true, nil
	case "guildId":
		return group.GuildID(), true, nil
	case "channelId":
		return group.ChannelID(), true, nil
	case "groupName":
		return group.GroupName(), true, nil
	case "system":
		return group.System(), true, nil
	case "diceSideNum":
		return group.DiceSideNum(), true, nil
	case "diceSideExpr":
		return group.DiceSideExpr(), true, nil
	case "rollShaperMode":
		return group.RollShaperMode(), true, nil
	case "cocRuleIndex":
		return group.CocRuleIndex(), true, nil
	case "defaultHelpGroup":
		return group.DefaultHelpGroup(), true, nil
	case "helpPackages":
		return group.HelpPackageIDs(), true, nil
	case "showGroupWelcome":
		return group.ShowGroupWelcome(), true, nil
	case "groupWelcomeMessage":
		return group.GroupWelcomeMessage(), true, nil
	case "enteredTime":
		return group.EnteredAt(), true, nil
	case "inviteUserId":
		return group.InviteUserID(), true, nil
	case "recentDiceSendTime":
		return group.RecentDiceSendTime(), true, nil
	case "logOn":
		state, err := o.logState()
		return state.On, true, err
	case "logCurName":
		state, err := o.logState()
		return state.Name, true, err
	default:
		return nil, false, nil
	}
}

func (o *jsControlledGroup) logState() (GroupLogState, error) {
	if o.registry.authorizeMutation() == nil && o.context != nil {
		return o.context.ReadGroupLogState()
	}
	return o.value.GetLogState()
}

func (o *jsControlledGroup) HostSet(name string, value any) error {
	if o == nil || o.value == nil || o.registry == nil {
		return ErrJSInvocationExpired
	}
	if err := o.registry.authorizeMutation(); err != nil {
		return err
	}
	group := o.value
	switch name {
	case "active":
		converted, ok := value.(bool)
		if !ok {
			return jsHostTypeError(name, "boolean", value)
		}
		if o.context == nil || o.context.EndPoint == nil {
			return ErrJSInvocationExpired
		}
		return group.SetDiceActive(o.context.EndPoint.UserID, converted)
	case "groupName":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetGroupName(converted)
	case "guildId":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetGuildID(converted)
	case "channelId":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetChannelID(converted)
	case "system":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetSystem(converted)
	case "diceSideNum":
		converted, ok := jsHostInt64(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		return group.SetDiceSideNum(converted)
	case "diceSideExpr":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetDiceSideExpr(converted)
	case "rollShaperMode":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetRollShaperMode(converted)
	case "cocRuleIndex":
		converted, ok := jsHostInt(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		return group.SetCocRuleIndex(converted)
	case "defaultHelpGroup":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetDefaultHelpGroup(converted)
	case "helpPackages":
		converted, ok := jsHostStrings(value)
		if !ok {
			return jsHostTypeError(name, "string array", value)
		}
		return group.SetHelpPackageIDs(converted)
	case "showGroupWelcome":
		converted, ok := value.(bool)
		if !ok {
			return jsHostTypeError(name, "boolean", value)
		}
		return group.SetShowGroupWelcome(converted)
	case "groupWelcomeMessage":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetGroupWelcomeMessage(converted)
	case "enteredTime":
		converted, ok := jsHostInt64(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		return group.SetEnteredAt(converted)
	case "inviteUserId":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return group.SetInviteUserID(converted)
	case "recentDiceSendTime":
		converted, ok := jsHostInt64(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		group.SetRecentDiceSendTime(converted)
		return nil
	case "logOn":
		converted, ok := value.(bool)
		if !ok {
			return jsHostTypeError(name, "boolean", value)
		}
		if o.context == nil {
			return ErrJSInvocationExpired
		}
		return o.context.SetGroupLogOn(converted)
	case "logCurName":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		if o.context == nil {
			return ErrJSInvocationExpired
		}
		return o.context.SetGroupLogName(converted)
	case "diceId", "groupId":
		return fmt.Errorf("%w: %s", ErrJSImmutableHostProperty, name)
	default:
		return fmt.Errorf("%w: %s", ErrJSUnsupportedHostProperty, name)
	}
}

func (o *jsControlledGroup) HostKeys() []string { return jsGroupHostKeys }
func (o *jsControlledGroup) HostUnwrap(target reflect.Type) (any, error) {
	return o.registry.unwrap(target, reflect.TypeFor[*GroupInfo](), o.value)
}

type jsControlledPlayer struct {
	registry *jsInvocationRegistry
	value    *GroupPlayerInfo
}

var jsPlayerHostKeys = []string{
	"autoSetNameTemplate", "diceId", "diceSideNum", "groupId", "inGroup", "lastCommandTime", "name", "privilege", "userId",
}

func (o *jsControlledPlayer) HostGet(name string) (any, bool, error) {
	if o == nil || o.value == nil {
		return nil, false, ErrJSInvocationExpired
	}
	player := o.value
	switch name {
	case "diceId":
		return player.DiceID(), true, nil
	case "groupId":
		return player.GroupID(), true, nil
	case "userId":
		return player.UserID(), true, nil
	case "name":
		return player.Name(), true, nil
	case "privilege":
		return player.Privilege(), true, nil
	case "autoSetNameTemplate":
		return player.AutoSetNameTemplate(), true, nil
	case "lastCommandTime":
		return player.LastCommandAt(), true, nil
	case "diceSideNum":
		return player.DiceSideNum(), true, nil
	case "inGroup":
		return player.InGroup(), true, nil
	default:
		return nil, false, nil
	}
}

func (o *jsControlledPlayer) HostSet(name string, value any) error {
	if o == nil || o.value == nil || o.registry == nil {
		return ErrJSInvocationExpired
	}
	if err := o.registry.authorizeMutation(); err != nil {
		return err
	}
	player := o.value
	switch name {
	case "name":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return player.SetName(converted)
	case "privilege":
		converted, ok := jsHostInt(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		return player.SetPrivilege(converted)
	case "autoSetNameTemplate":
		converted, ok := value.(string)
		if !ok {
			return jsHostTypeError(name, "string", value)
		}
		return player.SetAutoSetNameTemplate(converted)
	case "lastCommandTime":
		converted, ok := jsHostInt64(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		return player.SetLastCommandAt(converted)
	case "diceSideNum":
		converted, ok := jsHostInt64(value)
		if !ok {
			return jsHostTypeError(name, "integer", value)
		}
		return player.SetDiceSideNum(converted)
	case "inGroup":
		converted, ok := value.(bool)
		if !ok {
			return jsHostTypeError(name, "boolean", value)
		}
		player.SetInGroup(converted)
		return nil
	case "diceId", "groupId", "userId":
		return fmt.Errorf("%w: %s", ErrJSImmutableHostProperty, name)
	default:
		return fmt.Errorf("%w: %s", ErrJSUnsupportedHostProperty, name)
	}
}

func (o *jsControlledPlayer) HostKeys() []string { return jsPlayerHostKeys }
func (o *jsControlledPlayer) HostUnwrap(target reflect.Type) (any, error) {
	return o.registry.unwrap(target, reflect.TypeFor[*GroupPlayerInfo](), o.value)
}

type jsControlledEndpoint struct {
	registry *jsInvocationRegistry
	value    *EndPointInfo
}

var jsEndpointHostKeys = []string{
	"baseInfo", "cmdExecutedLastTime", "cmdExecutedNum", "enable", "groupNum", "id", "nickname", "onlineTotalTime", "platform", "state", "userId",
}

func (o *jsControlledEndpoint) HostGet(name string) (any, bool, error) {
	if o == nil || o.value == nil {
		return nil, false, ErrJSInvocationExpired
	}
	endpoint := o.value
	switch name {
	case "baseInfo":
		return o, true, nil
	case "id":
		return endpoint.ID, true, nil
	case "nickname":
		return endpoint.Nickname, true, nil
	case "state":
		return endpoint.State, true, nil
	case "userId":
		return endpoint.UserID, true, nil
	case "groupNum":
		return endpoint.GroupNum, true, nil
	case "cmdExecutedNum":
		return endpoint.CmdExecutedNum, true, nil
	case "cmdExecutedLastTime":
		return endpoint.CmdExecutedLastTime, true, nil
	case "onlineTotalTime":
		return endpoint.OnlineTotalTime, true, nil
	case "platform":
		return endpoint.Platform, true, nil
	case "enable":
		return endpoint.Enable, true, nil
	default:
		return nil, false, nil
	}
}

func (o *jsControlledEndpoint) HostSet(name string, _ any) error {
	if o == nil || o.registry == nil {
		return ErrJSInvocationExpired
	}
	if err := o.registry.authorizeMutation(); err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrJSImmutableHostProperty, name)
}

func (o *jsControlledEndpoint) HostKeys() []string {
	return jsEndpointHostKeys
}

func (o *jsControlledEndpoint) HostUnwrap(target reflect.Type) (any, error) {
	return o.registry.unwrap(target, reflect.TypeFor[*EndPointInfo](), o.value)
}

func jsHostTypeError(name, want string, value any) error {
	return fmt.Errorf("%s requires %s, got %T", name, want, value)
}

func jsHostInt(value any) (int, bool) {
	converted, ok := jsHostInt64(value)
	if !ok || int64(int(converted)) != converted {
		return 0, false
	}
	return int(converted), true
}

func jsHostInt64(value any) (int64, bool) {
	if value == nil {
		return 0, false
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return reflected.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		converted := reflected.Uint()
		if converted > math.MaxInt64 {
			return 0, false
		}
		return int64(converted), true
	case reflect.Float32, reflect.Float64:
		converted := reflected.Float()
		if math.IsNaN(converted) || math.IsInf(converted, 0) || math.Trunc(converted) != converted || converted < math.MinInt64 || converted >= math.MaxInt64 {
			return 0, false
		}
		return int64(converted), true
	default:
		return 0, false
	}
}

func jsHostStrings(value any) ([]string, bool) {
	switch converted := value.(type) {
	case []string:
		return converted, true
	case []any:
		values := make([]string, len(converted))
		for index, item := range converted {
			text, ok := item.(string)
			if !ok {
				return nil, false
			}
			values[index] = text
		}
		return values, true
	default:
		return nil, false
	}
}

var (
	_ hostbridge.ControlledObjectScope = (*jsExecutionContext)(nil)
	_ hostbridge.ControlledObject      = (*jsControlledContext)(nil)
	_ hostbridge.ControlledObject      = (*jsControlledGroup)(nil)
	_ hostbridge.ControlledObject      = (*jsControlledPlayer)(nil)
	_ hostbridge.ControlledObject      = (*jsControlledEndpoint)(nil)
)
