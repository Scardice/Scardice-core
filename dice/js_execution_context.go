package dice

import "Scardice-core/utils/jsengine"

// jsExecutionContext identifies the script/plugin that owns one JS callback.
// The value is carried by the engine loop and is never stored on Dice, so
// concurrent runtime generations cannot overwrite one another.
type jsExecutionContext struct {
	Plugin  *ExtInfo
	Script  *JsScriptInfo
	Message *MsgContext
	// CompatibilityMode is live by default for existing callers. Replay and
	// rebuild callers must set it explicitly before entering host services.
	CompatibilityMode JSCompatibilityExecutionMode
	ExternalEffects   *JSExternalEffectTracker
	// Completion marks a context captured earlier and re-entered by a host
	// service when its work finished (fetch, filesystem, ...). It only changes
	// how the invocation is classified for accounting; identity is unchanged.
	Completion bool
}

// jsCompletionContext derives the context under which a host service resumes
// script after asynchronous work. The original context is left untouched
// because the callback that started the work may still be running under it.
func jsCompletionContext(context any) any {
	original, ok := context.(*jsExecutionContext)
	if !ok || original == nil || original.Completion {
		return context
	}
	derived := *original
	derived.Completion = true
	return &derived
}

// jsExecutionContextIdentity is the comparable identity of one execution
// context. Callers allocate a fresh context per realm entry, so providers need
// this identity to reuse one token instead of adding one per call.
type jsExecutionContextIdentity struct {
	Plugin  *ExtInfo
	Script  *JsScriptInfo
	Message *MsgContext
}

func (c *jsExecutionContext) ContextKey() any {
	if c == nil {
		return nil
	}
	return jsExecutionContextIdentity{Plugin: c.Plugin, Script: c.Script, Message: c.Message}
}

type jsExecutionContextKey struct{}

var revokedJSExecutionContext = func() *jsExecutionContext {
	message := &MsgContext{}
	message.executionReleased.Store(true)
	return &jsExecutionContext{Message: message}
}()

func jsOpaqueExecutionContext(value any) *jsExecutionContext {
	switch context := value.(type) {
	case *jsExecutionContext:
		return context
	case jsengine.RevokedExecutionScope, *jsengine.RevokedExecutionScope:
		return revokedJSExecutionContext
	default:
		return nil
	}
}

func jsContextForPlugin(plugin *ExtInfo) *jsExecutionContext {
	if plugin == nil {
		return nil
	}
	return &jsExecutionContext{Plugin: plugin, Script: plugin.Source}
}

func jsContextForMessage(plugin *ExtInfo, message *MsgContext) *jsExecutionContext {
	context := jsContextForPlugin(plugin)
	if context == nil {
		context = &jsExecutionContext{}
	}
	context.Message = message
	if message != nil {
		message.messageJSExecution()
	}
	return context
}

// Resolve authority from the calling owner, not from the target plugin or a
// Dice-global current transaction; another runtime may be executing concurrently.
func (d *Dice) currentJSMessageContext() *MsgContext {
	if d == nil || d.ExtLoopManager == nil {
		return nil
	}
	manager := d.ExtLoopManager
	manager.loopLock.RLock()
	defer manager.loopLock.RUnlock()
	for _, instance := range manager.instances {
		if jsengine.InOwner(instance.loop) {
			if execution := jsExecutionContextFor(instance.loop); execution != nil {
				return execution.Message
			}
		}
	}
	return nil
}

func jsExecutionContextFor(loop jsengine.Loop) *jsExecutionContext {
	if loop == nil {
		return nil
	}
	return jsOpaqueExecutionContext(jsengine.CurrentContext(loop))
}

func jsContextPlugin(context *jsExecutionContext) *ExtInfo {
	if context == nil {
		return nil
	}
	if context.Plugin != nil {
		return context.Plugin.GetRealExt()
	}
	return nil
}

func jsContextScript(context *jsExecutionContext) *JsScriptInfo {
	if context == nil {
		return nil
	}
	if context.Script != nil {
		return context.Script
	}
	if plugin := jsContextPlugin(context); plugin != nil {
		return plugin.Source
	}
	return nil
}

func jsContextSource(context *jsExecutionContext) *JsScriptInfo {
	if script := jsContextScript(context); script != nil {
		return script
	}
	if plugin := jsContextPlugin(context); plugin != nil {
		return plugin.Source
	}
	return nil
}
