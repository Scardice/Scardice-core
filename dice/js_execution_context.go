package dice

import "Scardice-core/utils/jsengine"

// jsExecutionContext identifies the script/plugin that owns one JS callback.
// The value is carried by the engine loop and is never stored on Dice, so
// concurrent runtime generations cannot overwrite one another.
type jsExecutionContext struct {
	Plugin *ExtInfo
	Script *JsScriptInfo
}

// jsExecutionContextIdentity is the comparable identity of one execution
// context. Callers allocate a fresh context per realm entry, so providers need
// this identity to reuse one token instead of adding one per call.
type jsExecutionContextIdentity struct {
	Plugin *ExtInfo
	Script *JsScriptInfo
}

func (c *jsExecutionContext) ContextKey() any {
	if c == nil {
		return nil
	}
	return jsExecutionContextIdentity{Plugin: c.Plugin, Script: c.Script}
}

type jsExecutionContextKey struct{}

func jsOpaqueExecutionContext(value any) *jsExecutionContext {
	context, _ := value.(*jsExecutionContext)
	return context
}

func jsContextForPlugin(plugin *ExtInfo) *jsExecutionContext {
	if plugin == nil {
		return nil
	}
	return &jsExecutionContext{Plugin: plugin, Script: plugin.Source}
}

func jsExecutionContextFor(loop jsengine.Loop) *jsExecutionContext {
	if loop == nil {
		return nil
	}
	context, ok := jsengine.CurrentContext(loop).(*jsExecutionContext)
	if !ok {
		return nil
	}
	return context
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
