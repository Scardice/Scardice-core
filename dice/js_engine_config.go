package dice

import "Scardice-core/utils/jsengine"

func (d *Dice) configuredJSEngine() jsengine.EngineID {
	if d == nil || d.Config() == nil {
		return jsengine.EngineGoja
	}
	id := jsengine.NormalizeEngineID(d.Config().JsEngine)
	if id == "" {
		return jsengine.EngineGoja
	}
	return id
}
