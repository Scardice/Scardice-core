package dice

import "Scardice-core/utils/jsengine"

func (d *Dice) configuredJSEngine() jsengine.EngineID {
	id := jsengine.NormalizeEngineID(d.Config.JsEngine)
	if id == "" {
		return jsengine.EngineGoja
	}
	return id
}
