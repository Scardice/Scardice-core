package dice

import "Scardice-core/utils/jsengine"

func (d *Dice) configuredJSEngine() (jsengine.EngineID, error) {
	return jsengine.ParseEngineID(d.Config.JsEngine)
}
