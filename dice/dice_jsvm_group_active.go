package dice

import (
	"github.com/dop251/goja"
)

// jsGroupActiveAccessor 把 GroupInfo.Active 从 goja 的结构体字段映射中隐藏，
// 再用 Object.prototype 上的访问器把 ctx.group.active 转发到加锁的
// IsActiveRaw/SetActiveRaw。这样脚本仍然可以读写 ctx.group.active，但不会绕过
// activeMu 与保存/通知协程竞争。
//
// 访问器只对带 isGroupInfoJS 方法的 GroupInfo 生效；普通 JS 对象赋值 active
// 时仍会创建自己的数据属性，保持原有 JSON.stringify / 枚举行为。
const jsGroupActiveAccessor = `(function () {
	var proto = Object.prototype;
	if (Object.prototype.hasOwnProperty.call(proto, 'active')) {
		return;
	}
	function isGroupInfo(obj) {
		return typeof obj.isGroupInfoJS === 'function' && obj.isGroupInfoJS();
	}
	Object.defineProperty(proto, 'active', {
		configurable: false,
		enumerable: false,
		get: function () {
			if (isGroupInfo(this)) {
				return this.isActiveRaw();
			}
			return undefined;
		},
		set: function (value) {
			if (isGroupInfo(this)) {
				this.setActiveRaw(!!value);
				return;
			}
			if (this === proto) {
				return;
			}
			try {
				Object.defineProperty(this, 'active', {
					value: value,
					writable: true,
					enumerable: true,
					configurable: true
				});
			} catch (e) {
				// 非扩展对象且不可扩展时保持静默；正常对象不会走到这里。
			}
		}
	});
})();`

func installJSGroupActiveAccessor(vm *goja.Runtime) error {
	_, err := vm.RunString(jsGroupActiveAccessor)
	return err
}
