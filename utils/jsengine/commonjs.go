package jsengine

import (
	"path"
	"strconv"
)

// CommonJSProgram wraps one source file in the CommonJS contract used by the
// plugin runtime. Callers execute the returned program in their own realm.
// TODO(局部重载/更新同名插件): 模块按文件名缓存在 globalThis.__scardiceCjsModules 里，同名文件再次加载不会重新执行，
// 加载中途抛错的脚本也会以半成品留在缓存中。局部更新、失败重试都需要按模块 ID 驱逐缓存的原语。
// subTODO(局部重载): 驱逐原语（Goja 可直接删除缓存项；QuickJS 原生 provider 能否卸载模块尚未验证）。
// subTODO(局部重载): require 解析时记录“调用方 -> 被依赖模块”的边，作为未声明依赖的补充。
func CommonJSProgram(filename, source string) string {
	moduleID := path.Clean(filename)
	return `(() => {
	const id = ` + strconv.Quote(moduleID) + `;
	const source = ` + strconv.Quote(source) + `;
	const modules = globalThis.__scardiceCjsModules ||
		(globalThis.__scardiceCjsModules = Object.create(null));
	if (!Object.prototype.hasOwnProperty.call(modules, "crypto") &&
		typeof globalThis.crypto === "object" && globalThis.crypto !== null) {
		modules.crypto = { exports: globalThis.crypto };
	}
	if (!globalThis.require) {
		globalThis.require = specifier => {
			if (!Object.prototype.hasOwnProperty.call(modules, specifier)) {
				throw new Error("Cannot find module '" + specifier + "'");
			}
			return modules[specifier].exports;
		};
	}
	if (Object.prototype.hasOwnProperty.call(modules, id)) {
		return modules[id].exports;
	}

	const module = { exports: {} };
	modules[id] = module;
	const dirname = ` + strconv.Quote(path.Dir(moduleID)) + `;
	const require = specifier => {
		let resolved = specifier;
		if (specifier.startsWith(".")) {
			const parts = (dirname + "/" + specifier).split("/");
			const normalized = [];
			for (const part of parts) {
				if (!part || part === ".") continue;
				if (part === "..") normalized.pop();
				else normalized.push(part);
			}
			resolved = "/" + normalized.join("/");
			if (!Object.prototype.hasOwnProperty.call(modules, resolved) &&
				Object.prototype.hasOwnProperty.call(modules, resolved + ".js")) {
				resolved += ".js";
			}
		}
		if (!Object.prototype.hasOwnProperty.call(modules, resolved)) {
			throw new Error("Cannot find module '" + specifier + "' from '" + id + "'");
		}
		return modules[resolved].exports;
	};
	const factory = Function("exports", "require", "module", "__filename", "__dirname", source);
	factory(module.exports, require, module, id, dirname);
	return module.exports;
})()`
}
