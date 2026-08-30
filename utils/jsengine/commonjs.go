package jsengine

import (
	"path"
	"strconv"
)

// CommonJSProgram wraps one source file in the CommonJS contract used by the
// plugin runtime. Callers execute the returned program in their own realm.
func CommonJSProgram(filename, source string) string {
	moduleID := path.Clean(filename)
	return `(() => {
	const id = ` + strconv.Quote(moduleID) + `;
	const source = ` + strconv.Quote(source) + `;
	const modules = globalThis.__scardiceCjsModules ||
		(globalThis.__scardiceCjsModules = Object.create(null));
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
