package dice

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/dop251/goja"
)

const (
	fsModuleName    = "fs"
	fsDataURIPrefix = "data://"
)

type jsFsResolvedPath struct {
	abs    string
	base   string
	isData bool
}

func jsFsEnable(vm *goja.Runtime, d *Dice) {
	_ = vm.Set(fsModuleName, jsFsEnsureObject(vm, d))
}

func jsFsRequire(vm *goja.Runtime, module *goja.Object, d *Dice) {
	_ = module.Set("exports", jsFsEnsureObject(vm, d))
}

func jsFsEnsureObject(vm *goja.Runtime, d *Dice) *goja.Object {
	if current := vm.Get(fsModuleName); !goja.IsUndefined(current) && !goja.IsNull(current) {
		if obj, ok := current.(*goja.Object); ok {
			return obj
		}
	}

	fsObj := vm.NewObject()
	_ = fsObj.Set("readFile", jsFsReadFile(vm, d))
	_ = fsObj.Set("writeFile", jsFsWriteFile(vm, d))
	_ = fsObj.Set("stat", jsFsStat(vm, d))
	_ = fsObj.Set("readDir", jsFsReadDir(vm, d))
	_ = fsObj.Set("mkdir", jsFsMkdir(vm, d))
	_ = fsObj.Set("remove", jsFsRemove(vm, d))
	_ = vm.Set(fsModuleName, fsObj)
	return fsObj
}

// jsFsResolveAbsolute 将 JS 侧路径解析为可直接用 os.* 操作的绝对路径。
//
// 三种路径风格:
//   - "data://X"  -> data/<dice-name>/extensions/<currentExtName>/data/X (按扩展隔离的用户数据)
//   - 绝对路径     -> 直传 (仅 AllowFilesystemUnrestrictedAccess=true)
//   - 普通相对路径 -> 相对核心可执行文件解析 (仅 AllowFilesystemUnrestrictedAccess=true)
func jsFsResolveAbsolute(d *Dice, raw string) (jsFsResolvedPath, error) {
	if raw == "" {
		return jsFsResolvedPath{}, errors.New("路径不能为空")
	}

	if rest, ok := strings.CutPrefix(raw, fsDataURIPrefix); ok {
		extName, err := jsFsCurrentExtName(d)
		if err != nil {
			return jsFsResolvedPath{}, err
		}
		if strings.Contains(rest, "\\") || jsFsHasWindowsVolumeName(rest) {
			return jsFsResolvedPath{}, fmt.Errorf("data:// 路径不允许穿越或绝对: %s", raw)
		}
		clean := filepath.Clean(rest)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || filepath.IsAbs(clean) {
			return jsFsResolvedPath{}, fmt.Errorf("data:// 路径不允许穿越或绝对: %s", raw)
		}
		base := filepath.Join(d.BaseConfig.DataDir, "extensions", extName, "data")
		absBase, absTarget, err := jsFsJoinInsideBase(base, clean)
		if err != nil {
			return jsFsResolvedPath{}, fmt.Errorf("data:// 路径不允许穿越或绝对: %s", raw)
		}
		return jsFsResolvedPath{abs: absTarget, base: absBase, isData: true}, nil
	}

	if !d.AdvancedConfig.AllowFilesystemUnrestrictedAccess {
		return jsFsResolvedPath{}, errors.New("当前未开启 AllowFilesystemUnrestrictedAccess,仅支持 data:// 路径")
	}

	if filepath.IsAbs(raw) {
		return jsFsResolvedPath{abs: raw}, nil
	}

	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	return jsFsResolvedPath{abs: filepath.Join(filepath.Dir(exe), raw)}, nil
}

func jsFsHasWindowsVolumeName(path string) bool {
	if filepath.VolumeName(path) != "" {
		return true
	}
	return len(path) >= 2 && path[1] == ':' && ((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z'))
}

func jsFsJoinInsideBase(base string, clean string) (string, string, error) {
	absBase, err := filepath.Abs(base)
	if err != nil {
		return "", "", err
	}
	absTarget, err := filepath.Abs(filepath.Join(absBase, clean))
	if err != nil {
		return "", "", err
	}
	if err := jsFsEnsureInsideBase(absBase, absTarget); err != nil {
		return "", "", err
	}
	return absBase, absTarget, nil
}

func jsFsEnsureInsideBase(absBase string, absTarget string) error {
	rel, err := filepath.Rel(absBase, absTarget)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("路径越过 data:// 根目录: %s", absTarget)
	}
	return nil
}

func jsFsEnsureExistingDataTargetInside(p jsFsResolvedPath) error {
	if !p.isData {
		return nil
	}
	realTarget, err := filepath.EvalSymlinks(p.abs)
	if err != nil {
		return err
	}
	absRealTarget, err := filepath.Abs(realTarget)
	if err != nil {
		return err
	}
	return jsFsEnsureInsideBase(p.base, absRealTarget)
}

func jsFsEnsureDataParentInside(p jsFsResolvedPath) error {
	if !p.isData {
		return nil
	}
	parent := filepath.Dir(p.abs)
	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}
	realParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return err
	}
	absRealParent, err := filepath.Abs(realParent)
	if err != nil {
		return err
	}
	return jsFsEnsureInsideBase(p.base, absRealParent)
}

func jsFsCurrentExtName(d *Dice) (string, error) {
	if d.JsCurrentPlugin != nil && d.JsCurrentPlugin.Name != "" {
		return d.JsCurrentPlugin.Name, nil
	}
	if d.JsLoadingScript != nil && d.JsLoadingScript.Name != "" {
		return d.JsLoadingScript.Name, nil
	}
	return "", errors.New("无法确定当前扩展身份,data:// 路径不可用")
}

func jsFsEnsureParent(p jsFsResolvedPath) error {
	if p.isData {
		return jsFsEnsureDataParentInside(p)
	}
	return os.MkdirAll(filepath.Dir(p.abs), 0755)
}

func jsFsThrow(vm *goja.Runtime, err error) {
	panic(vm.NewGoError(err))
}

func jsFsReadFile(vm *goja.Runtime, d *Dice) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		resolved, err := jsFsResolveAbsolute(d, call.Argument(0).String())
		if err != nil {
			jsFsThrow(vm, err)
		}
		if err = jsFsEnsureExistingDataTargetInside(resolved); err != nil {
			jsFsThrow(vm, err)
		}
		data, err := os.ReadFile(resolved.abs)
		if err != nil {
			jsFsThrow(vm, err)
		}
		return vm.ToValue(vm.NewArrayBuffer(data))
	}
}

func jsFsWriteFile(vm *goja.Runtime, d *Dice) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		resolved, err := jsFsResolveAbsolute(d, call.Argument(0).String())
		if err != nil {
			jsFsThrow(vm, err)
		}
		data, err := jsFsBytesFrom(call.Argument(1))
		if err != nil {
			jsFsThrow(vm, err)
		}
		mode := os.FileMode(0644)
		if len(call.Arguments) >= 3 {
			if v := call.Argument(2); !goja.IsUndefined(v) && !goja.IsNull(v) {
				mode = os.FileMode(v.ToInteger())
			}
		}
		if err := jsFsEnsureParent(resolved); err != nil {
			jsFsThrow(vm, err)
		}
		if err := os.WriteFile(resolved.abs, data, mode); err != nil {
			jsFsThrow(vm, err)
		}
		return goja.Undefined()
	}
}

func jsFsStat(vm *goja.Runtime, d *Dice) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		resolved, err := jsFsResolveAbsolute(d, call.Argument(0).String())
		if err != nil {
			jsFsThrow(vm, err)
		}
		if err = jsFsEnsureExistingDataTargetInside(resolved); err != nil {
			jsFsThrow(vm, err)
		}
		info, err := os.Stat(resolved.abs)
		if err != nil {
			jsFsThrow(vm, err)
		}
		result := vm.NewObject()
		_ = result.Set("name", info.Name())
		_ = result.Set("size", info.Size())
		_ = result.Set("mode", uint32(info.Mode()))
		_ = result.Set("modTime", info.ModTime().Unix())
		_ = result.Set("isDir", info.IsDir())
		return result
	}
}

func jsFsReadDir(vm *goja.Runtime, d *Dice) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		resolved, err := jsFsResolveAbsolute(d, call.Argument(0).String())
		if err != nil {
			jsFsThrow(vm, err)
		}
		if err = jsFsEnsureExistingDataTargetInside(resolved); err != nil {
			jsFsThrow(vm, err)
		}
		entries, err := os.ReadDir(resolved.abs)
		if err != nil {
			jsFsThrow(vm, err)
		}
		arr := make([]map[string]interface{}, 0, len(entries))
		for _, e := range entries {
			arr = append(arr, map[string]interface{}{
				"name":  e.Name(),
				"isDir": e.IsDir(),
			})
		}
		return vm.ToValue(arr)
	}
}

func jsFsMkdir(vm *goja.Runtime, d *Dice) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		resolved, err := jsFsResolveAbsolute(d, call.Argument(0).String())
		if err != nil {
			jsFsThrow(vm, err)
		}
		mode := os.FileMode(0755)
		if len(call.Arguments) >= 2 {
			if v := call.Argument(1); !goja.IsUndefined(v) && !goja.IsNull(v) {
				mode = os.FileMode(v.ToInteger())
			}
		}
		if err := jsFsEnsureDataParentInside(resolved); err != nil {
			jsFsThrow(vm, err)
		}
		if err := os.MkdirAll(resolved.abs, mode); err != nil {
			jsFsThrow(vm, err)
		}
		if err := jsFsEnsureExistingDataTargetInside(resolved); err != nil {
			jsFsThrow(vm, err)
		}
		return goja.Undefined()
	}
}

func jsFsRemove(vm *goja.Runtime, d *Dice) func(goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		resolved, err := jsFsResolveAbsolute(d, call.Argument(0).String())
		if err != nil {
			jsFsThrow(vm, err)
		}
		if err := jsFsEnsureExistingDataTargetInside(resolved); err != nil {
			jsFsThrow(vm, err)
		}
		if err := os.Remove(resolved.abs); err != nil {
			jsFsThrow(vm, err)
		}
		return goja.Undefined()
	}
}

func jsFsBytesFrom(v goja.Value) ([]byte, error) {
	if goja.IsUndefined(v) || goja.IsNull(v) {
		return nil, errors.New("写入数据不能为空")
	}
	exported := v.Export()
	switch x := exported.(type) {
	case string:
		return []byte(x), nil
	case []byte:
		return x, nil
	case []interface{}:
		out := make([]byte, len(x))
		for i, item := range x {
			n, ok := item.(int64)
			if !ok {
				if f, fok := item.(float64); fok {
					n = int64(f)
					ok = true
				}
			}
			if !ok {
				return nil, errors.New("写入数据数组元素必须是数字")
			}
			out[i] = byte(n)
		}
		return out, nil
	}
	return nil, errors.New("无法识别的写入数据类型,期望 string / []byte / number[]")
}
