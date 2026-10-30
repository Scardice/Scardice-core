# JavaScript 值导出契约

`jsengine.Value` 通过 `Object()` 和 `ExportPrimitive()` 提供引擎中立的值读取边界。通用 Core 代码先识别对象，再导出原语；`Export()` 保留为引擎特定兼容接口。

## 原语转换

`ExportPrimitive() (any, error)` 返回以下稳定分类。

| JavaScript 值 | Go 结果 | 错误分类 |
| --- | --- | --- |
| `undefined`、`null` | `nil` | `jsengine.ErrNoPrimitiveValue` |
| Boolean | `bool` | `nil` |
| String | `string` | `nil` |
| Number 或原生整数 tag | 适配器原生的 `int64`、`uint64` 或 `float64` | `nil` |
| Object、Function、Host Object、Host Function | `nil` | 包装 `jsengine.ErrPrimitiveExportUnsupported` |
| Provider 判定为 stale 的值 | `nil` | Provider 生命周期错误 |

调用方把 `nil Value` 作为缺省结果分支处理。`errors.Is` 用于识别 `ErrNoPrimitiveValue` 与 `ErrPrimitiveExportUnsupported`；错误文本可附带 `object`、`host function` 或原生 tag 等诊断。

该边界的输出集合为 Boolean、String 和数值标量。对象图、map、slice、Go 指针、interface 投影和 JSON 文本采用对应的显式对象或 JSON 接口。

## 对象读取

对象结果通过 `Value.Object()` 进入 `jsengine.Object`。

1. 调用 `Object()`；返回对象时，在当前 owner 回调内使用 `Has`、`Get` 和 `Set`。
2. 返回值为空时，调用 `ExportPrimitive()` 处理原语或 nullish 分类。
3. getter 错误敏感路径使用 `FallibleObject.GetWithError`，并传播脚本异常。

Native Object 和 Host Object 都实现该对象接口。`Object.Has` 使用 Provider 的属性语义；QuickJS Provider 采用 own-property 检查。

## Promise 结果

Promise 通过 `jsengine.ObservePromise` 保持值归属。

`PromiseObserver.ObservePromise` 在 runtime owner 上注册 settlement。普通值由当前回调立即消费；Promise fulfillment 或 rejection 在 owner 上同步调用一次 `settled`，settlement 值的有效期覆盖该回调。

Goja 实现先用 `ExportType` 确认 `*goja.Promise`，再读取原始 Promise；普通对象按原值交付。Native 实现使用启动期保留的 Promise helper，并在对应 owner scope 内交付 settlement。

## `Export()` 兼容接口

`Export()` 服务于已经持有具体引擎值的兼容路径。

| 实现或调用域 | `Export()` 语义 |
| --- | --- |
| `utils/jsengine/goja` | 使用 Goja 原生导出表示；Boolean、String 和 Number 原语可复制为 Go 标量，对象与函数归属当前 realm scope。 |
| `utils/jsengine/native` | 返回标量、`nativeObject` 或 `nativeFunction` 适配器值，使用当前 runtime 与 scope。 |
| `dice.gojaEngineValue` | 为现有 Goja callback 适配器提供原始 Goja 导出。 |
| Goja 专用插件模块 | 读取 Promise、ArrayBuffer、typed byte 值、JWK、Host handle 与协议数组等引擎内部类型。 |

通用 solve、message preprocess 和 API 执行路径使用 `Object()`、`ExportPrimitive()` 与 `ObservePromise()`。Goja Promise 检测、文件系统 byte 输入和 Goja 插件内部类型继续使用具体引擎接口。

## API 与 Core 消费语义

Core 在值所属的 Loop 回调内完成分类。

- `api/js.go` 的执行结果通过 `ExportPrimitive()` 写入响应。原语写入 `ret`；`undefined` 与 `null` 写入 JSON `null`；对象、函数和宿主引用产生 `result: true`、`ret: null` 和带分类文本的 `err`。
- Message preprocess 先读取 Object 字段，再按原语契约读取字符串和 nullish 字段。
- JS solve 先识别 Object 结果，再区分 nullish 与标量结果。
- Host callback 的对象、函数和集合通过 HostBridge 编解码器按目标类型转换。

## Runtime ABI 映射

Runtime ABI v1 使用 `value_type` 区分 `UNDEFINED`、`NULL`、`BOOL`、`I64`、`U64`、`F64`、`STRING`、`OBJECT`、`HOST_OBJECT`、`HOST_FUNCTION` 与 `FUNCTION`。原语转换调用对应的 `value_to_*`，字符串使用两次 `required` 缓冲区协议。

Object 通过 `object_get`、`object_set` 和 `object_has` 访问。每个结果句柄归属当前调用 scope；适配器在 scope 结束时释放普通值，并在 runtime 关闭前配对释放内部持久值。JSON 解析通过 `jsengine.JSONParser` 返回同一 scope 内的引擎原生对象。

运行时所有权、上下文和关闭顺序见[运行时架构](architecture.md)。
