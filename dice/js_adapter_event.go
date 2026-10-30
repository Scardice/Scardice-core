package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strconv"
	"strings"

	"github.com/dop251/goja"

	"Scardice-core/adapterapi"
	"Scardice-core/utils/jsengine"
	gojaengine "Scardice-core/utils/jsengine/goja"
)

var errAdapterExtensionUnavailable = errors.New("adapter extension is no longer active")

func checkAdapterScriptEnabledLocked(source *JsScriptInfo, generation int64) error {
	if source.runtimeDeleted {
		return fmt.Errorf("%w: plugin source was deleted", errAdapterExtensionUnavailable)
	}
	if !source.Enable {
		return fmt.Errorf("%w: plugin source is disabled", errAdapterExtensionUnavailable)
	}
	if generation == 0 || source.runtimeGeneration != generation {
		return fmt.Errorf("%w: plugin source runtime generation changed", errAdapterExtensionUnavailable)
	}
	return nil
}

func checkAdapterScriptEnabled(source *JsScriptInfo, generation int64) error {
	if source == nil {
		return fmt.Errorf("%w: plugin source is unavailable", errAdapterExtensionUnavailable)
	}
	source.runtimeStateMu.RLock()
	defer source.runtimeStateMu.RUnlock()
	return checkAdapterScriptEnabledLocked(source, generation)
}

// AdapterEventView is the detached per-extension view used by native Go hooks.
// JavaScript hooks receive an engine-native object parsed from RawJSON instead.
type AdapterEventView struct {
	EndPoint *EndPointInfo  `jsbind:"endPoint" json:"endPoint"`
	Type     string         `jsbind:"type"     json:"type"`
	Protocol string         `jsbind:"protocol" json:"protocol"`
	Body     map[string]any `jsbind:"body"     json:"body"`
	RawJSON  string         `jsbind:"rawJson"  json:"rawJson"`
}

type adapterJSONPrimitiveKind uint8

const (
	adapterJSONNull adapterJSONPrimitiveKind = iota
	adapterJSONBool
	adapterJSONNumber
	adapterJSONString
)

type adapterJSONPrimitive struct {
	kind   adapterJSONPrimitiveKind
	text   string
	truth  bool
	number float64
}

type parsedAdapterEventFilter struct {
	allEvents bool
	events    map[string]struct{}
	where     map[string][]adapterJSONPrimitive
}

func adapterJSONPrimitiveValue(value any) (adapterJSONPrimitive, bool) {
	if value == nil {
		return adapterJSONPrimitive{kind: adapterJSONNull}, true
	}
	if number, ok := value.(json.Number); ok {
		parsed, err := number.Float64()
		if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) {
			return adapterJSONPrimitive{}, false
		}
		return adapterJSONPrimitive{kind: adapterJSONNumber, number: parsed}, true
	}

	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Bool:
		return adapterJSONPrimitive{kind: adapterJSONBool, truth: reflected.Bool()}, true
	case reflect.String:
		return adapterJSONPrimitive{kind: adapterJSONString, text: reflected.String()}, true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return adapterJSONPrimitive{kind: adapterJSONNumber, number: float64(reflected.Int())}, true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return adapterJSONPrimitive{kind: adapterJSONNumber, number: float64(reflected.Uint())}, true
	case reflect.Float32, reflect.Float64:
		number := reflected.Float()
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return adapterJSONPrimitive{}, false
		}
		return adapterJSONPrimitive{kind: adapterJSONNumber, number: number}, true
	default:
		return adapterJSONPrimitive{}, false
	}
}

func adapterJSONPrimitives(value any) ([]adapterJSONPrimitive, error) {
	if value != nil {
		reflected := reflect.ValueOf(value)
		if reflected.Kind() == reflect.Array || reflected.Kind() == reflect.Slice {
			values := make([]adapterJSONPrimitive, 0, reflected.Len())
			for index := range reflected.Len() {
				primitive, ok := adapterJSONPrimitiveValue(reflected.Index(index).Interface())
				if !ok {
					return nil, fmt.Errorf("array item %d is not a JSON primitive", index)
				}
				values = append(values, primitive)
			}
			return values, nil
		}
	}
	primitive, ok := adapterJSONPrimitiveValue(value)
	if !ok {
		return nil, errors.New("value is not a JSON primitive or primitive array")
	}
	return []adapterJSONPrimitive{primitive}, nil
}

func adapterEventNames(value any) (map[string]struct{}, error) {
	if value == nil {
		return nil, errors.New("events must be \"all\" or an array of event types")
	}
	reflected := reflect.ValueOf(value)
	if reflected.Kind() != reflect.Array && reflected.Kind() != reflect.Slice {
		return nil, errors.New("events must be \"all\" or an array of event types")
	}
	events := make(map[string]struct{}, reflected.Len())
	for index := range reflected.Len() {
		item := reflected.Index(index).Interface()
		name, ok := item.(string)
		if !ok || name == "" || name == "all" {
			return nil, fmt.Errorf("events item %d must be a non-empty explicit event type", index)
		}
		events[name] = struct{}{}
	}
	return events, nil
}

func parseAdapterEventFilter(filter map[string]any) (parsedAdapterEventFilter, error) {
	parsed := parsedAdapterEventFilter{}
	if len(filter) == 0 {
		return parsed, nil
	}
	for key := range filter {
		if key != "events" && key != "where" {
			return parsedAdapterEventFilter{}, fmt.Errorf("unknown adapterEventFilter field %q", key)
		}
	}
	if value, exists := filter["events"]; exists {
		if name, ok := value.(string); ok {
			if name != "all" {
				return parsedAdapterEventFilter{}, errors.New("adapterEventFilter.events string must be \"all\"")
			}
			parsed.allEvents = true
			parsed.events = nil
		} else {
			events, err := adapterEventNames(value)
			if err != nil {
				return parsedAdapterEventFilter{}, fmt.Errorf("adapterEventFilter.events: %w", err)
			}
			parsed.events = events
		}
	}
	whereValue, exists := filter["where"]
	if !exists {
		return parsed, nil
	}
	where, ok := whereValue.(map[string]any)
	if !ok {
		return parsedAdapterEventFilter{}, errors.New("adapterEventFilter.where must be an object")
	}
	parsed.where = make(map[string][]adapterJSONPrimitive, len(where))
	for field, value := range where {
		if field == "" {
			return parsedAdapterEventFilter{}, errors.New("adapterEventFilter.where field names must not be empty")
		}
		values, err := adapterJSONPrimitives(value)
		if err != nil {
			return parsedAdapterEventFilter{}, fmt.Errorf("adapterEventFilter.where.%s: %w", field, err)
		}
		parsed.where[field] = values
	}
	return parsed, nil
}

func adapterGojaPrimitive(value goja.Value) (adapterJSONPrimitive, bool) {
	if value == nil || goja.IsUndefined(value) {
		return adapterJSONPrimitive{}, false
	}
	switch value := value.(type) {
	case *goja.Symbol:
		return adapterJSONPrimitive{}, false
	case *goja.Object:
		if len(value.Symbols()) != 0 {
			return adapterJSONPrimitive{}, false
		}
		switch value.ClassName() {
		case "Boolean", "Number", "String":
		default:
			return adapterJSONPrimitive{}, false
		}
	}
	return adapterJSONPrimitiveValue(value.Export())
}

func adapterGojaArray(value goja.Value) (*goja.Object, int) {
	array, ok := value.(*goja.Object)
	if !ok || array.ClassName() != "Array" || len(array.Symbols()) != 0 {
		return nil, 0
	}
	return array, int(array.Get("length").ToInteger())
}

func adapterGojaPrimitives(value goja.Value) ([]adapterJSONPrimitive, error) {
	if array, length := adapterGojaArray(value); array != nil {
		values := make([]adapterJSONPrimitive, 0, length)
		for index := range length {
			primitive, ok := adapterGojaPrimitive(array.Get(strconv.Itoa(index)))
			if !ok {
				return nil, fmt.Errorf("array item %d is not a JSON primitive", index)
			}
			values = append(values, primitive)
		}
		return values, nil
	}
	primitive, ok := adapterGojaPrimitive(value)
	if !ok {
		return nil, errors.New("value is not a JSON primitive or primitive array")
	}
	return []adapterJSONPrimitive{primitive}, nil
}

func parseGojaAdapterEventFilter(value goja.Value) (parsedAdapterEventFilter, error) {
	parsed := parsedAdapterEventFilter{}
	if value == nil || goja.IsUndefined(value) || goja.IsNull(value) {
		return parsed, nil
	}
	filter, ok := value.(*goja.Object)
	if !ok || filter.ClassName() != "Object" || len(filter.Symbols()) != 0 {
		return parsedAdapterEventFilter{}, errors.New("adapterEventFilter must be an object with string keys")
	}
	for _, key := range filter.Keys() {
		switch key {
		case "events":
			value := filter.Get(key)
			if name, ok := adapterGojaPrimitive(value); ok && name.kind == adapterJSONString {
				if name.text != "all" {
					return parsedAdapterEventFilter{}, errors.New("adapterEventFilter.events string must be \"all\"")
				}
				parsed.allEvents = true
				continue
			}
			array, length := adapterGojaArray(value)
			if array == nil {
				return parsedAdapterEventFilter{}, errors.New("adapterEventFilter.events must be \"all\" or an array of event types")
			}
			parsed.events = make(map[string]struct{}, length)
			for index := range length {
				name, ok := adapterGojaPrimitive(array.Get(strconv.Itoa(index)))
				if !ok || name.kind != adapterJSONString || name.text == "" || name.text == "all" {
					return parsedAdapterEventFilter{}, fmt.Errorf("adapterEventFilter.events item %d must be a non-empty explicit event type", index)
				}
				parsed.events[name.text] = struct{}{}
			}
		case "where":
			where, ok := filter.Get(key).(*goja.Object)
			if !ok || where.ClassName() != "Object" || len(where.Symbols()) != 0 {
				return parsedAdapterEventFilter{}, errors.New("adapterEventFilter.where must be an object with string keys")
			}
			fields := where.Keys()
			parsed.where = make(map[string][]adapterJSONPrimitive, len(fields))
			for _, field := range fields {
				if field == "" {
					return parsedAdapterEventFilter{}, errors.New("adapterEventFilter.where field names must not be empty")
				}
				values, err := adapterGojaPrimitives(where.Get(field))
				if err != nil {
					return parsedAdapterEventFilter{}, fmt.Errorf("adapterEventFilter.where.%s: %w", field, err)
				}
				parsed.where[field] = values
			}
		default:
			return parsedAdapterEventFilter{}, fmt.Errorf("unknown adapterEventFilter field %q", key)
		}
	}
	return parsed, nil
}

func (filter parsedAdapterEventFilter) matchesEventType(eventType string) bool {
	if filter.allEvents {
		return true
	}
	if filter.events == nil {
		return eventType == "notice"
	}
	_, ok := filter.events[eventType]
	return ok
}

func (primitive adapterJSONPrimitive) equal(other adapterJSONPrimitive) bool {
	if primitive.kind != other.kind {
		return false
	}
	switch primitive.kind {
	case adapterJSONNull:
		return true
	case adapterJSONBool:
		return primitive.truth == other.truth
	case adapterJSONNumber:
		return primitive.number == other.number
	case adapterJSONString:
		return primitive.text == other.text
	default:
		return false
	}
}

func (filter parsedAdapterEventFilter) matchesBody(body map[string]any) bool {
	for field, expected := range filter.where {
		actualValue, exists := body[field]
		if !exists {
			return false
		}
		actual, ok := adapterJSONPrimitiveValue(actualValue)
		if !ok {
			return false
		}
		matched := false
		for _, candidate := range expected {
			if actual.equal(candidate) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func decodeAdapterEventBody(raw string) (map[string]any, error) {
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.UseNumber()
	var body map[string]any
	if err := decoder.Decode(&body); err != nil {
		return nil, fmt.Errorf("decode adapter event body: %w", err)
	}
	if body == nil {
		body = map[string]any{}
	}
	return body, nil
}

func newAdapterEventView(event adapterapi.AdapterEvent, endpoint *EndPointInfo) (*AdapterEventView, error) {
	body, err := decodeAdapterEventBody(event.RawJSON)
	if err != nil {
		return nil, err
	}
	return &AdapterEventView{
		EndPoint: endpoint,
		Type:     event.Type,
		Protocol: event.Protocol,
		Body:     body,
		RawJSON:  event.RawJSON,
	}, nil
}

func newJSAdapterEventValue(runtime jsengine.Runtime, event adapterapi.AdapterEvent, endpoint *EndPointInfo) (jsengine.Value, error) {
	parser, ok := runtime.(jsengine.JSONParser)
	if !ok {
		return nil, errors.New("adapter event JavaScript runtime does not support native JSON parsing")
	}
	body, err := parser.ParseJSON(event.RawJSON)
	if err != nil {
		return nil, fmt.Errorf("parse adapter event JavaScript body: %w", err)
	}
	value, err := parser.ParseJSON("{}")
	if err != nil {
		return nil, fmt.Errorf("create adapter event JavaScript object: %w", err)
	}
	object := value.Object()
	if object == nil {
		return nil, errors.New("adapter event JavaScript value is not an object")
	}
	if err := object.Set("type", event.Type); err != nil {
		return nil, fmt.Errorf("set adapter event type: %w", err)
	}
	if err := object.Set("protocol", event.Protocol); err != nil {
		return nil, fmt.Errorf("set adapter event protocol: %w", err)
	}
	if err := object.Set("rawJson", event.RawJSON); err != nil {
		return nil, fmt.Errorf("set adapter event raw JSON: %w", err)
	}
	if err := object.Set("body", body); err != nil {
		return nil, fmt.Errorf("set adapter event body: %w", err)
	}
	if err := object.Set("endPoint", endpoint); err != nil {
		return nil, fmt.Errorf("set adapter event endpoint: %w", err)
	}
	return value, nil
}

func (d *Dice) adapterEventCandidates(callbackCtx *MsgContext) []*ExtInfo {
	if callbackCtx == nil {
		return append([]*ExtInfo(nil), d.ExtList...)
	}
	group := callbackCtx.Group
	if group == nil || (callbackCtx.MessageType == "group" && !group.IsActive(callbackCtx)) {
		return nil
	}
	_ = group.GetActivatedExtList(d)
	group.extInitMu.Lock()
	candidates := append([]*ExtInfo(nil), group.activatedExtList...)
	group.extInitMu.Unlock()
	return candidates
}

// checkAdapterExtensionCurrent is shared by event delivery and adapter host
// services. The extension argument must be the raw execution owner, not the
// result of GetRealExt: a stale real extension resolves to itself.
func (d *Dice) checkAdapterExtensionCurrent(extension *ExtInfo, generation int64, scope *MsgContext) error {
	if d == nil || extension == nil || extension.dice != d || d.ExtRegistry == nil {
		return errAdapterExtensionUnavailable
	}
	if extension.IsJsExt && !d.Config.JsEnable {
		return fmt.Errorf("%w: JavaScript extensions are disabled", errAdapterExtensionUnavailable)
	}
	if extension.JSLoopVersion != generation {
		return fmt.Errorf("%w: JavaScript runtime generation changed", errAdapterExtensionUnavailable)
	}
	source := extension.Source
	if source != nil {
		source.runtimeStateMu.RLock()
		defer source.runtimeStateMu.RUnlock()
		if err := checkAdapterScriptEnabledLocked(source, generation); err != nil {
			return err
		}
	}
	registered, ok := d.ExtRegistry.Load(extension.Name)
	if !ok || registered == nil {
		return fmt.Errorf("%w: extension is not registered", errAdapterExtensionUnavailable)
	}
	if registered.IsWrapper {
		if d.JsExtRegistry == nil {
			return fmt.Errorf("%w: plugin registry is unavailable", errAdapterExtensionUnavailable)
		}
		current, currentOK := d.JsExtRegistry.Load(registered.TargetName)
		if !currentOK || current != extension {
			return fmt.Errorf("%w: plugin was replaced or deleted", errAdapterExtensionUnavailable)
		}
	} else if registered != extension {
		return fmt.Errorf("%w: extension was replaced", errAdapterExtensionUnavailable)
	}

	if scope == nil || scope.Group == nil {
		return nil
	}
	if scope.MessageType == "group" && scope.EndPoint == nil {
		return fmt.Errorf("%w: group endpoint is unavailable", errAdapterExtensionUnavailable)
	}
	if scope.MessageType == "group" && !scope.Group.IsActive(scope) {
		return fmt.Errorf("%w: bot is disabled in the group", errAdapterExtensionUnavailable)
	}
	_ = scope.Group.GetActivatedExtList(d)
	scope.Group.extInitMu.Lock()
	defer scope.Group.extInitMu.Unlock()
	for _, activated := range scope.Group.activatedExtList {
		if activated == registered {
			return nil
		}
	}
	return fmt.Errorf("%w: extension is not active in this conversation", errAdapterExtensionUnavailable)
}

func (d *Dice) reportNativeAdapterEventError(scope *MsgContext, err error) {
	if err == nil {
		return
	}
	scope.recordJSExecutionError(err)
	if d != nil && d.Logger != nil {
		d.Logger.Errorf("扩展适配器事件回调异常: %v", err)
	}
}

func (d *Dice) dispatchNativeAdapterEvent(extension *ExtInfo, scope, callbackCtx *MsgContext, event adapterapi.AdapterEvent, endpoint *EndPointInfo) error {
	if extension == nil || extension.OnAdapterEvent == nil {
		return nil
	}
	if err := d.checkAdapterExtensionCurrent(extension, extension.JSLoopVersion, scope); err != nil {
		return nil
	}
	filter, err := parseAdapterEventFilter(extension.AdapterEventFilter)
	if err != nil {
		err = fmt.Errorf("extension %q adapter event filter: %w", extension.Name, err)
		d.reportNativeAdapterEventError(scope, err)
		return err
	}
	if !filter.matchesEventType(event.Type) {
		return nil
	}
	view, err := newAdapterEventView(event, endpoint)
	if err != nil {
		d.reportNativeAdapterEventError(scope, err)
		return err
	}
	if !filter.matchesBody(view.Body) {
		return nil
	}
	if err := d.checkAdapterExtensionCurrent(extension, extension.JSLoopVersion, scope); err != nil {
		return nil
	}
	if err := runEngineCallback(func() error {
		extension.OnAdapterEvent(callbackCtx, view)
		return nil
	}); err != nil {
		d.reportNativeAdapterEventError(scope, err)
		return err
	}
	return nil
}

func currentAdapterEventCallback(
	extension *ExtInfo,
	callbackCtx *MsgContext,
	view *AdapterEventView,
	event adapterapi.AdapterEvent,
	endpoint *EndPointInfo,
) jsHookValueCallback {
	switch {
	case extension.OnAdapterEvent != nil:
		return func(jsengine.Runtime) (jsengine.Value, error) {
			extension.OnAdapterEvent(callbackCtx, view)
			return nil, nil
		}
	case extension.OnAdapterEventCallback != nil:
		return func(runtime jsengine.Runtime) (jsengine.Value, error) {
			jsEvent, err := newJSAdapterEventValue(runtime, event, endpoint)
			if err != nil {
				return nil, err
			}
			return extension.OnAdapterEventCallback(callbackCtx, jsEvent)
		}
	case extension.OnAdapterEventGoja != nil:
		return func(runtime jsengine.Runtime) (jsengine.Value, error) {
			jsEvent, err := newJSAdapterEventValue(runtime, event, endpoint)
			if err != nil {
				return nil, err
			}
			gojaEvent, err := gojaengine.UnwrapValueForRuntime(runtime, jsEvent)
			if err != nil {
				return nil, err
			}
			return gojaengine.WrapValueForRuntime(runtime, extension.OnAdapterEventGoja(callbackCtx, gojaEvent))
		}
	default:
		return nil
	}
}

func (d *Dice) dispatchJSAdapterEvent(extension *ExtInfo, scope, callbackCtx *MsgContext, event adapterapi.AdapterEvent, endpoint *EndPointInfo) error {
	generation := extension.JSLoopVersion
	callback := func(runtime jsengine.Runtime) (jsengine.Value, error) {
		if err := d.checkAdapterExtensionCurrent(extension, generation, scope); err != nil {
			return nil, nil
		}
		if extension.OnAdapterEvent == nil && extension.OnAdapterEventCallback == nil && extension.OnAdapterEventGoja == nil {
			return nil, nil
		}
		var filter parsedAdapterEventFilter
		var err error
		if extension.AdapterEventFilterGoja != nil {
			filter, err = parseGojaAdapterEventFilter(extension.AdapterEventFilterGoja)
		} else {
			filter, err = parseAdapterEventFilter(extension.AdapterEventFilter)
		}
		if err != nil {
			return nil, fmt.Errorf("extension %q adapter event filter: %w", extension.Name, err)
		}
		if !filter.matchesEventType(event.Type) {
			return nil, nil
		}
		var body map[string]any
		if len(filter.where) != 0 || extension.OnAdapterEvent != nil {
			body, err = decodeAdapterEventBody(event.RawJSON)
			if err != nil {
				return nil, err
			}
			if !filter.matchesBody(body) {
				return nil, nil
			}
		}
		var view *AdapterEventView
		if extension.OnAdapterEvent != nil {
			view = &AdapterEventView{
				EndPoint: endpoint,
				Type:     event.Type,
				Protocol: event.Protocol,
				Body:     body,
				RawJSON:  event.RawJSON,
			}
		}
		if err := d.checkAdapterExtensionCurrent(extension, generation, scope); err != nil {
			return nil, nil
		}
		selected := currentAdapterEventCallback(extension, callbackCtx, view, event, endpoint)
		if selected == nil {
			return nil, nil
		}
		return selected(runtime)
	}
	return extension.dispatchValueWithJsCheck(d, jsCallbackAdapterEvent, "", false, callback, nil, scope)
}

// dispatchAdapterEvent invokes live subscriptions in extension order. It joins
// every returned Promise before returning, so the caller must keep scope alive
// until this method completes. callbackCtx is nil only for global events.
func (d *Dice) dispatchAdapterEvent(scope *MsgContext, callbackCtx *MsgContext, event adapterapi.AdapterEvent, endpoint *EndPointInfo) error {
	if d == nil || scope == nil {
		return errors.New("adapter event callback scope is unavailable")
	}
	if endpoint == nil {
		return errors.New("adapter event endpoint is unavailable")
	}
	if scope.Dice != d {
		return errors.New("adapter event callback scope belongs to another dice")
	}
	if callbackCtx != nil && callbackCtx != scope {
		return errors.New("adapter event callback context must own its scope")
	}
	if callbackCtx == nil && (scope.Group != nil || scope.Player != nil) {
		return errors.New("global adapter event callback scope must not contain conversation state")
	}
	if err := event.Validate(); err != nil {
		return err
	}
	scope.adapterEventUnattributed = event.Type != "message"
	if err := d.checkAdapterInboundCensor(scope, event); err != nil {
		if errors.Is(err, errAdapterCensorBlocked) {
			return nil
		}
		return err
	}
	for _, wrapper := range d.adapterEventCandidates(callbackCtx) {
		if wrapper == nil {
			continue
		}
		extension := wrapper
		if wrapper.IsWrapper {
			if d.JsExtRegistry == nil {
				continue
			}
			var ok bool
			extension, ok = d.JsExtRegistry.Load(wrapper.TargetName)
			if !ok || extension == nil {
				continue
			}
		}
		var err error
		if extension.IsJsExt {
			err = d.dispatchJSAdapterEvent(extension, scope, callbackCtx, event, endpoint)
		} else {
			err = d.dispatchNativeAdapterEvent(extension, scope, callbackCtx, event, endpoint)
		}
		if err != nil {
			return err
		}
	}
	return nil
}
