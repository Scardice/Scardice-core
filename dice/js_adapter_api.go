package dice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"Scardice-core/adapterapi"
	"Scardice-core/eventstore"
	"Scardice-core/utils/jsengine"
)

const jsAdapterCallTimeout = 10 * time.Second

type jsAdapterOperation struct {
	ID         string `jsbind:"id"`
	Status     string `jsbind:"status"`
	ResultCode string `jsbind:"resultCode"`
	ErrorCode  string `jsbind:"errorCode"`
}

func (d *Dice) checkAdapterAPIExecution(loop jsengine.Loop, generation int64, execution *jsExecutionContext) error {
	if d == nil || d.ExtLoopManager == nil || !jsengine.InOwner(loop) {
		return errJSRuntimeUnavailable
	}
	current, err := d.ExtLoopManager.GetLoop(generation)
	if err != nil || current != loop {
		return errJSCallbackStaleGeneration
	}
	switch active := jsengine.CurrentContext(loop).(type) {
	case nil:
	case *jsExecutionContext:
		if err := jsengine.ContextForExecution(active).Err(); err != nil {
			return err
		}
	default:
		return errJSCallbackWrongRealm
	}
	if execution == nil {
		// The trusted administrator console has no script or message scope.
		return nil
	}
	if !d.Config.JsEnable {
		return errAdapterExtensionUnavailable
	}
	if err := execution.ExecutionContext().Err(); err != nil {
		return err
	}
	if execution.Plugin != nil {
		return d.checkAdapterExtensionCurrent(execution.Plugin, generation, execution.Message)
	}
	return checkAdapterScriptEnabled(execution.Script, generation)
}

func (d *Dice) installJSAdapterHostAPI(runtime jsengine.Runtime, loop jsengine.Loop, seal jsengine.Object, generation int64) error {
	bridge := runtime.NewObject()
	// One retained callback per realm, not one retained native handle per call.
	// Only its owner may invoke it; provider goroutines carry plain Go data.
	var settle func(uint64, string, string, bool)
	if err := bridge.Set("bind", func(callback func(uint64, string, string, bool)) error {
		if callback == nil || settle != nil {
			return errors.New("adapter promise bridge is already initialized")
		}
		settle = callback
		return nil
	}); err != nil {
		return err
	}
	if err := bridge.Set("start", func(id uint64, endpointID, rawJSON string) error {
		execution := jsExecutionContextFor(loop)
		if err := d.checkAdapterAPIExecution(loop, generation, execution); err != nil {
			return err
		}
		request := adapterapi.AdapterCallRequest{EndpointID: adapterapi.EndpointID(endpointID), RawJSON: rawJSON}
		if err := request.Validate(); err != nil {
			return err
		}
		var message *MsgContext
		if execution != nil {
			message = execution.Message
		}
		if err := d.checkAdapterOutboundCensor(message, rawJSON); err != nil {
			return err
		}
		caller := d.ProviderCall
		if caller == nil || settle == nil {
			return errors.New("adapter direct-call service is unavailable")
		}
		if err := jsCompatibilityExternalAccess(execution); err != nil {
			return err
		}
		callContext, cancel := context.WithTimeout(jsengine.ContextForExecution(execution), jsAdapterCallTimeout)
		unregister, err := d.ExtLoopManager.registerJSCallbackWaiter(generation, func(error) { cancel() })
		if err != nil {
			cancel()
			return err
		}
		discard := func() {
			_ = jsengine.ScheduleWithContext(loop, nil, func(jsengine.Runtime) error {
				return runEngineCallback(func() error {
					settle(id, "", "", true)
					return nil
				})
			})
		}
		// Cancellation can happen after scheduling, before the owner admits the
		// completion. Retire that resolver even when the completion never runs.
		stopCleanup := context.AfterFunc(jsengine.ContextForExecution(execution), discard)
		go func() {
			defer unregister()
			defer cancel()
			result, callErr := caller.CallAPI(callContext, request)
			if callErr == nil {
				callErr = result.Validate()
			}
			finish := func(jsengine.Runtime) error {
				defer stopCleanup()
				if err := d.checkAdapterAPIExecution(loop, generation, execution); err != nil {
					return runEngineCallback(func() error {
						settle(id, "", "", true)
						return nil
					})
				}
				errorText := ""
				if callErr != nil {
					errorText = callErr.Error()
				}
				return runEngineCallback(func() error {
					settle(id, errorText, result.RawJSON, false)
					return nil
				})
			}
			if err := jsengine.ScheduleWithContext(loop, execution, finish); err != nil {
				stopCleanup()
				discard()
			}
		}()
		return nil
	}); err != nil {
		return err
	}
	if err := bridge.Set("enqueue", func(endpointID, rawJSON string) (AdapterAPIOperation, error) {
		execution := jsExecutionContextFor(loop)
		if err := d.checkAdapterAPIExecution(loop, generation, execution); err != nil {
			return AdapterAPIOperation{}, err
		}
		outbound, ok := d.OutboundBridge.(*DurableOutboundBridge)
		if !ok || outbound == nil {
			return AdapterAPIOperation{}, errors.New("adapter durable outbox is unavailable")
		}
		var message *MsgContext
		if execution != nil {
			message = execution.Message
		}
		if message == nil {
			message = &MsgContext{Dice: d, Session: d.ImSession, executionContext: jsengine.ContextForExecution(execution)}
			defer message.releaseExecutionState()
		}
		return outbound.EnqueueAdapterAPI(jsengine.ContextForExecution(execution), message, adapterapi.EndpointID(endpointID), rawJSON)
	}); err != nil {
		return err
	}
	if err := bridge.Set("operation", func(id string) (jsAdapterOperation, error) {
		execution := jsExecutionContextFor(loop)
		if err := d.checkAdapterAPIExecution(loop, generation, execution); err != nil {
			return jsAdapterOperation{}, err
		}
		if _, err := adapterapi.NewOperationID(id); err != nil {
			return jsAdapterOperation{}, err
		}
		if execution != nil {
			if outbound, ok := d.OutboundBridge.(*DurableOutboundBridge); ok && outbound != nil {
				if staged, exists := outbound.StagedAdapterAPIOperation(execution.Message, id); exists {
					return jsAdapterOperation{ID: staged.ID, Status: staged.Status}, nil
				}
			}
		}
		operations, ok := d.DurableStore.(eventstore.OperationRepository)
		if !ok {
			return jsAdapterOperation{}, errors.New("adapter operation store is unavailable")
		}
		operation, err := operations.GetOperation(jsengine.ContextForExecution(execution), id)
		if err != nil {
			return jsAdapterOperation{}, err
		}
		return jsAdapterOperation{ID: operation.OperationID, Status: operation.Status, ResultCode: operation.ResultCode, ErrorCode: operation.ErrorCode}, nil
	}); err != nil {
		return err
	}
	if err := runtime.Set("__scardiceAdapterBridge", bridge); err != nil {
		return err
	}
	value, err := runtime.RunString("<seal.adapter>", jsAdapterBootstrap)
	if err != nil {
		return fmt.Errorf("initialize adapter API: %w", err)
	}
	return setJSHostObject(seal, "adapter", value)
}

const jsAdapterBootstrap = `(function () {
  "use strict";
  const bridge = globalThis.__scardiceAdapterBridge;
  delete globalThis.__scardiceAdapterBridge;
  const parse = JSON.parse;
  const stringify = JSON.stringify;
  const pending = new Map();
  let nextID = 0;
  bridge.bind(function (id, error, raw, discard) {
    const entry = pending.get(id);
    pending.delete(id);
    if (!entry || discard) return;
    if (error) entry.reject(new Error(error));
    else entry.resolve(raw);
  });
  function endpointID(endpoint) {
    const id = typeof endpoint === "string" ? endpoint : endpoint && endpoint.id;
    if (typeof id !== "string" || !id) throw new TypeError("expected an endpoint object or endpoint ID");
    return id;
  }
  function requestJSON(action, params) {
    if (typeof action !== "string" || !action.trim()) throw new TypeError("action must be a nonempty string");
    return stringify({ action: action, params: params === undefined ? {} : params });
  }
  function rawRequest(raw) {
    if (typeof raw !== "string") throw new TypeError("request JSON must be a string");
    return raw;
  }
  function callApiRaw(endpoint, raw) {
    return new Promise(function (resolve, reject) {
      const id = ++nextID;
      const target = endpointID(endpoint);
      rawRequest(raw);
      pending.set(id, { resolve: resolve, reject: reject });
      try { bridge.start(id, target, raw); }
      catch (error) { pending.delete(id); reject(error); }
    });
  }
  return Object.freeze({
    callApi: async function (endpoint, action, params) {
      return parse(await callApiRaw(endpoint, requestJSON(action, params)));
    },
    callApiRaw: callApiRaw,
    enqueueApi: function (endpoint, action, params) {
      return bridge.enqueue(endpointID(endpoint), requestJSON(action, params));
    },
    enqueueApiRaw: function (endpoint, raw) {
      return bridge.enqueue(endpointID(endpoint), rawRequest(raw));
    },
    getOperation: function (id) {
      if (typeof id !== "string") throw new TypeError("operation ID must be a string");
      return bridge.operation(id);
    }
  });
})()`
