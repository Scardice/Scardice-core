package hostbridge

import (
	"errors"
	"reflect"
	"testing"
)

var errUntransferredTestCallback = errors.New("callback has not been handed to Go")

type handoffTestLease struct {
	transferred bool
}

// The callback fails until the real bridge hands its decoded value to Go. This
// codec exercises the optional ownership seam without needing a VM in this
// package; the native package separately covers real QuickJS retain/release.
type handoffTestCodec struct {
	session     *Session
	pending     []*handoffTestLease
	lastDecoded func() error
}

func (c *handoffTestCodec) Decode(value Value, target reflect.Type) (reflect.Value, error) {
	if value.Kind != KindCallback || target != reflect.TypeFor[func() error]() {
		return reflect.Value{}, errors.New("expected callback func() error")
	}
	lease := &handoffTestLease{}
	c.pending = append(c.pending, lease)
	callback := func() error {
		if !lease.transferred {
			return errUntransferredTestCallback
		}
		return nil
	}
	c.lastDecoded = callback
	return reflect.ValueOf(callback), nil
}

func (c *handoffTestCodec) Encode(value reflect.Value) (Value, error) {
	return c.session.toValueMode(value, false)
}

func (*handoffTestCodec) CallCallback(Value, []Value) (Value, error) {
	return UndefinedValue(), errors.New("explicit callback call is not used by this codec")
}

func (c *handoffTestCodec) CommitCallbacks() {
	for _, lease := range c.pending {
		lease.transferred = true
	}
	c.pending = nil
}

type handoffTestHost struct {
	Callback func() error `jsbind:"callback"`
}

func TestHostBridgeCommitsCallbacksBeforeCallingGo(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			session := NewSession()
			codec := &handoffTestCodec{session: session}
			var callbackErr error
			var retained func() error
			function, err := session.RegisterFunction(func(callback func() error) error {
				retained = callback
				callbackErr = callback()
				switch outcome {
				case "error":
					return errors.New("host error after accepting callback")
				case "panic":
					panic("host panic after accepting callback")
				default:
					return callbackErr
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = session.CallFunctionWithCodec(function, []Value{CallbackValue(1)}, codec)
			if outcome == "success" && err != nil || outcome != "success" && err == nil {
				t.Fatalf("%s call error = %v", outcome, err)
			}
			if callbackErr != nil {
				t.Fatalf("Go invoked an untransferred callback: %v", callbackErr)
			}
			if retained == nil {
				t.Fatal("Go did not retain its callback")
			}
			if err := retained(); err != nil {
				t.Fatalf("accepted callback lost its ownership after %s: %v", outcome, err)
			}
		})
	}
}

func TestHostBridgeFailedArgumentConversionDoesNotCommitCallbacks(t *testing.T) {
	session := NewSession()
	codec := &handoffTestCodec{session: session}
	called := false
	function, err := session.RegisterFunction(func(func() error, string) { called = true })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.CallFunctionWithCodec(function, []Value{CallbackValue(1), IntValue(7)}, codec); err == nil {
		t.Fatal("invalid later argument was accepted")
	}
	if called || codec.lastDecoded == nil {
		t.Fatalf("conversion did not stop before Go: called=%v decoded=%v", called, codec.lastDecoded != nil)
	}
	if err := codec.lastDecoded(); !errors.Is(err, errUntransferredTestCallback) {
		t.Fatalf("failed argument conversion committed a callback: %v", err)
	}
}

func TestHostBridgeCallbackAssignmentsCommitOnlyWritableValues(t *testing.T) {
	for _, target := range []string{"struct", "map", "slice", "extended slice", "read-only slice"} {
		t.Run(target, func(t *testing.T) {
			session := NewSession()
			codec := &handoffTestCodec{session: session}
			host := &handoffTestHost{}
			mapping := map[string]func() error{}
			items := []func() error{nil}
			var raw any = host
			name := "callback"
			callback := func() func() error { return host.Callback }
			switch target {
			case "map":
				raw = mapping
				callback = func() func() error { return mapping["callback"] }
			case "slice", "extended slice", "read-only slice":
				raw, name = &items, "0"
				index := 0
				if target == "extended slice" {
					name, index = "2", 2
				}
				if target == "read-only slice" {
					raw = items
				}
				callback = func() func() error { return items[index] }
			}
			ref, err := session.RegisterObject(raw)
			if err != nil {
				t.Fatal(err)
			}
			err = session.SetWithCodec(ref, name, CallbackValue(1), codec)
			if target == "read-only slice" {
				if err == nil || callback() != nil || codec.lastDecoded == nil {
					t.Fatalf("read-only slice mutation: error=%v assigned=%v decoded=%v", err, callback() != nil, codec.lastDecoded != nil)
				}
				if err := codec.lastDecoded(); !errors.Is(err, errUntransferredTestCallback) {
					t.Fatalf("read-only write committed a callback: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			assigned := callback()
			if assigned == nil {
				t.Fatal("callback was not assigned")
			}
			if err := assigned(); err != nil {
				t.Fatalf("assigned callback does not own its lease: %v", err)
			}
		})
	}
}

func TestHostBridgePartialSlicePushCommitsOnlyAcceptedCallbacks(t *testing.T) {
	session := NewSession()
	codec := &handoffTestCodec{session: session}
	items := []func() error{}
	ref, err := session.RegisterObject(&items)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.CallWithCodec(ref, "push", []Value{CallbackValue(1), StringValue("invalid callback"), CallbackValue(2)}, codec); err == nil {
		t.Fatal("slice push accepted a nonfunction after its first callback")
	}
	if len(items) != 1 || items[0] == nil {
		t.Fatalf("partial push did not preserve its accepted prefix: length=%d", len(items))
	}
	if err := items[0](); err != nil {
		t.Fatalf("accepted prefix callback was not handed off: %v", err)
	}
}
