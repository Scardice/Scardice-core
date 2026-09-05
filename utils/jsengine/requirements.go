package jsengine

import (
	"errors"
	"fmt"
)

// ErrRuntimeRequirements indicates that a provider or loop cannot satisfy the
// host profile required by its caller.
var ErrRuntimeRequirements = errors.New("JavaScript runtime requirements not satisfied")

// RuntimeRequirements describes the minimum host profile for one runtime
// consumer. Descriptor validation happens before opening a provider; loop
// validation confirms optional interfaces after the provider creates it.
type RuntimeRequirements struct {
	RequiredCapabilities      CapabilitySet
	RequireContextPropagation bool
}

// ValidateDescriptor rejects a provider before it can create a live runtime.
func (r RuntimeRequirements) ValidateDescriptor(descriptor Descriptor) error {
	missing := r.RequiredCapabilities &^ descriptor.Capabilities
	if missing != 0 {
		return fmt.Errorf("%w: provider %q is missing capability bits 0x%x", ErrRuntimeRequirements, descriptor.ID, uint64(missing))
	}
	if r.RequireContextPropagation && !descriptor.Capabilities.Has(CapabilityContextPropagation) {
		return fmt.Errorf("%w: provider %q does not advertise context propagation", ErrRuntimeRequirements, descriptor.ID)
	}
	return nil
}

// ValidateLoop confirms that the opened loop still satisfies the advertised
// descriptor and exposes every optional interface required by the host.
func (r RuntimeRequirements) ValidateLoop(loop Loop) error {
	if loop == nil {
		return fmt.Errorf("%w: provider returned a nil loop", ErrRuntimeRequirements)
	}
	if err := r.ValidateDescriptor(loop.Descriptor()); err != nil {
		return err
	}
	if r.RequireContextPropagation {
		if _, ok := loop.(ContextAwareLoop); !ok {
			return fmt.Errorf("%w: provider %q does not implement context propagation", ErrRuntimeRequirements, loop.Engine())
		}
	}
	return nil
}
