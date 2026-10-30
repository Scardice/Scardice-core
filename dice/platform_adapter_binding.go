package dice

// endpointRuntimeBinder is the remaining compatibility seam for in-process
// message helpers. Provider construction and lifecycle are owned by descriptors
// and EndpointSupervisor; binding only supplies the current Core shell pointer.
type endpointRuntimeBinder interface {
	bindEndpoint(*EndPointInfo)
}

func (adapter *PlatformAdapterGocq) bindEndpoint(endpoint *EndPointInfo) {
	adapter.EndPoint = endpoint
}

func (adapter *PlatformAdapterWalleQ) bindEndpoint(endpoint *EndPointInfo) {
	adapter.EndPoint = endpoint
}

func (adapter *PlatformAdapterOfficialQQ) bindEndpoint(endpoint *EndPointInfo) {
	adapter.EndPoint = endpoint
}

func (adapter *PlatformAdapterSatori) bindEndpoint(endpoint *EndPointInfo) {
	adapter.EndPoint = endpoint
}

func (adapter *PlatformAdapterMilky) bindEndpoint(endpoint *EndPointInfo) {
	adapter.EndPoint = endpoint
}

func (adapter *PlatformAdapterHTTP) bindEndpoint(endpoint *EndPointInfo) {
	adapter.EndPoint = endpoint
}
