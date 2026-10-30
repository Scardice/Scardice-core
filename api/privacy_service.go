package api

import (
	"sync"

	"Scardice-core/core/privacypurge"
)

var privacyPurgeState struct {
	sync.RWMutex
	service *privacypurge.Service
}

func RegisterPrivacyPurgeService(service *privacypurge.Service) {
	privacyPurgeState.Lock()
	privacyPurgeState.service = service
	privacyPurgeState.Unlock()
}
func privacyPurgeService() *privacypurge.Service {
	privacyPurgeState.RLock()
	defer privacyPurgeState.RUnlock()
	return privacyPurgeState.service
}
