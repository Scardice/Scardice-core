package main

import (
	"sync"

	"go.uber.org/zap"
)

func oncePprofStop(stop func()) func() {
	return sync.OnceFunc(stop)
}

func startPprofRecordIfEnabled(enabled bool, log *zap.SugaredLogger, bootTime int64) (func(), error) {
	if !enabled {
		return func() {}, nil
	}

	recorder, err := startPprofRecord(log, bootTime)
	if err != nil {
		return nil, err
	}
	return oncePprofStop(func() {
		recorder.stop(log)
	}), nil
}
