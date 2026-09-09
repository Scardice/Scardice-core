package api

import (
	"testing"

	"Scardice-core/endpoint"
)

func TestPureMutationCommandIDScopesOperationAndRequest(t *testing.T) {
	first := pureMutationCommandID(endpoint.CommandEnable, "ep-1", "request-a")
	if first != pureMutationCommandID(endpoint.CommandEnable, "ep-1", "request-a") { t.Fatal("same idempotency key did not produce stable command ID") }
	if first == pureMutationCommandID(endpoint.CommandEnable, "ep-1", "request-b") { t.Fatal("different enable requests reused command ID") }
	if first == pureMutationCommandID(endpoint.CommandDisable, "ep-1", "request-a") { t.Fatal("enable and disable reused command ID") }
	if first == pureMutationCommandID(endpoint.CommandUpdateConfig, "ep-1", "request-a") { t.Fatal("update and enable reused command ID") }
	if pureMutationCommandID(endpoint.CommandEnable, "ep-1", "") == pureMutationCommandID(endpoint.CommandEnable, "ep-1", "") { t.Fatal("requests without idempotency keys reused command ID") }
}
