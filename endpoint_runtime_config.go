package main

import (
	"errors"
	"strings"

	"Scardice-core/eventstore"
)

var errEndpointBootstrapConfig = errors.New("endpoint bootstrap requires database, key index, key roots, and database identity")

func endpointDatabaseConfigFromEnv(getenv func(string) string) (eventstore.DatabaseConfig, error) {
	if getenv == nil { return eventstore.DatabaseConfig{}, errEndpointBootstrapConfig }
	databasePath := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_DB"))
	if databasePath == "" { return eventstore.DatabaseConfig{}, nil }
	indexPath := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_KEY_INDEX"))
	rootsPath := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_KEY_ROOTS"))
	identity := strings.TrimSpace(getenv("SCARDICE_ENDPOINT_DB_ID"))
	if indexPath == "" || rootsPath == "" || identity == "" { return eventstore.DatabaseConfig{}, errEndpointBootstrapConfig }
	return eventstore.DatabaseConfig{
		Type: "sqlite", DSN: databasePath,
		KeySource: eventstore.NewUnixFileKeySource(indexPath, rootsPath),
		DatabaseIdentity: identity,
	}, nil
}
