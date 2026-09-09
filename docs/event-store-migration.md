# Event-store migration

Scardice starts only after an independently owned event database passes the
readiness gate. The legacy `migrate/v2` package is not executed by startup or
by the event-sourcing importer.

## Required startup configuration

Set these values before starting the binary:

```text
SCARDICE_ENDPOINT_DB=/var/lib/scardice/events.db
SCARDICE_ENDPOINT_KEY_INDEX=/var/lib/scardice/keys/index
SCARDICE_ENDPOINT_KEY_ROOTS=/var/lib/scardice/keys/roots
SCARDICE_ENDPOINT_DB_ID=events-prod-2026-09
SCARDICE_ADMIN_TOKEN=<stable bearer secret>
SCARDICE_ADMIN_PRINCIPAL_ID=local-admin
SCARDICE_ADMIN_ORIGINS=https://admin.example
```

The index and encryption roots are external key-provider material. The
startup process never copies them into a migration snapshot. The admin token
is supplied only in process configuration and is accepted in the
`Authorization: Bearer` header; query-string credentials are rejected.

SQLite event databases use one writer, WAL, foreign keys, and
`synchronous=FULL`. MySQL/PostgreSQL configuration is supported by the
`eventstore.DatabaseConfig` API, but the current executable environment
adapter is intentionally SQLite-only until a remote deployment supplies its
TLS and publication configuration.

## Fresh initialization

An empty event database is initialized with `store_readiness.mode=fresh` by
`eventstore.NewStore`. Startup then validates the pinned database identity,
index root, and projection/readiness metadata before constructing Core,
Supervisor, dispatcher, or the UI server.

If legacy state is present without an import-mode readiness record, startup
returns a migration-required error and does not start provider workers or the
legacy launcher.

## Import workflow

The package `migrate/eventsourcing` exposes the bounded workflow:

1. inventory the stopped source without mutating it;
2. run `DecidePreflight` for `ModeImport`;
3. create an owner-only snapshot tree;
4. re-check source metadata;
5. build a sorted, length-prefixed semantic manifest;
6. validate 500-record/8 MiB deterministic batches; and
7. publish `store_readiness.mode=import` only after validation.

Failed attempts are quarantined with an owner-only `.quarantine` marker.
Source metadata is checked again before publication. Credentials and message
bodies are not included in manifests.

A source inventory must declare a complete ownership map. Incomplete legacy
inventories are rejected rather than silently imported. The current importer
publishes validated readiness and manifest evidence; it does not yet seed all
legacy aggregate streams or perform a remote SQL publication. Operators must
keep the legacy release active and provide a complete source adapter before
using import mode for production data.

## Verification

Focused checks:

```bash
go test ./migrate/eventsourcing ./eventstore ./endpoint ./api
```

The full release gate is documented in the redesign plan. A migration is not
considered complete from unit tests alone: reopen the exact published target,
rebuild projections, compare semantic manifests, and verify the source digest
is unchanged.
