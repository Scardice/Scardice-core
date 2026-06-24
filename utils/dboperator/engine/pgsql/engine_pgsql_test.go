package pgsql_test

import (
	"testing"

	"Scardice-core/utils/constant"
	"Scardice-core/utils/dboperator/engine/pgsql"
)

func TestPGSQLEngineType(t *testing.T) {
	if got := (&pgsql.PGSQLEngine{}).Type(); got != constant.POSTGRESQL {
		t.Fatalf("PGSQLEngine.Type() = %q, want %q", got, constant.POSTGRESQL)
	}
}
