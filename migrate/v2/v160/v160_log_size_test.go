package v160

import "testing"

func Test_V160LogSizeRepairMigrate_succeeds_for_fresh_database(t *testing.T) {
	// Given
	operator := newMigrationTestOperator(t)

	// When
	cleanErr := V160LogIDZeroCleanMigrate(operator, func(string) {})
	repairErr := V160LogSizeRepairMigrate(operator, func(string) {})

	// Then
	if cleanErr != nil {
		t.Fatalf("clean fresh database: %v", cleanErr)
	}
	if repairErr != nil {
		t.Fatalf("repair fresh database: %v", repairErr)
	}
}
