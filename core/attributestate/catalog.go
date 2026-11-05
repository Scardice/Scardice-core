package attributestate

import (
	"context"
	"fmt"

	"Scardice-core/eventstore"
)

const (
	AttrsTypeCharacter = "character"
	AttrsTypeGroupUser = "group_user"
	AttrsTypeGroup     = "group"
	AttrsTypeUser      = "user"

	CharacterCatalog = "attributes/characters-by-owner/v1"
	BindingCatalog   = "attributes/bindings-by-character/v1"
)

// CatalogOwner returns the unambiguous owner identity used for catalog revisions.
func CatalogOwner(diceID, ownerID string) string {
	return fmt.Sprintf("%d:%s%d:%s", len(diceID), diceID, len(ownerID), ownerID)
}

type CatalogSnapshot struct {
	States   []State
	Catalog  string
	Owner    string
	Revision uint64
	Snapshot eventstore.DependencySnapshot
}

// ListCatalogProjected reads one Dice's projected attribute rows and the
// logical query-result revision from the same bounded snapshots. The catalog
// revision and generation/history token are carried across every page, so an
// owner-result change cannot be hidden by pagination.
func ListCatalogProjected(ctx context.Context, store any, diceID, catalog, ownerID string) (CatalogSnapshot, error) {
	repository, ok := store.(eventstore.ProjectionDependencyRepository)
	prefix, start, end, validDice := projectedDiceRowRange(diceID)
	if !ok || repository == nil || !validDice || catalog == "" || ownerID == "" {
		return CatalogSnapshot{}, ErrRepositoryUnavailable
	}
	request := eventstore.CatalogProjectionListRequest{
		Catalog: catalog, Owner: CatalogOwner(diceID, ownerID), ProjectionName: ProjectionName,
		RowKeyPrefix: prefix, RowKeyStart: start, RowKeyEnd: end, Limit: eventstore.MaxProjectionReadPageRows,
	}
	result := CatalogSnapshot{Catalog: catalog}
	for {
		page, err := repository.ListCatalogProjectionSnapshot(ctx, request)
		if err != nil {
			return CatalogSnapshot{}, err
		}
		if page.Catalog != catalog || page.Owner != CatalogOwner(diceID, ownerID) ||
			page.Snapshot.ProjectionGeneration == "" || len(page.Rows) > request.Limit ||
			page.Done != (len(page.Rows) == 0) {
			return CatalogSnapshot{}, ErrInvalidState
		}
		if page.Done {
			if page.NextRowKey != request.AfterRowKey {
				return CatalogSnapshot{}, ErrInvalidState
			}
		} else if page.NextRowKey == request.AfterRowKey ||
			page.NextRowKey != page.Rows[len(page.Rows)-1].RowKey {
			return CatalogSnapshot{}, ErrInvalidState
		}
		if result.Owner == "" {
			result.Owner = page.Owner
			result.Revision = page.CatalogRevision
			result.Snapshot = page.Snapshot
		} else if result.Revision != page.CatalogRevision || result.Snapshot != page.Snapshot || result.Owner != page.Owner {
			return CatalogSnapshot{}, eventstore.ErrParticipantConflict
		}
		for _, row := range page.Rows {
			if row.ProjectionGeneration != page.Snapshot.ProjectionGeneration ||
				row.ProjectionName != ProjectionName || row.RowKey == "" {
				return CatalogSnapshot{}, ErrInvalidState
			}
			state, err := decodeProjectedRow(row)
			if err != nil || state.DiceID != diceID {
				return CatalogSnapshot{}, ErrInvalidState
			}
			result.States = append(result.States, state)
		}
		if page.Done {
			return result, nil
		}
		request.AfterRowKey = page.NextRowKey
		request.ExpectedCatalogRevision = &result.Revision
		request.ExpectedSnapshot = &result.Snapshot
	}
}

func (snapshot CatalogSnapshot) CatalogRead() eventstore.CatalogReadExpectation {
	return eventstore.CatalogReadExpectation{Catalog: snapshot.Catalog, Owner: snapshot.Owner, ExpectedRevision: snapshot.Revision}
}

func (snapshot CatalogSnapshot) CatalogUpdate() eventstore.CatalogRevisionUpdate {
	return eventstore.CatalogRevisionUpdate{Catalog: snapshot.Catalog, Owner: snapshot.Owner, ExpectedRevision: snapshot.Revision}
}

func (snapshot CatalogSnapshot) ProjectionRead() eventstore.ProjectionReadExpectation {
	return eventstore.ProjectionReadExpectation{Generation: snapshot.Snapshot.ProjectionGeneration}
}
