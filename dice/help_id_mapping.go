package dice

import (
	"errors"
	"fmt"
	"sort"
	"strconv"

	"Scardice-core/dice/docengine"
)

func (m *HelpManager) rebuildDocIDs() error {
	ids, err := m.searchEngine.ListAllDocumentIDs()
	if err != nil {
		return fmt.Errorf("list help document IDs: %w", err)
	}
	m.docIDs = ids
	m.CurID = uint64(len(ids))
	return nil
}

func (m *HelpManager) GetItemByNumericID(id int) (*docengine.HelpTextItem, error) {
	if id <= 0 || id > len(m.docIDs) {
		return nil, errors.New("无效的帮助条目ID")
	}
	return m.searchEngine.GetItemByInternalID(m.docIDs[id-1])
}

func (m *HelpManager) GetItemByNumericIDString(id string) (*docengine.HelpTextItem, error) {
	numericID, err := strconv.Atoi(id)
	if err != nil {
		return nil, fmt.Errorf("parse help item ID %q: %w", id, err)
	}
	return m.GetItemByNumericID(numericID)
}

func (m *HelpManager) getNumericIDByInternalID(internalID string) (int, bool) {
	index := sort.SearchStrings(m.docIDs, internalID)
	if index >= len(m.docIDs) || m.docIDs[index] != internalID {
		return 0, false
	}
	return index + 1, true
}
