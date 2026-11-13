package docengine

import (
	"sort"
	"strconv"
)

func (d *BlugeSearchEngine) ensureNumericIDMappingLocked() error {
	if !d.numericIDDirty && d.idList != nil && d.idToNumber != nil {
		return nil
	}
	return d.rebuildNumericIDMappingLocked()
}

func (d *BlugeSearchEngine) rebuildNumericIDMappingLocked() error {
	ids, err := d.listAllDocumentIDsLocked()
	if err != nil {
		return err
	}

	sort.Strings(ids)
	d.idList = ids
	d.idToNumber = make(map[string]int, len(ids))
	for index, id := range ids {
		d.idToNumber[id] = index + 1
	}
	d.CurID = uint64(len(ids))
	d.numericIDDirty = false
	return nil
}

func (d *BlugeSearchEngine) numericID(id string) string {
	if number, ok := d.idToNumber[id]; ok {
		return strconv.Itoa(number)
	}
	return id
}

func (d *BlugeSearchEngine) ListAllDocumentIDs() ([]string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.ensureNumericIDMappingLocked(); err != nil {
		return nil, err
	}
	return append([]string(nil), d.idList...), nil
}
