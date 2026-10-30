package dice

import "sort"

// Snapshot returns sorted copies of the active ban-list items.
func (i *BanListInfo) Snapshot() []*BanListInfoItem {
	return i.snapshot()
}

func cloneBanListItem(item *BanListInfoItem) *BanListInfoItem {
	if item == nil {
		return nil
	}
	copyItem := *item
	copyItem.Times = append([]int64(nil), item.Times...)
	copyItem.Reasons = append([]string(nil), item.Reasons...)
	copyItem.Places = append([]string(nil), item.Places...)
	return &copyItem
}

func (i *BanListInfo) snapshot() []*BanListInfoItem {
	if i == nil {
		return []*BanListInfoItem{}
	}
	i.itemsMu.RLock()
	defer i.itemsMu.RUnlock()
	if i.Map == nil {
		return []*BanListInfoItem{}
	}
	items := make([]*BanListInfoItem, 0)
	i.Map.Range(func(_ string, item *BanListInfoItem) bool {
		if item != nil {
			items = append(items, cloneBanListItem(item))
		}
		return true
	})
	sort.Slice(items, func(a, b int) bool {
		left, right := items[a], items[b]
		leftTime, rightTime := left.BanUpdatedAt, right.BanUpdatedAt
		if leftTime == 0 {
			leftTime = left.BanTime
		}
		if rightTime == 0 {
			rightTime = right.BanTime
		}
		if leftTime != rightTime {
			return leftTime > rightTime
		}
		return left.ID < right.ID
	})
	return items
}

func (i *BanListInfo) PersistenceError() error {
	if i == nil {
		return nil
	}
	i.persistenceMu.Lock()
	defer i.persistenceMu.Unlock()
	return i.persistenceLoadErr
}
