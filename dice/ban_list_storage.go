package dice

import (
	"context"
	"errors"
	"sort"
)

// Snapshot returns sorted copies of the active ban-list items.
func (i *BanListInfo) Snapshot() []*BanListInfoItem {
	return i.snapshot()
}

// SnapshotForContext returns the transaction-local moderation list, including
// subjects created or deleted earlier in the same root.
func (i *BanListInfo) SnapshotForContext(ctx *MsgContext) ([]*BanListInfoItem, error) {
	if i == nil || i.Parent == nil {
		return []*BanListInfoItem{}, nil
	}
	if ctx == nil || ctx.callbackTransaction == nil {
		items, err := i.Parent.GetBanListWithError(context.Background())
		if err != nil {
			return nil, err
		}
		sortBanListItems(items)
		return items, nil
	}
	if ctx.Dice != nil && ctx.Dice != i.Parent {
		return nil, errors.New("ban list message context belongs to another dice")
	}
	repository, err := newModerationBanRepository(i.Parent)
	if err != nil {
		return nil, err
	}
	subjectIDs, err := repository.listSubjectIDs(ctx.domainContext())
	if err != nil {
		return nil, err
	}
	subjects := make(map[string]struct{}, len(subjectIDs))
	for _, subjectID := range subjectIDs {
		subjects[subjectID] = struct{}{}
	}
	overlay, err := i.Parent.moderationOverlaySnapshot(ctx.callbackTransaction.Domain())
	if err != nil {
		return nil, err
	}
	for subjectID, exists := range overlay {
		if exists {
			subjects[subjectID] = struct{}{}
		} else {
			delete(subjects, subjectID)
		}
	}
	items := make([]*BanListInfoItem, 0, len(subjects))
	for subjectID := range subjects {
		item, exists, readErr := i.Parent.ModerationItemForDomain(
			ctx.domainContext(), ctx.callbackTransaction.Domain(), subjectID,
		)
		if readErr != nil {
			return nil, readErr
		}
		if exists {
			items = append(items, item)
		}
	}
	sortBanListItems(items)
	return items, nil
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

func sortBanListItems(items []*BanListInfoItem) {
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
}

func (i *BanListInfo) snapshot() []*BanListInfoItem {
	if i == nil || i.Parent == nil {
		return []*BanListInfoItem{}
	}
	items, err := i.Parent.GetBanListWithError(context.Background())
	if err != nil {
		if i.Parent.Logger != nil {
			i.Parent.Logger.Errorf("黑白名单读取失败: %v", err)
		}
		return []*BanListInfoItem{}
	}
	return items
}

// PersistenceError performs a fresh authoritative read. It is retained for
// callers that previously checked the removed mutable-cache load status.
func (i *BanListInfo) PersistenceError() error {
	return i.LoadsWithError()
}
