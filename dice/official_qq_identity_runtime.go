package dice

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sealdice/botgo/dto"

	"Scardice-core/dice/service"
)

func (pa *PlatformAdapterOfficialQQ) migrateVerifiedIdentityAfterMe(
	ctx context.Context,
	d *Dice,
	identity *dto.User,
) (service.OfficialQQIdentityMigrationResult, error) {
	source := service.OfficialQQVerifiedIdentitySource{
		AppID:       pa.AppID,
		VerifiedUIN: identity.ID,
	}
	if identity.ID != "" {
		source.Groups = pa.currentOfficialQQIdentitySources(d)
	}
	migrator := service.NewOfficialQQIdentityMigrator(d.DBOperator, time.Now)
	return migrator.MigrateVerifiedSource(ctx, source, service.OfficialQQIdentityMigrationDefaultBatchSize)
}

func (pa *PlatformAdapterOfficialQQ) currentOfficialQQIdentitySources(d *Dice) []service.OfficialQQGroupIdentitySource {
	if d == nil || d.ImSession == nil || d.ImSession.ServiceAtNew == nil {
		return nil
	}
	account := strconv.FormatUint(pa.AppID, 10)
	groupPrefix := formatDiceIDOfficialQQGroupOpenID(account, "")
	membersByGroup := map[string]map[string]struct{}{}
	d.ImSession.ServiceAtNew.Range(func(groupID string, group *GroupInfo) bool {
		groupOpenID, ok := strings.CutPrefix(groupID, groupPrefix)
		if !ok || groupOpenID == "" {
			return true
		}
		members := map[string]struct{}{}
		membersByGroup[groupOpenID] = members
		if group == nil || group.Players == nil {
			return true
		}
		memberPrefix := formatDiceIDOfficialQQMemberOpenID(account, groupOpenID, "")
		group.Players.Range(func(userID string, _ *GroupPlayerInfo) bool {
			memberOpenID, ok := strings.CutPrefix(userID, memberPrefix)
			if ok && memberOpenID != "" {
				members[memberOpenID] = struct{}{}
			}
			return true
		})
		return true
	})

	groupOpenIDs := make([]string, 0, len(membersByGroup))
	for groupOpenID := range membersByGroup {
		groupOpenIDs = append(groupOpenIDs, groupOpenID)
	}
	sort.Strings(groupOpenIDs)
	sources := make([]service.OfficialQQGroupIdentitySource, 0, len(groupOpenIDs))
	for _, groupOpenID := range groupOpenIDs {
		members := make([]string, 0, len(membersByGroup[groupOpenID]))
		for memberOpenID := range membersByGroup[groupOpenID] {
			members = append(members, memberOpenID)
		}
		sort.Strings(members)
		sources = append(sources, service.OfficialQQGroupIdentitySource{
			GroupOpenID:   groupOpenID,
			MemberOpenIDs: members,
		})
	}
	return sources
}
