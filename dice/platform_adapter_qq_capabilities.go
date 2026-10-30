package dice

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type botGroupRoleResolver interface {
	botGroupRole(ctx *MsgContext, groupID string, bypassCache bool) (string, error)
}

func (adapter *PlatformAdapterGocq) botGroupRole(ctx *MsgContext, groupID string, bypassCache bool) (string, error) {
	botID := strings.TrimSpace(UserIDExtract(ctx.EndPoint.UserID))
	group := strings.TrimSpace(UserIDExtract(groupID))
	if botID == "" || group == "" {
		return "", errors.New("cannot resolve bot/group id")
	}
	member := adapter.getGroupMemberInfo(group, botID, bypassCache)
	if member == nil {
		return "", errors.New(errGetGroupMemberInfoNil)
	}
	return member.Role, nil
}

func (adapter *PlatformAdapterMilky) botGroupRole(ctx *MsgContext, groupID string, bypassCache bool) (string, error) {
	member, err := adapter.getGroupMemberInfo(groupID, ctx.EndPoint.UserID, bypassCache)
	if err != nil {
		return "", fmt.Errorf("get_group_member_info failed: %w", err)
	}
	if member == nil {
		return "", errors.New(errGetGroupMemberInfoNil)
	}
	return member.Role, nil
}

type officialQQIdentityAccountProvider interface {
	officialQQIdentityAccount() string
}

func (adapter *PlatformAdapterOfficialQQ) officialQQIdentityAccount() string {
	return strconv.FormatUint(adapter.AppID, 10)
}
