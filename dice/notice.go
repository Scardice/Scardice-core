package dice

import "strings"

type NoticeType string

const (
	NoticeTypeGroup    NoticeType = "group"
	NoticeTypeInvite   NoticeType = "invite"
	NoticeTypeBan      NoticeType = "ban"
	NoticeTypeCensor   NoticeType = "censor"
	NoticeTypeInactive NoticeType = "inactive"
	NoticeTypeSend     NoticeType = "send"
	NoticeTypeSystem   NoticeType = "system"
)

var AllNoticeTypes = []NoticeType{
	NoticeTypeGroup,
	NoticeTypeInvite,
	NoticeTypeBan,
	NoticeTypeCensor,
	NoticeTypeInactive,
	NoticeTypeSend,
	NoticeTypeSystem,
}

var validNoticeTypes = func() map[NoticeType]struct{} {
	result := make(map[NoticeType]struct{}, len(AllNoticeTypes))
	for _, noticeType := range AllNoticeTypes {
		result[noticeType] = struct{}{}
	}
	return result
}()

type NoticeTarget struct {
	ID                  string
	Disabled            bool
	NoticeTypes         []NoticeType
	HasNoticeTypeFilter bool
}

func ParseNoticeTarget(raw string) NoticeTarget {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	target := NoticeTarget{}
	end := len(parts)

	for end > 1 {
		suffix := strings.TrimSpace(parts[end-1])
		switch {
		case suffix == "disable":
			target.Disabled = true
			end--
		case strings.HasPrefix(suffix, "only="):
			if !target.HasNoticeTypeFilter {
				target.HasNoticeTypeFilter = true
				for _, value := range strings.Split(strings.TrimPrefix(suffix, "only="), ",") {
					noticeType := NoticeType(strings.TrimSpace(value))
					if _, ok := validNoticeTypes[noticeType]; ok {
						target.NoticeTypes = append(target.NoticeTypes, noticeType)
					}
				}
			}
			end--
		default:
			target.ID = strings.TrimSpace(strings.Join(parts[:end], ":"))
			target.NoticeTypes = normalizeNoticeTypes(target.NoticeTypes)
			return target
		}
	}

	target.ID = strings.TrimSpace(strings.Join(parts[:end], ":"))
	target.NoticeTypes = normalizeNoticeTypes(target.NoticeTypes)
	return target
}

func (target NoticeTarget) Allows(noticeType NoticeType) bool {
	if target.Disabled || target.ID == "" {
		return false
	}
	if !target.HasNoticeTypeFilter {
		return true
	}
	for _, allowed := range target.NoticeTypes {
		if allowed == noticeType {
			return true
		}
	}
	return false
}

func (target NoticeTarget) String() string {
	id := strings.TrimSpace(target.ID)
	if id == "" {
		return ""
	}

	var result strings.Builder
	result.WriteString(id)
	if target.Disabled {
		result.WriteString(":disable")
	}

	types := normalizeNoticeTypes(target.NoticeTypes)
	if target.HasNoticeTypeFilter && len(types) != len(AllNoticeTypes) {
		result.WriteString(":only=")
		for index, noticeType := range types {
			if index > 0 {
				result.WriteByte(',')
			}
			result.WriteString(string(noticeType))
		}
	}
	return result.String()
}

func (target NoticeTarget) Platform() (string, bool) {
	prefix, _, ok := strings.Cut(target.ID, ":")
	if !ok || prefix == "" {
		return "", false
	}
	platform, _, _ := strings.Cut(prefix, "-")
	return platform, platform != ""
}

func (target NoticeTarget) MatchesEndpoint(platform, protocolType string) bool {
	targetPlatform, ok := target.Platform()
	if !ok || targetPlatform == "Mail" {
		return false
	}

	switch targetPlatform {
	case "OpenQQ", "OpenQQCH":
		return platform == "QQ" && protocolType == "official"
	case "QQ":
		return platform == "QQ" && protocolType != "official"
	default:
		return targetPlatform == platform
	}
}

func (target NoticeTarget) IsGroup() bool {
	prefix, _, ok := strings.Cut(target.ID, ":")
	if !ok {
		return false
	}
	return strings.HasSuffix(prefix, "-Group") ||
		strings.HasSuffix(prefix, "-Channel") ||
		strings.HasSuffix(prefix, "-Guild")
}

func normalizeNoticeTypes(types []NoticeType) []NoticeType {
	selected := make(map[NoticeType]struct{}, len(types))
	for _, noticeType := range types {
		if _, ok := validNoticeTypes[noticeType]; ok {
			selected[noticeType] = struct{}{}
		}
	}

	result := make([]NoticeType, 0, len(selected))
	for _, noticeType := range AllNoticeTypes {
		if _, ok := selected[noticeType]; ok {
			result = append(result, noticeType)
		}
	}
	return result
}

func filterNoticeTargets(rawTargets []string, noticeType NoticeType) []NoticeTarget {
	targets := make([]NoticeTarget, 0, len(rawTargets))
	for _, raw := range rawTargets {
		target := ParseNoticeTarget(raw)
		if target.Allows(noticeType) {
			targets = append(targets, target)
		}
	}
	return targets
}

func filterNoticeTargetsForEndpoint(rawTargets []string, noticeType NoticeType, endpoint *EndPointInfo) []NoticeTarget {
	targets := filterNoticeTargets(rawTargets, noticeType)
	matched := make([]NoticeTarget, 0, len(targets))
	for _, target := range targets {
		if noticeTargetMatchesEndpoint(target, endpoint) {
			matched = append(matched, target)
		}
	}
	return matched
}
