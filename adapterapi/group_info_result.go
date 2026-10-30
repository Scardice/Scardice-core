package adapterapi

import "fmt"

// GroupInfoResult is the validated provider observation returned by a
// GroupInfoRefresh effect. CountKnown distinguishes an omitted provider field
// from a real zero value.
type GroupInfoResult struct {
	Conversation        ConversationID `json:"conversation"`
	Name                string         `json:"name"`
	MemberCount         uint32         `json:"memberCount,omitempty"`
	MaxMemberCount      uint32         `json:"maxMemberCount,omitempty"`
	MemberCountKnown    bool           `json:"memberCountKnown"`
	MaxMemberCountKnown bool           `json:"maxMemberCountKnown"`
}

func (info GroupInfoResult) Validate() error {
	if !info.Conversation.Valid() || len(info.Name) == 0 || len(info.Name) > MaxEffectFieldBytes {
		return fmt.Errorf("%w: invalid group info identity or name", ErrInvalidContract)
	}
	if (!info.MemberCountKnown && info.MemberCount != 0) || (!info.MaxMemberCountKnown && info.MaxMemberCount != 0) {
		return fmt.Errorf("%w: unknown group count carries a value", ErrInvalidContract)
	}
	if info.MemberCountKnown && info.MaxMemberCountKnown && info.MemberCount > info.MaxMemberCount {
		return fmt.Errorf("%w: group member count exceeds maximum", ErrInvalidContract)
	}
	return nil
}

func (info GroupInfoResult) ValidateForTarget(target EffectTarget) error {
	if err := info.Validate(); err != nil {
		return err
	}
	if err := target.Validate(); err != nil {
		return err
	}
	if target.Kind != TargetGroup || target.Conversation != info.Conversation || target.Member != "" {
		return fmt.Errorf("%w: group info does not bind its effect target", ErrInvalidContract)
	}
	return nil
}

func SucceededGroupInfoResult(info GroupInfoResult) EffectResult {
	return EffectResult{Outcome: EffectSucceeded, GroupInfo: &info}
}
