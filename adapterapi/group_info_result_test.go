package adapterapi

import (
	"strings"
	"testing"
)

func TestGroupInfoResultValidation(t *testing.T) {
	valid := GroupInfoResult{
		Conversation:        "QQ-Group:2002",
		Name:                "Group Name",
		MemberCount:         23,
		MaxMemberCount:      500,
		MemberCountKnown:    true,
		MaxMemberCountKnown: true,
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid group info rejected: %v", err)
	}
	result := SucceededGroupInfoResult(valid)
	if result.Outcome != EffectSucceeded || result.GroupInfo == nil {
		t.Fatalf("typed success result = %#v", result)
	}
	if err := result.Validate(); err != nil {
		t.Fatalf("typed success result rejected: %v", err)
	}
}

func TestGroupInfoResultBindsGroupTarget(t *testing.T) {
	info := GroupInfoResult{Conversation: "QQ-Group:2002", Name: "Group"}
	if err := info.ValidateForTarget(EffectTarget{Kind: TargetGroup, Conversation: "QQ-Group:2002"}); err != nil {
		t.Fatalf("matching group target rejected: %v", err)
	}
	if err := info.ValidateForTarget(EffectTarget{Kind: TargetGroup, Conversation: "QQ-Group:9999"}); err == nil {
		t.Fatal("mismatched group target accepted")
	}
	if err := info.ValidateForTarget(EffectTarget{Kind: TargetPerson, Conversation: "QQ-Group:2002"}); err == nil {
		t.Fatal("non-group target accepted")
	}
}

func TestGroupInfoResultRejectsMalformedProviderFacts(t *testing.T) {
	tests := []struct {
		name string
		info GroupInfoResult
	}{
		{
			name: "invalid conversation",
			info: GroupInfoResult{Conversation: "bad\nconversation", Name: "Group", MemberCount: 1, MaxMemberCount: 2, MemberCountKnown: true, MaxMemberCountKnown: true},
		},
		{
			name: "oversized name",
			info: GroupInfoResult{Conversation: "QQ-Group:2002", Name: strings.Repeat("x", MaxEffectFieldBytes+1), MemberCount: 1, MaxMemberCount: 2, MemberCountKnown: true, MaxMemberCountKnown: true},
		},
		{
			name: "member count exceeds maximum",
			info: GroupInfoResult{Conversation: "QQ-Group:2002", Name: "Group", MemberCount: 3, MaxMemberCount: 2, MemberCountKnown: true, MaxMemberCountKnown: true},
		},
		{
			name: "missing name",
			info: GroupInfoResult{Conversation: "QQ-Group:2002"},
		},
		{
			name: "unknown member count carries a value",
			info: GroupInfoResult{Conversation: "QQ-Group:2002", Name: "Group", MemberCount: 1},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.info.Validate(); err == nil {
				t.Fatalf("malformed group info accepted: %#v", test.info)
			}
		})
	}
}

func TestEffectResultRejectsGroupInfoOnNonSuccess(t *testing.T) {
	result := RetryableResult("provider_retry", "retry")
	result.GroupInfo = &GroupInfoResult{
		Conversation:        "QQ-Group:2002",
		Name:                "Group",
		MemberCount:         1,
		MaxMemberCount:      2,
		MemberCountKnown:    true,
		MaxMemberCountKnown: true,
	}
	if err := result.Validate(); err == nil {
		t.Fatalf("retryable result carried a success observation: %#v", result)
	}
}
