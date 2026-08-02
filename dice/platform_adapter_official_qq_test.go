package dice

import (
	"testing"

	"github.com/sealdice/botgo/dto"
)

func TestOfficialQQGroupMessage_convertsMemberRole(t *testing.T) {
	// Given
	adapter := &PlatformAdapterOfficialQQ{AppID: 123}
	payload := &dto.WSGroupATMessageData{
		GroupOpenID: "group-open-id",
		Author: &dto.User{
			MemberOpenID: "member-open-id",
			MemberRole:   "2",
		},
	}

	// When
	message := adapter.groupMsgToStdMsg(payload)

	// Then
	if message.Sender.GroupRole != "2" {
		t.Fatalf("GroupRole = %q, want %q", message.Sender.GroupRole, "2")
	}
}

func TestOfficialQQMediaInfo_decodesBase64FileInfo(t *testing.T) {
	// Given
	fileInfo := "ZmlsZS1pbmZv"

	// When
	media := newOfficialQQMediaInfo(fileInfo)

	// Then
	if got := string(media.FileInfo); got != "file-info" {
		t.Fatalf("FileInfo = %q, want %q", got, "file-info")
	}
}
