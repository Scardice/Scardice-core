package dice

import (
	"errors"
	"testing"

	"Scardice-core/adapterapi"
)

func TestUnsupportedFileAdaptersReportUnsupported(t *testing.T) {
	tests := []struct {
		name string
		send func() adapterapi.EffectResult
	}{
		{"HTTP person", func() adapterapi.EffectResult {
			return (&PlatformAdapterHTTP{}).SendFileToPerson(nil, "user", "/synthetic/file.txt", "")
		}},
		{"HTTP group", func() adapterapi.EffectResult {
			return (&PlatformAdapterHTTP{}).SendFileToGroup(nil, "group", "/synthetic/file.txt", "")
		}},
		{"Satori person", func() adapterapi.EffectResult {
			return (&PlatformAdapterSatori{}).SendFileToPerson(nil, "user", "/synthetic/file.txt", "")
		}},
		{"Satori group", func() adapterapi.EffectResult {
			return (&PlatformAdapterSatori{}).SendFileToGroup(nil, "group", "/synthetic/file.txt", "")
		}},
		{"Official QQ person", func() adapterapi.EffectResult {
			return (&PlatformAdapterOfficialQQ{}).SendFileToPerson(nil, "user", "/synthetic/file.txt", "")
		}},
		{"Official QQ group", func() adapterapi.EffectResult {
			return (&PlatformAdapterOfficialQQ{}).SendFileToGroup(nil, "group", "/synthetic/file.txt", "")
		}},
		{"WalleQ person", func() adapterapi.EffectResult {
			return (&PlatformAdapterWalleQ{}).SendFileToPerson(nil, "user", "/synthetic/file.txt", "")
		}},
		{"WalleQ group", func() adapterapi.EffectResult {
			return (&PlatformAdapterWalleQ{}).SendFileToGroup(nil, "group", "/synthetic/file.txt", "")
		}},
		{"Milky person", func() adapterapi.EffectResult {
			return (&PlatformAdapterMilky{}).SendFileToPerson(nil, "user", "/synthetic/file.txt", "")
		}},
		{"GoCQ without socket", func() adapterapi.EffectResult {
			return (&PlatformAdapterGocq{}).SendFileToGroup(nil, "QQ-Group:123", "/synthetic/file.txt", "")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := test.send()
			if err := result.Validate(); err != nil {
				t.Fatalf("file send result is invalid: %v", err)
			}
			if result.Outcome != adapterapi.EffectUnsupported {
				t.Fatalf("file send outcome = %v, want unsupported", result.Outcome)
			}
		})
	}
}

func TestMilkyGroupFileWithoutSessionDoesNotClaimUpload(t *testing.T) {
	result := (&PlatformAdapterMilky{}).SendFileToGroup(nil, "QQ-Group:123", "/synthetic/file.txt", "")
	if err := result.Validate(); err != nil {
		t.Fatalf("file send result is invalid: %v", err)
	}
	if result.Outcome != adapterapi.EffectTerminal {
		t.Fatalf("file send outcome = %v, want terminal provider-unavailable result", result.Outcome)
	}
}

type fakeMilkyFileUploader struct {
	fileID       string
	err          error
	groupID      int64
	fileURI      string
	fileName     string
	parentFolder string
}

func (uploader *fakeMilkyFileUploader) UploadGroupFile(groupID int64, fileURI, fileName, parentFolder string) (string, error) {
	uploader.groupID = groupID
	uploader.fileURI = fileURI
	uploader.fileName = fileName
	uploader.parentFolder = parentFolder
	return uploader.fileID, uploader.err
}

func TestMilkyGroupUploadRequiresSynchronousFileID(t *testing.T) {
	providerErr := errors.New("synthetic upload error")
	tests := []struct {
		name            string
		fileID          string
		err             error
		wantOutcome     adapterapi.EffectOutcome
		wantProviderID  string
		wantProviderErr error
	}{
		{name: "provider accepted", fileID: "provider-file-42", wantOutcome: adapterapi.EffectSucceeded, wantProviderID: "provider-file-42"},
		{name: "missing provider file id", wantOutcome: adapterapi.EffectAmbiguous},
		{name: "provider error", err: providerErr, wantOutcome: adapterapi.EffectAmbiguous, wantProviderErr: providerErr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			uploader := &fakeMilkyFileUploader{fileID: test.fileID, err: test.err}
			result, err := uploadMilkyGroupFile(uploader, 123, "file:///synthetic/export.log", "export.log")
			if err != nil && !errors.Is(err, test.wantProviderErr) {
				t.Fatalf("upload error = %v, want %v", err, test.wantProviderErr)
			}
			if test.wantProviderErr == nil && err != nil {
				t.Fatalf("unexpected upload error: %v", err)
			}
			if result.Outcome != test.wantOutcome || result.ProviderID != test.wantProviderID {
				t.Fatalf("upload result = %#v, want outcome %v and provider ID %q", result, test.wantOutcome, test.wantProviderID)
			}
			if err := result.Validate(); err != nil {
				t.Fatalf("upload result is invalid: %v", err)
			}
			if uploader.groupID != 123 || uploader.fileURI != "file:///synthetic/export.log" || uploader.fileName != "export.log" || uploader.parentFolder != "" {
				t.Fatalf("upload request = group %d, URI %q, filename %q, parent %q", uploader.groupID, uploader.fileURI, uploader.fileName, uploader.parentFolder)
			}
		})
	}
}
