package dice

import (
	"path/filepath"
	"strings"
	"testing"

	"Scardice-core/dice/docengine"
)

func TestHelpManagerGetContentResolvesResourcesRelativeToSource(t *testing.T) {
	packageRoot := filepath.Join(t.TempDir(), "cache", "packages", "author", "help-package")
	source := filepath.Join(packageRoot, "helpdoc", "rules.xlsx")
	item := &docengine.HelpTextItem{
		From: source,
		Content: "entry [图:./../assets/card.png] " +
			"[CQ:video,file=./../assets/video.mp4,cache=0]",
	}

	got := (&HelpManager{}).GetContent(item, 0)
	wantImage, err := filepath.Abs(filepath.Join(packageRoot, "assets", "card.png"))
	if err != nil {
		t.Fatal(err)
	}
	wantVideo, err := filepath.Abs(filepath.Join(packageRoot, "assets", "video.mp4"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "[图:"+filepath.ToSlash(wantImage)+"]") {
		t.Fatalf("help content image path was not resolved: %q", got)
	}
	if !strings.Contains(got, "file="+filepath.ToSlash(wantVideo)) || !strings.Contains(got, "cache=0") {
		t.Fatalf("help content CQ video path or parameters were not preserved: %q", got)
	}
}
