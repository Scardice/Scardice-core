package dice

import "testing"

func TestMergeOfficialQQGroupMemoryKeepsTargetActiveExt(t *testing.T) {
	target := &GroupInfo{
		GroupID:               "OpenQQ-Group:1-new",
		activatedExtList:      []*ExtInfo{{Name: "coc7"}},
		InactivatedExtSet:     StringSet{},
		UserInactivatedExtSet: StringSet{},
	}
	source := &GroupInfo{
		GroupID:               "OpenQQ-Group:bot-old",
		InactivatedExtSet:     StringSet{"coc7": {}, "fu": {}},
		UserInactivatedExtSet: StringSet{},
	}

	mergeOfficialQQGroupMemory(target, source, nil)

	if target.IsExtInactivated("coc7") {
		t.Fatal("target active extension must not become inactive because the old group marked it inactive")
	}
	if !target.IsExtInactivated("fu") {
		t.Fatal("old group's inactive extension should still be imported")
	}
}
