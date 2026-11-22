package main

import (
	"os"
	"path/filepath"
	"testing"

	"Scardice-core/dice"
)

func TestCheckDataDirWritable(t *testing.T) {
	dir := t.TempDir()
	if err := checkDataDirWritable(dir); err != nil {
		t.Fatalf("数据目录可写探测失败: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取探测目录失败: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("探测临时文件未清理: %v", entries)
	}
}

func TestCheckDataDirWritableMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing")
	if err := checkDataDirWritable(dir); err == nil {
		t.Fatal("目录不存在时应返回错误")
	}
}

func TestFormatEnabledEndpoints(t *testing.T) {
	endpoints := []*dice.EndPointInfo{
		{EndPointInfoBase: dice.EndPointInfoBase{Platform: "QQ", ProtocolType: "official", Nickname: "千千", Enable: true}},
		{EndPointInfoBase: dice.EndPointInfoBase{Platform: "KOOK", UserID: "kook-1", Enable: true}},
		{EndPointInfoBase: dice.EndPointInfoBase{Platform: "DISCORD", Nickname: "未启用", Enable: false}},
		{EndPointInfoBase: dice.EndPointInfoBase{Enable: true}},
	}

	enabled, total, labels := formatEnabledEndpoints(endpoints)
	if enabled != 3 || total != 4 {
		t.Fatalf("账号统计 = %d/%d, want 3/4", enabled, total)
	}
	want := "QQ/official <千千>、KOOK <kook-1>、未知平台 <未知账号>"
	if labels != want {
		t.Fatalf("账号清单 = %q, want %q", labels, want)
	}
}
