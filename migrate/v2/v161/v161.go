package v161

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"Scardice-core/dice"
	"Scardice-core/utils"
	operator "Scardice-core/utils/dboperator/engine"
	upgrade "Scardice-core/utils/upgrader"
)

const defaultServeConfigPath = "data/default/serve.yaml"

func V161MigrateNoticeTargets(configPath string) error {
	content, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("读取配置: %w", err)
	}

	var document yaml.Node
	if err = yaml.Unmarshal(content, &document); err != nil {
		return fmt.Errorf("解析配置: %w", err)
	}
	if len(document.Content) == 0 || document.Content[0].Kind != yaml.MappingNode {
		return errors.New("配置根节点不是映射")
	}

	root := document.Content[0]
	changed := false
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != "noticeIds" {
			continue
		}
		sequence := root.Content[index+1]
		if sequence.Kind != yaml.SequenceNode {
			return errors.New("noticeIds 不是列表")
		}
		for _, item := range sequence.Content {
			if item.Kind != yaml.ScalarNode {
				return errors.New("noticeIds 包含非字符串项目")
			}
			canonical := dice.ParseNoticeTarget(item.Value).String()
			if canonical != "" && canonical != item.Value {
				item.Value = canonical
				changed = true
			}
		}
		break
	}
	if !changed {
		return nil
	}

	modified, err := yaml.Marshal(&document)
	if err != nil {
		return fmt.Errorf("编码配置: %w", err)
	}
	if err := utils.AtomicWriteFile(filepath.Clean(configPath), modified, 0o644); err != nil {
		return fmt.Errorf("写入配置: %w", err)
	}
	return nil
}

var V161NoticeIDsMigration = upgrade.Upgrade{
	ID:         "011_V161NoticeIDsMigration",
	Idempotent: true,
	Description: `
# 升级说明
将旧通知 ID 规范化为可按分类筛选的通知目标；骰主列表继续仅用于权限判断。
`,
	Apply: func(logf func(string), _ operator.DatabaseOperator) error {
		logf("[INFO] V161 通知目标迁移开始")
		if err := V161MigrateNoticeTargets(defaultServeConfigPath); err != nil {
			return fmt.Errorf("迁移通知目标失败: %w", err)
		}
		logf("[INFO] V161 通知目标迁移完成")
		return nil
	},
}

// V161CopyDiceMastersToNoticeIDs 将骰主 ID 一次性补入通知列表。
//
// 已有通知目标会被保留；完全相同的 ID 不会重复添加。此函数本身保持可重复执行，
// “仅执行一次”由升级框架的迁移记录保证。
func V161CopyDiceMastersToNoticeIDs(configPath string) (int, error) {
	content, err := os.ReadFile(filepath.Clean(configPath))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// 新安装此时还没有 serve.yaml，由运行期默认配置负责初始化通知列表。
			return 0, nil
		}
		return 0, err
	}

	var config struct {
		DiceMasters []string `yaml:"diceMasters"`
		NoticeIDs   []string `yaml:"noticeIds"`
	}
	if err = yaml.Unmarshal(content, &config); err != nil {
		return 0, err
	}

	existing := make(map[string]struct{}, len(config.NoticeIDs))
	for _, target := range config.NoticeIDs {
		if id := dice.ParseNoticeTarget(target).ID; id != "" {
			existing[id] = struct{}{}
		}
	}

	added := 0
	for _, rawID := range config.DiceMasters {
		id := strings.TrimSpace(rawID)
		if id == "" {
			continue
		}
		if _, ok := existing[id]; ok {
			continue
		}
		config.NoticeIDs = append(config.NoticeIDs, id+":only=send")
		existing[id] = struct{}{}
		added++
	}
	if added == 0 {
		return 0, nil
	}

	var data map[string]any
	if err = yaml.Unmarshal(content, &data); err != nil {
		return 0, err
	}
	data["noticeIds"] = config.NoticeIDs

	modified, err := yaml.Marshal(data)
	if err != nil {
		return 0, err
	}
	if err = utils.AtomicWriteFile(filepath.Clean(configPath), modified, 0o644); err != nil {
		return 0, err
	}
	return added, nil
}

var V161CopyDiceMastersToNoticeIDsMigration = upgrade.Upgrade{
	ID:         "013_V161CopyDiceMastersToNoticeIDsMigration",
	Idempotent: true,
	Description: `
# 升级说明
将骰主 ID 一次性补入通知列表，并仅开启 send 分类，避免通知列表与骰主列表分离后骰主收不到代发通知。
`,
	Apply: func(logf func(string), _ operator.DatabaseOperator) error {
		logf("[INFO] V161 骰主通知列表补全开始")
		added, err := V161CopyDiceMastersToNoticeIDs(defaultServeConfigPath)
		if err != nil {
			return fmt.Errorf("迁移骰主 ID 到通知列表失败: %w", err)
		}
		logf(fmt.Sprintf("[INFO] V161 骰主通知列表补全完成，新增 %d 个通知目标", added))
		return nil
	},
}
