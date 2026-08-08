package v161

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
