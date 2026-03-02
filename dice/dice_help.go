package dice

import (
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"Scardice-core/dice/docengine"
	"Scardice-core/logger"

	"gopkg.in/yaml.v3"

	nanoid "github.com/matoous/go-nanoid/v2"

	"github.com/xuri/excelize/v2"
)

const HelpBuiltinGroup = "builtin"

const (
	Unload int = iota
	Loaded
	LoadError
)

type HelpDoc struct {
	Key        string `json:"key"`
	Name       string `json:"name"`
	Path       string `json:"path"`
	Group      string `json:"group"`
	Type       string `json:"type"`
	IsDir      bool   `json:"isDir"`
	LoadStatus int    `json:"loadStatus"`
	Deleted    bool   `json:"deleted"`

	Children []*HelpDoc `json:"children"`
}

type HelpTextItems []*docengine.HelpTextItem

func (e HelpTextItems) String(i int) string {
	return e[i].Title
}

func (e HelpTextItems) Len() int {
	return len(e)
}

type HelpManager struct {
	CurID        uint64
	EngineType   EngineType
	LoadingFn    string
	HelpDocTree  []*HelpDoc
	GroupAliases map[string]string
	// SearchEngine
	searchEngine docengine.SearchEngine

	Config *HelpConfig
	stop   atomic.Bool
	wg     sync.WaitGroup
}

type EngineType int

const (
	BleveSearch EngineType = iota // 0
	Clover                        // 1
	MeiliSearch                   // 2
)

const HelpConfigFilename = "help_config.yaml"
const helpIndexManifestPath = "./data/.cache/helpdoc/index_manifest.json"
const helpIndexManifestVersion = 1
const helpDocParsedCacheDir = "./data/.cache/helpdoc/parsed"
const helpDocParsedCacheVersion = 1

type HelpConfig struct {
	Aliases map[string][]string `json:"aliases" yaml:"aliases"`
}

type HelpDocFormat struct {
	Mod     string            `json:"mod"`
	Author  string            `json:"author"`
	Brief   string            `json:"brief"`
	Comment string            `json:"comment"`
	Helpdoc map[string]string `json:"helpdoc"`
}

type helpDocParsedCache struct {
	Version int                      `json:"version"`
	RelPath string                   `json:"relPath"`
	Size    int64                    `json:"size"`
	ModTime int64                    `json:"modTime"`
	Items   []docengine.HelpTextItem `json:"items"`
}

func (m *HelpManager) loadSearchEngineWithMode(reuse bool) error {
	if runtime.GOARCH == "arm64" {
		// 等木落测试，测试之前先不实现这个Clover模式，如果直接就能用，那也不必再实现他了
		m.EngineType = BleveSearch
	}
	if !reuse {
		// 删除旧版本数据，这里先不改，先集中精力测试BleveSearch
		_ = os.RemoveAll("./data/.cache/helpdoc/index")
		_ = os.RemoveAll("./data/_index")
		_ = os.RemoveAll("./_help_cache")
	} else {
		if err := migrateHelpIndexDir(); err != nil {
			logger.M().Warnf("[帮助文档] 索引迁移失败: %v", err)
		}
	}
	switch m.EngineType {
	case Clover:
	case BleveSearch:
		engine, err := docengine.NewBleveSearchEngine(reuse)
		if err != nil {
			return err
		}
		m.searchEngine = engine
	default:
		// 如果BleveSearch兼容性差，到时候全部回退到Clover查询
		return errors.New("unhandled default case")
	}
	return nil
}

func (m *HelpManager) Close() {
	// 关闭Bucket，并删除所有数据
	// TODO:暂时先不动删除逻辑
	m.stop.Store(true)
	m.wg.Wait()
	if m.searchEngine != nil {
		m.searchEngine.Close()
	}
	_ = os.RemoveAll("./_help_cache")
}

func (m *HelpManager) Load(internalCmdMap CmdMapCls, extList []*ExtInfo) {
	m.stop.Store(false)
	m.wg.Add(1)
	defer m.wg.Done()
	log := logger.M()
	if m.shouldStop() {
		return
	}
	oldManifest, _ := loadHelpIndexManifest()
	curManifest := buildHelpIndexManifest(m.EngineType, internalCmdMap, extList)
	reuse := canReuseHelpIndex(oldManifest, &curManifest)
	if reuse {
		log.Infof("[帮助文档] 尝试复用索引并进行增量更新")
	} else {
		log.Infof("[帮助文档] 重建索引")
	}
	if err := m.loadSearchEngineWithMode(reuse); err != nil && reuse {
		log.Warnf("[帮助文档] 索引复用失败，改为重建: %v", err)
		reuse = false
		if m.searchEngine != nil {
			m.searchEngine.Close()
		}
		if err2 := m.loadSearchEngineWithMode(false); err2 != nil {
			log.Errorf("初始化帮助文档失败，帮助文档不可用! %v", err2)
			return
		}
	} else if err != nil {
		log.Errorf("初始化帮助文档失败，帮助文档不可用! %v", err)
		return
	}

	if m.shouldStop() {
		return
	}
	if reuse && m.searchEngine.GetTotalID() == 0 {
		log.Warnf("[帮助文档] 复用索引为空，改为重建")
		reuse = false
		m.searchEngine.Close()
		if err2 := m.loadSearchEngineWithMode(false); err2 != nil {
			log.Errorf("初始化帮助文档失败，帮助文档不可用! %v", err2)
			return
		}
	}

	if reuse {
		if m.shouldStop() {
			return
		}
		if oldManifest != nil {
			m.searchEngine.SetTotalID(oldManifest.TotalID)
		}
		m.HelpDocTree = m.buildHelpDocTreeOnly()
		m.loadHelpConfigIfExists()
		changed, err := m.updateHelpIndexIncremental(oldManifest.Files, curManifest.Files)
		if err != nil {
			log.Warnf("[帮助文档] 增量更新失败，改为重建: %v", err)
			m.searchEngine.Close()
			if err2 := m.loadSearchEngineWithMode(false); err2 != nil {
				log.Errorf("初始化帮助文档失败，帮助文档不可用! %v", err2)
				return
			}
		} else {
			if m.shouldStop() {
				return
			}
			log.Infof("[帮助文档] 增量更新完成，变更: %v", changed)
			m.CurID = m.searchEngine.GetTotalID()
			if oldManifest != nil && !changed {
				curManifest.TotalID = oldManifest.TotalID
			} else {
				curManifest.TotalID = m.CurID
			}
			if err := writeHelpIndexManifest(curManifest); err != nil {
				log.Warnf("[帮助文档] 写入索引清单失败: %v", err)
			}
			log.Infof("[帮助文档] 复用现有索引完成，共计加载条目:%d", m.CurID)
			return
		}
	}

	if m.shouldStop() {
		return
	}
	_ = m.AddItem(docengine.HelpTextItem{
		Group: HelpBuiltinGroup,
		Title: "骰点",
		Content: `.help 骰点：
 .r  //丢一个100面骰
.r d10 //丢一个10面骰(数字可改)
.r 3d6 //丢3个6面骰(数字可改)
.ra 侦查 //侦查技能检定
.ra 侦查+10 //技能临时加值检定
.ra 3#p 射击 // 连续射击三次`,
		PackageName: "帮助",
	})

	_ = m.AddItem(docengine.HelpTextItem{
		Group: HelpBuiltinGroup,
		Title: "扩展",
		Content: `.help 扩展：
扩展功能可以让你开关部分指令。
例如你希望你的骰子是纯TRPG骰，那么可以通过.ext xxx off关闭一系列娱乐模块。
或者目前正在进行dnd5e游戏，你可以通过如下指令开关dnd特化扩展。COC亦然。
注意一点，不同扩展允许存在同名指令，例如dnd和coc都有st和rc，但他们本质上不是同一个指令，并不通用，还请注意。

.ext coc7 on // 打开coc7版扩展
.ext dnd5e off // 关闭dnd5版扩展

.ext dnd5e on // 打开dnd5版扩展
.ext coc7 off // 关闭coc7版扩展
`,
		PackageName: "帮助",
	})

	_ = m.AddItem(docengine.HelpTextItem{
		Group: HelpBuiltinGroup,
		Title: "跑团",
		Content: `.help 跑团：
.st 力量50 //载入技能/属性
.coc // coc7版人物做成
.dnd // dnd5版任务做成
.pc new <角色名> // 创建角色并自动绑卡，无角色名则为当前
.pc tag <角色名> // 当前群绑卡/解除绑卡(不填角色名)
.pc save <角色名> // 保存角色[不绑卡时需要手动保存]，无角色名则为当前
.pc load <角色名> // 加载角色[不绑卡]，无角色名则为当前
.pc list //列出当前角色
.pc del <角色名> //删除角色
.setcoc 2 //设置为coc2版房规
.nn 张三 //将自己的角色名设置为张三
`,
		PackageName: "帮助",
	})

	m.HelpDocTree = make([]*HelpDoc, 0)
	entries, err := os.ReadDir("data/helpdoc")
	if err != nil {
		log.Errorf("unable to read helpdoc folder: %v", err)
	}
	start := time.Now() // 获取当前时间
	totalEntries := len(entries)
	for i, entry := range entries {
		progress := float64(i+1) / float64(totalEntries) * 100
		log.Infof("[帮助文档] 处理用户定义帮助文档组[文件夹]: 当前帮助文档加载进度: %s %.2f%% (%d/%d)", entry.Name(), progress, i+1, totalEntries)
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if filepath.Base(entry.Name()) == HelpConfigFilename {
			m.loadHelpConfig()
			continue
		}
		var child HelpDoc
		child.Key = generateHelpDocKey()
		child.Name = entry.Name()
		child.Path = path.Join("data/helpdoc", entry.Name())
		child.IsDir = entry.IsDir()
		if child.IsDir {
			child.Group = entry.Name()
			child.Type = "dir"
			child.Children = make([]*HelpDoc, 0)
		} else {
			child.Group = "default"
			child.Type = filepath.Ext(child.Path)
		}
		buildHelpDocTree(&child, func(d *HelpDoc) {
			if !d.IsDir {
				ok := m.loadHelpDoc(d.Group, d.Path)
				// TODO: Batch过大好像不会释放……
				err = m.AddItemApply(false)
				if ok && err == nil {
					d.LoadStatus = Loaded
				} else {
					d.LoadStatus = LoadError
				}
			}
		})
		m.HelpDocTree = append(m.HelpDocTree, &child)
	}
	err = m.AddItemApply(false)
	if err != nil {
		log.Errorf("加载用户自定义帮助文档出现异常!: %v", err)
	}
	log.Infof("[帮助文档] 用户定义的帮助文档组已加载完成!")
	log.Infof("[帮助文档] 正在处理指令相关（含插件）帮助文档组")
	err = m.addInternalCmdHelp(internalCmdMap)
	if err != nil {
		log.Errorf("加载内置指令帮助文档出现异常: %v", err)
	}
	err = m.AddItemApply(false)
	if err != nil {
		log.Errorf("加载内置指令帮助文档出现异常: %v", err)
	}
	err = m.addExternalCmdHelp(extList)
	if err != nil {
		log.Errorf("加载插件指令帮助文档出现异常: %v", err)
	}
	err = m.AddItemApply(true)
	if err != nil {
		log.Errorf("加载插件指令帮助文档出现异常: %v", err)
	}
	log.Infof("[帮助文档] 指令相关（含插件）帮助文档组已加载完成!")
	m.CurID = m.searchEngine.GetTotalID()
	elapsed := time.Since(start) // 计算执行时间
	log.Infof("帮助文档加载完毕，共耗费时间: %s 共计加载条目:%d\n", elapsed, m.CurID)
	curManifest.TotalID = m.CurID
	if err := writeHelpIndexManifest(curManifest); err != nil {
		log.Warnf("[帮助文档] 写入索引清单失败: %v", err)
	}
}

func (m *HelpManager) loadHelpConfig() {
	data, err := os.ReadFile(filepath.Join("./data/helpdoc", HelpConfigFilename))
	if err != nil {
		panic(err)
	}
	var config HelpConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		panic(err)
	}
	m.Config = &config
	m.refreshHelpGroupAliases(config)
}

func (m *HelpManager) loadHelpConfigIfExists() {
	data, err := os.ReadFile(filepath.Join("./data/helpdoc", HelpConfigFilename))
	if err != nil {
		return
	}
	var config HelpConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		logger.M().Errorf("读取 help_config.yaml 发生错误: %v", err)
		return
	}
	m.Config = &config
	m.refreshHelpGroupAliases(config)
}

type helpDocFileInfo struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"modTime"`
}

type helpIndexManifest struct {
	Version     int               `json:"version"`
	EngineType  EngineType        `json:"engineType"`
	VersionCode int64             `json:"versionCode"`
	Fingerprint string            `json:"fingerprint"`
	Files       []helpDocFileInfo `json:"files"`
	TotalID     uint64            `json:"totalId"`
}

func loadHelpIndexManifest() (*helpIndexManifest, error) {
	data, err := os.ReadFile(helpIndexManifestPath)
	if err != nil {
		return nil, err
	}
	var manifest helpIndexManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func buildHelpIndexManifest(engineType EngineType, internalCmdMap CmdMapCls, extList []*ExtInfo) helpIndexManifest {
	curFiles, _ := collectHelpDocFiles("./data/helpdoc")
	fingerprint := buildHelpIndexFingerprint(internalCmdMap, extList)
	return helpIndexManifest{
		Version:     helpIndexManifestVersion,
		EngineType:  engineType,
		VersionCode: VERSION_CODE,
		Fingerprint: fingerprint,
		Files:       curFiles,
	}
}

func canReuseHelpIndex(old *helpIndexManifest, cur *helpIndexManifest) bool {
	if old == nil || cur == nil {
		return false
	}
	if old.Version != helpIndexManifestVersion {
		return false
	}
	if old.EngineType != cur.EngineType {
		return false
	}
	if old.VersionCode != VERSION_CODE {
		return false
	}
	if old.Fingerprint != cur.Fingerprint {
		return false
	}
	return true
}

func writeHelpIndexManifest(manifest helpIndexManifest) error {
	_ = os.MkdirAll(filepath.Dir(helpIndexManifestPath), 0o755)
	data, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return os.WriteFile(helpIndexManifestPath, data, 0o644)
}

func (m *HelpManager) updateHelpIndexIncremental(oldFiles, curFiles []helpDocFileInfo) (bool, error) {
	changed := false
	if m.shouldStop() {
		return false, nil
	}
	oldMap := map[string]helpDocFileInfo{}
	for _, i := range oldFiles {
		oldMap[i.Path] = i
	}
	curMap := map[string]helpDocFileInfo{}
	for _, i := range curFiles {
		curMap[i.Path] = i
	}

	for path := range oldMap {
		if m.shouldStop() {
			return false, nil
		}
		if _, ok := curMap[path]; !ok {
			changed = true
			fullPath := helpDocFullPathFromRel(path)
			if m.searchEngine != nil {
				if err := m.searchEngine.DeleteByFrom(fullPath); err != nil {
					return changed, err
				}
			}
		}
	}

	added := false
	for path, cur := range curMap {
		if m.shouldStop() {
			return false, nil
		}
		old, exists := oldMap[path]
		if !exists || old.Size != cur.Size || old.ModTime != cur.ModTime {
			changed = true
			fullPath := helpDocFullPathFromRel(path)
			if exists {
				if m.searchEngine != nil {
					if err := m.searchEngine.DeleteByFrom(fullPath); err != nil {
						return changed, err
					}
				}
			}
			group := helpDocGroupFromRel(path)
			if ok := m.loadHelpDoc(group, fullPath); !ok {
				return changed, fmt.Errorf("load helpdoc failed: %s", fullPath)
			}
			added = true
		}
	}

	if added {
		if err := m.AddItemApply(false); err != nil {
			return changed, err
		}
	}
	return changed, nil
}

func helpDocGroupFromRel(rel string) string {
	rel = filepath.ToSlash(rel)
	parts := strings.Split(rel, "/")
	if len(parts) > 1 && parts[0] != "" {
		return parts[0]
	}
	return "default"
}

func helpDocFullPathFromRel(rel string) string {
	return filepath.ToSlash(filepath.Join("data/helpdoc", rel))
}

func (m *HelpManager) shouldStop() bool {
	return m.stop.Load()
}

func migrateHelpIndexDir() error {
	newDir := "./data/.cache/helpdoc/index"
	oldDir := "./data/_index"
	if _, err := os.Stat(newDir); err == nil {
		return nil
	}
	if _, err := os.Stat(oldDir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(newDir), 0o755); err != nil {
		return err
	}
	if err := os.Rename(oldDir, newDir); err != nil {
		return err
	}
	return nil
}

func collectHelpDocFiles(root string) ([]helpDocFileInfo, error) {
	var files []helpDocFileInfo
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if strings.HasPrefix(d.Name(), ".") {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if d.Name() == HelpConfigFilename {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(d.Name()))
		if ext != ".json" && ext != ".xlsx" {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		files = append(files, helpDocFileInfo{
			Path:    filepath.ToSlash(rel),
			Size:    info.Size(),
			ModTime: info.ModTime().Unix(),
		})
		return nil
	})
	if err != nil && os.IsNotExist(err) {
		return []helpDocFileInfo{}, nil
	}
	return files, err
}

func buildHelpIndexFingerprint(internalCmdMap CmdMapCls, extList []*ExtInfo) string {
	h := sha256.New()
	write := func(s string) {
		_, _ = h.Write([]byte(s))
		_, _ = h.Write([]byte{0})
	}

	cmdKeys := make([]string, 0, len(internalCmdMap))
	for k := range internalCmdMap {
		cmdKeys = append(cmdKeys, k)
	}
	sort.Strings(cmdKeys)
	for _, k := range cmdKeys {
		v := internalCmdMap[k]
		write("cmd:" + k)
		write(v.ShortHelp)
		write(v.Help)
	}

	sort.Slice(extList, func(i, j int) bool {
		var a, b string
		if extList[i] != nil {
			a = extList[i].Name
		}
		if extList[j] != nil {
			b = extList[j].Name
		}
		return a < b
	})
	for _, ext := range extList {
		if ext == nil {
			continue
		}
		write("ext:" + ext.Name)
		write(ext.Version)
		if ext.GetDescText != nil {
			write(ext.GetDescText(ext))
		}
		cmdMap := ext.GetCmdMap()
		extCmdKeys := make([]string, 0, len(cmdMap))
		for k := range cmdMap {
			extCmdKeys = append(extCmdKeys, k)
		}
		sort.Strings(extCmdKeys)
		for _, k := range extCmdKeys {
			v := cmdMap[k]
			write("extcmd:" + k)
			write(v.ShortHelp)
			write(v.Help)
		}
	}

	return hex.EncodeToString(h.Sum(nil))
}

func (m *HelpManager) buildHelpDocTreeOnly() []*HelpDoc {
	log := logger.M()
	tree := make([]*HelpDoc, 0)
	entries, err := os.ReadDir("data/helpdoc")
	if err != nil {
		log.Errorf("unable to read helpdoc folder: %v", err)
		return tree
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		if filepath.Base(entry.Name()) == HelpConfigFilename {
			continue
		}
		var child HelpDoc
		child.Key = generateHelpDocKey()
		child.Name = entry.Name()
		child.Path = path.Join("data/helpdoc", entry.Name())
		child.IsDir = entry.IsDir()
		if child.IsDir {
			child.Group = entry.Name()
			child.Type = "dir"
			child.Children = make([]*HelpDoc, 0)
		} else {
			child.Group = "default"
			child.Type = filepath.Ext(child.Path)
		}
		buildHelpDocTree(&child, func(d *HelpDoc) {
			if d.IsDir {
				return
			}
			ext := strings.ToLower(filepath.Ext(d.Path))
			if ext == ".json" || ext == ".xlsx" {
				d.LoadStatus = Loaded
			} else {
				d.LoadStatus = Unload
			}
		})
		tree = append(tree, &child)
	}
	return tree
}

func (m *HelpManager) refreshHelpGroupAliases(config HelpConfig) {
	// 先清空旧的别名
	m.GroupAliases = make(map[string]string)
	for group, aliases := range config.Aliases {
		if len(aliases) > 0 {
			for _, alias := range aliases {
				m.GroupAliases[alias] = group
			}
		}
	}
}

func (m *HelpManager) SaveHelpConfig(config *HelpConfig) error {
	m.Config = config
	m.refreshHelpGroupAliases(*config)

	data, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join("./data/helpdoc", HelpConfigFilename), data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (m *HelpManager) loadHelpDoc(group string, path string) bool {
	log := logger.M()
	if m.shouldStop() {
		return false
	}
	log.Infof("[帮助文档] 加载: %s", path)
	fileExt := filepath.Ext(path)

	switch fileExt {
	case ".json":
		m.LoadingFn = path
		items, ok := m.loadHelpDocItemsFromCache(group, path)
		if !ok {
			var err error
			items, err = parseHelpDocJSON(group, path)
			if err != nil {
				log.Error("HelpManager.loadHelpDoc", err)
				return false
			}
			m.saveHelpDocItemsToCache(path, items)
		}
		for _, item := range items {
			_ = m.AddItem(item)
		}
		return true
	case ".xlsx":
		// 梨骰帮助文件
		m.LoadingFn = path
		items, ok := m.loadHelpDocItemsFromCache(group, path)
		if !ok {
			var err error
			items, err = parseHelpDocXLSX(group, path)
			if err != nil {
				log.Error("HelpManager.loadHelpDoc", err)
				return false
			}
			m.saveHelpDocItemsToCache(path, items)
		}
		for _, item := range items {
			_ = m.AddItem(item)
		}
		return true
	}
	return false
}

func parseHelpDocJSON(group string, path string) ([]docengine.HelpTextItem, error) {
	var items []docengine.HelpTextItem
	pack, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	data := HelpDocFormat{}
	if err := json.Unmarshal(pack, &data); err != nil {
		return nil, err
	}
	for k, v := range data.Helpdoc {
		items = append(items, docengine.HelpTextItem{
			Group:       group,
			From:        path,
			Title:       k,
			Content:     v,
			PackageName: data.Mod,
		})
	}
	return items, nil
}

func parseHelpDocXLSX(group string, path string) ([]docengine.HelpTextItem, error) {
	var items []docengine.HelpTextItem
	f, err := excelize.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()

	for index, s := range f.GetSheetList() {
		rows, err := f.GetRows(s)
		if err == nil {
			var synonymCount int
			for i, row := range rows {
				if i == 0 {
					synonymCount, err = validateXlsxHeaders(row)
					if err == nil {
						// 跳过第一行
						continue
					} else {
						return nil, fmt.Errorf("%s sheet %d(zero-based): %w", path, index, err)
					}
				}
				if len(row) < 3 {
					continue
				}
				var keyBuilder strings.Builder
				keyBuilder.WriteString(row[0])
				for j := range synonymCount {
					if len(row[1+j]) > 0 {
						keyBuilder.WriteString("/")
						keyBuilder.WriteString(row[1+j])
					}
				}
				key := keyBuilder.String()
				content := row[synonymCount+1]

				items = append(items, docengine.HelpTextItem{
					Group:       group,
					From:        path,
					Title:       key,
					Content:     content,
					PackageName: s,
				})
			}
		}
	}
	return items, nil
}

func helpDocCacheKey(path string) string {
	rel, err := filepath.Rel("data/helpdoc", path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	sum := sha256.Sum256([]byte(rel))
	return hex.EncodeToString(sum[:])
}

func (m *HelpManager) loadHelpDocItemsFromCache(group string, path string) ([]docengine.HelpTextItem, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	_ = os.MkdirAll(helpDocParsedCacheDir, 0o755)
	cachePath := filepath.Join(helpDocParsedCacheDir, helpDocCacheKey(path)+".gob")
	f, err := os.Open(cachePath)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	var cache helpDocParsedCache
	dec := gob.NewDecoder(f)
	if decErr := dec.Decode(&cache); decErr != nil {
		return nil, false
	}
	if cache.Version != helpDocParsedCacheVersion {
		return nil, false
	}
	rel, err := filepath.Rel("data/helpdoc", path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	if cache.RelPath != rel || cache.Size != st.Size() || cache.ModTime != st.ModTime().Unix() {
		return nil, false
	}
	for i := range cache.Items {
		cache.Items[i].Group = group
		cache.Items[i].From = path
	}
	return cache.Items, true
}

func (m *HelpManager) saveHelpDocItemsToCache(path string, items []docengine.HelpTextItem) {
	st, err := os.Stat(path)
	if err != nil {
		return
	}
	rel, err := filepath.Rel("data/helpdoc", path)
	if err != nil {
		rel = path
	}
	rel = filepath.ToSlash(rel)
	cache := helpDocParsedCache{
		Version: helpDocParsedCacheVersion,
		RelPath: rel,
		Size:    st.Size(),
		ModTime: st.ModTime().Unix(),
		Items:   items,
	}
	_ = os.MkdirAll(helpDocParsedCacheDir, 0o755)
	cachePath := filepath.Join(helpDocParsedCacheDir, helpDocCacheKey(path)+".gob")
	tmpPath := cachePath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		return
	}
	enc := gob.NewEncoder(f)
	if err := enc.Encode(&cache); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return
	}
	_ = os.Rename(tmpPath, cachePath)
}

// validateXlsxHeaders 验证 xlsx 格式 helpdoc 的表头是否是 Key Synonym（可能有多列） Content Description Catalogue Tag
func validateXlsxHeaders(headers []string) (int, error) {
	if len(headers) < 3 {
		return 0, errors.New("helpdoc格式错误，缺少必须列 Key Synonym Content")
	}

	var (
		index    int
		expected string
	)
	var synonymCount int
	expected = "key"
out:
	for index < len(headers) {
		// 放宽同义词大小写校验
		header := strings.ToLower(headers[index])
		switch expected {
		case "key":
			if header != "key" {
				return 0, fmt.Errorf("helpdoc表头格式错误，第%d列表头必须是Key，当前为%s", index+1, header)
			}
			expected = "synonym"
			index++
		case "synonym":
			if header != "synonym" {
				return 0, fmt.Errorf("helpdoc表头格式错误，第%d列表头必须是Synonym，当前为%s", index+1, header)
			}
			expected = "content"
			index++
			synonymCount++
		case "content":
			if header == "" || header == "synonym" {
				// 有多列同义词
				index++
				synonymCount++
				continue
			} else if header != "content" {
				return 0, fmt.Errorf("helpdoc表头格式错误，第%d列表头必须是为空白（表示同义词列）或者Content，当前为%s", index+1, header)
			}
			expected = "description"
			index++
		case "description":
			if header != "description" {
				return 0, fmt.Errorf("helpdoc表头格式错误，第%d列表头必须是Description，当前为%s", index+1, header)
			}
			expected = "catalogue"
			index++
		case "catalogue":
			if header != "catalogue" {
				return 0, fmt.Errorf("helpdoc表头格式错误，第%d列表头必须是Catalogue，当前为%s", index+1, header)
			}
			expected = "tag"
			index++
		case "tag":
			if header != "tag" {
				return 0, fmt.Errorf("helpdoc表头格式错误，第%d列表头必须是Tag", index+1)
			}
			break out
		default:
			return 0, fmt.Errorf("错误的表头校验状态，当前等待表头%s，实际获得%s", expected, header)
		}
	}
	return synonymCount, nil
}

func (m *HelpManager) addCmdMap(packageName string, cmdMap CmdMapCls) error {
	log := logger.M()
	for k, v := range cmdMap {
		content := v.Help
		if content == "" {
			content = v.ShortHelp
		}
		err := m.AddItem(docengine.HelpTextItem{
			Group:       HelpBuiltinGroup,
			Title:       k,
			Content:     content,
			PackageName: packageName,
		})
		if err != nil {
			log.Errorf("AddCmdMapItem err:%v", err)
			return err
		}
	}
	return nil
}

func (m *HelpManager) addInternalCmdHelp(cmdMap CmdMapCls) error {
	err := m.addCmdMap("核心指令", cmdMap)
	if err != nil {
		return err
	}
	return nil
}

func (m *HelpManager) addExternalCmdHelp(ext []*ExtInfo) error {
	for _, i := range ext {
		err := m.AddItem(docengine.HelpTextItem{
			Group:       HelpBuiltinGroup,
			Title:       i.Name,
			Content:     i.GetDescText(i),
			PackageName: "扩展模块",
		})
		if err != nil {
			return err
		}
		err = m.addCmdMap(i.Name, i.GetCmdMap())
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *HelpManager) AddItem(item docengine.HelpTextItem) error {
	if m.shouldStop() || m.searchEngine == nil {
		return nil
	}
	_, err := m.searchEngine.AddItem(item)
	return err
}

func (m *HelpManager) AddItemApply(end bool) error {
	if m.shouldStop() || m.searchEngine == nil {
		return nil
	}
	err := m.searchEngine.AddItemApply(end)
	if err != nil {
		return err
	}
	return nil
}

func (m *HelpManager) Search(ctx *MsgContext, text string, titleOnly bool, pageSize, pageNum int, group string) (res *docengine.GeneralSearchResult, total, pageStart, pageEnd int, err error) {
	return m.searchEngine.Search(ctx.Group.HelpPackages, text, titleOnly, pageSize, pageNum, group)
}

func (m *HelpManager) GetSuffixText() string {
	return m.searchEngine.GetSuffixText()
}

func (m *HelpManager) GetPrefixText() string {
	return m.searchEngine.GetPrefixText()
}

func (m *HelpManager) GetShowBestOffset() int {
	return m.searchEngine.GetShowBestOffset()
}

func (m *HelpManager) GetContent(item *docengine.HelpTextItem, depth int) string {
	if depth > 7 {
		return "{递归层数过多，不予显示}"
	}
	txt := item.Content
	re := regexp.MustCompile(`\{[^}\n]+\}`)
	matched := re.FindAllStringSubmatchIndex(txt, -1)
	if len(matched) == 0 {
		return txt
	}

	result := strings.Builder{}
	formattedIdx := 0
	for _, i := range matched {
		left := i[0]
		right := i[1]

		if left != 0 && txt[left-1] == '\\' {
			result.WriteString(txt[formattedIdx : left-1])
			if right > 1 && txt[right-2] == '\\' {
				result.WriteString(txt[left : right-2])
				result.WriteByte('}')
			} else {
				result.WriteString(txt[left:right])
			}
			formattedIdx = right
			continue
		}

		result.WriteString(txt[formattedIdx:left])
		formattedIdx = right
		name := txt[left+1 : right-1]
		// 搜索TitleOnly，严格匹配Title的情形
		// 如果查询到对应数据，那么就调用m.GetContent
		valueResult, err := m.searchEngine.GetHelpTextItemByTermTitle(name)
		if err != nil {
			result.WriteByte('{')
			result.WriteString(name)
			result.WriteString(" - 未能找到}")
		} else {
			result.WriteString(m.GetContent(valueResult, depth+1))
		}
	}
	result.WriteString(txt[formattedIdx:])
	return result.String()
}

func generateHelpDocKey() string {
	key, _ := nanoid.Generate("0123456789abcdef", 16)
	return key
}

// 修改 buildHelpDocTree 函数签名，添加进度参数
func buildHelpDocTree(node *HelpDoc, fn func(d *HelpDoc)) {
	// 收集所有节点
	allNodes := []*HelpDoc{node}

	for i := 0; i < len(allNodes); i++ {
		current := allNodes[i]

		p, err := os.Stat(current.Path)
		if err != nil {
			continue
		}

		if !p.IsDir() {
			continue
		}

		subs, err := os.ReadDir(current.Path)
		if err != nil {
			continue
		}

		current.Children = make([]*HelpDoc, 0)

		for _, sub := range subs {
			if strings.HasPrefix(sub.Name(), ".") {
				continue
			}

			var child HelpDoc
			child.Key = generateHelpDocKey()
			child.Name = sub.Name()
			child.Path = path.Join(current.Path, sub.Name())
			child.Group = current.Group
			child.IsDir = sub.IsDir()

			if sub.IsDir() {
				child.Type = "dir"
				child.Children = make([]*HelpDoc, 0)
			} else {
				child.Type = filepath.Ext(sub.Name())
			}

			allNodes = append(allNodes, &child)
			current.Children = append(current.Children, &child)
		}
	}
	for _, current := range allNodes {
		// 调用处理函数
		fn(current)
	}
}

func (m *HelpManager) UploadHelpDoc(src io.Reader, group string, name string) error {
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	group = strings.ReplaceAll(group, "/", "_")
	group = strings.ReplaceAll(group, "\\", "_")
	if group == "default" {
		// 默认组直接上传到helpdoc文件夹中
		group = ""
	}

	dirPath := filepath.Join("./data/helpdoc", group)
	err := os.MkdirAll(dirPath, 0755)
	if err != nil {
		return err
	}

	filePath := filepath.Join(dirPath, name)
	dst, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func(dst *os.File) {
		_ = dst.Close()
	}(dst)

	if _, err = io.Copy(dst, src); err != nil {
		return err
	}

	var groupExists bool
	for _, groupDir := range m.HelpDocTree {
		if groupDir.Name == group {
			groupExists = true
			groupDir.Deleted = false

			var fileExists bool
			for _, child := range groupDir.Children {
				if child.Name == name && filepath.Clean(child.Path) == filepath.Clean(filePath) && !child.Deleted {
					if child.LoadStatus == Unload {
						child.Deleted = false
						fileExists = true
					} else {
						child.Deleted = true
					}
				}
			}
			if !fileExists {
				groupDir.Children = append(groupDir.Children, &HelpDoc{
					Key:   generateHelpDocKey(),
					Name:  name,
					Path:  filePath,
					Group: group,
					Type:  filepath.Ext(filePath),
				})
			}
			break
		}
	}
	if !groupExists {
		if group != "" {
			newGroupDir := HelpDoc{
				Key:      generateHelpDocKey(),
				Name:     group,
				Path:     dirPath,
				Group:    group,
				Type:     "dir",
				IsDir:    true,
				Children: make([]*HelpDoc, 0),
			}
			newGroupDir.Children = append(newGroupDir.Children, &HelpDoc{
				Key:   generateHelpDocKey(),
				Name:  name,
				Path:  filePath,
				Group: group,
				Type:  filepath.Ext(filePath),
			})
			m.HelpDocTree = append(m.HelpDocTree, &newGroupDir)
		} else {
			m.HelpDocTree = append(m.HelpDocTree, &HelpDoc{
				Key:   generateHelpDocKey(),
				Name:  name,
				Path:  filePath,
				Group: "default",
				Type:  filepath.Ext(filePath),
			})
		}
	}

	return nil
}

func (m *HelpManager) DeleteHelpDoc(keys []string) error {
	keySet := make(map[string]bool)
	for _, key := range keys {
		keySet[key] = true
	}

	for _, node := range m.HelpDocTree {
		err := traverseHelpDocTree(node, func(d *HelpDoc) error {
			if !d.IsDir {
				_, ok := keySet[d.Key]
				if ok {
					_, err := os.Stat(d.Path)
					if !os.IsNotExist(err) {
						err := os.Remove(d.Path)
						if err != nil {
							return err
						}
					}
					d.Deleted = true
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
		_, ok := keySet[node.Key]
		if ok {
			_, err := os.Stat(node.Path)
			if !os.IsNotExist(err) {
				err := os.RemoveAll(node.Path)
				if err != nil {
					return err
				}
			}
			node.Deleted = true
		}
	}
	return nil
}

func traverseHelpDocTree(root *HelpDoc, fn func(node *HelpDoc) error) error {
	if root == nil {
		return nil
	}
	err := fn(root)
	if err != nil {
		return err
	}

	if len(root.Children) == 0 {
		return nil
	}

	for _, child := range root.Children {
		err := traverseHelpDocTree(child, fn)
		if err != nil {
			return err
		}
	}
	return nil
}

type HelpTextVo struct {
	ID          int    `json:"id"`
	Group       string `json:"group"`
	From        string `json:"from"`
	Title       string `json:"title"`
	Content     string `json:"content"`
	PackageName string `json:"packageName"`
	KeyWords    string `json:"keyWords"`
}

type HelpTextVos []HelpTextVo

func (h HelpTextVos) Len() int {
	return len(h)
}

func (h HelpTextVos) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
}

func (h HelpTextVos) Less(i, j int) bool {
	return h[i].ID < h[j].ID
}

func (m *HelpManager) GetHelpItemPage(pageNum, pageSize int, id, group, from, title string) (int, HelpTextVos) {
	if pageNum <= 0 || pageSize <= 0 {
		return 0, HelpTextVos{}
	}

	// 如果ID不为空
	if id != "" {
		// 加载对应ID的数据
		item, err := m.searchEngine.GetItemByID(id)
		// 若成功
		if err == nil {
			// 返回这条数据
			vo := HelpTextVo{
				Group:       item.Group,
				From:        item.From,
				Title:       item.Title,
				Content:     item.Content,
				PackageName: item.PackageName,
				KeyWords:    item.KeyWords,
			}
			vo.ID, _ = strconv.Atoi(id)
			return 1, HelpTextVos{vo}
		}
		return 0, HelpTextVos{}
	}
	// ID为空的情形，分页查询数据
	total, result, err := m.searchEngine.PaginateDocuments(pageSize, pageNum, group, from, title)
	if err != nil {
		return 0, nil
	}
	var items = make(HelpTextVos, 0)
	for _, item := range result {
		vo := HelpTextVo{
			Group:       item.Group,
			From:        item.From,
			Title:       item.Title,
			Content:     item.Content,
			PackageName: item.PackageName,
			KeyWords:    item.KeyWords,
		}
		vo.ID, _ = strconv.Atoi(id)
		items = append(items, vo)
	}
	return int(total), items
}

// SetDefaultHelpGroup 设置群默认搜索分组
func (group *GroupInfo) SetDefaultHelpGroup(target string) {
	group.DefaultHelpGroup = target
}
