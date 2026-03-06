package dice

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	wr "github.com/mroth/weightedrand"
	"github.com/xuri/excelize/v2"

	"Scardice-core/logger"
)

type NamesGenerator struct {
	NamesInfo map[string]map[string][]string
}

const (
	namesCacheDir      = "./data/.cache/names"
	namesCacheFilename = "names_cache.gob.zst"
	namesCacheVersion  = 1
)

type namesCacheFileInfo struct {
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	ModTime int64  `json:"modTime"`
}

type namesCache struct {
	Version   int                            `json:"version"`
	Files     []namesCacheFileInfo           `json:"files"`
	NamesInfo map[string]map[string][]string `json:"namesInfo"`
}

func (ng *NamesGenerator) Load() {
	_ = os.MkdirAll("./data/names", 0755)
	_ = os.MkdirAll(namesCacheDir, 0755)

	nameInfo := map[string]map[string][]string{}
	ng.NamesInfo = nameInfo

	files := []string{"./data/names/names.xlsx", "./data/names/names-dnd.xlsx"}
	if cached, ok := loadNamesCache(files); ok {
		ng.NamesInfo = cached
		return
	}

	for _, fn := range files {
		f, err := excelize.OpenFile(fn)
		if err != nil {
			logger.M().Warn("加载names信息出错", fn, err)
			continue
		}

		for _, sheetName := range f.GetSheetList() {
			words := map[string][]string{}
			columns, err := f.Cols(sheetName)
			if err == nil {
				for columns.Next() {
					column, _ := columns.Rows(excelize.Options{RawCellValue: true})
					if len(column) > 0 {
						// 首行为标题，如“男性名” 其他行为内容，如”济民 珍祥“
						name := column[0]
						var values []string
						for _, i := range column[1:] {
							if i == "" {
								break
							}
							values = append(values, i)
						}
						// values := column[1:] // 注意行数是以最大行数算的，所以会出现很多空行，不能这样取
						words[name] = values
					}
				}
			}
			nameInfo[sheetName] = words
		}

		if err := f.Close(); err != nil {
			logger.M().Error("NamesGenerator.Load", err)
		}
	}

	if err := saveNamesCache(files, ng.NamesInfo); err != nil {
		logger.M().Warn("写入names缓存失败", err)
	}
}

func loadNamesCache(files []string) (map[string]map[string][]string, bool) {
	cachePath := filepath.Join(namesCacheDir, namesCacheFilename)
	var cache namesCache
	if err := loadGobCacheFile(cachePath, &cache); err != nil {
		return nil, false
	}
	if cache.Version != namesCacheVersion {
		return nil, false
	}
	curFiles, err := collectNamesFiles(files)
	if err != nil {
		return nil, false
	}
	if !namesFilesEqual(cache.Files, curFiles) {
		return nil, false
	}
	return cache.NamesInfo, true
}

func saveNamesCache(files []string, names map[string]map[string][]string) error {
	curFiles, err := collectNamesFiles(files)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	cache := namesCache{
		Version:   namesCacheVersion,
		Files:     curFiles,
		NamesInfo: names,
	}
	cachePath := filepath.Join(namesCacheDir, namesCacheFilename)
	return saveGobCacheFile(cachePath, &cache)
}

func collectNamesFiles(files []string) ([]namesCacheFileInfo, error) {
	var infos []namesCacheFileInfo
	for _, fn := range files {
		st, err := os.Stat(fn)
		if err != nil {
			return nil, err
		}
		infos = append(infos, namesCacheFileInfo{
			Path:    filepath.ToSlash(fn),
			Size:    st.Size(),
			ModTime: st.ModTime().Unix(),
		})
	}
	return infos, nil
}

func namesFilesEqual(a, b []namesCacheFileInfo) bool {
	if len(a) != len(b) {
		return false
	}
	am := map[string]namesCacheFileInfo{}
	for _, i := range a {
		am[i.Path] = i
	}
	for _, i := range b {
		j, ok := am[i.Path]
		if !ok {
			return false
		}
		if j.Size != i.Size || j.ModTime != i.ModTime {
			return false
		}
	}
	return true
}

func (ng *NamesGenerator) NameGenerate(rule string) string {
	// 规则说明:
	// 基本形式为 {sheetName:columnName} 例如 {中文:姓氏}
	// 权重扩展 {中文:姓氏@姓氏权重}
	// 位置扩展 {英文:名字} ({英文:名字中文#英文:名字.index}) 意思是在“名字中文”这一列中取值，行数与“名字”这一列的行数相同

	re := regexp.MustCompile(`\{[^}]+}`)
	tmpVars := map[string]int{}

	getList := func(inner string) []string {
		// TODO: 可在ng加缓存优化速度
		sp := strings.Split(inner, ":")
		if len(sp) > 1 {
			m, exists := ng.NamesInfo[sp[0]]
			if exists {
				lst, exists := m[sp[1]]
				if exists {
					return lst
				}
			}
		}
		return []string{}
	}

	getIntList := func(inner string) []int {
		// TODO: 可在ng加缓存优化速度
		lst := getList(inner)
		var result []int
		for _, i := range lst {
			weight, err := strconv.Atoi(i)
			if err != nil {
				_ = fmt.Errorf("权重转换出错，并非整数: %s, 来自 %s", i, rule)
				weight = 1
			}
			result = append(result, weight)
		}
		return result
	}

	parseWeight := func(inner string) (c *wr.Chooser, restText string, err error) {
		// TODO: 可加缓存，避免每次解析
		sp := strings.SplitN(inner, "@", 2)
		var choices []wr.Choice
		if len(sp) > 1 {
			lst := getList(sp[0])
			weightLst := getIntList(sp[1])

			// 取最小的，防止越界
			length := len(lst)
			length2 := len(weightLst)
			if length > length2 {
				length = length2
			}

			for index := range length {
				choices = append(choices, wr.NewChoice(index, uint(weightLst[index])))
			}
			restText = sp[0]
		} else {
			// 这里注意一点，如果遇到 {英文:名字中文#英文:名字.index} 这样的格式，choices会是空的
			// 但是没关系，因为不需要生成带权随机器
			lst := getList(inner)
			for index := range lst {
				choices = append(choices, wr.NewChoice(index, 1))
			}
			restText = inner
		}

		if len(choices) != 0 {
			c, err = wr.NewChooser(choices...)
		}
		return c, restText, err
	}

	parseInner := func(inner string, c *wr.Chooser) string {
		sp := strings.Split(inner, "#")
		if len(sp) > 1 {
			// 读取位置流程
			index := tmpVars[sp[1]]
			lst := getList(sp[0])
			if index < len(lst) {
				return lst[index]
			}
		} else {
			// 正常流程
			lst := getList(inner)
			if len(lst) == 0 {
				tmpVars[inner+".index"] = 0
				return ""
			}
			index := c.Pick().(int) // 取得权重
			tmpVars[inner+".index"] = index
			return lst[index]
		}
		return ""
	}

	var result strings.Builder
	lastLeft := 0
	for _, i := range re.FindAllStringIndex(rule, -1) {
		var c *wr.Chooser
		var err error
		inner := rule[i[0]+1 : i[1]-1]
		result.WriteString(rule[lastLeft:i[0]])
		c, inner, err = parseWeight(inner)
		if err != nil {
			result.WriteString("<语句错误>")
		} else {
			result.WriteString(parseInner(inner, c))
		}
		lastLeft = i[1]
	}

	result.WriteString(rule[lastLeft:])
	return result.String()
}
