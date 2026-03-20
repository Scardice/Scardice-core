package docengine

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"sync/atomic"

	"github.com/blevesearch/bleve/v2"
	"github.com/blevesearch/bleve/v2/analysis/analyzer/simple"
	"github.com/blevesearch/bleve/v2/search/query"
	index "github.com/blevesearch/bleve_index_api"

	"Scardice-core/logger"
)

type BleveSearchEngine struct {
	Index     bleve.Index
	batch     *bleve.Batch
	batchSize int
	CurID     uint64
	reuse     bool
}

var indexDir = "./data/.cache/helpdoc/index"
var reSpace = regexp.MustCompile(`\s+`)

// getNextID 使用原子操作，避免并发问题
func (d *BleveSearchEngine) getNextID() string {
	// 使用原子操作安全递增 CurID
	nextID := atomic.AddUint64(&d.CurID, 1)
	return strconv.FormatUint(nextID, 10)
}

// NewEngine 创建并初始化 BleveSearchEngine
func NewBleveSearchEngine(reuse bool) (*BleveSearchEngine, error) {
	engine := &BleveSearchEngine{reuse: reuse}
	err := engine.Init()
	if err != nil {
		return nil, err
	}
	return engine, nil
}

func (d *BleveSearchEngine) GetSuffixText() string {
	return "(本次搜索由全文搜索完成)"
}

func (d *BleveSearchEngine) GetPrefixText() string {
	return "[全文搜索]"
}

func (d *BleveSearchEngine) GetShowBestOffset() int {
	return 1
}

func (d *BleveSearchEngine) Init() error {
	if d.reuse {
		if _, err := os.Stat(indexDir); err != nil {
			return err
		}
		i, err := bleve.Open(indexDir)
		if err != nil {
			return err
		}
		d.Index = i
		// 初始化ID列表（复用索引时以文档数为准）
		if count, err := d.Index.DocCount(); err == nil {
			d.CurID = count
		}
	} else {
		mapping := bleve.NewIndexMapping()
		// 不依赖 helpdoc 索引的动态字段，并禁用了动态 doc_values，以减小索引体积
		mapping.DocValuesDynamic = false
		mapping.StoreDynamic = false
		docMapping := bleve.NewDocumentMapping()
		docMapping.Dynamic = false
		// 禁用隐式 _all 复合字段
		docMapping.AddSubDocumentMapping("_all", bleve.NewDocumentDisabledMapping())

		contentFieldMapping := bleve.NewTextFieldMapping()
		titleFieldMapping := bleve.NewTextFieldMapping()
		keywordMapping := bleve.NewKeywordFieldMapping()
		contentFieldMapping.DocValues = false
		contentFieldMapping.IncludeInAll = false
		titleFieldMapping.DocValues = false
		titleFieldMapping.IncludeInAll = false
		keywordMapping.DocValues = false
		keywordMapping.IncludeInAll = false
		// 试图：不区分大小写的搜索方案
		keywordMapping.Analyzer = simple.Name
		// 注意： 这里group,from,package都是keywordMapping
		// title既要做分词匹配，又要做精确匹配，需要特殊配置它
		// 下面这些GPT说的，如果不对，随便改。
		// 不需要分词，只需要支持模糊匹配（类似 SQL 中的 LIKE），那么 keyword 类型的字段 是最合适的选择。
		// keyword 类型的字段会将整个字段值作为一个整体存储，适合精确匹配和通配符匹配（如 NewWildcardQuery）。
		docMapping.AddFieldMappingsAt("group", keywordMapping)
		docMapping.AddFieldMappingsAt("from", keywordMapping)
		docMapping.AddFieldMappingsAt("title", titleFieldMapping)
		// Content才是真正的文档
		docMapping.AddFieldMappingsAt("content", contentFieldMapping)
		docMapping.AddFieldMappingsAt("package", keywordMapping)
		mapping.AddDocumentMapping("helpdoc", docMapping)
		mapping.TypeField = "_type"
		i, err := bleve.New(indexDir, mapping)
		if err != nil {
			return err
		}
		d.Index = i
		// 初始化ID列表
		d.CurID = 0
	}
	// 初始化新的batch
	d.batch = d.Index.NewBatch()
	return nil
}

func (d *BleveSearchEngine) Close() {
	if d.Index != nil {
		_ = d.Index.Close()
		d.Index = nil
	}
}

func (d *BleveSearchEngine) GetTotalID() uint64 {
	return d.CurID
}

func (d *BleveSearchEngine) SetTotalID(total uint64) {
	d.CurID = total
}

// AddItem 这里引用了dice，其实不妥，应该将它单独拆出来的。
func (d *BleveSearchEngine) AddItem(item HelpTextItem) (string, error) {
	// 如果batch为空，初始化一个batch
	if d.batch == nil {
		return "", errors.New("已通过end参数执行AddItemApply，不允许新增文档。请检查代码逻辑")
	}
	id := d.getNextID()
	data := map[string]string{
		"group":   item.Group,
		"from":    item.From,
		"title":   item.Title,
		"content": item.Content,
		"package": item.PackageName,
		"_type":   "helpdoc",
	}
	d.batchSize++
	// 五十一次执行
	if d.batchSize >= 50 {
		err := d.AddItemApply(false)
		d.batchSize = 0
		if err != nil {
			return "", err
		}
	}
	return id, d.batch.Index(id, data)
}

// AddItemApply 这里认为是真正执行插入文档的逻辑
// 由于现在已经将执行函数改为了可按文件执行，所以可以按文件进行Apply，这应当不会有太大的量级。
// end代表是否是最后一次执行，一般用在所有的数据都处理完之后，关闭逻辑的时候使用，如bleve batch重复利用后最后销毁
func (d *BleveSearchEngine) AddItemApply(end bool) error {
	if d.batch != nil {
		// 执行batch
		err := d.Index.Batch(d.batch)
		if err != nil {
			return err
		}
		// 如果是最后一批
		if end {
			d.batch.Reset()
			d.batch = nil
		} else {
			// 否则仅重置batch
			d.batch.Reset()
		}
		return err
	}
	return nil
}

func (d *BleveSearchEngine) DeleteByFrom(from string) error {
	if d.Index == nil {
		return nil
	}

	// "from" 字段当前使用 simple analyzer，路径会被切词；直接 TermQuery 整个路径
	// 无法稳定命中旧文档。删除时退回为全量扫描命中字段值后再批量删除，
	// 这样可以兼容已存在的索引数据。
	var ids []string
	offset := 0
	for {
		req := bleve.NewSearchRequestOptions(bleve.NewMatchAllQuery(), 200, offset, false)
		req.Fields = []string{"from"}
		res, err := d.Index.Search(req)
		if err != nil {
			return err
		}
		if len(res.Hits) == 0 {
			break
		}
		for _, hit := range res.Hits {
			if fmt.Sprintf("%v", hit.Fields["from"]) == from {
				ids = append(ids, hit.ID)
			}
		}
		offset += len(res.Hits)
		if uint64(offset) >= res.Total {
			break
		}
	}

	if len(ids) == 0 {
		return nil
	}

	batch := d.Index.NewBatch()
	for _, id := range ids {
		batch.Delete(id)
	}
	if err := d.Index.Batch(batch); err != nil {
		return err
	}
	return nil
}

func (d *BleveSearchEngine) Search(helpPackages []string, text string, titleOnly bool, pageSize, pageNum int, group string) (*GeneralSearchResult, int, int, int, error) {
	// 在标题中查找
	queryTitle := query.NewMatchPhraseQuery(text)
	queryTitle.SetField("title")

	titleOrContent := bleve.NewDisjunctionQuery(queryTitle)

	// 在正文中查找
	if !titleOnly {
		for _, i := range reSpace.Split(text, -1) {
			queryContent := query.NewMatchPhraseQuery(i)
			queryContent.SetField("content")
			titleOrContent.AddQuery(queryContent)
		}
	}

	andQuery := bleve.NewConjunctionQuery(titleOrContent)

	// 限制查询组
	for _, i := range helpPackages {
		queryPack := query.NewMatchPhraseQuery(i)
		queryPack.SetField("package")
		andQuery.AddQuery(queryPack)
	}

	// 查询指定文档组
	if group != "" {
		queryPack := query.NewMatchPhraseQuery(group)
		queryPack.SetField("group")
		andQuery.AddQuery(queryPack)
	}

	req := bleve.NewSearchRequestOptions(andQuery, pageSize, (pageNum-1)*pageSize, false)
	// 设置要被返回的数据
	req.Fields = []string{"*"}
	res, err := d.Index.Search(req)
	if err != nil {
		return nil, 0, 0, 0, err
	}
	var resultList = make(MatchCollection, 0)
	for _, hit := range res.Hits {
		result := MatchResult{
			ID:     hit.ID,
			Fields: hit.Fields,
			Score:  hit.Score,
		}
		resultList = append(resultList, &result)
	}
	// 转换搜索格式
	responseResult := GeneralSearchResult{
		Hits:  resultList,
		Total: res.Total,
	}
	total := int(res.Total)
	pageStart := (pageNum - 1) * pageSize
	pageEnd := pageStart + len(res.Hits)
	return &responseResult, total, pageStart, pageEnd, nil
}

func (d *BleveSearchEngine) PaginateDocuments(pageSize, pageNum int, group, from, title string) (uint64, []*HelpTextItem, error) {
	var items []*HelpTextItem
	// 只有Keyword才支持NewTermQuery
	conjunctionQuery := bleve.NewConjunctionQuery()
	if group != "" {
		groupQuery := bleve.NewWildcardQuery(fmt.Sprintf("*%s*", group))
		groupQuery.SetField("group")
		conjunctionQuery.AddQuery(groupQuery)
	}
	if from != "" {
		fromQuery := bleve.NewWildcardQuery(fmt.Sprintf("*%s*", from))
		fromQuery.SetField("from")
		conjunctionQuery.AddQuery(fromQuery)
	}
	if title != "" {
		titleQuery := bleve.NewWildcardQuery(fmt.Sprintf("*%s*", title))
		titleQuery.SetField("title")
		conjunctionQuery.AddQuery(titleQuery)
	}

	// 计算分页参数
	fromInt := (pageNum - 1) * pageSize // 起始位置
	if fromInt < 0 {
		fromInt = 0
	}
	var searchRequest *bleve.SearchRequest
	// 创建查询请求，设置分页参数
	if group == "" && from == "" && title == "" {
		searchRequest = bleve.NewSearchRequestOptions(bleve.NewMatchAllQuery(), pageSize, fromInt, false)
	} else {
		searchRequest = bleve.NewSearchRequestOptions(conjunctionQuery, pageSize, fromInt, true)
	}
	searchRequest.Fields = []string{"*"} // 设置需要返回的字段

	// 执行查询
	searchResult, err := d.Index.Search(searchRequest)
	if err != nil {
		return 0, nil, err
	}

	// 处理结果
	for _, hit := range searchResult.Hits {
		fields := hit.Fields
		item := &HelpTextItem{
			Group:       fmt.Sprintf("%v", fields["group"]),
			From:        fmt.Sprintf("%v", fields["from"]),
			Title:       fmt.Sprintf("%v", fields["title"]),
			Content:     fmt.Sprintf("%v", fields["content"]),
			PackageName: fmt.Sprintf("%v", fields["package"]),
			KeyWords:    "",  // 暂时空值
			RelatedExt:  nil, // 暂时空值
		}
		items = append(items, item)
	}
	return searchResult.Total, items, nil
}

func (d *BleveSearchEngine) GetItemByID(id string) (*HelpTextItem, error) {
	log := logger.M()
	document, err := d.Index.Document(id)
	if err != nil {
		return nil, err
	}
	// 检查是否找到文档
	if document == nil {
		return nil, errors.New("未找到匹配的文档")
	}
	item := HelpTextItem{}
	// 看了看源码，意思就是这样访问文档内的所有fields
	document.VisitFields(func(field index.Field) {
		name := field.Name()
		value := string(field.Value())
		// 这里的代码有点抽象……
		switch name {
		case "group":
			item.Group = value
		case "from":
			item.From = value
		case "title":
			item.Title = value
		case "content":
			item.Content = value
		case "package":
			item.PackageName = value
			// 好像会碰到Type的参数？
		default:
			log.Debugf("这是个什么参数 %s", name)
		}
	})
	return &item, nil
}

// 精确查询title
func (d *BleveSearchEngine) GetHelpTextItemByTermTitle(title string) (*HelpTextItem, error) {
	newTermQuery := query.NewMatchQuery(title)
	newTermQuery.SetField("title") // 精确匹配title
	req := bleve.NewSearchRequest(newTermQuery)
	req.Fields = []string{"*"}
	res, err := d.Index.Search(req)
	if err != nil {
		return nil, err
	}
	// 取出结果
	if len(res.Hits) > 0 {
		fields := res.Hits[0].Fields
		return &HelpTextItem{
			Group:       fmt.Sprintf("%v", fields["group"]),
			From:        fmt.Sprintf("%v", fields["from"]),
			Title:       fmt.Sprintf("%v", fields["title"]),
			Content:     fmt.Sprintf("%v", fields["content"]),
			PackageName: fmt.Sprintf("%v", fields["package"]),
			// 这俩是什么东西？！
			KeyWords:   "",
			RelatedExt: nil,
		}, nil
	}
	return nil, errors.New("查询失败，未查询到数据")
}
