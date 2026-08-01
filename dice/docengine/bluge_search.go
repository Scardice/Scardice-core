package docengine

import (
	"context"
	"errors"
	"fmt"

	"github.com/fy0/bluge"
)

func (d *BlugeSearchEngine) Search(helpPackages []string, text string, titleOnly bool, pageSize, pageNum int, group string) (*GeneralSearchResult, int, int, int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	titleOrContent := bluge.NewBooleanQuery().SetMinShould(1)
	titleOrContent.AddShould(bluge.NewMatchPhraseQuery(text).SetField("title"))
	if !titleOnly {
		for _, term := range reSpace.Split(text, -1) {
			if term != "" {
				titleOrContent.AddShould(bluge.NewMatchPhraseQuery(term).SetField("content"))
			}
		}
	}

	query := bluge.NewBooleanQuery().AddMust(titleOrContent)
	for _, packageName := range helpPackages {
		query.AddMust(bluge.NewTermQuery(packageName).SetField("package"))
	}
	if group != "" {
		query.AddMust(bluge.NewTermQuery(normalizeExactValue(group)).SetField(groupExactField))
	}

	pageSize, pageStart := normalizePagination(pageSize, pageNum)
	reader, err := d.readerLocked()
	if err != nil {
		return nil, 0, 0, 0, err
	}
	defer func() { _ = reader.Close() }()

	request := bluge.NewTopNSearch(pageSize, query).SetFrom(pageStart).WithStandardAggregations()
	matches, err := reader.Search(context.Background(), request)
	if err != nil {
		return nil, 0, 0, 0, fmt.Errorf("search help documents: %w", err)
	}
	if err := d.ensureNumericIDMappingLocked(); err != nil {
		return nil, 0, 0, 0, fmt.Errorf("build search result ID mapping: %w", err)
	}

	results := make(MatchCollection, 0, pageSize)
	for {
		match, nextErr := matches.Next()
		if nextErr != nil {
			return nil, 0, 0, 0, fmt.Errorf("read help search result: %w", nextErr)
		}
		if match == nil {
			break
		}
		internalID, fields, visitErr := storedFields(match)
		if visitErr != nil {
			return nil, 0, 0, 0, fmt.Errorf("read help search fields: %w", visitErr)
		}
		results = append(results, &MatchResult{
			ID:     d.numericID(internalID),
			Fields: fields,
			Score:  match.Score,
		})
	}

	total := int(matches.Aggregations().Count())
	return &GeneralSearchResult{Hits: results, Total: uint64(total)}, total, pageStart, pageStart + len(results), nil
}

func normalizePagination(pageSize, pageNum int) (size, start int) {
	if pageSize < 0 {
		pageSize = 0
	}
	pageStart := (pageNum - 1) * pageSize
	if pageStart < 0 {
		pageStart = 0
	}
	return pageSize, pageStart
}

func (d *BlugeSearchEngine) PaginateDocuments(pageSize, pageNum int, group, from, title string) (uint64, []*HelpTextItem, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	queries := make([]bluge.Query, 0, 3)
	if group != "" {
		queries = append(queries, bluge.NewWildcardQuery("*"+normalizeExactValue(group)+"*").SetField(groupExactField))
	}
	if from != "" {
		queries = append(queries, bluge.NewWildcardQuery("*"+from+"*").SetField("from"))
	}
	if title != "" {
		queries = append(queries, bluge.NewWildcardQuery("*"+title+"*").SetField("title"))
	}
	var query bluge.Query = bluge.NewMatchAllQuery()
	if len(queries) > 0 {
		query = bluge.NewBooleanQuery().AddMust(queries...)
	}

	pageSize, pageStart := normalizePagination(pageSize, pageNum)
	reader, err := d.readerLocked()
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = reader.Close() }()

	request := bluge.NewTopNSearch(pageSize, query).SetFrom(pageStart).WithStandardAggregations()
	matches, err := reader.Search(context.Background(), request)
	if err != nil {
		return 0, nil, fmt.Errorf("paginate help documents: %w", err)
	}
	items := make([]*HelpTextItem, 0, pageSize)
	for {
		match, nextErr := matches.Next()
		if nextErr != nil {
			return 0, nil, fmt.Errorf("read paged help document: %w", nextErr)
		}
		if match == nil {
			break
		}
		internalID, fields, visitErr := storedFields(match)
		if visitErr != nil {
			return 0, nil, fmt.Errorf("read paged help document fields: %w", visitErr)
		}
		items = append(items, helpItemFromFields(internalID, fields))
	}
	return matches.Aggregations().Count(), items, nil
}

func (d *BlugeSearchEngine) GetItemByInternalID(id string) (*HelpTextItem, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.getItemByInternalIDLocked(id)
}

func (d *BlugeSearchEngine) getItemByInternalIDLocked(id string) (*HelpTextItem, error) {
	reader, err := d.readerLocked()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	matches, err := reader.Search(context.Background(), bluge.NewTopNSearch(1, bluge.NewTermQuery(id).SetField("_id")))
	if err != nil {
		return nil, fmt.Errorf("find help document by ID: %w", err)
	}
	match, err := matches.Next()
	if err != nil {
		return nil, fmt.Errorf("read help document by ID: %w", err)
	}
	if match == nil {
		return nil, errors.New("未找到匹配的文档")
	}
	internalID, fields, err := storedFields(match)
	if err != nil {
		return nil, fmt.Errorf("read stored help document: %w", err)
	}
	return helpItemFromFields(internalID, fields), nil
}

func (d *BlugeSearchEngine) GetHelpTextItemByTermTitle(title string) (*HelpTextItem, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	reader, err := d.readerLocked()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	matches, err := reader.Search(context.Background(), bluge.NewTopNSearch(1, bluge.NewMatchQuery(title).SetField("title")))
	if err != nil {
		return nil, fmt.Errorf("find help document by title: %w", err)
	}
	match, err := matches.Next()
	if err != nil {
		return nil, fmt.Errorf("read help document by title: %w", err)
	}
	if match == nil {
		return nil, errors.New("查询失败，未查询到数据")
	}
	internalID, fields, err := storedFields(match)
	if err != nil {
		return nil, fmt.Errorf("read stored help document: %w", err)
	}
	return helpItemFromFields(internalID, fields), nil
}
