package docengine

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fy0/bluge"
	"github.com/fy0/bluge/search"
)

const deleteSearchBatchSize = 1000

func helpDocument(id string, item HelpTextItem) *bluge.Document {
	return bluge.NewDocument(id).
		AddField(bluge.NewStoredOnlyField("group", []byte(item.Group))).
		AddField(bluge.NewKeywordField(groupExactField, normalizeExactValue(item.Group))).
		AddField(bluge.NewKeywordField("from", item.From).StoreValue()).
		AddField(bluge.NewTextField("title", item.Title).StoreValue().SearchTermPositions()).
		AddField(bluge.NewTextField("content", item.Content).StoreValue().SearchTermPositions()).
		AddField(bluge.NewKeywordField("package", item.PackageName).StoreValue())
}

func normalizeExactValue(value string) string {
	return strings.ToLower(value)
}

func storedFields(match *search.DocumentMatch) (string, map[string]interface{}, error) {
	internalID := ""
	fields := make(map[string]interface{}, 5)
	err := match.VisitStoredFields(func(field string, value []byte) bool {
		if field == "_id" {
			internalID = string(value)
		} else {
			fields[field] = string(value)
		}
		return true
	})
	return internalID, fields, err
}

func helpItemFromFields(internalID string, fields map[string]interface{}) *HelpTextItem {
	return &HelpTextItem{
		InternalID:  internalID,
		Group:       fmt.Sprintf("%v", fields["group"]),
		From:        fmt.Sprintf("%v", fields["from"]),
		Title:       fmt.Sprintf("%v", fields["title"]),
		Content:     fmt.Sprintf("%v", fields["content"]),
		PackageName: fmt.Sprintf("%v", fields["package"]),
	}
}

func (d *BlugeSearchEngine) DeleteByFrom(path string) error {
	return d.deleteByField("from", path)
}

func (d *BlugeSearchEngine) deleteByField(field, value string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.Writer == nil {
		return nil
	}
	deletedAny := false
	for {
		reader, err := d.Writer.Reader()
		if err != nil {
			return fmt.Errorf("open search index reader: %w", err)
		}
		query := bluge.NewTermQuery(value).SetField(field)
		matches, err := reader.Search(context.Background(), bluge.NewTopNSearch(deleteSearchBatchSize, query))
		if err != nil {
			_ = reader.Close()
			return fmt.Errorf("search documents to delete: %w", err)
		}

		ids := make([]string, 0, deleteSearchBatchSize)
		for {
			match, nextErr := matches.Next()
			if nextErr != nil {
				_ = reader.Close()
				return fmt.Errorf("read document to delete: %w", nextErr)
			}
			if match == nil {
				break
			}
			id, _, visitErr := storedFields(match)
			if visitErr != nil {
				_ = reader.Close()
				return fmt.Errorf("read stored document ID: %w", visitErr)
			}
			if id != "" {
				ids = append(ids, id)
			}
		}
		if err := reader.Close(); err != nil {
			return fmt.Errorf("close search index reader: %w", err)
		}
		if len(ids) == 0 {
			break
		}

		batch := bluge.NewBatch()
		for _, id := range ids {
			batch.Delete(bluge.Identifier(id))
		}
		if err := d.Writer.Batch(batch); err != nil {
			return fmt.Errorf("delete search index documents: %w", err)
		}
		deletedAny = true
		if len(ids) < deleteSearchBatchSize {
			break
		}
	}

	if deletedAny {
		d.numericIDDirty = true
	}
	return nil
}

func (d *BlugeSearchEngine) readerLocked() (*bluge.Reader, error) {
	if d.Writer == nil {
		return nil, errors.New("搜索引擎已关闭")
	}
	reader, err := d.Writer.Reader()
	if err != nil {
		return nil, fmt.Errorf("open search index reader: %w", err)
	}
	return reader, nil
}

func (d *BlugeSearchEngine) listAllDocumentIDsLocked() ([]string, error) {
	reader, err := d.readerLocked()
	if err != nil {
		return nil, err
	}
	defer func() { _ = reader.Close() }()

	matches, err := reader.Search(context.Background(), bluge.NewAllMatches(bluge.NewMatchAllQuery()))
	if err != nil {
		return nil, fmt.Errorf("list search index documents: %w", err)
	}
	ids := make([]string, 0)
	for {
		match, nextErr := matches.Next()
		if nextErr != nil {
			return nil, fmt.Errorf("read search index document: %w", nextErr)
		}
		if match == nil {
			break
		}
		id, _, visitErr := storedFields(match)
		if visitErr != nil {
			return nil, fmt.Errorf("read stored document ID: %w", visitErr)
		}
		if id != "" {
			ids = append(ids, id)
		}
	}
	return ids, nil
}
