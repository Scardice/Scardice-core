package docengine

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"

	"github.com/fy0/bluge"
	"github.com/fy0/bluge/index"
	"github.com/oklog/ulid/v2"
)

const (
	DefaultIndexDir = "./data/.cache/helpdoc/index"
	indexSchemaFile = "schema_version"
	indexSchema     = "1"
	groupExactField = "_group_exact"
	writeBatchSize  = 50
)

var (
	indexDir = DefaultIndexDir
	reSpace  = regexp.MustCompile(`\s+`)
)

type BlugeSearchEngine struct {
	mu sync.Mutex

	Writer    *bluge.Writer
	batch     *index.Batch
	batchSize int
	CurID     uint64

	freshlyCreated bool
	idList         []string
	idToNumber     map[string]int
	numericIDDirty bool
}

func NewBlugeSearchEngine() (*BlugeSearchEngine, error) {
	engine := &BlugeSearchEngine{}
	if err := engine.Init(); err != nil {
		return nil, fmt.Errorf("initialize Bluge search engine: %w", err)
	}
	return engine, nil
}

func (d *BlugeSearchEngine) Init() error {
	writer, freshlyCreated, err := openBlugeWriter(indexDir)
	if err != nil {
		return err
	}

	d.Writer = writer
	d.freshlyCreated = freshlyCreated
	d.batch = bluge.NewBatch()
	d.numericIDDirty = true
	if err := d.rebuildNumericIDMappingLocked(); err != nil {
		_ = writer.Close()
		d.Writer = nil
		return fmt.Errorf("build numeric ID mapping: %w", err)
	}
	return nil
}

func openBlugeWriter(path string) (*bluge.Writer, bool, error) {
	compatible, exists, err := hasCompatibleBlugeIndex(path)
	if err != nil {
		return nil, false, err
	}
	freshlyCreated := !compatible
	if exists && !compatible {
		if err = os.RemoveAll(path); err != nil {
			return nil, false, fmt.Errorf("remove incompatible search index: %w", err)
		}
	}

	writer, err := bluge.OpenWriter(bluge.DefaultConfig(path))
	if err != nil {
		return nil, false, fmt.Errorf("open Bluge writer: %w", err)
	}
	if err := os.WriteFile(filepath.Join(path, indexSchemaFile), []byte(indexSchema), 0o600); err != nil {
		_ = writer.Close()
		return nil, false, fmt.Errorf("write search index schema: %w", err)
	}
	return writer, freshlyCreated, nil
}

func hasCompatibleBlugeIndex(path string) (compatible, exists bool, err error) {
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, fmt.Errorf("read search index directory: %w", err)
	}

	hasSnapshot := false
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".snp" {
			hasSnapshot = true
			break
		}
	}
	schema, err := os.ReadFile(filepath.Join(path, indexSchemaFile))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, true, fmt.Errorf("read search index schema: %w", err)
	}
	return hasSnapshot && string(schema) == indexSchema, true, nil
}

func (d *BlugeSearchEngine) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.Writer != nil {
		_ = d.Writer.Close()
		d.Writer = nil
	}
}

func (d *BlugeSearchEngine) IndexFreshlyCreated() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.freshlyCreated
}

func (d *BlugeSearchEngine) GetTotalID() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.CurID
}

func (d *BlugeSearchEngine) GetSuffixText() string {
	return "(本次搜索由全文搜索完成)"
}

func (d *BlugeSearchEngine) GetPrefixText() string {
	return "[全文搜索]"
}

func (d *BlugeSearchEngine) GetShowBestRelativeGap() float64 {
	return 0.25
}

func (d *BlugeSearchEngine) getNextID() string {
	return ulid.Make().String()
}

func (d *BlugeSearchEngine) AddItem(item HelpTextItem) (string, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.batch == nil {
		return "", errors.New("已通过end参数执行AddItemApply，不允许新增文档。请检查代码逻辑")
	}
	id := d.getNextID()
	document := helpDocument(id, item)
	d.batch.Update(document.ID(), document)
	d.batchSize++
	if d.batchSize >= writeBatchSize {
		if err := d.addItemApplyLocked(false); err != nil {
			return "", err
		}
	}
	return id, nil
}

func (d *BlugeSearchEngine) AddItemApply(end bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.addItemApplyLocked(end)
}

func (d *BlugeSearchEngine) addItemApplyLocked(end bool) error {
	if d.batch == nil {
		return nil
	}
	if d.batchSize == 0 {
		if end {
			d.batch = nil
		}
		return nil
	}
	if d.Writer == nil {
		return errors.New("搜索引擎已关闭")
	}
	if err := d.Writer.Batch(d.batch); err != nil {
		return fmt.Errorf("apply search index batch: %w", err)
	}
	d.batch.Reset()
	d.batchSize = 0
	if end {
		d.batch = nil
	}
	d.numericIDDirty = true
	return nil
}

var _ SearchEngine = (*BlugeSearchEngine)(nil)
