package jsengine

// EntryKind identifies how an entry's source should be evaluated.
type EntryKind uint32

const (
	EntryScript EntryKind = iota
	EntryCommonJS
	EntryESModule
	// EntryExtension is the host extension entrypoint convention.
	EntryExtension
)

// Entry is an engine-neutral source entry.
type Entry struct {
	Filename string
	Source   string
	Kind     EntryKind
}
