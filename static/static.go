package static

import (
	"embed"
)

// //go:generate go run gen/download-fe.go
// NOTE(lyjjl): download-fe.go 负责下载 UI 资源，但是目前这一块逻辑还没有完全从海豹中剥离出来，暂时禁用

//go:embed frontend
var Frontend embed.FS

//go:embed scripts
var Scripts embed.FS
