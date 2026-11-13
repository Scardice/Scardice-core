package static

import (
	"embed"
)

// //go:generate go run gen/download-fe.go
// NOTE(lyjjl): download-fe.go 负责下载 UI 资源，但是目前这一块逻辑还没有完全从海豹中剥离出来，暂时禁用

// NOTE(lyjjl): 前端构建产物文件名可能会以“_”开头，如果不写“all:”这些文件会被忽略 https://pkg.go.dev/embed
//
//go:embed all:frontend
var Frontend embed.FS

//go:embed scripts
var Scripts embed.FS
