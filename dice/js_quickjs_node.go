package dice

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	nodeabort "github.com/Scardice/quickjs_nodejs/abort"
	nodeblob "github.com/Scardice/quickjs_nodejs/blob"
	nodebuffer "github.com/Scardice/quickjs_nodejs/buffer"
	nodeconsole "github.com/Scardice/quickjs_nodejs/console"
	nodecrypto "github.com/Scardice/quickjs_nodejs/crypto"
	nodeeventloop "github.com/Scardice/quickjs_nodejs/eventloop"
	nodefetch "github.com/Scardice/quickjs_nodejs/fetch"
	nodefs "github.com/Scardice/quickjs_nodejs/fs"
	nodelimits "github.com/Scardice/quickjs_nodejs/limits"
	nodemessagechannel "github.com/Scardice/quickjs_nodejs/messagechannel"
	nodemodule "github.com/Scardice/quickjs_nodejs/module"
	nodeprocess "github.com/Scardice/quickjs_nodejs/process"
	nodestructuredclone "github.com/Scardice/quickjs_nodejs/structuredclone"
	nodeurl "github.com/Scardice/quickjs_nodejs/url"
	nodeutil "github.com/Scardice/quickjs_nodejs/util"
	nodewebsocket "github.com/Scardice/quickjs_nodejs/websocket"
	quickjs "github.com/buke/quickjs-go"
	gorilla "github.com/gorilla/websocket"
	"go.uber.org/zap"
	"gopkg.in/elazarl/goproxy.v1"
)

type quickJSNodeEnvironment struct {
	registry *nodemodule.Registry
	globals  []nodeeventloop.GlobalInstaller
}

type quickJSNodeLogger struct {
	logger *zap.SugaredLogger
}

func (logger quickJSNodeLogger) Debug(message string) {
	if logger.logger != nil {
		logger.logger.Debug(message)
	}
}

func (logger quickJSNodeLogger) Debugf(format string, args ...any) {
	if logger.logger != nil {
		logger.logger.Debugf(format, args...)
	}
}

func (logger quickJSNodeLogger) Info(message string) {
	if logger.logger != nil {
		logger.logger.Info(message)
	}
}

func (logger quickJSNodeLogger) Infof(format string, args ...any) {
	if logger.logger != nil {
		logger.logger.Infof(format, args...)
	}
}

func (logger quickJSNodeLogger) Warn(message string) {
	if logger.logger != nil {
		logger.logger.Warn(message)
	}
}

func (logger quickJSNodeLogger) Warnf(format string, args ...any) {
	if logger.logger != nil {
		logger.logger.Warnf(format, args...)
	}
}

func (logger quickJSNodeLogger) Error(message string) {
	if logger.logger != nil {
		logger.logger.Error(message)
	}
}

func (logger quickJSNodeLogger) Errorf(format string, args ...any) {
	if logger.logger != nil {
		logger.logger.Errorf(format, args...)
	}
}

type proxyRoundTripper struct {
	handler http.Handler
}

func (transport proxyRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.handler == nil {
		return nil, errors.New("QuickJS fetch proxy handler is nil")
	}
	recorder := httptest.NewRecorder()
	transport.handler.ServeHTTP(recorder, request)
	response := recorder.Result()
	response.Request = request
	return response, nil
}

func snapshotProcessEnv() map[string]string {
	snapshot := make(map[string]string)
	for _, key := range []string{"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES", "LC_TIME", "TZ"} {
		if value, ok := os.LookupEnv(key); ok {
			snapshot[key] = value
		}
	}
	return snapshot
}

func (d *Dice) quickJSFSOptions() ([]nodefs.Option, error) {
	if d.AdvancedConfig.AllowFilesystemUnrestrictedAccess {
		return []nodefs.Option{
			nodefs.WithUnrestrictedAccess(),
			nodefs.WithPathResolver(d.resolveQuickJSUnrestrictedFSPath),
			nodefs.WithPolicy(func(nodefs.Request) error { return nil }),
			// Goja permits host links in unrestricted mode, but data:// retains
			// its extension-local symlink boundary.
			nodefs.WithSymlinkPolicy(d.authorizeQuickJSFSSymlink),
		}, nil
	}

	root := filepath.Join(d.BaseConfig.DataDir, "extensions")
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return []nodefs.Option{
		nodefs.WithRoot(root),
		nodefs.WithPathResolver(d.resolveQuickJSFSPath),
		// The resolver emits only validated extension data paths; worker Policy
		// calls cannot safely consult the transient current-plugin identity.
		nodefs.WithPolicy(func(nodefs.Request) error { return nil }),
	}, nil
}

func (d *Dice) ensureQuickJSFSDataRoot(extensionName string) error {
	root, err := filepath.EvalSymlinks(filepath.Join(d.BaseConfig.DataDir, "extensions"))
	if err != nil {
		return err
	}
	for _, path := range []string{
		filepath.Join(root, extensionName),
		filepath.Join(root, extensionName, "data"),
	} {
		if err := ensureQuickJSFSDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func ensureQuickJSFSDirectory(path string) error {
	if err := os.Mkdir(path, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("QuickJS fs 数据目录不是目录")
	}
	return nil
}

// resolveQuickJSFSPath captures the calling extension identity before the fs
// Promise transfers work to a worker goroutine.
func (d *Dice) resolveQuickJSFSPath(raw string) (string, error) {
	rest, ok := strings.CutPrefix(raw, fsDataURIPrefix)
	if !ok {
		return "", errors.New("QuickJS fs 仅支持 data:// 路径")
	}
	extensionName, err := jsFsCurrentExtName(d)
	if err != nil {
		return "", err
	}
	if extensionName == "." || extensionName == ".." ||
		strings.ContainsAny(extensionName, `/\`) || jsFsHasWindowsVolumeName(extensionName) {
		return "", errors.New("当前扩展身份无效")
	}
	if strings.Contains(rest, `\`) || jsFsHasWindowsVolumeName(rest) {
		return "", errors.New("data:// 路径不允许穿越或绝对")
	}
	clean := filepath.Clean(rest)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || filepath.IsAbs(clean) {
		return "", errors.New("data:// 路径不允许穿越或绝对")
	}
	if err := d.ensureQuickJSFSDataRoot(extensionName); err != nil {
		return "", err
	}
	return filepath.ToSlash(filepath.Join(extensionName, "data", clean)), nil
}

// resolveQuickJSUnrestrictedFSPath aligns QuickJS with Goja's explicit
// AllowFilesystemUnrestrictedAccess behavior.
func (d *Dice) resolveQuickJSUnrestrictedFSPath(raw string) (string, error) {
	if strings.HasPrefix(raw, fsDataURIPrefix) {
		relative, err := d.resolveQuickJSFSPath(raw)
		if err != nil {
			return "", err
		}
		return filepath.Join(d.BaseConfig.DataDir, "extensions", filepath.FromSlash(relative)), nil
	}
	resolved, err := jsFsResolveAbsolute(d, raw)
	if err != nil {
		return "", err
	}
	return resolved.abs, nil
}

// authorizeQuickJSFSSymlink preserves Goja's data:// isolation while the
// advanced setting permits host paths and their symbolic links.
func (d *Dice) authorizeQuickJSFSSymlink(request nodefs.Request) error {
	for _, path := range []string{request.Path, request.Destination} {
		if d.isQuickJSFSDataPath(path) {
			return errors.New("QuickJS fs 的 data:// 路径不允许跟随符号链接")
		}
	}
	return nil
}

func (d *Dice) isQuickJSFSDataPath(path string) bool {
	root, err := filepath.Abs(filepath.Join(d.BaseConfig.DataDir, "extensions"))
	if err != nil {
		return false
	}
	target, err := filepath.Abs(filepath.FromSlash(path))
	if err != nil || jsFsEnsureInsideBase(root, target) != nil {
		return false
	}
	relative, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	return len(parts) >= 2 && parts[1] == "data"
}

func (d *Dice) newQuickJSNodeEnvironment(printer *PrinterFunc) (quickJSNodeEnvironment, error) {
	resourceLimits, err := nodelimits.NewRuntime(d.quickJSNodeResourceLimits())
	if err != nil {
		return quickJSNodeEnvironment{}, err
	}
	environment := snapshotProcessEnv()
	transport := proxyRoundTripper{handler: goproxy.NewProxyHttpServer()}
	dialer := nodewebsocket.DialerFunc(func(ctx context.Context, target string, header http.Header) (nodewebsocket.Conn, *http.Response, error) {
		return (&gorilla.Dialer{}).DialContext(ctx, target, header)
	})
	fetchOptions := []nodefetch.Option{
		nodefetch.WithTransport(transport),
		nodefetch.WithResourceLimits(resourceLimits),
	}
	websocketOptions := []nodewebsocket.Option{
		nodewebsocket.WithDialer(dialer),
		nodewebsocket.WithResourceLimits(resourceLimits),
	}

	fsOptions, err := d.quickJSFSOptions()
	if err != nil {
		return quickJSNodeEnvironment{}, err
	}
	fsOptions = append(fsOptions, nodefs.WithResourceLimits(resourceLimits))

	registry := nodemodule.NewRegistry()
	for _, definition := range []nodemodule.Definition{
		nodebuffer.Module(),
		nodeblob.Module(),
		nodeconsole.ModuleWithPrinter(printer),
		nodeprocess.Module(nodeprocess.WithEnvSnapshot(environment)),
		nodeurl.Module(),
		nodeutil.Module(),
		nodecrypto.Module(),
		nodefetch.Module(fetchOptions...),
		nodefs.Module(fsOptions...),
		nodefs.PromisesModule(fsOptions...),
		nodemessagechannel.Module(),
		nodewebsocket.Module(websocketOptions...),
		nodeabort.Module(),
		nodestructuredclone.Module(),
	} {
		if err := registry.Add(definition); err != nil {
			return quickJSNodeEnvironment{}, err
		}
	}

	globals := []nodeeventloop.GlobalInstaller{
		registry.EnableRequire,
		nodebuffer.InstallGlobal,
		nodeblob.InstallGlobal,
		func(ctx *quickjs.Context) error {
			return nodeconsole.InstallGlobalWithPrinter(ctx, printer)
		},
		func(ctx *quickjs.Context) error {
			return nodeprocess.InstallGlobal(ctx, nodeprocess.WithEnvSnapshot(environment))
		},
		nodeurl.InstallGlobal,
		func(ctx *quickjs.Context) error {
			return nodecrypto.InstallGlobal(ctx, nodecrypto.WithResourceLimits(resourceLimits))
		},
		nodeabort.InstallGlobal,
		nodestructuredclone.InstallGlobal,
		nodemessagechannel.InstallGlobal,
		func(ctx *quickjs.Context) error {
			return nodefetch.InstallGlobal(ctx, fetchOptions...)
		},
		func(ctx *quickjs.Context) error {
			return nodewebsocket.InstallGlobal(ctx, websocketOptions...)
		},
	}
	return quickJSNodeEnvironment{registry: registry, globals: globals}, nil
}
