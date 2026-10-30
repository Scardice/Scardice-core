package dice

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var defaultLagrangeV2Config = `{
    "$schema": "https://raw.githubusercontent.com/LagrangeDev/LagrangeV2/refs/heads/main/Lagrange.Milky/Resources/appsettings_schema.json",
    "Logging": {
        "LogLevel": {
            "Default": "Information",
        },
    },
    "Core": {
        // "Server": {
        //     Whether to automatically reconnect to the server
        //     "AutoReconnect": true,

        //     Whether to use IPv6 to connect to the server
        //     "UseIPv6Network": false,

        //     Whether to automatically select the fastest server
        //     "GetOptimumServer": true,
        // },
        "Signer": {
            // Signer URL
            "Url": "{NTSignServer地址}",

            // Signer token
            // "Token": null

            // Proxy for connect signer
            // only supports Http proxy
            // "ProxyUrl": null,
        },
        "Login": {
            // Account uin
            // If the Uin is inconsistent with the actual login account, quick login will not be possible
            "Uin": {账号UIN},
            
            // Account password
            // Set to null to login via QrCode
            // "Password": null,

            // Device Name
            // Only valid when logging in without Keystore
            "DeviceName": "Ubuntu 22.04",

            // Whether to try to log in automatically after disconnection
            // "AutoReLogin": true,

            // Whether to use ASCII compatible QrCode
            // "CompatibleQrCode": false,

            // Whether to use the online validating parser provided by the mysterious person
            // "UseOnlineCaptchaResolver": true,
        },
    },
    "Milky": {
        // The host that Milky service listens on
        // Look https://learn.microsoft.com/zh-cn/dotnet/fundamentals/runtime-libraries/system-net-httplistener
        // If you use * to expose your data to all networks, please ensure proper security settings
        // e.g. setting a access token, configuring a firewall
        "Host": "127.0.0.1",

        // The port that the Milky service listens on
        "Port": {WS端口},

        // The path prefix that Milky service listens on
        // "Prefix": "/",

        // Token for verification, Set to null to disable
        "AccessToken": "{访问Token}",

        // Whether to enable WebSocket service
        // "EnabledWebSocket": true,

        // Set to null to disable the WebHook service
        // "WebHook": null, // Default
        // "WebHook": {
        //     // WebHook Target URL
        //     "Url": "http://127.0.0.1:3001/webhook"
        // }

        // "Message": {
        //     // Whether to ignore messages sent by Bot
        //     "IgnoreBotMessage": false,
        //     "Cache": {
        //         "Policy": "LRU",
        //         // Maximum cache capacity
        //         "Capacity": 1000,
        //     },
        // },
    },
}
`

var defaultYogurtConfig = `{
    "configVersion": 3,
    "protocol": {
        "uin": {账号UIN},
        "password": "",
        "os": "Linux",
        "version": "46494",
        "signApiUrl": "{NTSignServer地址}",
        "pcLagrangeSignToken": "placeholder",
        "androidUseLegacySign": false
    },
    "milky": {
        "http": {
            "host": "127.0.0.1",
            "port": {WS端口},
            "prefix": "",
            "accessToken": "{访问Token}",
            "corsOrigins": []
        },
        "webhook": {
            "endpoints": []
        },
        "reportSelfMessage": true,
        "preloadContacts": false,
        "ffmpegPath": ""
    },
    "logging": {
        "ansiLevel": "ANSI256",
        "coreLogLevel": "DEBUG"
    },
    "security": {
        "skipOnLaunchListenAddressCheck": false
    },
    "debug": {
        "enableFaceDetailsApi": false
    }
}`

var SealSignV3Url = ``

type milkyBuiltInSignals struct {
	qrcode                  string
	qrcodeWaitingForScan    string
	qrcodeWaitingForConfirm string
	qrcodeCancelled         string
	online                  string
	qrcodeExpired           string
}

func milkyBuiltInConfigFileName(mode string) string {
	switch mode {
	case "lagrangeV2":
		return "appsettings.jsonc"
	case "yogurt":
		return "config.json"
	default:
		return ""
	}
}

func getMilkyBuiltInSignals(mode string) milkyBuiltInSignals {
	switch mode {
	case "lagrangeV2":
		return milkyBuiltInSignals{
			qrcode:                  "Fetch QrCode Success",
			qrcodeWaitingForScan:    "Fetch QrCode Success",
			qrcodeWaitingForConfirm: "QrCode State: 53",
			qrcodeCancelled:         "QrCode State: 54",
			online:                  "successfully logged in",
			qrcodeExpired:           "QrCode State: 17",
		}
	case "yogurt":
		return milkyBuiltInSignals{
			qrcode:                  "二维码文件已保存",
			qrcodeWaitingForScan:    "二维码状态：WAITING_FOR_SCAN",
			qrcodeWaitingForConfirm: "二维码状态：WAITING_FOR_CONFIRMATION",
			qrcodeCancelled:         "用户取消了登录",
			online:                  "已上线",
			qrcodeExpired:           "二维码已过期",
		}
	default:
		return milkyBuiltInSignals{}
	}
}

func containsMilkyBuiltInSignal(line string, signal string) bool {
	return signal != "" && strings.Contains(line, signal)
}

func getMilkyBuiltInLoginStateFromLine(line string, signals milkyBuiltInSignals) MilkyLoginState {
	switch {
	case containsMilkyBuiltInSignal(line, signals.online):
		return MilkyLoginStateQRConnected
	case containsMilkyBuiltInSignal(line, signals.qrcodeWaitingForConfirm) || strings.Contains(line, "WAITING_FOR_CONFIRMATION") || strings.Contains(line, "QrCode State: 53"):
		return MilkyLoginStateQRWaitingForConfirm
	case containsMilkyBuiltInSignal(line, signals.qrcodeCancelled) || strings.Contains(line, "CANCELLED") || strings.Contains(line, "QrCode State: 54"):
		return MilkyLoginStateCancelled
	case containsMilkyBuiltInSignal(line, signals.qrcodeExpired) || strings.Contains(line, "CODE_EXPIRED") || strings.Contains(line, "QrCode State: 17"):
		return MilkyLoginStateCodeExpired
	case containsMilkyBuiltInSignal(line, signals.qrcodeWaitingForScan) || strings.Contains(line, "WAITING_FOR_SCAN"):
		return MilkyLoginStateQRWaitingForScan
	default:
		return MilkyLoginStateInit
	}
}

func applyMilkyBuiltInLoginTerminalState(d *Dice, ep *EndPointInfo, state MilkyLoginState) {
	pa := ep.Adapter.(*PlatformAdapterMilky)
	pa.BuiltInLoginState = state
	pa.QrCodeData = nil
	ep.Enable = false
	ep.State = StateDisconnected
	if d != nil {
		d.LastUpdatedTime = time.Now().Unix()
		d.Save(false)
	}
}

func BuiltinMilkyClientKill(dice *Dice, conn *EndPointInfo) {
	defer func() {
		if r := recover(); r != nil {
			dice.Logger.Error("内置 Milky 客户端清理报错: ", r)
		}
	}()
	pa, ok := conn.Adapter.(*PlatformAdapterMilky)
	if !ok {
		return
	}
	if pa.BuiltInMode == "" {
		return
	}
	defer func() {
		pa.MilkyProcess = nil
	}()
	if pa.MilkyProcess != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() {
			<-ctx.Done()
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				dice.Logger.Error("Milky 进程未能在 5 秒内退出，可能需要手动结束")
			}
		}()
		err := pa.MilkyProcess.Stop()
		if err != nil {
			dice.Logger.Error("停止 Milky 进程失败: ", err)
		}
		_ = pa.MilkyProcess.Wait()
	}
}

// GenerateMilkyConfig 似乎暂时不需要 APPInfo, 如果以后需要了再改成双返回值
func GenerateMilkyConfig(port int, signServerUrl string, accessToken string, info *EndPointInfo) []byte {
	pa := info.Adapter.(*PlatformAdapterMilky)
	switch pa.BuiltInMode {
	case "lagrangeV2":
		conf := strings.ReplaceAll(defaultLagrangeV2Config, "{WS端口}", strconv.Itoa(port))
		conf = strings.ReplaceAll(conf, "{NTSignServer地址}", signServerUrl)
		conf = strings.ReplaceAll(conf, "{账号UIN}", info.UserID[3:])
		conf = strings.ReplaceAll(conf, "{访问Token}", accessToken)
		return []byte(conf)
	case "yogurt":
		conf := strings.ReplaceAll(defaultYogurtConfig, "{WS端口}", strconv.Itoa(port))
		conf = strings.ReplaceAll(conf, "{NTSignServer地址}", signServerUrl)
		conf = strings.ReplaceAll(conf, "{账号UIN}", info.UserID[3:])
		conf = strings.ReplaceAll(conf, "{访问Token}", accessToken)
		return []byte(conf)
	default:
		return nil
	}
}

func findKeystoreFiles(root string) ([]string, error) {
	var matches []string
	re := regexp.MustCompile(`^\d+\.keystore$`)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && re.MatchString(d.Name()) {
			matches = append(matches, path)
		}

		return nil
	})

	return matches, err
}

func MilkyRemoveSession(dice *Dice, conn *EndPointInfo) {
	workDir := filepath.Join(dice.BaseConfig.DataDir, conn.RelWorkDir)
	keyStores, err := findKeystoreFiles(workDir)
	if err != nil {
		dice.Logger.Errorf("查找 keystore 文件失败: %v", err)
	}
	for _, file := range keyStores {
		if _, err := os.Stat(file); err == nil {
			_ = os.Remove(file)
		}
	}
}
