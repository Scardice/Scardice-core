package dice

import (
	crand "crypto/rand"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/ShiraazMoollatjie/goluhn"
	"github.com/google/uuid"
)

type deviceFile struct {
	Display      string         `json:"display"`
	Product      string         `json:"product"`
	Device       string         `json:"device"`
	Board        string         `json:"board"`
	Model        string         `json:"model"`
	FingerPrint  string         `json:"finger_print"`
	BootID       string         `json:"boot_id"`
	ProcVersion  string         `json:"proc_version"`
	Protocol     int            `json:"protocol"` // 0: iPad 1: Android 2: AndroidWatch  // 3 macOS 4 企点
	IMEI         string         `json:"imei"`
	Brand        string         `json:"brand"`
	Bootloader   string         `json:"bootloader"`
	BaseBand     string         `json:"base_band"`
	SimInfo      string         `json:"sim_info"`
	OSType       string         `json:"os_type"`
	MacAddress   string         `json:"mac_address"`
	IPAddress    []int32        `json:"ip_address"`
	WifiBSSID    string         `json:"wifi_bssid"`
	WifiSSID     string         `json:"wifi_ssid"`
	ImsiMd5      string         `json:"imsi_md5"`
	AndroidID    string         `json:"android_id"`
	APN          string         `json:"apn"`
	VendorName   string         `json:"vendor_name"`
	VendorOSName string         `json:"vendor_os_name"`
	Version      *osVersionFile `json:"version"`
}

type osVersionFile struct {
	Incremental string `json:"incremental"`
	Release     string `json:"release"`
	Codename    string `json:"codename"`
	Sdk         uint32 `json:"sdk"`
}

func randomMacAddress() string {
	buf := make([]byte, 6)
	_, err := crand.Read(buf)
	if err != nil {
		return "00:16:ea:ae:3c:40"
	}
	// Set the local bit
	buf[0] |= 2
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", buf[0], buf[1], buf[2], buf[3], buf[4], buf[5])
}

func RandString(n int) string {
	r := rand.New(rand.NewSource(time.Now().Unix()))

	bytes := make([]byte, n)
	for i := range n {
		b := r.Intn(26) + 65
		bytes[i] = byte(b)
	}
	return string(bytes)
}

// model	设备
// "iPhone11,2"	iPhone XS
// "iPhone11,8"	iPhone XR
// "iPhone12,1"	iPhone 11
// "iPhone13,2"	iPhone 12
// "iPad8,1"	iPad Pro
// "iPad11,2"	iPad mini
// "iPad13,2"	iPad Air 4
// "Apple Watch"	Apple Watch

func GenerateDeviceJSONIos(protocol int) (string, []byte, error) {
	bootID := uuid.New()
	imei := goluhn.Generate(15) // 注意，这个imei是完全胡乱创建的，并不符合imei规则
	androidID := fmt.Sprintf("%X", rand.Uint64())

	deviceJSON := deviceFile{
		Display:      "iPhone",      // Rom的名字 比如 Flyme 1.1.2（魅族rom）  JWR66V（Android nexus系列原生4.3rom）
		Product:      RandString(6), // 产品名，比如这是小米6的代号
		Device:       RandString(6),
		Board:        RandString(6),  // 主板:骁龙835                                                                    //
		Brand:        "Apple",        // 品牌
		Model:        "iPhone13,2",   // 型号
		Bootloader:   "unknown",      // unknown不需要改
		FingerPrint:  RandString(24), // 指纹
		BootID:       bootID.String(),
		ProcVersion:  "1.0", // 很长，后面 builder省略了
		BaseBand:     "",    // 基带版本 4.3CPL2-... 一大堆，直接不写
		SimInfo:      "",
		OSType:       "iOS",
		MacAddress:   randomMacAddress(),
		IPAddress:    []int32{192, 168, rand.Int31() % 255, rand.Int31()%253 + 2}, // 192.168.x.x
		WifiBSSID:    randomMacAddress(),
		WifiSSID:     "<unknown ssid>",
		IMEI:         imei,
		AndroidID:    androidID, // 原版的 androidId和Display内容一样，我没看协议，但是按android文档上说应该是64-bit number的hex，姑且这么做
		APN:          "wifi",
		VendorName:   "Apple", // 这个和下面一个选项(VendorOSName)都属于意义不明，找不到相似对应，不知道是啥
		VendorOSName: "Apple",
		Protocol:     protocol,
		Version: &osVersionFile{
			Incremental: "OCACNFA", // Build.Version.INCREMENTAL, MIUI12: V12.5.3.0.RJBCNXM
			Release:     "11",
			Codename:    "REL",
			Sdk:         29,
		},
	}

	if protocol == 2 {
		deviceJSON.Model = "Apple Watch"
	}

	if protocol == 3 {
		deviceJSON.Model = "mac OS X"
	}

	a, b := json.Marshal(deviceJSON)
	return deviceJSON.Model, a, b
}

func GenerateDeviceJSONAndroidWatch(protocol int) (string, []byte, error) {
	bootID := uuid.New()
	imei := goluhn.Generate(15) // 注意，这个imei是完全胡乱创建的，并不符合imei规则
	androidID := fmt.Sprintf("%X", rand.Uint64())

	deviceJSON := deviceFile{
		Display:      "MIRAI.142521.001", // Rom的名字 比如 Flyme 1.1.2（魅族rom）  JWR66V（Android nexus系列原生4.3rom）
		Product:      "mirai",            // 产品名，比如这是小米6的代号
		Device:       "mirai",
		Board:        "mirai",                                                           // 主板:骁龙835                                                                    //
		Brand:        "Apple",                                                           // 品牌
		Model:        "mirai",                                                           // 型号
		Bootloader:   "unknown",                                                         // unknown不需要改
		FingerPrint:  "mamoe/mirai/mirai:10/MIRAI.200122.001/9108230:user/release-keys", // 指纹
		BootID:       bootID.String(),
		ProcVersion:  "Linux version 3.0.31-zli0DMkg (android-build@xxx.xxx.xxx.xxx.com)", // 很长，后面 builder省略了
		BaseBand:     "",                                                                  // 基带版本 4.3CPL2-... 一大堆，直接不写
		SimInfo:      "T-Mobile",
		OSType:       "android",
		MacAddress:   randomMacAddress(),
		IPAddress:    []int32{192, 168, rand.Int31() % 255, rand.Int31()%253 + 2}, // 192.168.x.x
		WifiBSSID:    randomMacAddress(),
		WifiSSID:     "<unknown ssid>",
		IMEI:         imei,
		AndroidID:    androidID, // 原版的 androidId和Display内容一样，我没看协议，但是按android文档上说应该是64-bit number的hex，姑且这么做
		APN:          "wifi",
		VendorName:   "MIUI", // 这个和下面一个选项(VendorOSName)都属于意义不明，找不到相似对应，不知道是啥
		VendorOSName: "mirai",
		Protocol:     protocol,
		Version: &osVersionFile{
			Incremental: "5891938", // Build.Version.INCREMENTAL, MIUI12: V12.5.3.0.RJBCNXM
			Release:     "10",
			Codename:    "REL",
			Sdk:         29,
		},
	}

	a, b := json.Marshal(deviceJSON)
	return deviceJSON.Model, a, b
}

func GenerateDeviceJSONAllRandom(protocol int) (string, []byte, error) {
	bootID := uuid.New()
	imei := goluhn.Generate(15) // 注意，这个imei是完全胡乱创建的，并不符合imei规则
	androidID := fmt.Sprintf("%X", rand.Uint64())

	deviceJSON := deviceFile{
		Display:      RandString(6), // Rom的名字 比如 Flyme 1.1.2（魅族rom）  JWR66V（Android nexus系列原生4.3rom）
		Product:      RandString(6), // 产品名，比如这是小米6的代号
		Device:       RandString(6),
		Board:        RandString(6),  // 主板:骁龙835                                                                    //
		Brand:        RandString(12), // 品牌
		Model:        RandString(24), // 型号
		Bootloader:   "unknown",      // unknown不需要改
		FingerPrint:  RandString(24), // 指纹
		BootID:       bootID.String(),
		ProcVersion:  "1.0", // 很长，后面 builder省略了
		BaseBand:     "",    // 基带版本 4.3CPL2-... 一大堆，直接不写
		SimInfo:      "",
		OSType:       "android",
		MacAddress:   randomMacAddress(),
		IPAddress:    []int32{192, 168, rand.Int31() % 255, rand.Int31()%253 + 2}, // 192.168.x.x
		WifiBSSID:    randomMacAddress(),
		WifiSSID:     "<unknown ssid>",
		IMEI:         imei,
		AndroidID:    androidID, // 原版的 androidId和Display内容一样，我没看协议，但是按android文档上说应该是64-bit number的hex，姑且这么做
		APN:          "wifi",
		VendorName:   RandString(12), // 这个和下面一个选项(VendorOSName)都属于意义不明，找不到相似对应，不知道是啥
		VendorOSName: RandString(12),
		Protocol:     protocol,
		Version: &osVersionFile{
			Incremental: "OCACNFA", // Build.Version.INCREMENTAL, MIUI12: V12.5.3.0.RJBCNXM
			Release:     "11",
			Codename:    "REL",
			Sdk:         29,
		},
	}

	a, b := json.Marshal(deviceJSON)
	return deviceJSON.Model, a, b
}

func GenerateDeviceJSON(dice *Dice, protocol int) (string, []byte, error) {
	switch protocol {
	case 0, 3:
		return GenerateDeviceJSONIos(protocol)
	case 2:
		return GenerateDeviceJSONAndroidWatch(protocol)
	case 1:
		return GenerateDeviceJSONAndroid(dice, protocol)
	default:
		return GenerateDeviceJSONAllRandom(protocol)
	}
}

func GenerateDeviceJSONAndroid(dice *Dice, protocol int) (string, []byte, error) {
	// check if ./my_device.json exists
	if _, err := os.Stat("./my_device.json"); err == nil {
		dice.Logger.Info("检测到my_device.json，将使用该文件中的设备信息")
		// file exists
		data, err := os.ReadFile("./my_device.json")
		if err == nil {
			deviceJSON := deviceFile{}
			err = json.Unmarshal(data, &deviceJSON)
			if err == nil {
				deviceJSON.Protocol = protocol
				a, b := json.Marshal(deviceJSON)
				return deviceJSON.Model, a, b
			}
			dice.Logger.Warn("读取./my_device.json失败，将使用随机设备信息。原因为JSON解析错误: " + err.Error())
		}
		dice.Logger.Warn("读取./my_device.json失败，将使用随机设备信息")
	}

	pool := androidDevicePool
	imei := goluhn.Generate(15) // 注意，这个imei是完全胡乱创建的，并不符合imei规则
	androidID := fmt.Sprintf("%X", rand.Uint64())

	m := pool[rand.Int()%len(pool)]
	deviceJSON := m.data

	deviceJSON.MacAddress = randomMacAddress()
	deviceJSON.IPAddress = []int32{192, 168, rand.Int31() % 255, rand.Int31()%253 + 2} // 192.168.x.x
	deviceJSON.IMEI = imei
	deviceJSON.AndroidID = androidID
	deviceJSON.Protocol = protocol

	a, b := json.Marshal(deviceJSON)
	return deviceJSON.Model, a, b
}

func BuiltinQQServeProcessKillBase(dice *Dice, conn *EndPointInfo, isSync bool) {
	f := func() {
		defer func() {
			if r := recover(); r != nil {
				dice.Logger.Error("内置 QQ 客户端清理报错: ", r)
				// go-cqhttp/lagrange 进程退出: exit status 1
			}
		}()

		pa, ok := conn.Adapter.(*PlatformAdapterGocq)
		if !ok {
			return
		}
		if !pa.UseInPackClient {
			return
		}

		// 重置状态
		conn.State = 0
		pa.GoCqhttpState = 0
		pa.GoCqhttpQrcodeData = nil

		if pa.BuiltinMode == "lagrange" {
			workDir := lagrangeGetWorkDir(dice, conn)
			qrcodeFile := filepath.Join(workDir, fmt.Sprintf("qr-%s.png", conn.UserID[3:]))
			if _, err := os.Stat(qrcodeFile); err == nil {
				// 如果已经存在二维码文件，将其删除
				_ = os.Remove(qrcodeFile)
				dice.Logger.Info("onebot: 删除已存在的二维码文件")
			}
		}

		// 注意这个会panic，因此recover捕获了
		if pa.GoCqhttpProcess != nil {
			p := pa.GoCqhttpProcess
			pa.GoCqhttpProcess = nil
			// sigintwindows.SendCtrlBreak(p.Cmds[0].Process.Pid)
			_ = p.Stop()
			_ = p.Wait() // 等待进程退出，因为Stop内部是Kill，这是不等待的
		}
	}
	if isSync {
		f()
	} else {
		go f()
	}
}

func BuiltinQQServeProcessKill(dice *Dice, conn *EndPointInfo) {
	BuiltinQQServeProcessKillBase(dice, conn, false)
}

type GoCqhttpLoginInfo struct {
	UIN              int64
	Password         string //nolint:gosec
	Protocol         int
	AppVersion       string
	IsAsyncRun       bool
	UseSignServer    bool
	SignServerConfig *SignServerConfig
}

type SignServerConfig struct {
	SignServers          []*SignServer `json:"signServers"          yaml:"signServers"`
	RuleChangeSignServer int           `json:"ruleChangeSignServer" yaml:"ruleChangeSignServer"`
	MaxCheckCount        int           `json:"maxCheckCount"        yaml:"maxCheckCount"`
	SignServerTimeout    int           `json:"signServerTimeout"    yaml:"signServerTimeout"`
	AutoRegister         bool          `json:"autoRegister"         yaml:"autoRegister"`
	AutoRefreshToken     bool          `json:"autoRefreshToken"     yaml:"autoRefreshToken"`
	RefreshInterval      int           `json:"refreshInterval"      yaml:"refreshInterval"`
}

type SignServer struct {
	URL           string `json:"url"           yaml:"url"`
	Key           string `json:"key"           yaml:"key"`
	Authorization string `json:"authorization" yaml:"authorization"`
}

func GoCqhttpServe(dice *Dice, conn *EndPointInfo, loginInfo GoCqhttpLoginInfo) {
	pa := conn.Adapter.(*PlatformAdapterGocq)
	// if pa.GoCqHttpState != StateCodeInit {
	//	return
	//}

	if pa.UseInPackClient {
		log := dice.Logger

		log.Warnf("不支持或已经废弃的内置适配器模式: %s", pa.BuiltinMode)
		conn.State = 3
		pa.GoCqhttpState = StateCodeLoginFailed
		dice.Save(false)
	} else {
		pa.GoCqhttpState = StateCodeLoginSuccessed
		pa.GoCqhttpLoginSucceeded = true
		dice.Save(false)
		go ServeQQ(dice, conn)
	}
}
