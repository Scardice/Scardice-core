package dice

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"Scardice-core/utils"
)

// 云端SignInfo.Servers结构
type SignServerInfo struct {
	Name     string `json:"name"`
	Url      string `json:"url"`
	Latency  int    `json:"latency"`
	Selected bool   `json:"selected"`
	Ignored  bool   `json:"ignored"`
	Note     string `json:"note"`
}

// 云端SignInfo结构
type SignInfo struct {
	Version  string                 `json:"version"`
	Appinfo  map[string]interface{} `json:"appinfo"`
	Servers  []*SignServerInfo      `json:"servers"`
	Selected bool                   `json:"selected"`
	Ignored  bool                   `json:"ignored"`
	Note     string                 `json:"note"`
}

// 小概率出现并发读写，需上锁
var mu sync.Mutex

func LagrangeGetSignInfo(dice *Dice) ([]SignInfo, error) {
	mu.Lock()
	defer mu.Unlock()
	cachePath := filepath.Join(dice.BaseConfig.DataDir, "extra/SignInfo.cache")
	signInfo, err := lagrangeGetSignInfoFromCloud(cachePath)
	if err == nil && len(signInfo) > 0 {
		return signInfo, nil
	}
	dice.Logger.Infof("无法从云端获取SignInfo，即将读取本地缓存数据, 原因: %s", err.Error())

	signInfo, err = lagrangeGetSignInfoFromCache(cachePath)
	if err == nil && len(signInfo) > 0 {
		return signInfo, nil
	}
	dice.Logger.Infof("无法从本地缓存获取SignInfo，即将读取内置数据, 原因: %s", err.Error())

	if err = json.Unmarshal([]byte(signInfoJson), &signInfo); err == nil {
		lagrangeGetSignServerLatency(signInfo)
		return signInfo, nil
	}
	dice.Logger.Infof("无法从内置数据获取SignInfo，请联系开发者上报问题, 原因: %s", err.Error())
	return nil, errors.New("内置SignInfo信息有误")
}

func lagrangeGetSignInfoFromCloud(cachePath string) ([]SignInfo, error) {
	now := time.Now()
	unixTimestamp := now.Unix()
	url := fmt.Sprintf("https://d1.sealdice.com/sealsign/signinfo.json?v=%v", unixTimestamp)
	c := http.Client{
		Timeout: 3 * time.Second,
	}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var signInfo []SignInfo
	err = json.Unmarshal(body, &signInfo)
	if err != nil {
		return nil, err
	}
	_ = utils.AtomicWriteFile(cachePath, body, 0o644)
	lagrangeGetSignServerLatency(signInfo)
	return signInfo, nil
}

func lagrangeGetSignInfoFromCache(cachePath string) ([]SignInfo, error) {
	var err error
	if _, err = os.Stat(cachePath); err == nil {
		var file []byte
		if file, err = os.ReadFile(cachePath); err == nil {
			var signInfo []SignInfo
			if err = json.Unmarshal(file, &signInfo); err == nil {
				lagrangeGetSignServerLatency(signInfo)
				return signInfo, nil
			}
		}
	}
	return nil, err
}

func lagrangeGetSignServerLatency(signInfo []SignInfo) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	c := &http.Client{
		Timeout: 3 * time.Second,
	}
	for _, si := range signInfo {
		for _, server := range si.Servers {
			wg.Add(1)
			go func(server *SignServerInfo) {
				defer wg.Done()
				latency := testLatency(c, server.Url)
				mu.Lock()
				server.Latency = latency
				mu.Unlock()
			}(server)
		}
	}
	wg.Wait()
}

func testLatency(c *http.Client, url string) int {
	start := time.Now()
	resp, err := c.Get(url)
	if err != nil {
		return 999
	}
	defer resp.Body.Close()
	duration := time.Since(start)
	return int(duration.Milliseconds())
}

var signInfoJson string = `
[
  {
    "version": "39038",
    "appinfo": {
      "Os": "Linux",
      "VendorOs": "linux",
      "Kernel": "Linux",
      "MiscBitmap": 32764,
      "PtVersion": "2.0.0",
      "SsoVersion": 19,
      "PackageName": "com.tencent.qq",
      "WtLoginSdk": "nt.wtlogin.0.0.1",
      "AppId": 1600001615,
      "MainSigMap": 169742560,
      "SubSigMap": 0,
      "NTLoginType": 1,
      "CurrentVersion": "3.2.19-39038",
      "AppClientVersion": 39038,
      "SubAppId": 537313942,
      "AppIdQrCode": 537313942
    },
    "servers": [
      {
        "name": "海豹V2",
        "url": "https://lwxmagic3.sealdice.com/api/sign/39038"
      },
      {
        "name": "aaa1",
        "url": "http://milkymagic.cblkseal.tech/api/sign/39038",
        "selected": true
      },
      {
        "name": "雪桃-莱茵主环",
        "url": "https://de.seal-sign.xuetao.host/39038",
        "note": "德国法兰克福：稳、抗压，大陆基本稳定可用但延迟偏高。能用时优先选它。（运行代价轻）"
      },
      {
        "name": "雪桃-云界律域",
        "url": "https://cf-seal-sign.xuetao.host/39038",
        "note": "Cloudflare反代：海外很快，大陆转圈圈，适合备用。（运行代价轻）"
      },
      {
        "name": "雪桃-寰网引路",
        "url": "https://seal-sign.xuetao.host/39038",
        "note": "【其他稳请优先用其他】全球CDN入口：亚太CDN对华，Cloudflare对国际。低延迟，稳定。（运行代价高）"
      }
    ]
  },
  {
    "version": "40768",
    "appinfo": {
      "Os": "Linux",
      "Kernel": "Linux",
      "VendorOs": "linux",
      "CurrentVersion": "3.2.20-40768",
      "PtVersion": "2.0.0",
      "MiscBitmap": 32764,
      "SsoVersion": 19,
      "PackageName": "com.tencent.qq",
      "WtLoginSdk": "nt.wtlogin.0.0.1",
      "AppId": 1600001615,
      "SubAppId": 537313942,
      "AppIdQrCode": 13697054,
      "AppClientVersion": 39038,
      "MainSigMap": 169742560,
      "SubSigMap": 0,
      "NTLoginType": 1
    },
    "servers": [
      {
        "name": "RSign",
        "url": "https://kic.cblkseal.tech/api/sign/40768"
      },
      {
        "name": "雪桃-莱茵主环",
        "url": "https://de.seal-sign.xuetao.host/40768",
        "note": "德国法兰克福：稳、抗压，大陆基本稳定可用但延迟偏高。能用时优先选它。（运行代价轻）",
        "selected": true
      },
      {
        "name": "雪桃-云界律域",
        "url": "https://cf-seal-sign.xuetao.host/40768",
        "note": "Cloudflare反代：海外很快，大陆转圈圈，适合备用。（运行代价轻）"
      },
      {
        "name": "雪桃-寰网引路",
        "url": "https://seal-sign.xuetao.host/40768",
        "note": "【其他稳请优先用其他】全球CDN入口：亚太CDN对华，Cloudflare对国际。低延迟，稳定。（运行代价高）"
      }
    ],
    "note": "如果39038能登录就不要选"
  },
  {
    "version": "41857",
    "appinfo": {
      "AppClientVersion": 41857,
      "AppId": 1600001615,
      "AppIdQrCode": 13697054,
      "CurrentVersion": "3.2.21-41857",
      "Kernel": "Linux",
      "MainSigMap": 169742560,
      "MiscBitmap": 32764,
      "NTLoginType": 1,
      "Os": "Linux",
      "PackageName": "com.tencent.qq",
      "PtVersion": "2.0.0",
      "SsoVersion": 19,
      "SubAppId": 537320197,
      "SubSigMap": 0,
      "VendorOs": "linux",
      "WtLoginSdk": "nt.wtlogin.0.0.1"
    },
    "servers": [
      {
        "name": "海豹V2",
        "url": "https://lwxmagic3.sealdice.com/api/sign/41857"
      },
      {
        "name": "RSign",
        "url": "https://kic.cblkseal.tech/api/sign/41857",
        "selected": true
      }
    ],
    "note": "如果39038或40768能登录就不要选"
  },
  {
    "version": "44343",
    "appinfo": {
      "Os": "Linux",
      "VendorOs": "linux",
      "Kernel": "Linux",
      "MiscBitmap": 32764,
      "PtVersion": "2.0.0",
      "SsoVersion": 19,
      "PackageName": "com.tencent.qq",
      "WtLoginSdk": "nt.wtlogin.0.0.1",
      "AppId": 1600001615,
      "MainSigMap": 169742560,
      "SubSigMap": 0,
      "NTLoginType": 1,
      "CurrentVersion": "3.2.23-44343",
      "AppClientVersion": 44343,
      "SubAppId": 537336639,
      "AppIdQrCode": 537336639
    },
    "servers": [
      {
        "name": "雪桃-莱茵主环",
        "url": "https://de.seal-sign.xuetao.host/44343",
        "note": "德国法兰克福：稳、抗压，大陆基本稳定可用但延迟偏高。能用时优先选它。（运行代价轻）",
        "selected": true
      },
      {
        "name": "雪桃-云界律域",
        "url": "https://cf-seal-sign.xuetao.host/44343",
        "note": "Cloudflare反代：海外很快，大陆转圈圈，适合备用。（运行代价轻）"
      },
      {
        "name": "雪桃-寰网引路",
        "url": "https://seal-sign.xuetao.host/44343",
        "note": "【其他稳请优先用其他】全球CDN入口：亚太CDN对华，Cloudflare对国际。低延迟，稳定。（运行代价高）"
      }
    ]
  },
  {
    "version": "45758",
    "appinfo": {
      "Os": "Linux",
      "VendorOs": "linux",
      "Kernel": "Linux",
      "MiscBitmap": 32764,
      "PtVersion": "2.0.0",
      "SsoVersion": 19,
      "PackageName": "com.tencent.qq",
      "WtLoginSdk": "nt.wtlogin.0.0.1",
      "AppId": 1600001615,
      "MainSigMap": 169742560,
      "SubSigMap": 0,
      "NTLoginType": 1,
      "CurrentVersion": "3.2.25-45758",
      "AppClientVersion": 45758,
      "SubAppId": 537340249,
      "AppIdQrCode": 537340249
    },
    "servers": [
      {
        "name": "雪桃-莱茵主环",
        "url": "https://de.seal-sign.xuetao.host/45758",
        "note": "德国法兰克福：稳、抗压，大陆基本稳定可用但延迟偏高。能用时优先选它。（运行代价轻）",
        "selected": true
      },
      {
        "name": "雪桃-云界律域",
        "url": "https://cf-seal-sign.xuetao.host/45758",
        "note": "Cloudflare反代：海外很快，大陆转圈圈，适合备用。（运行代价轻）"
      },
      {
        "name": "雪桃-寰网引路",
        "url": "https://seal-sign.xuetao.host/45758",
        "note": "【其他稳请优先用其他】全球CDN入口：亚太CDN对华，Cloudflare对国际。低延迟，稳定。（运行代价高）"
      }
    ],
    "selected": true
  }
]
`

var defaultLagrangeConfig = `
	{
		"Logging": {
			"LogLevel": {
				"Default": "Information",
				"Microsoft": "Warning",
				"Microsoft.Hosting.Lifetime": "Information"
			}
		},
		"SignServerUrl": "{NTSignServer地址}",
		"Account": {
			"Uin": {账号UIN},
			"Password": "",
			"Protocol": "Linux",
			"AutoReconnect": true,
			"GetOptimumServer": true
		},
		"Message": {
			"IgnoreSelf": true,
			"StringPost": false
		},
		"QrCode": {
			"ConsoleCompatibilityMode": false
		},
		"Implementations": [
			{
				"Type": "ForwardWebSocket",
				"Host": "127.0.0.1",
				"Port": {WS端口},
				"HeartBeatInterval": 5000,
				"AccessToken": ""
			}
		]
	}
	`
