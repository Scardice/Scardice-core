package dice

import (
	"testing"

	"github.com/dop251/goja"
)

func TestExposeDangerousJSValueRecursivelyExposesAndMutatesSealInst(t *testing.T) {
	vm := goja.New()
	d := &Dice{
		CommandPrefix:     []string{".", "。"},
		DiceMasters:       []string{"QQ:1001"},
		JsSealInstExposed: true,
		Config: Config{
			JsConfig:   JsConfig{JsEnable: true},
			MailConfig: MailConfig{MailEnable: false},
		},
		AdvancedConfig: AdvancedConfig{
			Show:                    true,
			Enable:                  true,
			ExposeDangerousSealInst: true,
		},
	}

	if err := vm.Set("sealInst", exposeDangerousJSValue(vm, d)); err != nil {
		t.Fatalf("vm.Set failed: %v", err)
	}

	script := `
		if (typeof sealInst.getDiceDataPath !== 'function') {
			throw new Error('missing getDiceDataPath');
		}
		if (typeof sealInst.save !== 'function') {
			throw new Error('missing save');
		}
		if (typeof sealInst.jsSealInstExposed !== 'undefined') {
			throw new Error('jsSealInstExposed should stay hidden');
		}
		if (sealInst.config.jsEnable !== true) {
			throw new Error('missing recursive jsEnable');
		}
		if (sealInst.Config.JsEnable !== true) {
			throw new Error('missing recursive JsEnable alias');
		}
		if (sealInst.advancedConfig.exposeDangerousSealInst !== true) {
			throw new Error('missing recursive advancedConfig');
		}
		if (!Array.isArray(sealInst.commandPrefix)) {
			throw new Error('commandPrefix is not an array');
		}
		if (!Array.isArray(sealInst.diceMasters)) {
			throw new Error('diceMasters is not an array');
		}
		sealInst.commandPrefix[0] = '!';
		sealInst.commandPrefix.push('/');
		sealInst.config.jsEnable = false;
		sealInst.config.mailEnable = true;
		sealInst.advancedConfig.exposeDangerousSealInst = false;
		sealInst.diceMasters.push('QQ:2002');
		({
			commandPrefix0: sealInst.commandPrefix[0],
			commandPrefix2: sealInst.commandPrefix[2],
			jsEnable: sealInst.config.jsEnable,
			mailEnable: sealInst.config.mailEnable,
			exposeDangerousSealInst: sealInst.advancedConfig.exposeDangerousSealInst,
			diceMastersLen: sealInst.diceMasters.length,
			keys: Object.keys(sealInst.config).slice(0, 12),
		});
	`

	value, err := vm.RunString(script)
	if err != nil {
		t.Fatalf("RunString failed: %v", err)
	}

	result := value.Export().(map[string]interface{})
	if result["commandPrefix0"] != "!" {
		t.Fatalf("unexpected commandPrefix[0]: %#v", result["commandPrefix0"])
	}
	if result["commandPrefix2"] != "/" {
		t.Fatalf("unexpected commandPrefix[2]: %#v", result["commandPrefix2"])
	}
	if result["jsEnable"] != false {
		t.Fatalf("unexpected jsEnable: %#v", result["jsEnable"])
	}
	if result["mailEnable"] != true {
		t.Fatalf("unexpected mailEnable: %#v", result["mailEnable"])
	}
	if result["exposeDangerousSealInst"] != false {
		t.Fatalf("unexpected exposeDangerousSealInst: %#v", result["exposeDangerousSealInst"])
	}
	if result["diceMastersLen"] != int64(2) {
		t.Fatalf("unexpected diceMasters length: %#v", result["diceMastersLen"])
	}

	if d.CommandPrefix[0] != "!" || d.CommandPrefix[2] != "/" {
		t.Fatalf("Go CommandPrefix was not updated: %#v", d.CommandPrefix)
	}
	if !d.Config.MailEnable || d.Config.JsEnable {
		t.Fatalf("Go Config was not updated: %#v", d.Config.MailConfig)
	}
	if d.AdvancedConfig.ExposeDangerousSealInst {
		t.Fatalf("Go AdvancedConfig was not updated: %#v", d.AdvancedConfig)
	}
	if len(d.DiceMasters) != 2 || d.DiceMasters[1] != "QQ:2002" {
		t.Fatalf("Go DiceMasters was not updated: %#v", d.DiceMasters)
	}
}
