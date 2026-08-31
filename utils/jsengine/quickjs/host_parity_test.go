package quickjs_test

import (
	"testing"

	"Scardice-core/utils/jsengine"
	"Scardice-core/utils/jsengine/hostparity"
	"Scardice-core/utils/jsengine/quickjs"
)

func TestQuickJSHostProxyParityContract(t *testing.T) {
	hostparity.Run(t, hostparity.Engine{
		Name: "legacy-quickjs-go",
		Open: func(t *testing.T) jsengine.Loop {
			t.Helper()
			loop, err := quickjs.New()
			if err != nil {
				t.Fatal(err)
			}
			return loop
		},
		ExposeDangerous: quickjs.ExposeDangerous,
	})
}
