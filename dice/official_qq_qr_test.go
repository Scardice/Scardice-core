package dice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOfficialQQQRLogin_createsScannableSessionWithHTTPFake(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/lite/create_bind_task" {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"retcode":0,"data":{"task_id":"task-13"}}`))
	}))
	defer server.Close()
	adapter := &PlatformAdapterOfficialQQ{
		qrClient: newOfficialQQQRHTTPClient(server.Client(), server.URL),
		qrEncoder: func(value string) ([]byte, error) {
			return []byte("fake-qr:" + value), nil
		},
	}

	err := adapter.beginQRLogin(context.Background(), "scardice")

	if err != nil {
		t.Fatalf("beginQRLogin() error = %v", err)
	}
	if adapter.QRLoginState != OfficialQQQRWaitingForScan {
		t.Fatalf("QRLoginState = %d", adapter.QRLoginState)
	}
	if adapter.QRURL != server.URL+"/qqbot/connect.html?task_id=task-13&source=scardice&_wv=2" {
		t.Fatalf("QRURL = %q", adapter.QRURL)
	}
	if string(adapter.QRCodeData) != "fake-qr:"+adapter.QRURL {
		t.Fatalf("QRCodeData = %q", adapter.QRCodeData)
	}
}
