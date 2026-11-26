package kook

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/websocket"
)

var errWebhookVerify = errors.New("web")

// maxWebhookBodyBytes 限制 webhook 解压后的请求体，避免 zlib 炸弹撑爆内存。
const maxWebhookBodyBytes = 64 << 20

// WebhookHandler provides a http.HandlerFunc for webhook.
func (s *Session) WebhookHandler() http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		defer request.Body.Close()
		var err error
		addCaller(s.Logger.Trace()).Msg("new request")
		if request.Method != "POST" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		var body io.Reader = io.LimitReader(request.Body, maxWebhookBodyBytes)
		defer request.Body.Close()
		buf := &bytes.Buffer{}
		if !strings.Contains(request.RequestURI, "compress=0") {
			zr, zerr := zlib.NewReader(body)
			if zerr != nil {
				addCaller(s.Logger.Error().Err("error", zerr)).Msg("error in init zlib")
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer zr.Close()
			body = zr
		}
		_, err = buf.ReadFrom(io.LimitReader(body, maxWebhookBodyBytes))
		if err != nil {
			addCaller(s.Logger.Error().Err("error", err)).Msg("error in reading body")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if s.Identify.WebsocketKey != nil {
			e := &struct {
				Encrypt string `json:"encrypt"`
			}{}
			err = json.NewDecoder(buf).Decode(e)
			if err != nil {
				addCaller(s.Logger.Error().Err("error", err)).Msg("error in parsing encrypted request")
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			base64Reader := base64.NewDecoder(base64.StdEncoding, strings.NewReader(e.Encrypt))
			newBuf := &bytes.Buffer{}
			_, err = newBuf.ReadFrom(base64Reader)
			if err != nil {
				addCaller(s.Logger.Error().Err("error", err)).Msg("error in decoding base64")
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			c, err := aes.NewCipher(s.Identify.WebsocketKey)
			if err != nil {
				addCaller(s.Logger.Error().Err("error", err)).Msg("error in creating cipher")
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			ciphertext := newBuf.Bytes()
			if len(ciphertext) < aes.BlockSize {
				addCaller(s.Logger.Warn()).Msg("encrypted payload too short")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			dec := cipher.NewCBCDecrypter(c, ciphertext[:aes.BlockSize])
			payloadReader := base64.NewDecoder(base64.StdEncoding, bytes.NewReader(ciphertext[aes.BlockSize:]))
			buf.Reset()
			_, err = buf.ReadFrom(io.LimitReader(payloadReader, maxWebhookBodyBytes))
			if err != nil {
				addCaller(s.Logger.Error().Err("error", err)).Msg("error in reading payload")
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			decrypted := buf.Bytes()
			if len(decrypted) == 0 || len(decrypted)%aes.BlockSize != 0 {
				addCaller(s.Logger.Warn()).Msg("invalid encrypted payload length")
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			dec.CryptBlocks(decrypted, decrypted)
		}
		e, err := s.onEvent(nil, websocket.TextMessage, buf.Bytes())
		if err == errWebhookVerify {
			i := &struct {
				Type        int    `json:"type"`
				ChannelType string `json:"channel_type"`
				Challenge   string `json:"challenge"`
				VerifyToken string `json:"verify_token"`
			}{}
			err = json.Unmarshal(e.Data, i)
			if err != nil {
				addCaller(s.Logger.Error().Err("error", err)).Msg("error in unmarshalling data")
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			if s.Identify.VerifyToken != "" && i.VerifyToken != s.Identify.VerifyToken {
				addCaller(s.Logger.Warn().Err("error", err)).Msg("received wrong data")
				writer.WriteHeader(http.StatusUnauthorized)
				return
			}
			_, err = writer.Write([]byte(`{"challenge":"` + i.Challenge + `"}`))
			if err != nil {
				s.Logger.Error().Err("error", err).Msg("error in writing to response")
				return
			}
			addCaller(s.Logger.Info()).Msg("webhook challenge done")
			return
		} else if err != nil {
			addCaller(s.Logger.Error().Err("error", err)).Msg("error in parsing event")
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}
