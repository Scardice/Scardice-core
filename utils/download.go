package utils

import (
	"compress/gzip"
	"errors"
	"io"
	"net/http"

	"Scardice-core/logger"
)

func DownloadFile(filepath string, url string) error {
	// Get the data
	// resp, err := http.Get(url)
	client := new(http.Client)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}

	request.Header.Add("Accept-Encoding", "gzip")
	resp, err := client.Do(request) //nolint:gosec
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusOK {
		if resp.Header.Get("Content-Encoding") == "gzip" {
			// 如果响应使用了GZIP压缩，需要解压缩
			var reader io.ReadCloser
			reader, err = gzip.NewReader(resp.Body)
			if err != nil {
				logger.M().Errorf("GZIP解压出错: %v", err)
				return err
			}
			defer reader.Close()
			return AtomicWriteReader(filepath, reader, 0o644)
		}

		return AtomicWriteReader(filepath, resp.Body, 0o644)
	}

	return errors.New("http status:" + resp.Status)
}
