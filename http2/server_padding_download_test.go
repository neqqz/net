//go:build !(go1.27 && !http2legacy)

// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2_test

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestServerPaddedDownloadKeepsFlowControl streams a response larger than the
// stream window can cover if padding were charged but never sent. Padding is
// charged against flow control by writeScheduler.Consume, so every padded DATA
// frame must really carry it (including the async write path used when a frame
// does not fit the write buffer); otherwise the peer never returns those
// bytes and the stream stalls once the leaked total reaches the window.
func TestServerPaddedDownloadKeepsFlowControl(t *testing.T) {
	const size = 400 << 20
	chunk := make([]byte, 32<<10)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fl := w.(http.Flusher)
		for sent := 0; sent < size; sent += len(chunk) {
			if _, err := w.Write(chunk); err != nil {
				return
			}
			fl.Flush()
		}
	}))
	srv.TLS = &tls.Config{NextProtos: []string{"h2"}}
	http2.ConfigureServer(srv.Config, &http2.Server{DataPaddingMin: 255, DataPaddingMax: 255})
	srv.StartTLS()
	defer srv.Close()

	tr := &http2.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 60 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil || n != size {
		t.Fatalf("download: got %d of %d bytes, err=%v", n, size, err)
	}
}
