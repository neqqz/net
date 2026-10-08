//go:build !(go1.27 && !http2legacy)

package http2

import (
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2/hpack"
)

func TestChromeFingerprintPreamble(t *testing.T) {
	cliConn, srvConn := net.Pipe()
	defer srvConn.Close()
	tr := &Transport{ChromeFingerprint: true, AllowHTTP: true}
	go func() {
		cc, err := tr.NewClientConn(cliConn)
		if err != nil {
			return
		}
		req, _ := http.NewRequest("POST", "https://example.com/p", http.NoBody)
		go cc.RoundTrip(req)
	}()
	srvConn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(ClientPreface))
	if _, err := io.ReadFull(srvConn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != ClientPreface {
		t.Fatalf("bad preface")
	}
	fr := NewFramer(io.Discard, srvConn)
	f, err := fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	sf, ok := f.(*SettingsFrame)
	if !ok {
		t.Fatalf("first frame %T", f)
	}
	want := []Setting{
		{SettingHeaderTableSize, 65536},
		{SettingEnablePush, 0},
		{SettingInitialWindowSize, 6291456},
		{SettingMaxHeaderListSize, 262144},
	}
	if sf.NumSettings() != len(want) {
		t.Fatalf("got %d settings", sf.NumSettings())
	}
	for i, w := range want {
		if g := sf.Setting(i); g != w {
			t.Errorf("setting %d = %v, want %v", i, g, w)
		}
	}
	f, err = fr.ReadFrame()
	if err != nil {
		t.Fatal(err)
	}
	wu, ok := f.(*WindowUpdateFrame)
	if !ok || wu.StreamID != 0 || wu.Increment != 15663105 {
		t.Fatalf("bad window update: %#v", f)
	}
	// next frames: possibly SETTINGS ack etc; find HEADERS and check pseudo order
	for i := 0; i < 5; i++ {
		f, err = fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if h, ok := f.(*HeadersFrame); ok {
			dec := hpack.NewDecoder(65536, nil)
			var names []string
			dec.SetEmitFunc(func(f hpack.HeaderField) { names = append(names, f.Name) })
			if _, err := dec.Write(h.HeaderBlockFragment()); err != nil {
				t.Fatal(err)
			}
			got := names[:4]
			wantN := []string{":method", ":authority", ":scheme", ":path"}
			for j := range wantN {
				if got[j] != wantN[j] {
					t.Fatalf("pseudo order %v, want %v", got, wantN)
				}
			}
			return
		}
	}
	t.Fatal("no HEADERS frame seen")
}
