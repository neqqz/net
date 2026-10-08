//go:build !(go1.27 && !http2legacy)

package http2

import (
	"math"
	"testing"
)

// Padding (pad-length byte + pad) counts against flow control (RFC 7540
// §6.9.1), so Consume must charge exactly what goes on the wire and never
// more than the window it was given.
func TestConsumeChargesPaddingAgainstFlowControl(t *testing.T) {
	for i := 0; i < 500; i++ {
		st := &stream{
			id: 1,
			sc: &serverConn{
				maxFrameSize: 16384,
				srv:          &Server{DataPaddingMin: 5, DataPaddingMax: 40},
			},
		}
		const window = 120
		st.flow.add(window)
		wr := FrameWriteRequest{&writeData{1, make([]byte, 100), true, nil}, st, make(chan error, 1)}
		var onWire int
		for {
			consumed, rest, n := wr.Consume(math.MaxInt32)
			if n == 0 {
				break
			}
			wd := consumed.write.(*writeData)
			frame := len(wd.p)
			if len(wd.pad) > 0 {
				frame += 1 + len(wd.pad)
			}
			onWire += frame
			if n == 1 {
				break
			}
			wr = rest
		}
		if onWire > window {
			t.Fatalf("sent %d bytes with window %d", onWire, window)
		}
		if got, want := int(st.flow.available()), window-onWire; got != want {
			t.Fatalf("flow window left = %d, want %d (charged != wire size)", got, want)
		}
	}
}
