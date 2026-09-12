// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !(go1.27 && !http2legacy)

package http2

import "fmt"

// FrameWriteRequest is a request to write a frame.
//
// Deprecated: User-provided write schedulers are deprecated.
type FrameWriteRequest struct {
	// write is the interface value that does the writing, once the
	// WriteScheduler has selected this frame to write. The write
	// functions are all defined in write.go.
	write writeFramer

	// stream is the stream on which this frame will be written.
	// nil for non-stream frames like PING and SETTINGS.
	// nil for RST_STREAM streams, which use the StreamError.StreamID field instead.
	stream *stream

	// done, if non-nil, must be a buffered channel with space for
	// 1 message and is sent the return value from write (or an
	// earlier error) when the frame has been written.
	done chan error
}

// StreamID returns the id of the stream this frame will be written to.
// 0 is used for non-stream frames such as PING and SETTINGS.
func (wr FrameWriteRequest) StreamID() uint32 {
	if wr.stream == nil {
		if se, ok := wr.write.(StreamError); ok {
			// (*serverConn).resetStream doesn't set
			// stream because it doesn't necessarily have
			// one. So special case this type of write
			// message.
			return se.StreamID
		}
		return 0
	}
	return wr.stream.id
}

// isControl reports whether wr is a control frame for MaxQueuedControlFrames
// purposes. That includes non-stream frames and RST_STREAM frames.
func (wr FrameWriteRequest) isControl() bool {
	return wr.stream == nil
}

// DataSize returns the number of flow control bytes that must be consumed
// to write this entire frame. This is 0 for non-DATA frames.
func (wr FrameWriteRequest) DataSize() int {
	if wd, ok := wr.write.(*writeData); ok {
		return len(wd.p)
	}
	return 0
}

// Consume consumes min(n, available) bytes from this frame, where available
// is the number of flow control bytes available on the stream. Consume returns
// 0, 1, or 2 frames, where the integer return value gives the number of frames
// returned.
//
// If flow control prevents consuming any bytes, this returns (_, _, 0). If
// the entire frame was consumed, this returns (wr, _, 1). Otherwise, this
// returns (consumed, rest, 2), where 'consumed' contains the consumed bytes and
// 'rest' contains the remaining bytes. The consumed bytes are deducted from the
// underlying stream's flow control budget.
func (wr FrameWriteRequest) Consume(n int32) (FrameWriteRequest, FrameWriteRequest, int) {
	var empty FrameWriteRequest

	// Non-DATA frames are always consumed whole.
	wd, ok := wr.write.(*writeData)
	if !ok || len(wd.p) == 0 {
		return wr, empty, 1
	}

	// Might need to split after applying limits.
	allowed := wr.stream.flow.available()
	if n < allowed {
		allowed = n
	}
	if wr.stream.sc.maxFrameSize < allowed {
		allowed = wr.stream.sc.maxFrameSize
	}
	if allowed <= 0 {
		return empty, empty, 0
	}

	// wd.pad (if any) was already chosen by writeDataFromHandler, against
	// the *original*, unsplit len(wd.p) — before we knew how much of it
	// would actually fit in this wire frame. Recompute it here instead of
	// trusting that value, for two reasons:
	//  1. Correctness: the pad-length byte + padding count against the
	//     flow-control window exactly like the data does (RFC 7540
	//     §6.9.1). wr.stream.flow.take() below must charge for the whole
	//     wire frame, not just len(data), or our accounting silently
	//     drifts ahead of what the peer (correctly) decrements on
	//     receipt — see serverConn.processData's sc.inflow.take(f.Length)
	//     — until eventually the peer sees more bytes than it ever
	//     granted and kills the connection with a FLOW_CONTROL_ERROR
	//     GOAWAY. This reproduces in proportion to bytes/frames sent, not
	//     wall-clock time, so it shows up as "H2 randomly dies after a
	//     while" under sustained traffic rather than at connect time.
	//  2. Coverage: a writeData that has to be split across several DATA
	//     frames (len(wd.p) > allowed, the branch below) would otherwise
	//     carry wd.pad on only one fragment and silently send the rest
	//     unpadded — recomputing per fragment keeps every wire frame of a
	//     large write padded, not just the first.
	dataPaddingMax := wr.stream.sc.srv.DataPaddingMax
	// Reserve room for the worst case (pad-length byte + max padding) up
	// front, the same way the client side does in writeRequestBody, so
	// shrinking dataLen to fit "allowed" actually leaves space for
	// padding instead of consuming the whole budget as data and leaving
	// pickDataPaddingLen nothing to work with.
	overhead := 0
	if dataPaddingMax > 0 {
		overhead = 1 + dataPaddingMax
	}
	dataLen := len(wd.p)
	if dataLen+overhead > int(allowed) {
		dataLen = int(allowed) - overhead
		if dataLen < 0 {
			dataLen = 0
		}
	}
	var pad []byte
	if dataPaddingMax > 0 {
		room := int(allowed) - dataLen - 1
		if room < 0 {
			room = 0
		}
		padLen := pickDataPaddingLen(wr.stream.sc.srv.DataPaddingMin, dataPaddingMax, dataLen, dataLen+1+room)
		if padLen > room {
			padLen = room
		}
		pad = dataPadding(padLen)
	}
	// Charge exactly what goes on the wire (data + pad-length byte + pad),
	// which may be less than the "allowed"/overhead reservation above —
	// any unused reservation just isn't spent, it is never a place we can
	// end up charging *more* than the peer actually receives.
	chargedBytes := dataLen + len(pad)
	if len(pad) > 0 {
		chargedBytes++ // pad-length field
	}
	// NB: cast cannot overflow because chargedBytes <= allowed <= math.MaxInt32.
	wr.stream.flow.take(int32(chargedBytes))

	if dataLen < len(wd.p) {
		consumed := FrameWriteRequest{
			stream: wr.stream,
			write: &writeData{
				streamID: wd.streamID,
				p:        wd.p[:dataLen],
				// Even if the original had endStream set, there
				// are bytes remaining because dataLen < len(wd.p),
				// so we know endStream is false.
				endStream: false,
				pad:       pad,
			},
			// Our caller is blocking on the final DATA frame, not
			// this intermediate frame, so no need to wait.
			done: nil,
		}
		rest := FrameWriteRequest{
			stream: wr.stream,
			write: &writeData{
				streamID:  wd.streamID,
				p:         wd.p[dataLen:],
				endStream: wd.endStream,
				// pad deliberately not carried over: it was sized
				// for *this* fragment's dataLen and belongs only
				// on it. The remaining fragment gets its own pad
				// chosen fresh next time Consume() runs on it.
			},
			done: wr.done,
		}
		return consumed, rest, 2
	}

	// The frame is consumed whole.
	wd.pad = pad
	return wr, empty, 1
}

// String is for debugging only.
func (wr FrameWriteRequest) String() string {
	var des string
	if s, ok := wr.write.(fmt.Stringer); ok {
		des = s.String()
	} else {
		des = fmt.Sprintf("%T", wr.write)
	}
	return fmt.Sprintf("[FrameWriteRequest stream=%d, ch=%v, writer=%v]", wr.StreamID(), wr.done != nil, des)
}

// replyToWriter sends err to wr.done and panics if the send must block
// This does nothing if wr.done is nil.
func (wr *FrameWriteRequest) replyToWriter(err error) {
	if wr.done == nil {
		return
	}
	select {
	case wr.done <- err:
	default:
		panic(fmt.Sprintf("unbuffered done channel passed in for type %T", wr.write))
	}
	wr.write = nil // prevent use (assume it's tainted after wr.done send)
}

// writeQueue is used by implementations of WriteScheduler.
//
// Each writeQueue contains a queue of FrameWriteRequests, meant to store all
// FrameWriteRequests associated with a given stream. This is implemented as a
// two-stage queue: currQueue[currPos:] and nextQueue. Removing an item is done
// by incrementing currPos of currQueue. Adding an item is done by appending it
// to the nextQueue. If currQueue is empty when trying to remove an item, we
// can swap currQueue and nextQueue to remedy the situation.
// This two-stage queue is analogous to the use of two lists in Okasaki's
// purely functional queue but without the overhead of reversing the list when
// swapping stages.
//
// writeQueue also contains prev and next, this can be used by implementations
// of WriteScheduler to construct data structures that represent the order of
// writing between different streams (e.g. circular linked list).
type writeQueue struct {
	currQueue []FrameWriteRequest
	nextQueue []FrameWriteRequest
	currPos   int

	prev, next *writeQueue
}

func (q *writeQueue) empty() bool {
	return (len(q.currQueue) - q.currPos + len(q.nextQueue)) == 0
}

func (q *writeQueue) push(wr FrameWriteRequest) {
	q.nextQueue = append(q.nextQueue, wr)
}

func (q *writeQueue) shift() FrameWriteRequest {
	if q.empty() {
		panic("invalid use of queue")
	}
	if q.currPos >= len(q.currQueue) {
		q.currQueue, q.currPos, q.nextQueue = q.nextQueue, 0, q.currQueue[:0]
	}
	wr := q.currQueue[q.currPos]
	q.currQueue[q.currPos] = FrameWriteRequest{}
	q.currPos++
	return wr
}

func (q *writeQueue) peek() *FrameWriteRequest {
	if q.currPos < len(q.currQueue) {
		return &q.currQueue[q.currPos]
	}
	if len(q.nextQueue) > 0 {
		return &q.nextQueue[0]
	}
	return nil
}

// consume consumes up to n bytes from q.s[0]. If the frame is
// entirely consumed, it is removed from the queue. If the frame
// is partially consumed, the frame is kept with the consumed
// bytes removed. Returns true iff any bytes were consumed.
func (q *writeQueue) consume(n int32) (FrameWriteRequest, bool) {
	if q.empty() {
		return FrameWriteRequest{}, false
	}
	consumed, rest, numresult := q.peek().Consume(n)
	switch numresult {
	case 0:
		return FrameWriteRequest{}, false
	case 1:
		q.shift()
	case 2:
		*q.peek() = rest
	}
	return consumed, true
}

type writeQueuePool []*writeQueue

// put inserts an unused writeQueue into the pool.
func (p *writeQueuePool) put(q *writeQueue) {
	for i := range q.currQueue {
		q.currQueue[i] = FrameWriteRequest{}
	}
	for i := range q.nextQueue {
		q.nextQueue[i] = FrameWriteRequest{}
	}
	q.currQueue = q.currQueue[:0]
	q.nextQueue = q.nextQueue[:0]
	q.currPos = 0
	*p = append(*p, q)
}

// get returns an empty writeQueue.
func (p *writeQueuePool) get() *writeQueue {
	ln := len(*p)
	if ln == 0 {
		return new(writeQueue)
	}
	x := ln - 1
	q := (*p)[x]
	(*p)[x] = nil
	*p = (*p)[:x]
	return q
}
