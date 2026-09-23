package nncp

import (
	"bytes"
	"io"
	"testing"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
)

// A packet that is still arriving must keep the session alive. On HF a
// 2.5 KiB file packet took minutes to arrive, no whole packet was seen for
// 2*PingTimeout, and the session was dropped while bytes kept coming.
func TestSPLivenessFollowsPartialPackets(t *testing.T) {
	var raw bytes.Buffer
	if _, err := xdr.Marshal(&raw, SPRaw{
		Magic:   MagicNNCPSv1.B,
		Payload: bytes.Repeat([]byte{0xA5}, 2560),
	}); err != nil {
		t.Fatal(err)
	}
	msg := raw.Bytes()

	state := &SPState{}
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		payload, err := state.ReadSP(pr)
		if err == nil && len(payload) != 2560 {
			t.Errorf("payload %d bytes, want 2560", len(payload))
		}
		done <- err
	}()

	if _, err := pw.Write(msg[:len(msg)/2]); err != nil {
		t.Fatal(err)
	}
	// Half a packet in: no whole packet yet, but bytes are arriving. The
	// reader stamps just after its Read returns, which can be after our
	// Write does, so allow it a moment.
	for i := 0; i < 100 && state.rxLastByte.Load() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !state.RxLastSeen.IsZero() {
		t.Fatal("a whole packet was counted before it arrived")
	}
	if !state.rxAlive(time.Now(), time.Second) {
		t.Fatal("session with bytes arriving counted as dead")
	}

	if _, err := pw.Write(msg[len(msg)/2:]); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if state.RxLastSeen.IsZero() {
		t.Fatal("whole packet not recorded")
	}
}

// A silent peer must still be dropped.
func TestSPLivenessDropsSilentPeer(t *testing.T) {
	now := time.Now()
	state := &SPState{RxLastSeen: now.Add(-3 * time.Minute)}
	if state.rxAlive(now, 2*time.Minute) {
		t.Fatal("peer silent for 3 min counted as alive (no bytes ever)")
	}
	state.rxLastByte.Store(now.Add(-150 * time.Second).UnixNano())
	if state.rxAlive(now, 2*time.Minute) {
		t.Fatal("peer whose last byte was 150 s ago counted as alive")
	}
	state.rxLastByte.Store(now.Add(-30 * time.Second).UnixNano())
	if !state.rxAlive(now, 2*time.Minute) {
		t.Fatal("peer that sent a byte 30 s ago counted as dead")
	}
}
