package hfmodem

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func newTestConn() (*HFConn, net.Conn) {
	ours, tnc := net.Pipe()
	c := &HFConn{
		dataConn:      ours,
		ctrlDone:      make(chan struct{}),
		connectedCh:   make(chan struct{}),
		listenerOwned: true,
		connected:     true,
	}
	close(c.connectedCh)
	return c, tnc
}

// Once the TNC says DISCONNECTED, nothing more may reach its data channel:
// the bytes would wait in its buffer and open the next, unrelated session.
func TestWriteAfterDisconnectDoesNotReachTNC(t *testing.T) {
	c, tnc := newTestConn()
	defer tnc.Close()

	got := make(chan int, 1)
	go func() {
		buf := make([]byte, 64)
		tnc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _ := tnc.Read(buf)
		got <- n
	}()

	close(c.ctrlDone) // DISCONNECTED
	n, err := c.Write(make([]byte, 32))
	if n != 0 || !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Write after disconnect: n=%d err=%v, want 0, net.ErrClosed", n, err)
	}
	if n := <-got; n != 0 {
		t.Fatalf("the TNC received %d bytes after DISCONNECTED", n)
	}
}

func TestReadAfterDisconnectIsEOF(t *testing.T) {
	c, tnc := newTestConn()
	defer tnc.Close()
	close(c.ctrlDone)
	if _, err := c.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("Read after disconnect: %v, want io.EOF", err)
	}
}

// A Read already blocked on the shared data channel when DISCONNECTED arrives
// is woken, as the listener does, and ends the session with io.EOF instead of
// waiting for the online deadline.
func TestBlockedReadEndsOnDisconnect(t *testing.T) {
	c, tnc := newTestConn()
	defer tnc.Close()

	done := make(chan error, 1)
	go func() {
		_, err := c.Read(make([]byte, 16))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)

	close(c.ctrlDone)
	c.dataConn.SetReadDeadline(time.Now())

	select {
	case err := <-done:
		if err != io.EOF {
			t.Fatalf("blocked Read ended with %v, want io.EOF", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocked Read did not end on disconnect")
	}
}

// While the link is up, data flows as before.
func TestReadWriteWhileConnected(t *testing.T) {
	c, tnc := newTestConn()
	defer tnc.Close()

	go func() {
		buf := make([]byte, 5)
		io.ReadFull(tnc, buf)
		tnc.Write([]byte("pong"))
	}()
	if n, err := c.Write([]byte("hello")); n != 5 || err != nil {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "pong" {
		t.Fatalf("Read: %q %v", buf, err)
	}
}
