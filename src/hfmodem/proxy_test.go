package hfmodem

import (
	"bufio"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeTNC counts control connections to a TNC and drops each one at once.
func fakeTNC(t *testing.T) (port int, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted = new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, accepted
}

// fakeDaemon serves the proxy socket and answers every DIAL with reply.
func fakeDaemon(t *testing.T, reply string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	old := ProxySocketPath
	ProxySocketPath = path
	t.Cleanup(func() { ln.Close(); ProxySocketPath = old })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			bufio.NewReader(c).ReadString('\n')
			fmt.Fprintf(c, "%s\n", reply)
			c.Close()
		}
	}()
}

// A dial the daemon attempted and failed must not be retried directly on the
// TNC: Mercury serves one control client, and a second one next to the
// daemon's listener takes the TNC from it (bench, 25 Sep 2026: after the
// daemon's dial timed out, nncp-call opened its own control connection).
func TestNoDirectTNCAfterDaemonDialFails(t *testing.T) {
	port, accepted := fakeTNC(t)
	fakeDaemon(t, "ERR dial to PU2UIT-3 timed out")

	addr := fmt.Sprintf("mercury://127.0.0.1:%d/PU2UIT-3?mycall=PU2UIT-2&bw=2300", port)
	conn, err := NewConn(addr)
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded, want the daemon's error")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error %q, want the daemon's timeout", err)
	}
	time.Sleep(200 * time.Millisecond)
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d direct control connection(s) to the TNC after the daemon's dial failed", n)
	}
}

// Without a daemon, nncp-call still talks to the TNC itself.
func TestDirectTNCWithoutDaemon(t *testing.T) {
	port, accepted := fakeTNC(t)
	old := ProxySocketPath
	ProxySocketPath = filepath.Join(t.TempDir(), "absent.sock")
	t.Cleanup(func() { ProxySocketPath = old })

	addr := fmt.Sprintf("mercury://127.0.0.1:%d/PU2UIT-3?mycall=PU2UIT-2&bw=2300", port)
	done := make(chan error, 1)
	go func() {
		conn, err := NewConn(addr)
		if conn != nil {
			conn.Close()
		}
		done <- err
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("direct dial did not return")
	}
	if accepted.Load() == 0 {
		t.Fatal("no daemon, but nncp-call never reached the TNC")
	}
}
