package nncp

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// pinginterval is per node: an HF neighbour can ping rarely (every PING costs
// a modem turn and a frame of airtime), everyone else keeps PingTimeout.
func TestPingIntervalPerNode(t *testing.T) {
	node, err := NewNodeGenerate()
	if err != nil {
		t.Fatal(err)
	}
	id := Base32Codec.EncodeToString(node.Id[:])
	exch := Base32Codec.EncodeToString(node.ExchPub[:])
	sign := Base32Codec.EncodeToString(node.SignPub[:])
	neigh := func(extra string) string {
		return `{ id: ` + id + `
			exchpub: ` + exch + `
			signpub: ` + sign + `
			` + extra + ` }`
	}
	cfgRaw := `{
		spool: /tmp/spool
		log: /tmp/log
		self: {
			id: ` + id + `
			exchpub: ` + exch + `
			exchprv: ` + Base32Codec.EncodeToString(node.ExchPrv[:]) + `
			signpub: ` + sign + `
			signprv: ` + Base32Codec.EncodeToString(node.SignPrv[:]) + `
			noiseprv: ` + Base32Codec.EncodeToString(node.NoisePrv[:]) + `
			noisepub: ` + Base32Codec.EncodeToString(node.NoisePub[:]) + `
		}
		neigh: {
			self: ` + neigh("") + `
			hf: ` + neigh("pinginterval: 300") + `
			lan: ` + neigh("") + `
		}
	}`
	cfg, err := CfgParse([]byte(cfgRaw))
	if err != nil {
		t.Fatal(err)
	}

	hf, err := NewNode("hf", cfg.Neigh["hf"])
	if err != nil {
		t.Fatal(err)
	}
	lan, err := NewNode("lan", cfg.Neigh["lan"])
	if err != nil {
		t.Fatal(err)
	}
	if hf.PingInterval != 300*time.Second {
		t.Errorf("hf PingInterval = %v, want 5m0s", hf.PingInterval)
	}
	if lan.PingInterval != PingTimeout {
		t.Errorf("lan PingInterval = %v, want the default %v", lan.PingInterval, PingTimeout)
	}

	// SP pings, and judges the peer dead, by the node's interval.
	if got := (&SPState{Node: hf}).pingInterval(); got != 300*time.Second {
		t.Errorf("SP ping interval for hf = %v, want 5m0s", got)
	}
	if got := (&SPState{Node: lan}).pingInterval(); got != PingTimeout {
		t.Errorf("SP ping interval for lan = %v, want %v", got, PingTimeout)
	}
	if got := (&SPState{}).pingInterval(); got != PingTimeout {
		t.Errorf("SP ping interval without a node = %v, want %v", got, PingTimeout)
	}

	// cfgdir round trip.
	dir := filepath.Join(t.TempDir(), "cfg")
	if err = CfgToDir(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "neigh", "lan", "pinginterval")); err == nil {
		t.Error("pinginterval saved for a node without one")
	}
	back, err := DirToCfg(dir)
	if err != nil {
		t.Fatal(err)
	}
	if p := back.Neigh["hf"].PingInterval; p == nil || *p != 300 {
		t.Error("pinginterval did not round-trip through cfgdir")
	}
	if back.Neigh["lan"].PingInterval != nil {
		t.Error("pinginterval appeared for lan after the round trip")
	}

	// Zero would mean pinging in a tight loop.
	zero := uint(0)
	bad := cfg.Neigh["hf"]
	bad.PingInterval = &zero
	if _, err = NewNode("bad", bad); err == nil {
		t.Error("pinginterval 0 accepted")
	}
}
