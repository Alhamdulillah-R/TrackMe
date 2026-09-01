package server

import (
	"testing"
	"time"

	"github.com/pagpeter/trackme/pkg/types"
)

func TestTCPSynStoragePreservesFirstPacket(t *testing.T) {
	srv := NewServer()
	first := types.TCPSynDetails{TTL: 47}
	second := types.TCPSynDetails{TTL: 46}

	srv.StoreTCPSyn("192.0.2.1:54321", first, "first")
	srv.StoreTCPSyn("192.0.2.1:54321", second, "second")

	details, p0f, ok := srv.TakeTCPSyn("192.0.2.1:54321")
	if !ok {
		t.Fatal("stored SYN was not returned")
	}
	if details.TTL != first.TTL || p0f != "first" {
		t.Fatalf("got details=%+v p0f=%q, want first SYN", details, p0f)
	}
	if _, _, ok := srv.TakeTCPSyn("192.0.2.1:54321"); ok {
		t.Fatal("SYN was not removed after being claimed")
	}
}

func TestPruneTCPSyn(t *testing.T) {
	srv := NewServer()
	srv.StoreTCPSyn("192.0.2.1:54321", types.TCPSynDetails{}, "raw")
	srv.PruneTCPSyn(time.Now().Add(time.Second))

	if _, _, ok := srv.TakeTCPSyn("192.0.2.1:54321"); ok {
		t.Fatal("expired SYN was not pruned")
	}
}

func TestTCPSynStorageIsBounded(t *testing.T) {
	srv := newServerWithTCPSynLimits(2, time.Minute)

	srv.StoreTCPSyn("192.0.2.1:1", types.TCPSynDetails{}, "first")
	srv.StoreTCPSyn("192.0.2.1:2", types.TCPSynDetails{}, "second")
	srv.StoreTCPSyn("192.0.2.1:3", types.TCPSynDetails{}, "third")

	if _, _, ok := srv.TakeTCPSyn("192.0.2.1:3"); ok {
		t.Fatal("stored a SYN after reaching the cache limit")
	}
	if _, _, ok := srv.TakeTCPSyn("192.0.2.1:1"); !ok {
		t.Fatal("cache limit displaced an existing SYN")
	}
}

func TestTCPSynStorageExpires(t *testing.T) {
	srv := newServerWithTCPSynLimits(1, time.Millisecond)
	srv.StoreTCPSyn("192.0.2.1:54321", types.TCPSynDetails{}, "raw")

	time.Sleep(10 * time.Millisecond)
	if _, _, ok := srv.TakeTCPSyn("192.0.2.1:54321"); ok {
		t.Fatal("expired SYN was returned")
	}

	srv.StoreTCPSyn("192.0.2.1:54322", types.TCPSynDetails{}, "new")
	if _, _, ok := srv.TakeTCPSyn("192.0.2.1:54322"); !ok {
		t.Fatal("expired SYN did not release its cache slot")
	}
}
