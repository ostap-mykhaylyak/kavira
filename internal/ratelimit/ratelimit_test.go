package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenDeny(t *testing.T) {
	l := New(3, time.Minute)
	for i := 0; i < 3; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatalf("call %d: want allowed within burst", i)
		}
	}
	if l.Allow("1.2.3.4") {
		t.Fatal("want denied after burst")
	}
	if !l.Allow("5.6.7.8") {
		t.Fatal("other key must have its own bucket")
	}
}

func TestRefillOverTime(t *testing.T) {
	now := time.Unix(0, 0)
	l := New(60, time.Minute) // 1 token/second
	l.now = func() time.Time { return now }

	for i := 0; i < 60; i++ {
		l.Allow("ip")
	}
	if l.Allow("ip") {
		t.Fatal("bucket should be empty")
	}
	now = now.Add(2 * time.Second)
	if !l.Allow("ip") || !l.Allow("ip") {
		t.Fatal("2s at 1 token/s should allow 2 more")
	}
	if l.Allow("ip") {
		t.Fatal("third call should be denied again")
	}
}

func TestNilInboundAllowsEverything(t *testing.T) {
	var i *Inbound
	if !i.ConnAllowed("x") || !i.MsgAllowed("x") || !i.RcptAllowed("x") {
		t.Fatal("nil Inbound must allow everything")
	}
}
