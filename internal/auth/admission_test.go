package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionBoundedAndExpires(t *testing.T) {
	a := NewAdmission(2)
	now := time.Now()
	a.now = func() time.Time { return now }
	if !a.Allow("account", "a", 2) || !a.Allow("account", "a", 2) || a.Allow("account", "a", 2) {
		t.Fatal("rate limit")
	}
	if !a.Allow("account", "b", 2) || a.Allow("account", "c", 2) {
		t.Fatal("storage limit bypassed")
	}
	now = now.Add(time.Minute)
	if !a.Allow("account", "c", 2) {
		t.Fatal("expired keys not recovered")
	}
}

func TestAdmissionConcurrent(t *testing.T) {
	a := NewAdmission(10)
	var allowed atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Go(func() {
			if a.Allow("account", "same", 10) {
				allowed.Add(1)
			}
		})
	}
	wg.Wait()
	if allowed.Load() != 10 {
		t.Fatal(allowed.Load())
	}
}
