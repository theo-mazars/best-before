package vulns

import (
	"testing"
	"time"
)

// Pages ask for the status while matching runs, for minutes on a large
// report, and while a reload waits for it: the status must not wait.
func TestStatusDoesNotWaitForMatching(t *testing.T) {
	db := &DB{}
	db.mu.RLock() // a match in progress
	defer db.mu.RUnlock()
	go func() { db.mu.Lock(); db.mu.Unlock() }() // a reload waiting for it
	time.Sleep(10 * time.Millisecond)

	done := make(chan struct{})
	go func() { db.Status(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Status waited for matching")
	}
}
