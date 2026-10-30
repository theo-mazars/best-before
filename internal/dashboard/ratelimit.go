package dashboard

import (
	"sync"
	"time"
)

// rateLimiter is a token bucket per key: burst requests at once, then one
// every interval.
type rateLimiter struct {
	burst    float64
	interval time.Duration
	now      func() time.Time

	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// maxBuckets bounds memory; full buckets are dropped first.
const maxBuckets = 10000

func newRateLimiter(burst int, interval time.Duration, now func() time.Time) *rateLimiter {
	return &rateLimiter{burst: float64(burst), interval: interval, now: now, buckets: map[string]*bucket{}}
}

func (l *rateLimiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			l.prune(now)
			if len(l.buckets) >= maxBuckets {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens += float64(now.Sub(b.last)) / float64(l.interval)
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (l *rateLimiter) prune(now time.Time) {
	full := time.Duration(l.burst) * l.interval
	for k, b := range l.buckets {
		if now.Sub(b.last) >= full {
			delete(l.buckets, k)
		}
	}
}
