package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"sync"
	"time"
)

type bucket struct {
	start time.Time
	count int
}

// Admission bounds both request rate and key storage. Full key storage rejects
// new keys rather than evicting active limits. Each replica owns its budget.
type Admission struct {
	mu      sync.Mutex
	key     [32]byte
	buckets map[[32]byte]bucket
	maxKeys int
	now     func() time.Time
}

func NewAdmission(maxKeys int) *Admission {
	a := &Admission{buckets: make(map[[32]byte]bucket), maxKeys: maxKeys, now: time.Now}
	if _, err := rand.Read(a.key[:]); err != nil {
		panic("cannot initialize admission key")
	}
	return a
}

func (a *Admission) Allow(kind, value string, limit int) bool {
	m := hmac.New(sha256.New, a.key[:])
	m.Write([]byte(kind))
	m.Write([]byte{0})
	m.Write([]byte(value))
	var key [32]byte
	copy(key[:], m.Sum(nil))
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	b, exists := a.buckets[key]
	if !exists && len(a.buckets) >= a.maxKeys {
		for k, v := range a.buckets {
			if now.Sub(v.start) >= time.Minute {
				delete(a.buckets, k)
			}
		}
		if len(a.buckets) >= a.maxKeys {
			return false
		}
	}
	if b.start.IsZero() || now.Sub(b.start) >= time.Minute {
		b = bucket{start: now}
	}
	if b.count >= limit {
		return false
	}
	b.count++
	a.buckets[key] = b
	return true
}
