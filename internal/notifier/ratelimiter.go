package notifier

import (
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	mu sync.Mutex

	// tokens is the current number of available tokens
	tokens float64

	// maxTokens is the maximum number of tokens (bucket size)
	maxTokens float64

	// refillRate is the number of tokens added per second
	refillRate float64

	// lastRefill is the last time tokens were refilled
	lastRefill time.Time

	// blocked counts how many requests were blocked
	blocked int64

	// allowed counts how many requests were allowed
	allowed int64
}

// NewRateLimiter creates a new rate limiter with the specified rate per minute
func NewRateLimiter(ratePerMinute int) *RateLimiter {
	if ratePerMinute <= 0 {
		ratePerMinute = 10 // default to 10 per minute
	}

	maxTokens := float64(ratePerMinute)
	refillRate := float64(ratePerMinute) / 60.0 // tokens per second

	return &RateLimiter{
		tokens:     maxTokens,
		maxTokens:  maxTokens,
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Allow checks if a request should be allowed and consumes a token if so
func (r *RateLimiter) Allow() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.refill()

	if r.tokens >= 1 {
		r.tokens--
		r.allowed++
		return true
	}

	r.blocked++
	return false
}

// refill adds tokens based on elapsed time
func (r *RateLimiter) refill() {
	now := time.Now()
	elapsed := now.Sub(r.lastRefill).Seconds()
	r.lastRefill = now

	r.tokens += elapsed * r.refillRate
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
}

// Stats returns rate limiter statistics
func (r *RateLimiter) Stats() RateLimiterStats {
	r.mu.Lock()
	defer r.mu.Unlock()

	return RateLimiterStats{
		TokensAvailable: r.tokens,
		MaxTokens:       r.maxTokens,
		Allowed:         r.allowed,
		Blocked:         r.blocked,
	}
}

// Reset resets the rate limiter to full capacity
func (r *RateLimiter) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.tokens = r.maxTokens
	r.lastRefill = time.Now()
	r.allowed = 0
	r.blocked = 0
}

// UpdateRate updates the rate limit
func (r *RateLimiter) UpdateRate(ratePerMinute int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if ratePerMinute <= 0 {
		ratePerMinute = 10
	}

	r.maxTokens = float64(ratePerMinute)
	r.refillRate = float64(ratePerMinute) / 60.0

	// Don't exceed new max
	if r.tokens > r.maxTokens {
		r.tokens = r.maxTokens
	}
}

// RateLimiterStats holds statistics about the rate limiter
type RateLimiterStats struct {
	// TokensAvailable is the current number of available tokens
	TokensAvailable float64

	// MaxTokens is the maximum token capacity
	MaxTokens float64

	// Allowed is the number of requests that were allowed
	Allowed int64

	// Blocked is the number of requests that were blocked
	Blocked int64
}

// RateLimiterRegistry manages multiple rate limiters by channel name
type RateLimiterRegistry struct {
	mu       sync.RWMutex
	limiters map[string]*RateLimiter
}

// NewRateLimiterRegistry creates a new registry
func NewRateLimiterRegistry() *RateLimiterRegistry {
	return &RateLimiterRegistry{
		limiters: make(map[string]*RateLimiter),
	}
}

// GetOrCreate returns an existing rate limiter or creates a new one
func (r *RateLimiterRegistry) GetOrCreate(channelName string, ratePerMinute int) *RateLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()

	if limiter, exists := r.limiters[channelName]; exists {
		return limiter
	}

	limiter := NewRateLimiter(ratePerMinute)
	r.limiters[channelName] = limiter
	return limiter
}

// Get returns a rate limiter if it exists
func (r *RateLimiterRegistry) Get(channelName string) (*RateLimiter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	limiter, exists := r.limiters[channelName]
	return limiter, exists
}

// Remove removes a rate limiter
func (r *RateLimiterRegistry) Remove(channelName string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.limiters, channelName)
}

// Update updates or creates a rate limiter with new settings
func (r *RateLimiterRegistry) Update(channelName string, ratePerMinute int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if limiter, exists := r.limiters[channelName]; exists {
		limiter.UpdateRate(ratePerMinute)
	} else {
		r.limiters[channelName] = NewRateLimiter(ratePerMinute)
	}
}

// AllStats returns statistics for all rate limiters
func (r *RateLimiterRegistry) AllStats() map[string]RateLimiterStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make(map[string]RateLimiterStats)
	for name, limiter := range r.limiters {
		stats[name] = limiter.Stats()
	}
	return stats
}
