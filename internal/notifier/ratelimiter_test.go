package notifier

import (
	"testing"
	"time"
)

func TestRateLimiter_Allow(t *testing.T) {
	// Create a rate limiter allowing 60 per minute (1 per second)
	limiter := NewRateLimiter(60)

	// Should allow initial requests up to the limit
	for i := 0; i < 60; i++ {
		if !limiter.Allow() {
			t.Errorf("Request %d should be allowed", i)
		}
	}

	// Next request should be blocked
	if limiter.Allow() {
		t.Error("Request should be blocked after exhausting tokens")
	}
}

func TestRateLimiter_Refill(t *testing.T) {
	// Create a rate limiter allowing 600 per minute (10 per second)
	// This means 100ms = 1 token refilled
	limiter := NewRateLimiter(600)

	// Exhaust all tokens
	for i := 0; i < 600; i++ {
		limiter.Allow()
	}

	// Wait for refill - 150ms should give ~1.5 tokens at 10 tokens/sec
	time.Sleep(150 * time.Millisecond)

	// Should have at least 1 token now
	if !limiter.Allow() {
		t.Error("Request should be allowed after refill time")
	}
}

func TestRateLimiter_Stats(t *testing.T) {
	limiter := NewRateLimiter(10)

	// Allow some requests
	limiter.Allow()
	limiter.Allow()

	stats := limiter.Stats()
	if stats.Allowed != 2 {
		t.Errorf("Allowed = %d, want 2", stats.Allowed)
	}
	if stats.Blocked != 0 {
		t.Errorf("Blocked = %d, want 0", stats.Blocked)
	}
}

func TestRateLimiter_Reset(t *testing.T) {
	limiter := NewRateLimiter(5)

	// Exhaust tokens
	for i := 0; i < 5; i++ {
		limiter.Allow()
	}

	// Reset
	limiter.Reset()

	stats := limiter.Stats()
	if stats.Allowed != 0 {
		t.Errorf("Allowed after reset = %d, want 0", stats.Allowed)
	}
	if stats.TokensAvailable != 5 {
		t.Errorf("TokensAvailable after reset = %f, want 5", stats.TokensAvailable)
	}
}

func TestRateLimiterRegistry(t *testing.T) {
	registry := NewRateLimiterRegistry()

	// Get or create
	limiter1 := registry.GetOrCreate("channel1", 10)
	limiter2 := registry.GetOrCreate("channel1", 20) // Should return same limiter

	if limiter1 != limiter2 {
		t.Error("GetOrCreate should return the same limiter for the same channel")
	}

	// Get
	limiter, exists := registry.Get("channel1")
	if !exists {
		t.Error("Channel should exist")
	}
	if limiter != limiter1 {
		t.Error("Get should return the same limiter")
	}

	// Remove
	registry.Remove("channel1")
	_, exists = registry.Get("channel1")
	if exists {
		t.Error("Channel should not exist after removal")
	}
}

func TestRateLimiter_UpdateRate(t *testing.T) {
	limiter := NewRateLimiter(10)

	limiter.UpdateRate(20)

	stats := limiter.Stats()
	if stats.MaxTokens != 20 {
		t.Errorf("MaxTokens after update = %f, want 20", stats.MaxTokens)
	}
}
