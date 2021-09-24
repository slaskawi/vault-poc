package storage

import (
	"fmt"
	"testing"
)

func TestIsErrNotFound(t *testing.T) {
	err := fmt.Errorf("an error of some kind: %w", ErrNotFound)
	if !IsErrNotFound(err) {
		t.Fatal("expected ErrNotFound, got:", err)
	}
}

func TestCapabilities(t *testing.T) {
	cap := CapabilityDistributedLocking | CapabilityWatching
	if !cap.Has(CapabilityDistributedLocking) {
		t.Fatal("unexpected cap:", cap)
	}
	if !cap.Has(CapabilityWatching) {
		t.Fatal("unexpected cap:", cap)
	}
	if cap.Has(CapabilityNone) {
		t.Fatal("unexpected cap:", cap)
	}
}
