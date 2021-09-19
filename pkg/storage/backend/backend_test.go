package backend

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
