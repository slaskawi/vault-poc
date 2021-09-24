package auth

import (
	"fmt"
	"time"
)

const (
	TokenDefaultTTL        = time.Hour
	TokenLength            = 20
	authPrefix             = ".auth/"
	authTokensPrefix       = authPrefix + "tokens/"
	tokenIDPrefix          = "kt"
	tokenReferenceIDPrefix = "kr"
)

var (
	ErrTokenInvalid      = fmt.Errorf("invalid token")
	ErrTokenNotFound     = fmt.Errorf("token not found or expired")
	ErrTokenNotActiveYet = fmt.Errorf("token not allowed to be used yet")
	ErrForbidden         = fmt.Errorf("no permission to peform this action")
)

// AuthBackend interface.
type AuthBackend interface {
	// Initialize is called when the barrier is first initialized.
	Initialize() error

	// Name is used in the key path for the backend's storage.
	Name() string
}
