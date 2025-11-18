package domain

import "time"

// User represents an end user that can authenticate within a tenant.
type User struct {
	ID             int64
	TenantID       int64
	Email          string
	EmailVerified  bool
	PasswordHash   string
	Name           string
	Phone          string
	PhoneVerified  bool
	AvatarURL      string
	Status         string
	PictureURL     string
	Blocked        bool
	FailedAttempts int
	LockedUntil    time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}
