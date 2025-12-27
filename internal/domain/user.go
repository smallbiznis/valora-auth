package domain

import "time"

// User represents an end user that can authenticate within an org.
type User struct {
	ID            int64
	OrgID         int64
	Email         string
	EmailVerified bool
	PasswordHash  string
	Name          string
	Phone         string
	PhoneVerified bool
	AvatarURL     string
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
