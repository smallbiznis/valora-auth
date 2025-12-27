package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	hashTime    uint32 = 3
	hashMemory  uint32 = 64 * 1024
	hashThreads uint8  = 2
	hashKeyLen  uint32 = 32
	hashSaltLen        = 16
)

var errInvalidHash = errors.New("invalid password hash")

// Hash returns an argon2id hash string including parameters and salt.
func Hash(password string) (string, error) {
	salt := make([]byte, hashSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	sum := argon2.IDKey([]byte(password), salt, hashTime, hashMemory, hashThreads, hashKeyLen)
	encodedSalt := base64.RawStdEncoding.EncodeToString(salt)
	encodedHash := base64.RawStdEncoding.EncodeToString(sum)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		hashMemory,
		hashTime,
		hashThreads,
		encodedSalt,
		encodedHash,
	), nil
}

// Verify checks a password against the encoded argon2id hash.
func Verify(password, hash string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errInvalidHash
	}

	version, err := parseVersion(parts[2])
	if err != nil || version != argon2.Version {
		return false, errInvalidHash
	}

	mem, timeCost, threads, err := parseParams(parts[3])
	if err != nil {
		return false, errInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, errInvalidHash
	}

	expected, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, errInvalidHash
	}

	actual := argon2.IDKey([]byte(password), salt, timeCost, mem, threads, uint32(len(expected)))
	return subtle.ConstantTimeCompare(actual, expected) == 1, nil
}

func parseVersion(value string) (int, error) {
	if !strings.HasPrefix(value, "v=") {
		return 0, errInvalidHash
	}
	return strconv.Atoi(strings.TrimPrefix(value, "v="))
}

func parseParams(value string) (uint32, uint32, uint8, error) {
	parts := strings.Split(value, ",")
	if len(parts) != 3 {
		return 0, 0, 0, errInvalidHash
	}

	mem, err := parseUint32Param(parts[0], "m=")
	if err != nil {
		return 0, 0, 0, errInvalidHash
	}
	timeCost, err := parseUint32Param(parts[1], "t=")
	if err != nil {
		return 0, 0, 0, errInvalidHash
	}
	threadsVal, err := parseUint32Param(parts[2], "p=")
	if err != nil || threadsVal > 255 {
		return 0, 0, 0, errInvalidHash
	}
	return mem, timeCost, uint8(threadsVal), nil
}

func parseUint32Param(value, prefix string) (uint32, error) {
	if !strings.HasPrefix(value, prefix) {
		return 0, errInvalidHash
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, prefix), 10, 32)
	if err != nil {
		return 0, errInvalidHash
	}
	return uint32(parsed), nil
}
