// Package hash is wrapper package around argon2
// Derived from Alex Edwards's code
// @origin https://gist.github.com/alexedwards/34277fae0f48abe36822b375f0f6a621
package hash

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Errors
var (
	ErrInvalidHash         = errors.New("the encoded hash is not in the correct format")
	ErrIncompatibleVersion = errors.New("incompatible version of argon2")
)

// hash params
type params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	saltLength  uint32
	keyLength   uint32
}

var hashParam = &params{
	memory:      64 * 1024,
	iterations:  3,
	parallelism: 2,
	saltLength:  16,
	keyLength:   32,
}

// Run hashes a text with argon2 algorithm
func Run(text string) (hashed string, err error) {
	// Generate a cryptographically secure random salt
	salt, err := generateRandomBytes(hashParam.saltLength)
	if err != nil {
		return "", err
	}

	// Argon2id
	hash := argon2.IDKey(
		[]byte(text),
		salt,
		hashParam.iterations,
		hashParam.memory,
		hashParam.parallelism,
		hashParam.keyLength,
	)

	// argon2 hash representation
	hashed = fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		hashParam.memory,
		hashParam.iterations,
		hashParam.parallelism,
		base64.RawStdEncoding.EncodeToString(salt), // Base64 encode the salt
		base64.RawStdEncoding.EncodeToString(hash), // Base64 encode the hashed text
	)

	return hashed, nil
}

func generateRandomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Verify the hash with argon2 algorithm
func Verify(plaintext, hashed string) (match bool, err error) {
	// Extract the parameters
	p, salt, hash, err := decodeHash(hashed)
	if err != nil {
		return false, err
	}

	// Hash with the given parameters
	hash2 := argon2.IDKey([]byte(plaintext), salt, p.iterations, p.memory, p.parallelism, p.keyLength)

	// subtle.ConstantTimeCompare() function prevents timing attacks
	return subtle.ConstantTimeCompare(hash, hash2) == 1, nil
}

func decodeHash(hashed string) (p *params, salt, hash []byte, err error) {
	chuck := strings.Split(hashed, "$")
	if len(chuck) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(chuck[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, err
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &params{}
	_, err = fmt.Sscanf(chuck[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err = base64.RawStdEncoding.DecodeString(chuck[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.saltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(chuck[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.keyLength = uint32(len(hash))

	return p, salt, hash, nil
}

// RunFile hashes a file with sha1 algorithm
//
// Returns hex encoded string representation
func RunFile(filepath string) (string, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Get sha1 algorithm and hash the file
	hash := sha1.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	hashedBytes := hash.Sum(nil)
	hashed := hex.EncodeToString(hashedBytes)
	return hashed, nil
}

// RunSha1 hashes strings with sha1 algorithm
//
// RunSha1 can take more than one string; the order of param matters
//
// Returns hex encoded string representation
func RunSha1(str ...string) string {
	// Get sha1 algorithm and hash the file
	hash := sha1.New()
	for _, s := range str {
		io.WriteString(hash, s)
	}
	hashedBytes := hash.Sum(nil)
	hashed := hex.EncodeToString(hashedBytes)
	return hashed
}
