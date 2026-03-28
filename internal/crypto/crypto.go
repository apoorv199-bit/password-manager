package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	KeyLength = 32 // 256-bit key
	SaltSize  = 16
	NonceSize = 12 // AES-GCM standard nonce size
)

// GenerateRandomBytes returns cryptographically secure random bytes.
func GeneraterandomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	_, err := io.ReadFull(rand.Reader, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// DeriveKey derives a secure key from the master password using Argon2id.
func DeriveKey(password string, salt []byte, memory uint32, iterations uint32, parallelism uint8) []byte {
	return argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, KeyLength)
}

// Encrypt encrypts plaintext using AES-256-GCM.
func Encrypt(key []byte, plaintext []byte) (nonce []byte, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	nonce, err = GeneraterandomBytes(gcm.NonceSize())
	if err != nil {
		return nil, nil, err
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return nonce, ciphertext, nil
}

// Decrypt decrypts AES-256-GCM ciphertext.
func Decrypt(key []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("invalid nonce size")
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("decryption failed: wrong password or corrupted vault")
	}

	return plaintext, nil
}

// EncodeB64 encodes bytes to base64 string.
func EncodeB64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// DecodeB64 decodes base64 string to bytes.
func DecodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
