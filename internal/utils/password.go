package utils

import (
	"crypto/rand"
	"math/big"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?/|"

func GeneratePassword(length int) (string, error) {
	if length < 8 {
		length = 8
	}

	password := make([]byte, length)
	max := big.NewInt(int64(len(charset)))

	for i := range password {
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		password[i] = charset[n.Int64()]
	}
	return string(password), nil
}
