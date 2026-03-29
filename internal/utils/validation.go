package utils

import (
	"errors"
	"unicode"
)

func ValidateMasterPassword(password string) error {
	if len(password) < 8 {
		return errors.New("master password must be at least 8 characters long")
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool

	for _, ch := range password {
		switch {
		case unicode.IsUpper(ch):
			hasUpper = true
		case unicode.IsLower(ch):
			hasLower = true
		case unicode.IsDigit(ch):
			hasDigit = true
		case unicode.IsPunct(ch) || unicode.IsSymbol(ch):
			hasSymbol = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSymbol {
		return errors.New("master password must contain uppercase, lowercase, digit, and symbol")
	}

	return nil
}
