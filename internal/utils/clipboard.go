package utils

import (
	"fmt"
	"time"

	"github.com/atotto/clipboard"
)

// CopyToClipboard copies text and optionally clears it after timeout.
func CopyToClipboard(text string, clearAfter time.Duration) error {
	if err := clipboard.WriteAll(text); err != nil {
		return err
	}

	fmt.Println("Copied to clipboard.")

	if clearAfter > 0 {
		go func(expected string) {
			time.Sleep(clearAfter)

			current, err := clipboard.ReadAll()
			if err == nil && current == expected {
				clipboard.WriteAll("")
				fmt.Println("Clipboard cleared.")
			}
		}(text)
	}

	return nil
}
