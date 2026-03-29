package utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

var reader = bufio.NewReader(os.Stdin)

func Prompt(label string) (string, error) {
	fmt.Println(label)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(input), nil
}

func PromptPassword(label string) (string, error) {
	fmt.Println(label)
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(passwordBytes)), nil
}
