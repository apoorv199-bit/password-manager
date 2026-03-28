package main

import (
	"fmt"
	"os"
	"password-manager-cli/internal/utils"
	"password-manager-cli/internal/vault"
)

const vaultPath = "data/vault.json"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		return
	}

	command := os.Args[1]

	switch command {
	case "init":
		handleInit()
	case "add":
		handleAdd()
	case "list":
		handleList()
	case "get":
		handleGet()
	default:
		fmt.Println("Unknown command:", command)
		printUsage()
	}
}

func handleInit() {
	password, err := utils.PromtPassword("Set master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	confirm, err := utils.PromtPassword("Confirm master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if password != confirm {
		fmt.Println("Passwords do not match")
		return
	}

	err = vault.InitVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Vault initialized successfully")
}

func handleAdd() {
	password, err := utils.PromtPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	v, vf, key, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	site, _ := utils.Promt("Site: ")
	username, _ := utils.Promt("Username: ")
	pass, _ := utils.Promt("Password: ")
	notes, _ := utils.Promt("Notes: ")

	vault.AddItem(v, site, username, pass, notes)

	if err := vault.SaveVault(vaultPath, v, vf, key); err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Credential added successfully")
}

func handleList() {
	password, err := utils.PromtPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	v, _, _, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	items := vault.ListItems(v)
	if len(items) == 0 {
		fmt.Println("Vault is empty")
		return
	}

	fmt.Println("\nStored Credentials:")
	for i, item := range items {
		fmt.Printf("%d. %s (%s)\n", i+1, item.Site, item.Username)
	}
}

func handleGet() {
	password, err := utils.PromtPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	v, _, _, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	site, _ := utils.Promt("Enter site: ")
	item := vault.FindItemsBySite(*v, site)
	if item == nil {
		fmt.Println("No credential found")
		return
	}

	fmt.Println("\nCredential Details:")
	fmt.Println("Site     :", item.Site)
	fmt.Println("Username :", item.Username)
	fmt.Println("Password :", item.Password)
	fmt.Println("Notes    :", item.Notes)
	fmt.Println("Created  :", item.CreatedAt)
	fmt.Println("Updated  :", item.UpdatedAt)
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  go run ./cmd init   - Initialize vault")
	fmt.Println("  go run ./cmd add    - Add credential")
	fmt.Println("  go run ./cmd list   - List credentials")
	fmt.Println("  go run ./cmd get    - Get credential by site")
}
