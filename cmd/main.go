package main

import (
	"fmt"
	"os"
	"password-manager-cli/internal/utils"
	"password-manager-cli/internal/vault"
	"strconv"
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
	case "search":
		handleSearch()
	case "update":
		handleUpdate()
	case "delete":
		handleDelete()
	case "generate-password":
		handleGeneratePassword()
	case "change-master-password":
		handleChangeMasterPassword()
	default:
		fmt.Println("Unknown command:", command)
		printUsage()
	}
}

func handleInit() {
	password, err := utils.PromptPassword("Set master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	confirm, err := utils.PromptPassword("Confirm master password: ")
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
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	v, vf, key, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	site, _ := utils.Prompt("Site: ")
	username, _ := utils.Prompt("Username: ")
	pass, _ := utils.Prompt("Password: ")
	notes, _ := utils.Prompt("Notes: ")

	vault.AddItem(v, site, username, pass, notes)

	if err := vault.SaveVault(vaultPath, v, vf, key); err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Credential added successfully")
}

func handleList() {
	password, err := utils.PromptPassword("Enter master password: ")
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
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	v, _, _, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	site, _ := utils.Prompt("Enter site: ")
	item := vault.FindItemsBySite(v, site)
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

func handleSearch() {
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	v, _, _, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	query, _ := utils.Prompt("Search query: ")
	results := vault.SearchItems(v, query)

	if len(results) == 0 {
		fmt.Println("No matching credentials found")
		return
	}

	fmt.Println("\nSearch Results:")
	for i, item := range results {
		fmt.Printf("%d. %s (%s)\n", i+1, item.Site, item.Username)
	}
}

func handleUpdate() {
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	v, vf, key, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	site, _ := utils.Prompt("Enter site to update: ")
	item := vault.FindItemsBySite(v, site)
	if item == nil {
		fmt.Println("No credential found")
		return
	}

	username, _ := utils.Prompt("New username: ")
	pass, _ := utils.Prompt("New password: ")
	notes, _ := utils.Prompt("New notes: ")

	if ok := vault.UpdateItem(v, site, username, pass, notes); !ok {
		fmt.Println("Update failed")
		return
	}

	if err := vault.SaveVault(vaultPath, v, vf, key); err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Credential updated successfully")
}

func handleDelete() {
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	v, vf, key, err := vault.LoadVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	site, _ := utils.Prompt("Enter site to delete: ")
	if ok := vault.DeleteItem(v, site); !ok {
		fmt.Println("No credential found for site:", site)
		return
	}

	if err := vault.SaveVault(vaultPath, v, vf, key); err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Credential deleted successfully")
}

func handleGeneratePassword() {
	lengthStr, _ := utils.Prompt("Password length (default 8): ")
	length := 8

	if lengthStr != "" {
		if parsed, err := strconv.Atoi(lengthStr); err == nil {
			length = parsed
		}
	}

	password, err := utils.GeneratePassword(length)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Generated Password:", password)
}

func handleChangeMasterPassword() {
	oldPassword, err := utils.PromptPassword("Enter current master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	v, _, _, err := vault.LoadVault(vaultPath, oldPassword)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	newPassword, err := utils.PromptPassword("Enter new master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if err := utils.ValidateMasterPassword(newPassword); err != nil {
		fmt.Println("Weak master password:", err)
		return
	}

	confirm, err := utils.PromptPassword("Confirm new master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if newPassword != confirm {
		fmt.Println("Passwords do not match")
		return
	}

	if err := vault.ChangeMasterPassword(vaultPath, v, newPassword); err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Master password changed successfully")
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  go run ./cmd init                    - Initialize vault")
	fmt.Println("  go run ./cmd add                     - Add credential")
	fmt.Println("  go run ./cmd list                    - List credentials")
	fmt.Println("  go run ./cmd get                     - Get credential by site")
	fmt.Println("  go run ./cmd search                  - Search credentials")
	fmt.Println("  go run ./cmd update                  - Update credential")
	fmt.Println("  go run ./cmd delete                  - Delete credential")
	fmt.Println("  go run ./cmd generate-password       - Generate secure password")
	fmt.Println("  go run ./cmd change-master-password  - Change master password")
}
