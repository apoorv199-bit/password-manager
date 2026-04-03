package main

import (
	"fmt"
	"os"
	"password-manager-cli/internal/utils"
	"password-manager-cli/internal/vault"
	"strconv"
	"time"
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
	case "copy-password":
		handleCopyPassword()
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

	if err := utils.ValidateMasterPassword(password); err != nil {
		fmt.Println("Weak master password:", err)
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

	vaultKey, vf, err := vault.UnlockVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	site, _ := utils.Prompt("Site: ")
	username, _ := utils.Prompt("Username: ")

	pass, _ := utils.Prompt("Password (leave blank to auto-generate): ")
	if pass == "" {
		pass, err = utils.GeneratePassword(12)
		if err != nil {
			fmt.Println("Error generating password:", err)
			return
		}
		fmt.Println("Generated Password:", pass)
	}

	notes, _ := utils.Prompt("Notes: ")

	item := vault.GenerateItem(site, username, pass, notes)

	if err = vault.AddItem(vf, vaultKey, item); err != nil {
		fmt.Println("Error:", err)
		return
	}

	if err := vault.SaveVault(vaultPath, vf); err != nil {
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

	vaultKey, vf, err := vault.UnlockVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	items := vault.ListItems(vf)
	if len(items) == 0 {
		fmt.Println("Vault is empty")
		return
	}

	fmt.Println("\nStored Credentials:")
	for i, item := range items {
		fullItem, err := vault.DecryptItem(item, vaultKey)
		if err != nil {
			fmt.Printf("%d. [%s] %s (error decrypting)\n", i+1, item.ID, item.Site)
			continue
		}

		fmt.Printf("%d. [%s] %s (%s)\n", i+1, item.ID, item.Site, fullItem.Username)
	}
}

func handleGet() {
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	vaultKey, vf, err := vault.UnlockVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	id, _ := utils.Prompt("Enter credential ID: ")
	item, err := vault.GetFullItemByID(vf, vaultKey, id)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if item == nil {
		fmt.Println("No credential found")
		return
	}

	fmt.Println("\nCredential Details:")
	fmt.Println("Site     :", item.Site)
	fmt.Println("Username :", item.Username)
	fmt.Println("Notes    :", item.Notes)
	fmt.Println("Created  :", item.CreatedAt)
	fmt.Println("Updated  :", item.UpdatedAt)

	reveal, _ := utils.Prompt("Reveal password? (y/N): ")
	if reveal == "y" || reveal == "Y" {
		fmt.Println("Password: ", item.Password)
	}
}

func handleSearch() {
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	vaultKey, vf, err := vault.UnlockVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	query, _ := utils.Prompt("Search query: ")
	results := vault.SearchItems(vf, query)

	if len(results) == 0 {
		fmt.Println("No matching credentials found")
		return
	}

	fmt.Println("\nSearch Results:")
	for i, item := range results {
		fullItem, err := vault.DecryptItem(item, vaultKey)
		if err != nil {
			fmt.Printf("%d. [%s] %s (error decrypting)\n", i+1, item.ID, item.Site)
			continue
		}

		fmt.Printf("%d. [%s] %s (%s)\n", i+1, item.ID, item.Site, fullItem.Username)
	}
}

func handleUpdate() {
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	vaultKey, vf, err := vault.UnlockVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	id, _ := utils.Prompt("Enter credential ID to update: ")

	existing, err := vault.GetFullItemByID(vf, vaultKey, id)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if existing == nil {
		fmt.Println("No credential found")
		return
	}

	fmt.Println("Leave field blank to keep current value")

	username, _ := utils.Prompt(fmt.Sprintf("New username [%s]: ", existing.Username))
	pass, _ := utils.Prompt("New password [hidden]: ")
	notes, _ := utils.Prompt(fmt.Sprintf("New notes [%s]: ", existing.Notes))

	if username == "" {
		username = existing.Username
	}
	if pass == "" {
		pass = existing.Password
	}
	if notes == "" {
		notes = existing.Notes
	}

	ok, err := vault.UpdateItemByID(vf, vaultKey, id, username, pass, notes)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	if !ok {
		fmt.Println("Update failed")
		return
	}

	if err := vault.SaveVault(vaultPath, vf); err != nil {
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

	_, vf, err := vault.UnlockVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	id, _ := utils.Prompt("Enter credential ID to delete: ")

	if ok := vault.DeleteItemByID(vf, id); !ok {
		fmt.Println("No credential found for ID:", id)
		return
	}

	if err := vault.SaveVault(vaultPath, vf); err != nil {
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

	if err := vault.ChangeMasterPassword(vaultPath, oldPassword, newPassword); err != nil {
		fmt.Println("Error:", err)
		return
	}

	fmt.Println("Master password changed successfully")
}

func handleCopyPassword() {
	password, err := utils.PromptPassword("Enter master password: ")
	if err != nil {
		fmt.Println("Error: ", err)
		return
	}

	vaultKey, vf, err := vault.UnlockVault(vaultPath, password)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	id, _ := utils.Prompt("Enter credential ID: ")
	item, err := vault.GetFullItemByID(vf, vaultKey, id)
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if item == nil {
		fmt.Println("No credential found")
		return
	}

	timeoutStr, _ := utils.Prompt("Clear clipboard after (seconds, default 15): ")
	timeout := 15
	if timeoutStr != "" {
		if parsed, err := strconv.Atoi(timeoutStr); err == nil && parsed > 0 {
			timeout = parsed
		}
	}

	err = utils.CopyToClipboard(item.Password, time.Duration(timeout)*time.Second)
	if err != nil {
		fmt.Println("Error copying to clipboard:", err)
		return
	}

	fmt.Printf("Password copied for '%s' (%s). Clipboard will clear in %d seconds\n", item.Site, item.Username, timeout)

	// Keep the main function alive until clipboard is cleared
	time.Sleep(time.Duration(timeout+1) * time.Second)
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
