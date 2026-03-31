package vault

import (
	"encoding/json"
	"errors"
	"os"
	"password-manager-cli/internal/crypto"
	"password-manager-cli/internal/models"
	"strings"
	"time"
)

const (
	DefaultKDFMemory      = 19 * 1024 // 19 MiB
	DefaultKDFIterations  = 2
	DefaultKDFParallelism = 1
)

func InitVault(filePath string, masterPassword string) error {
	_, err := os.Stat(filePath)
	if err == nil {
		return errors.New("vault already exists")
	}

	// Generate salt for Argon2id
	salt, err := crypto.GeneraterandomBytes(crypto.SaltSize)
	if err != nil {
		return err
	}

	// Derive Master Unlock Key (MUK - master unlock key)
	muk := crypto.DeriveKey(masterPassword, salt, DefaultKDFMemory, DefaultKDFIterations, DefaultKDFParallelism)

	// Generate Random Vault Key
	vaultKey, err := crypto.GeneraterandomBytes(32)
	if err != nil {
		return err
	}

	// Wrap (encrypt) Vault Key using MUK
	nonce, wrappedVK, err := crypto.Encrypt(muk, vaultKey)
	if err != nil {
		return err
	}

	vaultFile := models.VaultFile{
		Version: 2,
		KDF: models.KDFParams{
			Salt:        crypto.EncodeB64(salt),
			Memory:      DefaultKDFMemory,
			Iterations:  DefaultKDFIterations,
			Parallelism: DefaultKDFParallelism,
		},
		WrappedVaultKey: crypto.EncodeB64(wrappedVK),
		VaultKeyNonce:   crypto.EncodeB64(nonce),
		Items:           []models.EncryptedItem{},
	}

	return writeVaultFile(filePath, vaultFile)
}

// UnlockVault unlocks the vault by:
// - deriving MUK from password
// - decrypting wrapped Vault Key
func UnlockVault(filePath, password string) ([]byte, *models.VaultFile, error) {
	vf, err := readVaultFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	salt, err := crypto.DecodeB64(vf.KDF.Salt)
	if err != nil {
		return nil, nil, err
	}

	muk := crypto.DeriveKey(password, salt, vf.KDF.Memory, vf.KDF.Iterations, vf.KDF.Parallelism)

	nonce, err := crypto.DecodeB64(vf.VaultKeyNonce)
	if err != nil {
		return nil, nil, err
	}

	wrappedVK, err := crypto.DecodeB64(vf.WrappedVaultKey)
	if err != nil {
		return nil, nil, err
	}

	vaultKey, err := crypto.Decrypt(muk, nonce, wrappedVK)
	if err != nil {
		return nil, nil, err
	}

	return vaultKey, vf, nil
}

// SaveVault persists the current vault file to disk.
func SaveVault(filePath string, vf *models.VaultFile) error {
	return writeVaultFile(filePath, *vf)
}

// ChangeMasterPassword changes the master password by:
// - unlocking current Vault Key using old password
// - deriving a new MUK from new password
// - re-wrapping the same Vault Key
func ChangeMasterPassword(filePath string, oldPassword, newPassword string) error {
	vaultKey, vf, err := UnlockVault(filePath, oldPassword)
	if err != nil {
		return err
	}

	newSalt, err := crypto.GeneraterandomBytes(crypto.SaltSize)
	if err != nil {
		return err
	}

	newMUK := crypto.DeriveKey(newPassword, newSalt, DefaultKDFMemory, DefaultKDFIterations, DefaultKDFParallelism)

	newNonce, newWrappedVK, err := crypto.Encrypt(newMUK, vaultKey)
	if err != nil {
		return err
	}

	vf.KDF.Salt = crypto.EncodeB64(newSalt)
	vf.WrappedVaultKey = crypto.EncodeB64(newWrappedVK)
	vf.VaultKeyNonce = crypto.EncodeB64(newNonce)

	return writeVaultFile(filePath, *vf)
}

// EncryptItem encrypts a plaintext VaultItem into an EncryptedItem using Vault Key.
func EncryptItem(item models.VaultItem, vaultKey []byte) (*models.EncryptedItem, error) {
	plaintext, err := json.Marshal(item)
	if err != nil {
		return nil, err
	}

	nonce, ciphertext, err := crypto.Encrypt(vaultKey, plaintext)
	if err != nil {
		return nil, err
	}

	return &models.EncryptedItem{
		ID:         item.ID,
		Site:       item.Site,
		Nonce:      crypto.EncodeB64(nonce),
		Ciphertext: crypto.EncodeB64(ciphertext),
	}, nil
}

// DecryptItem decrypts one EncryptedItem into its plaintext VaultItem.
func DecryptItem(enc models.EncryptedItem, vaultKey []byte) (*models.VaultItem, error) {
	nonce, err := crypto.DecodeB64(enc.Nonce)
	if err != nil {
		return nil, err
	}

	ciphertext, err := crypto.DecodeB64(enc.Ciphertext)
	if err != nil {
		return nil, err
	}

	plaintext, err := crypto.Decrypt(vaultKey, nonce, ciphertext)
	if err != nil {
		return nil, err
	}

	var vaultItem models.VaultItem
	if err := json.Unmarshal(plaintext, &vaultItem); err != nil {
		return nil, err
	}

	return &vaultItem, nil
}

// DecryptAllItems decrypts all vault items.
func DecryptAllItems(vf *models.VaultFile, vaultKey []byte) ([]models.VaultItem, error) {
	var items []models.VaultItem

	for _, encItem := range vf.Items {
		item, err := DecryptItem(encItem, vaultKey)
		if err != nil {
			return nil, err
		}
		items = append(items, *item)
	}
	return items, nil
}

// AddItem adds a new encrypted item to the vault.
func AddItem(vf *models.VaultFile, vaultKey []byte, item models.VaultItem) error {
	encItem, err := EncryptItem(item, vaultKey)
	if err != nil {
		return err
	}

	vf.Items = append(vf.Items, *encItem)
	return nil
}

// ListItems returns encrypted items (metadata visible, secrets still encrypted).
// Useful for showing site list without decrypting secrets.
func ListItems(vf *models.VaultFile) []models.EncryptedItem {
	return vf.Items
}

// SearchItems searches by plaintext metadata only (currently site).
func SearchItems(vf *models.VaultFile, query string) []models.EncryptedItem {
	query = strings.ToLower(query)
	var results []models.EncryptedItem

	for _, item := range vf.Items {
		if strings.Contains(strings.ToLower(item.Site), query) {
			results = append(results, item)
		}
	}
	return results
}

// FindEncryptedItemByID returns the encrypted record by ID.
func FindEncryptedItemByID(vf *models.VaultFile, id string) *models.EncryptedItem {
	for i := range vf.Items {
		if vf.Items[i].ID == id {
			return &vf.Items[i]
		}
	}
	return nil
}

// FindEncryptedItemsBySite returns all encrypted items for a site.
func FindEncryptedItemsBySite(vf *models.VaultFile, site string) []models.EncryptedItem {
	var results []models.EncryptedItem
	for _, item := range vf.Items {
		if strings.EqualFold(item.Site, site) {
			results = append(results, item)
		}
	}
	return results
}

// GetFullItemByID returns the fully decrypted VaultItem by ID.
func GetFullItemByID(vf *models.VaultFile, vaultKey []byte, id string) (*models.VaultItem, error) {
	for _, item := range vf.Items {
		if item.ID == id {
			return DecryptItem(item, vaultKey)
		}
	}
	return nil, nil
}

// UpdateItemByID updates one item by:
// - locating encrypted record
// - decrypting only that item
// - modifying plaintext
// - re-encrypting only that item
func UpdateItemByID(vf *models.VaultFile, vaultKey []byte, id, username, password, notes string) (bool, error) {
	for i := range vf.Items {
		if vf.Items[i].ID == id {
			vaultItem, err := DecryptItem(vf.Items[i], vaultKey)
			if err != nil {
				return false, err
			}

			vaultItem.Username = username
			vaultItem.Password = password
			vaultItem.Notes = notes
			vaultItem.UpdatedAt = time.Now().Format(time.RFC3339)

			updatedEnc, err := EncryptItem(*vaultItem, vaultKey)
			if err != nil {
				return false, err
			}

			vf.Items[i] = *updatedEnc

			return true, nil
		}
	}
	return false, nil
}

// DeleteItemByID deletes an item by ID without needing decryption.
func DeleteItemByID(vf *models.VaultFile, id string) bool {
	for i := range vf.Items {
		if vf.Items[i].ID == id {
			vf.Items = append(vf.Items[:i], vf.Items[i+1:]...)
			return true
		}
	}
	return false
}

// GenerateItem creates a new VaultItem with timestamps and ID.
func GenerateItem(site, username, password, notes string) models.VaultItem {
	now := time.Now().Format(time.RFC3339)

	return models.VaultItem{
		ID:        generateID(),
		Site:      site,
		Username:  username,
		Password:  password,
		Notes:     notes,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func generateID() string {
	b, _ := crypto.GeneraterandomBytes(8)
	return crypto.EncodeB64(b)
}

func writeVaultFile(filePath string, vaultFile models.VaultFile) error {
	data, err := json.MarshalIndent(vaultFile, "", " ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

func readVaultFile(filePath string) (*models.VaultFile, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var vaultFile models.VaultFile
	if err := json.Unmarshal(data, &vaultFile); err != nil {
		return nil, err
	}

	return &vaultFile, nil
}
