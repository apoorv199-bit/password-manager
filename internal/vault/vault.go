package vault

import (
	"encoding/json"
	"errors"
	"os"
	"password-manager-cli/internal/crypto"
	"password-manager-cli/internal/models"
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

	salt, err := crypto.GeneraterandomBytes(crypto.SaltSize)
	if err != nil {
		return err
	}

	key := crypto.DeriveKey(masterPassword, salt, DefaultKDFMemory, DefaultKDFIterations, DefaultKDFParallelism)

	emptyVault := models.Vault{
		Items: []models.VaultItem{},
	}

	plaintext, err := json.Marshal(emptyVault)
	if err != nil {
		return err
	}

	nonce, ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return err
	}

	vaultFile := models.VaultFile{
		Version:           1,
		KDFSalt:           crypto.EncodeB64(salt),
		KDFMemory:         DefaultKDFMemory,
		KDFIterations:     DefaultKDFIterations,
		KDFParallelism:    DefaultKDFParallelism,
		EncryptionNonce:   crypto.EncodeB64(nonce),
		EncryptedValutB64: crypto.EncodeB64(ciphertext),
	}

	return writeVaultFile(filePath, vaultFile)
}

func LoadVault(filepath string, masterPassword string) (*models.Vault, *models.VaultFile, []byte, error) {
	vaultFile, err := readVaultFile(filepath)
	if err != nil {
		return nil, nil, nil, err
	}

	salt, err := crypto.DecodeB64(vaultFile.KDFSalt)
	if err != nil {
		return nil, nil, nil, err
	}

	nonce, err := crypto.DecodeB64(vaultFile.EncryptionNonce)
	if err != nil {
		return nil, nil, nil, err
	}

	ciphertext, err := crypto.DecodeB64(vaultFile.EncryptedValutB64)
	if err != nil {
		return nil, nil, nil, err
	}

	key := crypto.DeriveKey(masterPassword, salt, DefaultKDFMemory, DefaultKDFIterations, DefaultKDFParallelism)

	plaintext, err := crypto.Decrypt(key, nonce, ciphertext)
	if err != nil {
		return nil, nil, nil, err
	}

	var vault models.Vault
	if err := json.Unmarshal(plaintext, &vault); err != nil {
		return nil, nil, nil, err
	}

	return &vault, vaultFile, key, nil
}

func SaveVault(filePath string, vault *models.Vault, vaultFile *models.VaultFile, key []byte) error {
	plaintext, err := json.Marshal(vault)
	if err != nil {
		return err
	}

	nonce, ciphertext, err := crypto.Encrypt(key, plaintext)
	if err != nil {
		return err
	}

	vaultFile.EncryptionNonce = crypto.EncodeB64(nonce)
	vaultFile.EncryptedValutB64 = crypto.EncodeB64(ciphertext)

	return writeVaultFile(filePath, *vaultFile)
}

func AddItem(vault *models.Vault, site, username, password, notes string) {
	now := time.Now().Format(time.RFC3339)

	item := models.VaultItem{
		ID:        generateID(),
		Site:      site,
		Username:  username,
		Password:  password,
		Notes:     notes,
		CreatedAt: now,
		UpdatedAt: now,
	}

	vault.Items = append(vault.Items, item)
}

func FindItemsBySite(vault models.Vault, site string) *models.VaultItem {
	for i := range vault.Items {
		if vault.Items[i].Site == site {
			return &vault.Items[i]
		}
	}
	return nil
}

func ListItems(vault *models.Vault) []models.VaultItem {
	return vault.Items
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
