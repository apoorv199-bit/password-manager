package models

type KDFParams struct {
	Salt        string `json:"salt"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
}

type EncryptedItem struct {
	ID         string `json:"id"`
	Site       string `json:"site"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type VaultFile struct {
	Version         int             `json:"version"`
	KDF             KDFParams       `json:"kdf"`
	WrappedVaultKey string          `json:"wrapped_vault_key"`
	VaultKeyNonce   string          `json:"vault_key_nonce"`
	Items           []EncryptedItem `json:"items"`
}

type VaultItem struct {
	ID        string `json:"id"`
	Site      string `json:"site"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	Notes     string `json:"notes"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}
