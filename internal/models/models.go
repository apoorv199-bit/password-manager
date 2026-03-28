package models

type VaultFile struct {
	Version           int    `json:"version"`
	KDFSalt           string `json:"kdf_salt"`
	KDFMemory         uint32 `json:"kdf_memory"`
	KDFIterations     uint32 `json:"kdf_iterations"`
	KDFParallelism    uint8  `json:"kdf_parallelism"`
	EncryptionNonce   string `json:"encryption_nonce"`
	EncryptedValutB64 string `json:"encrypted_vault_b64"`
}

type Vault struct {
	Items []VaultItem `json:"items"`
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
