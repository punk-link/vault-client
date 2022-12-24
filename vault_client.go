package vaultClient

type VaultClient interface {
	Get(token string, engineName string, secretName string) map[string]any
}
