package vaultClient

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	vault "github.com/hashicorp/vault/api"
	auth "github.com/hashicorp/vault/api/auth/approle"
	httpClient "github.com/punk-link/http-client"
	"github.com/punk-link/logger"
	"github.com/punk-link/vault-client/models"
)

type VaultClientService struct {
	logger                    logger.Logger
	mutex                     sync.Mutex
	options                   *VaultClientOptions
	roleContainerHttpClient   httpClient.HttpClient[models.RoleContainer]
	secretContainerHttpClient httpClient.HttpClient[models.SecretContainer]
}

func New(options *VaultClientOptions, logger logger.Logger) VaultClient {
	httpConfig := httpClient.DefaultConfig(logger)
	roleContainerHttpClient := httpClient.New[models.RoleContainer](httpConfig)
	secretContainerHttpClient := httpClient.New[models.SecretContainer](httpConfig)

	return &VaultClientService{
		logger:                    logger,
		options:                   options,
		roleContainerHttpClient:   roleContainerHttpClient,
		secretContainerHttpClient: secretContainerHttpClient,
	}
}

func (t *VaultClientService) Get(token string, engineName string, secretName string) map[string]any {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	config := vault.DefaultConfig()
	config.Address = t.options.Endpoint

	vaultClient, err := vault.NewClient(config)
	if err != nil {
		t.logger.LogFatal(err, "Vault exception: %s", err.Error())
	}

	roleId := t.getRoleId(token)
	secretId := t.getSecretId(token)

	appRoleAuth, err := auth.NewAppRoleAuth(roleId, secretId)
	if err != nil {
		t.logger.LogFatal(err, "Unable to initialize AppRole auth method: %s", err.Error())
	}

	authInfo, err := vaultClient.Auth().Login(context.Background(), appRoleAuth)
	if err != nil {
		t.logger.LogFatal(err, "Unable to login to AppRole auth method: %s", err.Error())
	}
	if authInfo == nil {
		t.logger.LogFatal(err, "No auth info was returned after login")
	}

	secret, err := vaultClient.KVv2(engineName).Get(context.Background(), secretName)
	if err != nil {
		t.logger.LogFatal(err, "Unable to read secret: %s", err.Error())
	}

	return secret.Data
}

func (t *VaultClientService) getRoleId(token string) string {
	url := fmt.Sprintf("%s/v1/auth/approle/role/%s/role-id", t.options.Endpoint, t.options.RoleName)
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.logger.LogFatal(err, "Vault exception: %s", err.Error())
	}

	request.Header.Add("X-Vault-Token", token)
	roleContainer, err := t.roleContainerHttpClient.MakeRequest(request)
	if err != nil {
		t.logger.LogFatal(err, "Vault exception: %s", err.Error())
	}

	return roleContainer.Data.Id
}

func (t *VaultClientService) getSecretId(token string) *auth.SecretID {
	url := fmt.Sprintf("%s/v1/auth/approle/role/%s/secret-id", t.options.Endpoint, t.options.RoleName)
	request, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		t.logger.LogFatal(err, "Vault exception: %s", err.Error())
	}

	request.Header.Add("X-Vault-Token", token)
	roleContainer, err := t.secretContainerHttpClient.MakeRequest(request)
	if err != nil {
		t.logger.LogFatal(err, "Vault exception: %s", err.Error())
	}

	return &auth.SecretID{FromString: roleContainer.Data.Id}
}
