package com.staples.siam.aic.management.samlcertmgr.config;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;

/**
 * DefaultAzureCredential resolves to the App Service's managed identity in
 * Azure, and falls back to Azure CLI / VS Code / environment-variable
 * credentials for local development (run {@code az login} first).
 */
public final class AzureClients {

    private AzureClients() {
    }

    public static SecretClient secretClient(String keyVaultUri) {
        return new SecretClientBuilder()
                .vaultUrl(keyVaultUri)
                .credential(new DefaultAzureCredentialBuilder().build())
                .buildClient();
    }
}