# General Guidelines for usage with KMS providers.

## 1. HashiCorp Vault

### Key Storage

* Install and configure HashiCorp Vault.
* Enable the KV secrets engine: 
```bash 
vault secrets enable -path=envcloak kv 
```
* Store the key in Vault: 
```bash
vault kv put envcloak/key key=$(cat key.txt)
```

### Key Retrieval

* Authenticate with Vault:
    * Using a token: 
    ```bash
    export VAULT_TOKEN=<your-vault-token>
    ```
    * Or use a method like AppRole or `Kubernetes` auth for automated systems.

* Retrieve the key: 
```bash 
vault kv get -field=key envcloak/key > key.txt 
```

### Integrating in CI/CD

* Use Vault's CLI or API to fetch keys during pipeline execution. For example:

* Add a script in your CI pipeline: 
```bash
vault kv get -field=key envcloak/key > key.txt && \
envcloak decrypt --input .env.enc --output .env --key-file key.txt
```

## 2. AWS KMS with Secrets Manager

### Key Storage

* Store the key in AWS Secrets Manager: 
```bash 
aws secretsmanager create-secret \
--name envcloak/key \
--secret-string "$(cat key.txt)" 
```

### Key Retrieval

* Retrieve the key using AWS CLI: 
```bash
aws secretsmanager get-secret-value \
--secret-id envcloak/key \
--query SecretString \
--output text > key.txt 
```

### Integrating in CI/CD

* Use an IAM role for the CI/CD system with access to the secret.
* Add a script in your pipeline: 
```bash
KEY=$(aws secretsmanager get-secret-value --secret-id envcloak/key \
--query SecretString --output text) echo "$KEY" > key.txt && \
envcloak decrypt --input .env.enc --output .env --key-file key.txt
```

## 3. Google Cloud KMS with Secret Manager

### Key Storage

* Store the key in Google Secret Manager: 
```bash 
echo -n "$(cat key.txt)" | gcloud secrets create envcloak-key \
--data-file=- --replication-policy="automatic" 
```

### Key Retrieval

* Grant your CI/CD service account the `roles/secretmanager.secretAccessor` role.
* Retrieve the key: 
```bash
gcloud secrets versions access latest --secret="envcloak-key" > key.txt
```

### Integrating in CI/CD

* Authenticate with a service account key or use a GCP-managed CI/CD system with a properly scoped service account.
* Add a step in your pipeline: 
```bash 
gcloud secrets versions access latest --secret="envcloak-key" > key.txt && \
envcloak decrypt --input .env.enc --output .env --key-file key.txt 
```

## General Guidelines for Secure Key Management

* Role-Based Access Control (RBAC): Ensure that only authorized users or services can access the keys.
* Audit Logging: Enable logging for all access to secrets for auditing and compliance.
* Key Rotation:
    * Periodically rotate keys in the KMS.
    * Re-encrypt the environment files with the new key.
* Automated Integration:
    * Use the native SDKs or APIs for these KMS providers in your applications or CI/CD pipelines for seamless integration.