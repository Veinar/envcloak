# EnvCloak: CLI examples

EnvCloak simplifies managing sensitive environment variables by encrypting and decrypting .env files securely. It supports generating encryption keys, encrypting/decrypting files, and rotating keys efficiently. Designed for developers and CI/CD pipelines, EnvCloak is the security superhero your project needs! 🛡️

## Usage

> **Dry Run:** With all required params **for each command** you can use `--dry-run` flag to check if command will pass or fail - without destroying your project 😅

### Key Generation

#### 1. Generate a Key from a Password and Salt

```bash
envcloak generate-key-from-password --password "YourTopSecretPassword" \
--salt "e3a1c8b0d4f6e2c7a5b9d6f0cr2ad1a2" --output secretkey.key
```

**Description:** Derives a key from a password and a salt. The salt ensures uniqueness, preventing duplicate keys from identical passwords. 
**By default:**
* If a `.gitignore` exists, it appends the key file name to it.
* If `.gitignore` doesn't exist, it creates one and includes the key file name.

> **Not recommended:** you may bypass this by additional flag `--no-gitignore`. ⚠

#### 2. Generate a Key from a Password Without a Salt

```bash
envcloak generate-key-from-password --password "YourTopSecretPassword" --output secretkey.key
```

**Description:** Derives a key from a password and a randomly generated salt. The salt is stored for future use. 
**By default:**
* If a `.gitignore` exists, it appends the key file name to it.
* If `.gitignore` doesn't exist, it creates one and includes the key file name.

> **Not recommended:** you may bypass this by additional flag `--no-gitignore`. ⚠

#### 3. Generate a Random Key

```bash
envcloak generate-key --output secretkey.key
```

**Description:** Creates a random encryption key. 
**By default:**
* If a `.gitignore` exists, it appends the key file name to it.
* If `.gitignore` doesn't exist, it creates one and includes the key file name.

> **Not recommended:** you may bypass this by additional flag `--no-gitignore`. ⚠

### Encrypting Variables

```bash
envcloak encrypt --input .env --output .env.enc --key-file mykey.key
```

**Description:** Encrypts your `.env` file into `.env.enc`. The original file remains unchanged.

### Decrypting Variables

```bash
envcloak decrypt --input .env.enc --output .env --key-file mykey.key
```

**Description:** Decrypts `.env.enc` back to `.env`. Ensure the `key-file` used matches the one from the encryption step.

### Rotating Keys

```bash
envcloak rotate-keys --input .env.enc --old-key-file oldkey.key \
--new-key-file newkey.key --output .env.enc.new
```

**Description:** Re-encrypts an encrypted file with a new key, ensuring minimal disruption when rotating encryption keys.

## Use Cases

### 1. Secure Environment Variables in CI/CD Pipelines

Problem: Sharing sensitive data like API keys or database credentials in a CI/CD pipeline.
Solution: Use EnvCloak to encrypt .env files during deployment:

1. Before commit
```bash
# Generate key
envcloak generate-key --output secretkey.key
# Encrypt sensitive data
envcloak encrypt --input .env --output .env.enc --key-file secretkey.key
git add .env.enc
git commit -m "Secure .env file"
```
2. During build/deploy
```bash
# Decrypt for normal use
envcloak decrypt --input .env.enc --output .env --key-file secretkey.key
```
> You must provide `secretkey.key` in CI/CD workflow in secure way.

The decrypted `.env` file is ready for use in your application.

### 2. Setting Up a New Project

Problem: Sharing initial credentials and configurations with your team securely.
Solution: Encrypt the `.env` file before distributing:

1. Generate key
```bash
envcloak generate-key --output myproject.key
```
2. Encrypt sensitive data
```bash
envcloak encrypt --input .env --output .env.enc --key-file myproject.key
```
Distribute the `.env.enc` file and keep the `myproject.key` secure.

## Best Practices

* Never commit keys: Always use `.gitignore` to exclude `key` files.
* Secure `password`s and `salt`s: Treat them as sensitive as the `key`s themselves.
* Automate `encryption`/`decryption`: Include EnvCloak commands in CI/CD pipelines or scripts for consistency.