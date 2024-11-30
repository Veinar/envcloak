# ⛨ Security Policy

This document outlines the security policies and practices for the **EnvCloak** project, ensuring the tool is secure and reliable for managing encrypted environment variables.

## 🔩 Supported Versions

The following table indicates the versions of **EnvCloak** currently supported with security updates:

| Version   | Supported          |
|-----------|--------------------|
| > 0.3     | :white_check_mark: |
| ≤ 0.3     | :x:                |

## 🚨 Reporting a Vulnerability

If you discover a security vulnerability in **EnvCloak**, please report it to the project author.  
Or create issue describing what is wrong.

## ℹ️ Known Security Risks

### 1. Key Storage in Plaintext
- **Risk**: Keys are stored as plaintext files (e.g., `.key` extension) and may be exposed if file permissions are weak or the file is mishandled.
- **Mitigation**:
  - Store key files in secure locations with restricted permissions (`chmod 600` recommended).
  - Use secure directories or storage solutions (e.g., encrypted storage or key management services).
  - Avoid committing key files to version control systems.

### 2. Tampering with Encrypted Files
- **Risk**: Encrypted files could be tampered with, leading to undetected data corruption or malicious injection.
- **Mitigation**:
  - **EnvCloak** implements a double SHA-3 verification:
    1. A SHA-3 hash is generated for the encrypted file.
    2. A second SHA-3 hash is generated from the content of the file during encryption.
  - **EnvCloak will not decrypt files if SHA validation fails**, ensuring file integrity. To bypass this validation, users must explicitly use the `--skip-sha-validation` flag.
  - Use the `envcloak compare` command to verify file integrity.

### 3. Improper Key Rotation
- **Risk**: Key rotation errors could lead to data being unrecoverable or inconsistencies between environments.
- **Mitigation**:
  - Use the `--dry-run` option during key rotation to preview changes before applying them.
  - Backup all encrypted files before initiating key rotation.

### 4. Key Recreation via Password and Salt
- **Risk**: If a key is generated using a password and salt, the same key can be recreated if both the password and salt are known.
- **Mitigation**:
  - Use sufficiently long and unique passwords.
  - Avoid using predictable or commonly reused salts.
  - Consider generating random keys without relying on passwords when possible.

### 5. Directory Encryption Risks
- **Risk**: Encrypting entire directories without care may include unintended sensitive or system-critical files.
- **Mitigation**:
  - Use the `--preview` option to list files before encryption.
  - Avoid running **EnvCloak** on system-critical paths without reviewing the target files.

### 6. Unauthorized Access
- **Risk**: Weak file permissions or mishandled decryption keys could expose sensitive data to unauthorized users.
- **Mitigation**:
  - Ensure encrypted files are stored with restricted access (`chmod 600` recommended).
  - Do not store decrypted files or plaintext keys in accessible locations.

### 7. Outdated Algorithms
- **Risk**: Encryption algorithms used by **EnvCloak** may become outdated or insecure over time.
- **Mitigation**:
  - **EnvCloak** currently uses **AES-256**, a widely trusted encryption standard.
  - Regular audits will ensure algorithms remain up-to-date with industry standards.
  - A migration mechanism will be provided if future updates require transitioning to a new algorithm.

## 🦑 Best Practices for Secure Usage

1. **Key Management**:
   - Store key files securely, with restricted access (`chmod 600`).
   - Use extensions like `.key` to clearly differentiate key files from other files.
   - Rotate keys periodically using the `envcloak rotate` command.

2. **Environment File Handling**:
   - Do not store plaintext `.env` files in version control systems.
   - Encrypt sensitive `.env` files using the `envcloak encrypt` command.

3. **File Permissions**:
   - Restrict access to encrypted files (`chmod 600` on Linux systems).
   - Ensure only authorized users have access to the decryption key.

4. **Tamper Detection**:
   - Leverage the double SHA-3 verification feature to detect unauthorized changes to encrypted files.
   - Be cautious when using `--skip-sha-validation`, as this bypasses integrity checks.

5. **Integration Security**:
   - Pass sensitive keys or data via environment variables in CI/CD pipelines.
   - Avoid logging sensitive data during encryption or decryption processes.

## Contact

For any security-related concerns or questions, please contact the project author via the email address listed on their [GitHub profile](https://github.com/Veinar) or Package (pypi) site https://pypi.org/project/envcloak/.  
We appreciate your support in keeping **EnvCloak** secure for everyone. 🥳
