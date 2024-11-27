# SHA Checksum Mechanism in EnvCloak

EnvCloak includes a SHA checksum mechanism, enabled by default during encryption, to ensure the integrity of both encrypted files and their plaintext content. This mechanism calculates:

- `file_sha`: The checksum of the entire file that was encrypted.
- `sha`: The checksum of the plaintext content before encryption.

SHA checksums are validated during decryption unless explicitly bypassed with the `--no-sha-validation` flag. This dual redundancy ensures that both the file and its content are protected from tampering or corruption. 🛡️

---

## Behavior and Use Cases

### **Case 1: Decrypting a Non-Corrupted File Created with SHA**
```
$ envcloak decrypt --input ./tests/mock/sha_variables.env.enc --output variables_decrypted.env --key-file ./tests/mock/mykey.key
File ./tests/mock/sha_variables.env.enc decrypted -> variables_decrypted.env using key ./tests/mock/mykey.key
```

✅ Decryption proceeds normally when both `file_sha` and `sha` are present and valid.

---

### **Case 2: Decrypting a Non-Corrupted File Created Without SHA**
```
$ envcloak decrypt --input ./tests/mock/variables.env.enc --output variables_decrypted_no_sha.env --key-file ./tests/mock/mykey.key
⚠️ Warning: file_sha missing. Encrypted file integrity check skipped.
⚠️ Warning: sha missing. Plaintext integrity check skipped.
File ./tests/mock/variables.env.enc decrypted -> variables_decrypted_no_sha.env using key ./tests/mock/mykey.key
```

⚠️ When SHA checksums are absent, EnvCloak issues warnings but proceeds with decryption.

---

### **Case 3: Decrypting a Non-Corrupted File Using `--no-sha-validation`**
```
$ envcloak decrypt --input ./tests/mock/variables.env.enc --output variables_decrypted_no_sha.env --key-file ./tests/mock/mykey.key --no-sha-validation
File ./tests/mock/variables.env.enc decrypted -> variables_decrypted_no_sha.env using key ./tests/mock/mykey.key
```

⚠️ The `--no-sha-validation` flag disables all integrity checks, allowing decryption without warnings.

---

### **Case 4: Decrypting a Non-Corrupted File with SHA Using `--no-sha-validation`**
```
$ envcloak decrypt --input ./tests/mock/sha_variables.env.enc --output variables_decrypted.env --key-file ./tests/mock/mykey.key --no-sha-validation
File ./tests/mock/sha_variables.env.enc decrypted -> variables_decrypted.env using key ./tests/mock/mykey.key
```

⚠️ Using `--no-sha-validation`, decryption bypasses SHA integrity checks even when SHA values are present.

---

### **Case 5: Decrypting a Corrupted File Without Using `--no-sha-validation`**
```
$ envcloak decrypt --input ./tests/mock/sha_variables_broken.env.enc --output variables_decrypted_broken.env --key-file ./tests/mock/mykey.key                      
Error during decryption: Failed to decrypt the file.
Details: Integrity check failed. The file may have been tampered with or corrupted.
```

❌ EnvCloak detects corruption and halts decryption when SHA validation fails.

---

### **Case 6: Decrypting a Corrupted File Using `--no-sha-validation`**
```
$ envcloak decrypt --input ./tests/mock/sha_variables_broken.env.enc --output variables_decrypted_broken.env --key-file ./tests/mock/mykey.key --no-sha-validation
File ./tests/mock/sha_variables_broken.env.enc decrypted -> variables_decrypted_broken.env using key ./tests/mock/mykey.key
```

⚠️ The `--no-sha-validation` flag disables integrity checks, allowing decryption to proceed even for corrupted files. This may result in untrustworthy outputs.

---

## Adding Documentation References

### Main README Updates

In the **Decrypting Variables** and **Best Practices** sections, add the following sentence:

> EnvCloak includes SHA validation to ensure the integrity of encrypted files and their content. For details, see [SHA Checksum Mechanism](./docs/sha_checksum.md).

---

### CLI README Updates

Under the **Decrypting Variables** section, add the following:

> SHA validation ensures encrypted file integrity during decryption. Use `--no-sha-validation` cautiously when skipping these checks. See [SHA Checksum Mechanism](./docs/sha_checksum.md) for more information.

---

## Best Practices for SHA Validation

1. **Use Default Settings**: Since SHA is automatically applied during encryption, rely on default validation for better security. 🔒
2. **Limit Use of `--no-sha-validation`**: Skip SHA checks only when absolutely sure of file integrity, such as in testing environments. 🚧
3. **Respond to Errors**: Pay close attention to integrity failures, which may indicate file tampering or corruption. 🛠️

EnvCloak’s built-in SHA mechanism adds a robust layer of protection for your sensitive environment files. Keeping checks enabled ensures secure workflows and reliable decryption. 💪
