# Recursive Processing in EnvCloak

EnvCloak provides the `--recursive` option to process directories and their subdirectories for encryption and decryption operations. This option enables secure handling of multiple files in nested folder structures, simplifying workflows for developers and CI/CD systems. 📂🔒

---

## Behavior of `--recursive`

### Encryption
When using the `--recursive` option with the `encrypt` command, EnvCloak:

1. **Processes all files** in the specified directory and its subdirectories. ✅
2. **Maintains directory structure** in the output location. 🗂️
3. **Skips single-file inputs:** If the input is a single file, `--recursive` is ignored as recursion is unnecessary. 🚫

Example:
```bash
$ envcloak encrypt --directory ./myproject --output ./myproject.enc --key-file mykey.key --recursive
Encrypting ./myproject/config/.env -> ./myproject.enc/config/.env.enc
Encrypting ./myproject/app/.env -> ./myproject.enc/app/.env.enc
...
```

---

### Decryption
When using the `--recursive` option with the `decrypt` command, EnvCloak:

1. **Decrypts all files** in the specified directory and its subdirectories. 🔓
2. **Maintains directory structure** in the output location. 🗂️
3. **Skips files that are not encrypted.** 🚫

Example:
```bash
$ envcloak decrypt --directory ./myproject.enc --output ./myproject --key-file mykey.key --recursive
Decrypting ./myproject.enc/config/.env.enc -> ./myproject/config/.env
Decrypting ./myproject.enc/app/.env.enc -> ./myproject/app/.env
...
```

---

## Limitations and Caveats

1. **Symlinks**: EnvCloak does not follow symbolic links during recursive operations. Any symlinked files or directories are ignored to prevent unintended behavior. 🔗🚫
2. **Unsupported Inputs**: The `--recursive` flag is ignored if the input is a single file. 📄
3. **File-Specific Flags**: Flags that apply to individual files (e.g., `--skip-sha-validation`) are applied uniformly across all processed files. ⚙️

---

## Best Practices for Using `--recursive`

1. **Check Output Directory**: Ensure the specified output directory is empty or properly organized to avoid overwriting files inadvertently. ⚠️
2. **Avoid Symlinks**: Do not rely on symbolic links within directories to be processed. Symlinks are ignored by design. 🔗❌
3. **Verify Results**: After recursive operations, review the output directory to ensure all intended files have been processed. 🕵️‍♂️

By leveraging `--recursive`, EnvCloak simplifies the secure encryption and decryption of large projects with deeply nested file structures, ensuring both efficiency and consistency in your workflows. 🚀✨
