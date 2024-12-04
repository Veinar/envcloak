
<p align="center">
<img src="https://veinar.pl/envcloak.png" alt="logo" width="350"/>
</p>

<p align="center" style="background-color:#FF0000; color:white; padding:10px; border-radius:8px; font-size:14px; line-height:1.5;">
⚠️ <strong>IMPORTANT NOTE: EnvCloak is NOT Limited to .env Files!</strong>⚠️<br> 
EnvCloak was originally built to secure <b>.env</b> files, but it can encrypt and decrypt <strong>any file type</strong>.<br>
Use it for <i>.json</i>, <i>.yaml</i>, <i>.txt</i>, <i>binary files</i>, or <i>any sensitive data.</i><br>
<br>
<span style="font-style:italic;">The name may be misleading, but the tool is far more versatile than it suggests!</span>
</p>

# 🔒 EnvCloak

> "Because Your Secrets Deserve Better Than Plaintext!"

![GitHub License](https://img.shields.io/github/license/Veinar/envcloak)
![Contrib Welcome](https://img.shields.io/badge/contributions-welcome-blue)
![Looking for](https://img.shields.io/badge/looking%20for-maintainers-228B22)
![Code style](https://img.shields.io/badge/code%20style-black-black)
![CI/CD Pipeline](https://github.com/Veinar/envcloak/actions/workflows/test.yaml/badge.svg)
![Build Pipeline](https://github.com/Veinar/envcloak/actions/workflows/build.yaml/badge.svg)
[![codecov](https://codecov.io/gh/Veinar/envcloak/graph/badge.svg?token=CJG1H1VUEX)](https://codecov.io/gh/Veinar/envcloak)
[![CodeFactor](https://www.codefactor.io/repository/github/veinar/envcloak/badge)](https://www.codefactor.io/repository/github/veinar/envcloak)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/9736/badge)](https://www.bestpractices.dev/projects/9736)

![PyPI - Status](https://img.shields.io/pypi/status/envcloak?label=pypi%20status)
![PyPI - Version](https://img.shields.io/pypi/v/envcloak)
![PyPI - Downloads](https://img.shields.io/pypi/dm/envcloak)
![PyPI - Python Version](https://img.shields.io/pypi/pyversions/envcloak)



Welcome to EnvCloak, the ultimate sidekick for developers, ops folks, and anyone who’s ever accidentally committed an API key to version control. (Yes, I know… it happens to the best of us. 😅) EnvCloak takes the stress out of managing environment variables by wrapping them in the cozy blanket of encryption, so you can focus on building awesome things—without the lingering fear of a security breach.

> If you find EnvCloak useful, please ⭐ the repository. It helps others discover this project! - thank you!

## 🛠️ Installation

In order to install `envcloak` simply run:
```bash
pip install envcloak
```
or if you want `dev` tools too 😎:
```bash
pip install envcloak[dev]
```

> 👋 There are also [self-contained binaries](examples/cli/README.md#get-yourself-a-envcloak-without-requirement-to-use-python-) for `Windows`, `Linux` and `MacOS`, don't have to use python at all! 🥳

## 🚀 Example Workflow

> ℹ️ More examples are present in [examples](./examples) section.

### Generating key:

```bash
# With password and salt
envcloak generate-key-from-password --password "YourTopSecretPassword" \
--salt "e3a1c8b0d4f6e2c7a5b9d6f0cr2ad1a2" --output secretkey.key

# With password without salt (we will add random salt then)
envcloak generate-key-from-password --password "YourTopSecretPassword" --output secretkey.key

# From random password and salt
envcloak generate-key --output secretkey.key
```

![generate-key-gif](https://veinar.pl/envcloak-generate-key.gif)

> **What it does:** generates your private key used to encrypt and decrypt files. **Appends (or creates if needed) .gitignore as well** as super-hero should! 🎉

> ⚠ **If someone knows your password and salt (option 1) can recreate same `key` - keep those variables safe as `key` itself** ⚠

### Encrypting Variables:

```bash
envcloak encrypt --input .env --output .env.enc --key-file mykey.key
```

![encrypt-gif](https://veinar.pl/envcloak-encrypt.gif)

> **What it does:** Encrypts your `.env` file with a specified key, outputting a sparkling `.env.enc` file.

### Decrypting Variables:

```bash
envcloak decrypt --input .env.enc --output .env --key-file mykey.key
```

![decrypt-gif](https://veinar.pl/envcloak-decrypt.gif)

> **What it does:** Decrypts the `.env.enc` file back to `.env` using the same key. Voilà!

or you may want to use it ...

### 🐍 In Your Python Code

```python
from envcloak import load_encrypted_env

load_encrypted_env('.env.enc', key_file='mykey.key').to_os_env()
# Now os.environ contains the decrypted variables

```
> **What it does:** Loads decrypted variables directly into `os.environ`. Secrets delivered, stress-free.

## 🛠️ Implementation Details
🔑 Encryption Algorithm

* Powered by AES-256-GCM for speed and security.
* Provides [`sha3` validation](docs/sha_validation.md) of files and content.

🗝️ Key Storage

* Local key files with strict permissions.
* Secure environment variables for CI/CD systems.

🗂️ File Handling

* Works with individual files.
* Works with directories using `--directory` instead of `--input` on `encrypt` and `decrypt`.
> ℹ️ EnvCloak process files in batch one-by-one. 
* Can [recursively](docs/recursive.md) encrypt or decrypt directories.
* Can list files in directory that will be encrypted using `--preview` flag (ℹ️ only for directories and it does not commit the operation!).

🚦 Error Handling

* Clear, friendly error messages for any hiccups.
* Gracefully handles missing keys or corrupted files.

✅ Compatibility of pipelines and systems

* k8s / OKD / OCP deployments
* Jenkins pipelines
* Azure Pipelines
* Github Workflows
* Gitlab CI/CD Pipelines


## 🎉 Why EnvCloak?

Because you deserve peace of mind. EnvCloak wraps your environment variables in layers of encryption goodness, protecting them from prying eyes and accidental slips. Whether you’re a solo dev or part of a big team, this tool is here to make managing secrets simple, secure, and downright pleasant.

So go ahead—secure your `.env` like a boss. And remember, EnvCloak isn’t just a tool; it’s your secret-keeping partner in crime. (But the good kind of crime. 😎)

### Comparison of EnvCloak with Alternatives

| Tool          | Strengths                               | Weaknesses                              |
|---------------|----------------------------------------|-----------------------------------------|
| **EnvCloak**  | Lightweight, Python-native, simple to integrate with CI/CD workflows. | Limited ecosystem compared to established tools. |
| [**Sops**](https://github.com/mozilla/sops)      | Integrates with cloud providers, supports partial file encryption. | More complex to configure for beginners. |
| [**BlackBox**](https://github.com/StackExchange/blackbox)  | Simple file-based encryption for Git repos. | Limited to GPG, lacks flexibility.     |
| [**Vault**](https://www.vaultproject.io/)     | Robust, enterprise-grade with dynamic secrets. | High complexity, overkill for small projects. |
| [**Confidant**](https://lyft.github.io/confidant/) | AWS IAM integration, designed for secure CI/CD workflows. | Requires AWS, limited to its ecosystem. |
| [**Doppler**](https://www.doppler.com/)   | Centralized secret management with CI/CD integration. | Paid plans for advanced features, cloud-reliant. |

> **Key Differentiator for EnvCloak**: Focused specifically on Python developers and lightweight CI/CD needs, making it ideal for small to medium projects.

## 🌟  Hall of Fame

A huge thanks to all our amazing contributors! 🎉

<a href="https://github.com/Veinar/envcloak/graphs/contributors">
<img src="https://contrib.rocks/image?repo=Veinar/envcloak"/>
</a>

## 🔗 Get Started Today!

Don’t let your API keys end up in the wrong hands (or on Twitter). Grab EnvCloak now and start encrypting like a pro.

Happy `env` Cloaking! 🕵️‍♂️
