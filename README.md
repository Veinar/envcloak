# 🔒 EnvCloak

> "Because Your Secrets Deserve Better Than Plaintext!"

![GitHub License](https://img.shields.io/github/license/Veinar/envcloak)
![Contrib Welcome](https://img.shields.io/badge/contributions-welcome-blue)
![Code style](https://img.shields.io/badge/code%20style-black-black)
![CI/CD Pipeline](https://github.com/Veinar/envcloak/actions/workflows/test_and_build.yaml/badge.svg)


Welcome to EnvCloak, the ultimate sidekick for developers, ops folks, and anyone who’s ever accidentally committed an API key to version control. (Yes, I know… it happens to the best of us. 😅) EnvCloak takes the stress out of managing environment variables by wrapping them in the cozy blanket of encryption, so you can focus on building awesome things—without the lingering fear of a security breach.

## 🌟 Key Features

🔒 Encryption & Decryption

* Encryption: Securely encrypt environment variables to safely store them in repositories or share them among team members. Secrets stay secrets, even in the wild.
* Decryption: Seamlessly decrypt variables at runtime or during deployment. Your app gets what it needs without compromising security.

🎯 Ease of Use

* Simple Commands: Easy-to-use CLI commands or library functions for both encrypting and decrypting variables. No degree in cryptography required!
* Workflow Integration: Works beautifully with your development pipelines, CI/CD setups, and deployment scripts.

🔑 Key Management

* Local Keys: Use locally stored encryption keys for simplicity.
* Key Rotation: Rotate keys like a pro without breaking a sweat—or your workflow.

🧩 Compatibility

* Python Support: Tailored for Python-based applications.
* Docker-Friendly: Perfect for decrypting data before your containerized app kicks off.
* File Format Variety: Handles .env, JSON, YAML, XML—you name it, we encrypt it. (Except your cat photos. Sorry.)

🛡️ Security Best Practices

* Strong Encryption: Leveraging AES-256-GCM because your secrets deserve the best.
* Secure Storage: Encrypted files and keys adhere to industry best practices for safety.
* Access Control: Keep decryption power limited to authorized users only.

🤖 Automation-Friendly

* Scriptable: Designed for hands-off use in scripts and automated processes.
* CI/CD Integration: Works with GitHub Actions, Jenkins, GitLab CI/CD, and more. Your pipeline just got smarter.

## 🎯 Usage Scenarios

* Version Control Safety: Encrypt variables before committing. Because finding your database password on GitHub is a vibe... just not a good one.
* Team Collaboration: Share encrypted secrets without causing sleepless nights.
* Deployment Security: Inject secrets securely at runtime, no hardcoding required.
* CI/CD Love: Test and deploy without storing plaintext secrets in your pipeline.

## 🚀 Example Workflow

### Encrypting Variables:

```bash
envcloak encrypt --input .env --output .env.enc --key-file mykey.key
```
> **What it does:** Encrypts your `.env` file with a specified key, outputting a sparkling `.env.enc` file.

### Decrypting Variables:

```bash
envcloak decrypt --input .env.enc --output .env --key-file mykey.key
```
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

🗝️ Key Storage

* Local key files with strict permissions.
* Secure environment variables for CI/CD systems.

🗂️ File Handling

* Works with individual files.

🚦 Error Handling

* Clear, friendly error messages for any hiccups.
* Gracefully handles missing keys or corrupted files.

## 🎉 Why EnvCloak?

Because you deserve peace of mind. EnvCloak wraps your environment variables in layers of encryption goodness, protecting them from prying eyes and accidental slips. Whether you’re a solo dev or part of a big team, this tool is here to make managing secrets simple, secure, and downright pleasant.

So go ahead—secure your `.env` like a boss. And remember, EnvCloak isn’t just a tool; it’s your secret-keeping partner in crime. (But the good kind of crime. 😎)

## 🔗 Get Started Today!

Don’t let your API keys end up in the wrong hands (or on Twitter). Grab EnvCloak now and start encrypting like a pro.

Happy `env` Cloaking! 🕵️‍♂️
