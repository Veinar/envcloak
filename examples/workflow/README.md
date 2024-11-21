# Using EnvCloak in CI/CD Workflows for Decryption

EnvCloak simplifies the secure management of sensitive environment variables. In CI/CD workflows, the encrypted `.env.enc` file is typically created and committed manually, while the decryption happens automatically during deployment or application startup. This guide focuses on **decrypting variables** in workflows using both the `envcloak` CLI and Python code.

---

## Key Handling: Securely Storing `ENVCLOAK_KEY_B64`

The variable `ENVCLOAK_KEY_B64` is a **Base64-encoded string of the encryption key**. This encoding ensures the key's binary content can be safely stored in plaintext-compatible fields, such as CI/CD secrets. It should be stored securely using your CI/CD platform’s secrets management (e.g., GitHub Secrets, Jenkins Credentials, GitLab Vault).

### **How to Generate `ENVCLOAK_KEY_B64`**

1. Encode the key file to Base64:
   ```
   base64 mykey.key > mykey.key.b64
   ```

2. Copy the Base64 string from `mykey.key.b64` and store it as `ENVCLOAK_KEY_B64` in your CI/CD secrets.

---

## Workflow Examples: Decrypting Variables

### **GitHub Actions: Decrypt Variables with CLI Commands**

```yaml
name: Deploy Application

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: 3.9

      - name: Install EnvCloak
        run: pip install envcloak

      - name: Decrypt Environment Variables
        env:
          ENVCLOAK_KEY_B64: ${{ secrets.ENVCLOAK_KEY_B64 }}
        run: |
          echo "$ENVCLOAK_KEY_B64" | base64 --decode > mykey.key
          envcloak decrypt --input .env.enc --output .env --key-file mykey.key

      - name: Run Application
        run: |
          export $(cat .env | xargs)
          python app.py
```

---

### **GitLab CI/CD: Decrypt Variables**

```yaml
stages:
  - deploy

deploy_app:
  stage: deploy
  image: python:3.9
  before_script:
    - pip install envcloak
  script:
    - echo "$ENVCLOAK_KEY_B64" | base64 --decode > mykey.key
    - envcloak decrypt --input .env.enc --output .env --key-file mykey.key
    - export $(cat .env | xargs)
    - python app.py
```

---

### **Jenkins Pipeline: Decrypt Variables with CLI**

```groovy
pipeline {
    agent any

    environment {
        ENVCLOAK_KEY_B64 = credentials('jenkins-envcloak-key-b64') // Store Base64 key in Jenkins credentials
    }

    stages {
        stage('Setup') {
            steps {
                script {
                    sh 'pip install envcloak'
                    sh 'echo ${ENVCLOAK_KEY_B64} | base64 --decode > mykey.key'
                }
            }
        }
        stage('Decrypt Variables') {
            steps {
                script {
                    sh 'envcloak decrypt --input path/to/.env.enc --output .env --key-file mykey.key'
                }
            }
        }
        stage('Run Application') {
            steps {
                script {
                    sh 'export $(cat .env | xargs)'
                    sh 'python app.py'
                }
            }
        }
    }
}
```

---

### **Azure Pipelines: Decrypt Variables**

```yaml
trigger:
  branches:
    include:
      - main

jobs:
- job: Deploy
  displayName: Deploy Application
  pool:
    vmImage: 'ubuntu-latest'
  steps:
  - task: UsePythonVersion@0
    inputs:
      versionSpec: '3.x'
  - script: |
      pip install envcloak
      echo "$ENVCLOAK_KEY_B64" | base64 --decode > mykey.key
      envcloak decrypt --input .env.enc --output .env --key-file mykey.key
      export $(cat .env | xargs)
      python app.py
    displayName: Decrypt and Run Application
```

---

## Using EnvCloak in Python Code

### **GitHub Actions: Using Python Code for Decryption**

```yaml
name: Deploy Application with Python

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: 3.9

      - name: Install Dependencies
        run: pip install envcloak

      - name: Run Application with Decrypted Variables
        env:
          ENVCLOAK_KEY_B64: ${{ secrets.ENVCLOAK_KEY_B64 }}
        run: |
          echo "$ENVCLOAK_KEY_B64" | base64 --decode > mykey.key
          python -c "
          from envcloak import load_encrypted_env;
          load_encrypted_env('.env.enc', key_file='mykey.key').to_os_env()
          "
          python app.py
```

---

## Best Practices

1. **Base64-Encode Keys**:
   - Binary keys may contain non-printable characters. Always encode them to Base64 before storing them in secrets.

2. **Secure Secrets Storage**:
   - Store `ENVCLOAK_KEY_B64` in your CI/CD platform’s secrets management (e.g., GitHub Secrets, Jenkins Credentials, GitLab Vault).

3. **Automate Decryption**:
   - Automate the decryption process in your pipeline to securely load sensitive variables.

---

`EnvCloak` provides a secure and flexible approach to managing encrypted environment variables in workflows using both CLI commands and Python code. 🌟
