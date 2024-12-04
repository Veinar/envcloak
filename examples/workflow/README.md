# Using EnvCloak in CI/CD Workflows for Decryption

EnvCloak simplifies the secure management of sensitive environment variables. In CI/CD workflows, the encrypted `.env.enc` file is typically created and committed manually, while the decryption happens automatically during deployment or application startup. This guide focuses on **decrypting variables** in workflows using both the `envcloak` CLI and Python code.

> Examples how to integrate KMS in CI/CD process can be found [here](integration_with_kms.md). 💎

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


## Using Envcloak for Secure Variable Management in Kubernetes Environments

In Kubernetes-based systems, sensitive configuration data such as API keys, database credentials, or other environment variables are typically stored securely using **Secrets**. These secrets can be encrypted and managed securely with tools like **Envcloak**. Below is a workflow describing how to integrate Envcloak into Kubernetes deployments for decrypting and utilizing sensitive environment variables.

---

### **Workflow Overview:**

1. **Encrypt Sensitive Variables:**
   - Use Envcloak to encrypt sensitive environment variables before committing them to a Git repository. Store the encrypted `.env.enc` file in your application repository.

2. **Store Decryption Key Securely:**
   - The decryption key (Base64-encoded) is stored in a Kubernetes Secret.

3. **Configure Your Deployment:**
   - Mount the Kubernetes Secret as an environment variable in your pod or as a file.

4. **Decrypt at Runtime:**
   - Use an **initContainer** or **entrypoint script** to decrypt the `.env.enc` file into a usable `.env` format before starting your application.

---

### **Example Kubernetes Manifest**

Below is an example of deploying an application that uses Envcloak to securely decrypt environment variables.

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  labels:
    app: secure-app
spec:
  replicas: 1
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      containers:
      - name: app-container
        image: my-app:latest
        command: ["/bin/bash", "-c", "--"]
        args: ["source /app/.env && exec python app.py"]
        env:
        - name: ENVCLOAK_KEY_B64
          valueFrom:
            secretKeyRef:
              name: envcloak-key
              key: ENVCLOAK_KEY_B64
        volumeMounts:
        - name: decrypted-env
          mountPath: /app/.env
          subPath: .env
        resources:
          limits:
            memory: "256Mi"
            cpu: "500m"
      # Where magic happens
      initContainers:
      - name: decrypt-env
        image: python:3.9
        command: ["/bin/sh", "-c"]
        args:
        - |
          pip install envcloak &&
          echo "$ENVCLOAK_KEY_B64" | base64 --decode > /app/mykey.key &&
          envcloak decrypt --input /app/.env.enc --output /app/.env --key-file /app/mykey.key
        env:
        - name: ENVCLOAK_KEY_B64
          valueFrom:
            secretKeyRef:
              name: envcloak-key
              key: ENVCLOAK_KEY_B64
        volumeMounts:
        - name: encrypted-env
          mountPath: /app/.env.enc
          subPath: .env.enc
        - name: decrypted-env
          mountPath: /app/.env
          subPath: .env
      volumes:
      - name: encrypted-env
        configMap:
          name: encrypted-env-file
      - name: decrypted-env
        emptyDir: {}

```

---

### **Key Components Explained:**

1. **Secrets for Decryption Key:**
   - The Base64-encoded decryption key is stored securely in Kubernetes Secrets.

   ```yaml
   apiVersion: v1
   kind: Secret
   metadata:
     name: envcloak-key
   type: Opaque
   data:
     ENVCLOAK_KEY_B64: <base64-encoded-key>
   ```

2. **ConfigMap for Encrypted File:**
   - The encrypted `.env.enc` file is stored in a ConfigMap.

   ```yaml
   apiVersion: v1
   kind: ConfigMap
   metadata:
     name: encrypted-env-file
   data:
     .env.enc: |
       <contents-of-encrypted-file>
   ```

3. **InitContainer for Decryption:**
   - The `decrypt-env` InitContainer decrypts the `.env.enc` file into a usable `.env` file.

4. **Application Container:**
   - The main container sources the decrypted `.env` file before executing the application.

### **Benefits of This Approach:**
- **Secure Variable Management**: Secrets are encrypted and stored securely, minimizing exposure.
- **Flexibility**: The decryption process is abstracted, making it compatible with different workflows.
- **Compliance**: Sensitive information is never stored in plaintext within the repository or directly in Kubernetes manifests.

This method ensures robust security and seamless integration of sensitive environment variables in Kubernetes deployments.

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
