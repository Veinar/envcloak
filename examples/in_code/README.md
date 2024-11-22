# EnvCloak: In code examples

EnvCloak can be easily integrated into your Python application to securely load encrypted environment variables directly into your os.environ. Here's how you can do it:

## Installation

Ensure you have EnvCloak installed:
```bash
pip install envcloak
```

## Loading Encrypted Variables in Code

```python
import os
from envcloak import load_encrypted_env

# Load encrypted environment variables from a file
load_encrypted_env('path/to/your/env.enc', key_file='path/to/your/key.key').to_os_env()

# Now os.environ contains the decrypted variables
print("DB_USERNAME:", os.getenv("DB_USERNAME"))
print("DB_PASSWORD:", os.getenv("DB_PASSWORD"))

```

you may test it on our `mock` data:

```python
# test.py file in this dir
import os
from envcloak import load_encrypted_env

load_encrypted_env('tests/mock/variables.env.enc', key_file='tests/mock/mykey.key').to_os_env()
# Now os.environ contains the decrypted variables

# Check if specific variables are in os.environ
print("DB_USERNAME:", os.getenv("DB_USERNAME"))
print("DB_PASSWORD:", os.getenv("DB_PASSWORD"))
```

## Use Cases

* **Secure Application Configurations:** Load sensitive variables (e.g., API keys, database credentials) without exposing them in plaintext files.
* **Seamless CI/CD Integration:** Securely handle environment variables in automated pipelines.

---

`EnvCloak` makes managing sensitive configurations both simple and secure! 🌟