import os
from envcloak import load_encrypted_env

load_encrypted_env('tests/mock/variables.env.enc', key_file='tests/mock/mykey.key').to_os_env()
# Now os.environ contains the decrypted variables

# Check if specific variables are in os.environ
print("DB_USERNAME:", os.getenv("DB_USERNAME"))
print("DB_PASSWORD:", os.getenv("DB_PASSWORD"))