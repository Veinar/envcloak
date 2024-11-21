# import secrets # TODO: implement this
import os
from pathlib import Path
from .encryptor import derive_key


def generate_key_file(output_path: Path):
    """
    Generate a secure random encryption key, save it to a file.
    """
    key = os.urandom(32)  # Generate a 256-bit random key
    output_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
    with open(output_path, "wb") as key_file:
        key_file.write(key)
    print(f"Encryption key generated and saved to {output_path}")


def generate_key_from_password_file(password: str, output_path: Path, salt: str = None):
    """
    Derive an encryption key from a password and save it to a file.
    If no salt is provided, a random one is generated.

    :param password: The password used for key derivation.
    :param output_path: Path object representing the file where the key will be saved.
    :param salt: Optional hex-encoded salt (16 bytes as 32 hex characters).
    """
    if salt:
        if len(salt) != 32:  # Hex-encoded salt should be 16 bytes
            raise ValueError("Salt must be 16 bytes (32 hex characters).")
        salt_bytes = bytes.fromhex(salt)
    else:
        salt_bytes = os.urandom(16)  # Generate a random 16-byte salt

    # Derive the key
    key = derive_key(password, salt_bytes)

    # Ensure the output directory exists
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Write the derived key to the file
    with open(output_path, "wb") as key_file:
        key_file.write(key)

    print(f"Derived encryption key saved to {output_path}")
