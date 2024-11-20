import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from .constants import NONCE_SIZE, KEY_SIZE, SALT_SIZE


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a cryptographic key from a password and salt using PBKDF2.
    :param password: User-provided password.
    :param salt: Salt for key derivation (must be 16 bytes).
    :return: Derived key (32 bytes for AES-256).
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be exactly {SALT_SIZE} bytes.")

    if salt is None:
        salt = generate_salt()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())


def generate_salt() -> bytes:
    """
    Generate a secure random salt of the standard size.
    :return: Randomly generated salt (16 bytes).
    """
    return os.urandom(SALT_SIZE)


def encrypt(data: str, key: bytes) -> dict:
    """
    Encrypt the given data using AES-256-GCM.

    :param data: Plaintext data to encrypt.
    :param key: Encryption key (32 bytes for AES-256).
    :return: Dictionary with encrypted data, nonce, and associated metadata.
    """
    nonce = os.urandom(NONCE_SIZE)  # Generate a secure random nonce
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

    return {
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(encryptor.tag).decode(),
    }


def decrypt(encrypted_data: dict, key: bytes) -> str:
    """
    Decrypt the given encrypted data using AES-256-GCM.

    :param encrypted_data: Dictionary containing ciphertext, nonce, and tag.
    :param key: Decryption key (32 bytes for AES-256).
    :return: Decrypted plaintext.
    """
    nonce = base64.b64decode(encrypted_data["nonce"])
    ciphertext = base64.b64decode(encrypted_data["ciphertext"])
    tag = base64.b64decode(encrypted_data["tag"])

    cipher = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()


def encrypt_file(input_file: str, output_file: str, key: bytes):
    """
    Encrypt the contents of a file and write the result to another file.

    :param input_file: Path to the plaintext input file.
    :param output_file: Path to save the encrypted file.
    :param key: Encryption key (32 bytes for AES-256).
    """
    with open(input_file, "r", encoding="utf-8") as infile:
        data = infile.read()

    encrypted_data = encrypt(data, key)

    with open(output_file, "w", encoding="utf-8") as outfile:
        json.dump(encrypted_data, outfile, ensure_ascii=False)


def decrypt_file(input_file: str, output_file: str, key: bytes):
    """
    Decrypt the contents of a file and write the result to another file.

    :param input_file: Path to the encrypted input file.
    :param output_file: Path to save the decrypted file.
    :param key: Decryption key (32 bytes for AES-256).
    """
    with open(input_file, "r", encoding="utf-8") as infile:
        encrypted_data = json.load(infile)

    decrypted_data = decrypt(encrypted_data, key)

    with open(output_file, "w", encoding="utf-8") as outfile:
        outfile.write(decrypted_data)
