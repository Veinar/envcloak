"""
encryptor.py

This module implements core functionality for encrypting and decrypting files.
It handles file traversal, key management, and cryptographic operations to ensure secure data handling.
"""

import os
import base64
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import click
import secrets
from click import style
from envcloak.exceptions import (
    InvalidSaltException,
    InvalidKeyException,
    EncryptionException,
    DecryptionException,
    FileEncryptionException,
    FileDecryptionException,
    IntegrityCheckFailedException,
)
from envcloak.constants import NONCE_SIZE, KEY_SIZE, SALT_SIZE
from envcloak.utils import compute_sha256, debug_log


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a cryptographic key from a password and salt using PBKDF2.
    :param password: User-provided password.
    :param salt: Salt for key derivation (must be 16 bytes).
    :return: Derived key (32 bytes for AES-256).
    """
    if len(salt) != SALT_SIZE:
        raise InvalidSaltException(
            details=f"Expected salt of size {SALT_SIZE}, got {len(salt)} bytes."
        )
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=100000,
            backend=default_backend(),
        )
        return kdf.derive(password.encode())
    except Exception as e:
        raise InvalidKeyException(details=str(e)) from e


def generate_salt() -> bytes:
    """
    Generate a secure random salt of the standard size.
    :return: Randomly generated salt (16 bytes).
    """
    try:
        return secrets.token_bytes(SALT_SIZE)
    except Exception as e:
        raise EncryptionException(details=f"Failed to generate salt: {str(e)}") from e


def encrypt(data: str, key: bytes) -> dict:
    """
    Encrypt the given data using AES-256-GCM.

    :param data: Plaintext data to encrypt.
    :param key: Encryption key (32 bytes for AES-256).
    :return: Dictionary with encrypted data, nonce, and associated metadata.
    """
    try:
        nonce = secrets.token_bytes(NONCE_SIZE)  # Generate a secure random nonce
        cipher = Cipher(
            algorithms.AES(key), modes.GCM(nonce), backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data.encode()) + encryptor.finalize()

        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "tag": base64.b64encode(encryptor.tag).decode(),
        }
    except Exception as e:
        raise EncryptionException(details=str(e)) from e


def decrypt(encrypted_data: dict, key: bytes, validate_integrity: bool = True) -> str:
    """
    Decrypt the given encrypted data using AES-256-GCM.

    :param encrypted_data: Dictionary containing ciphertext, nonce, and tag.
    :param key: Decryption key (32 bytes for AES-256).
    :param validate_integrity: Whether to enforce integrity checks (default: True).
    :return: Decrypted plaintext.
    """
    try:
        nonce = base64.b64decode(encrypted_data["nonce"])
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        tag = base64.b64decode(encrypted_data["tag"])

        cipher = Cipher(
            algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
        )
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        if validate_integrity:
            # Validate plaintext hash if present
            if "sha" in encrypted_data:
                sha_hash = compute_sha256(plaintext.decode())
                if sha_hash != encrypted_data["sha"]:
                    raise IntegrityCheckFailedException(
                        details="Integrity check failed! The file may have been tampered with or corrupted."
                    )

        return plaintext.decode()
    except Exception as e:
        raise DecryptionException(details=str(e)) from e


def encrypt_file(input_file: str, output_file: str, key: bytes):
    """
    Encrypt the contents of a file and write the result to another file,
    including SHA-256 of the entire encrypted JSON structure.
    """
    try:
        with open(input_file, "r", encoding="utf-8") as infile:
            data = infile.read()

        # Encrypt plaintext
        encrypted_data = encrypt(data, key)

        # Compute hash of plaintext for integrity
        encrypted_data["sha"] = compute_sha256(data)

        # Compute hash of the entire encrypted structure
        file_hash = compute_sha256(json.dumps(encrypted_data, ensure_ascii=False))
        encrypted_data["file_sha"] = file_hash  # Store this hash in the structure

        with open(output_file, "w", encoding="utf-8") as outfile:
            json.dump(encrypted_data, outfile, ensure_ascii=False)
    except Exception as e:
        raise FileEncryptionException(details=str(e)) from e


def decrypt_file(
    input_file: str, output_file: str, key: bytes, validate_integrity: bool = True
):
    """
    Decrypt the contents of a file and validate SHA-256 integrity for both
    the plaintext and the encrypted file.

    :param input_file: Path to the encrypted input file.
    :param output_file: Path to save the decrypted file.
    :param key: Encryption key (32 bytes for AES-256).
    :param validate_integrity: Whether to enforce integrity checks (default: True).
    """
    try:
        with open(input_file, "r", encoding="utf-8") as infile:
            encrypted_data = json.load(infile)

        if validate_integrity:
            # Validate hash of the entire encrypted file (excluding file_sha)
            expected_file_sha = encrypted_data.get("file_sha")
            if expected_file_sha:
                # Exclude "file_sha" itself from the recomputed hash
                data_to_hash = encrypted_data.copy()
                data_to_hash.pop("file_sha")
                actual_file_sha = compute_sha256(
                    json.dumps(data_to_hash, ensure_ascii=False)
                )
                # print(f"Debug: Stored file_sha: {expected_file_sha}")
                # print(f"Debug: Computed file_sha: {actual_file_sha}")
                if expected_file_sha != actual_file_sha:
                    raise IntegrityCheckFailedException(
                        details="Encrypted file integrity check failed! The file may have been tampered with or corrupted."
                    )
            else:
                click.echo(
                    style(
                        "⚠️  Warning: file_sha missing. Encrypted file integrity check skipped.",
                        fg="yellow",
                    )
                )

        # Decrypt the plaintext
        decrypted_data = decrypt(
            encrypted_data, key, validate_integrity=validate_integrity
        )

        if validate_integrity:
            # Validate hash of plaintext
            if "sha" in encrypted_data:
                sha_hash = compute_sha256(decrypted_data)
                # print(f"Debug: Stored sha: {encrypted_data['sha']}")
                # print(f"Debug: Computed sha: {sha_hash}")
                if sha_hash != encrypted_data["sha"]:
                    raise IntegrityCheckFailedException(
                        details="Decrypted plaintext integrity check failed! The file may have been tampered with or corrupted."
                    )
            else:
                click.echo(
                    style(
                        "⚠️  Warning: sha missing. Plaintext integrity check skipped.",
                        fg="yellow",
                    )
                )

        # Write plaintext to the output file
        with open(output_file, "w", encoding="utf-8") as outfile:
            outfile.write(decrypted_data)
    except Exception as e:
        raise FileDecryptionException(details=str(e)) from e


def traverse_and_process_files(
    input_dir, output_dir, key, dry_run, debug, process_file, recursion=False
):
    """
    Traverse a directory recursively if `recursion` is enabled, process files,
    and replicate the directory structure in output_dir.

    :param input_dir: Source directory to traverse.
    :param output_dir: Target directory to replicate structure and save processed files.
    :param key: Encryption/decryption key.
    :param dry_run: Flag indicating if the operation should be simulated without making changes.
    :param debug: Debug flag for verbose logging.
    :param process_file: Callable to process individual files.
    :param recursion: Flag to enable or disable recursive traversal.
    """
    input_dir = Path(input_dir)
    output_dir = Path(output_dir)

    files_to_process = input_dir.rglob("*") if recursion else input_dir.iterdir()

    for file_path in files_to_process:
        if file_path.is_file():
            relative_path = file_path.relative_to(input_dir)
            target_path = output_dir / relative_path
            target_path.parent.mkdir(parents=True, exist_ok=True)

            output_file = str(target_path)
            if output_file.endswith(".enc"):
                output_file = output_file[:-4]  # Explicitly handle `.enc`

            if not dry_run:
                process_file(file_path, output_file, key, debug)
            else:
                debug_log(f"Dry-run: Would process {file_path} -> {output_file}", debug)
