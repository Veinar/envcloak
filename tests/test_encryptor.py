import os
import base64
import json
import pytest
from pathlib import Path
from envcloak.encryptor import (
    derive_key,
    generate_salt,
    encrypt,
    decrypt,
    encrypt_file,
    decrypt_file,
)
from envcloak.constants import SALT_SIZE, KEY_SIZE, NONCE_SIZE


def test_generate_salt():
    """
    Test that generate_salt produces a salt of the correct size.
    """
    salt = generate_salt()
    assert len(salt) == SALT_SIZE
    assert isinstance(salt, bytes)


def test_derive_key():
    """
    Test that derive_key produces a key of the correct size.
    """
    password = "test_password"
    salt = generate_salt()
    key = derive_key(password, salt)
    assert len(key) == KEY_SIZE
    assert isinstance(key, bytes)


def test_derive_key_invalid_salt():
    """
    Test that derive_key raises an error for invalid salt sizes.
    """
    password = "test_password"
    invalid_salt = os.urandom(SALT_SIZE - 1)  # Smaller than expected
    with pytest.raises(ValueError, match=f"Salt must be exactly {SALT_SIZE} bytes."):
        derive_key(password, invalid_salt)


def test_encrypt_and_decrypt():
    """
    Test that encrypting and decrypting a string works as expected.
    """
    key = os.urandom(KEY_SIZE)
    plaintext = "This is a test message."

    # Encrypt the data
    encrypted_data = encrypt(plaintext, key)
    assert "ciphertext" in encrypted_data
    assert "nonce" in encrypted_data
    assert "tag" in encrypted_data

    # Decrypt the data
    decrypted_text = decrypt(encrypted_data, key)
    assert decrypted_text == plaintext


def test_encrypt_and_decrypt_invalid_key():
    """
    Test that decrypting with an incorrect key raises an error.
    """
    key = os.urandom(KEY_SIZE)
    wrong_key = os.urandom(KEY_SIZE)
    plaintext = "This is a test message."

    encrypted_data = encrypt(plaintext, key)

    with pytest.raises(Exception):
        decrypt(encrypted_data, wrong_key)


def test_encrypt_and_decrypt_invalid_data():
    """
    Test that decrypting with invalid encrypted data raises an error.
    """
    key = os.urandom(KEY_SIZE)

    invalid_data = {
        "ciphertext": base64.b64encode(b"invalid").decode(),
        "nonce": base64.b64encode(os.urandom(NONCE_SIZE)).decode(),
        "tag": base64.b64encode(os.urandom(16)).decode(),
    }

    with pytest.raises(Exception):
        decrypt(invalid_data, key)


@pytest.fixture
def tmp_files(tmp_path):
    """
    Fixture for temporary plaintext and encrypted files.
    """
    plaintext_file = tmp_path / "plaintext.txt"
    encrypted_file = tmp_path / "encrypted.json"
    decrypted_file = tmp_path / "decrypted.txt"

    plaintext_file.write_text("This is a test file.")
    return plaintext_file, encrypted_file, decrypted_file


def test_encrypt_file(tmp_files):
    """
    Test encrypting a file.
    """
    plaintext_file, encrypted_file, _ = tmp_files
    key = os.urandom(KEY_SIZE)

    encrypt_file(plaintext_file, encrypted_file, key)

    # Verify the encrypted file exists and is valid JSON
    assert encrypted_file.exists()
    with open(encrypted_file, "r", encoding="utf-8") as f:
        encrypted_data = json.load(f)

    assert "ciphertext" in encrypted_data
    assert "nonce" in encrypted_data
    assert "tag" in encrypted_data


def test_decrypt_file(tmp_files):
    """
    Test decrypting a file.
    """
    plaintext_file, encrypted_file, decrypted_file = tmp_files
    key = os.urandom(KEY_SIZE)

    # Encrypt and then decrypt the file
    encrypt_file(plaintext_file, encrypted_file, key)
    decrypt_file(encrypted_file, decrypted_file, key)

    # Verify the decrypted file content matches the original plaintext
    with open(decrypted_file, "r", encoding="utf-8") as f:
        decrypted_text = f.read()

    assert decrypted_text == plaintext_file.read_text()


def test_encrypt_and_decrypt_file_invalid_key(tmp_files):
    """
    Test decrypting a file with an invalid key.
    """
    plaintext_file, encrypted_file, decrypted_file = tmp_files
    key = os.urandom(KEY_SIZE)
    wrong_key = os.urandom(KEY_SIZE)

    # Encrypt the file
    encrypt_file(plaintext_file, encrypted_file, key)

    # Attempt to decrypt with the wrong key
    with pytest.raises(Exception):
        decrypt_file(encrypted_file, decrypted_file, wrong_key)
