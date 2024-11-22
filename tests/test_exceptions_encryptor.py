import pytest
import os
import json
from envcloak.exceptions import (
    InvalidSaltException,
    InvalidKeyException,
    EncryptionException,
    DecryptionException,
    FileEncryptionException,
    FileDecryptionException,
)
from envcloak.encryptor import (
    derive_key,
    generate_salt,
    encrypt,
    decrypt,
    encrypt_file,
    decrypt_file,
)
from envcloak.constants import SALT_SIZE, KEY_SIZE, NONCE_SIZE


def test_derive_key_invalid_salt():
    password = "JustGiveItATry"
    invalid_salt = os.urandom(SALT_SIZE - 1)  # Invalid salt size

    with pytest.raises(InvalidSaltException, match="Expected salt of size"):
        derive_key(password, invalid_salt)


def test_derive_key_invalid_password():
    invalid_password = None  # Password must be a string
    salt = os.urandom(SALT_SIZE)

    with pytest.raises(InvalidKeyException, match="object has no attribute 'encode'"):
        derive_key(invalid_password, salt)


def test_generate_salt_error(monkeypatch):
    # Simulate os.urandom throwing an exception
    monkeypatch.setattr(
        os,
        "urandom",
        lambda _: (_ for _ in ()).throw(OSError("Random generation error")),
    )

    with pytest.raises(
        EncryptionException, match="Failed to generate salt: Random generation error"
    ):
        generate_salt()


def test_encrypt_invalid_key():
    data = "Sensitive data"
    invalid_key = os.urandom(KEY_SIZE - 1)  # Key must be 32 bytes

    with pytest.raises(EncryptionException, match="Invalid key size"):
        encrypt(data, invalid_key)


def test_decrypt_invalid_data():
    invalid_encrypted_data = {"ciphertext": "wrong", "nonce": "wrong", "tag": "wrong"}
    key = os.urandom(KEY_SIZE)

    with pytest.raises(
        DecryptionException,
        match=r"Error: Failed to decrypt the data\.\nDetails: Invalid base64-encoded string.*",
    ):
        decrypt(invalid_encrypted_data, key)


def test_encrypt_file_error(tmp_path):
    input_file = tmp_path / "nonexistent.txt"  # File does not exist
    output_file = tmp_path / "output.enc"
    key = os.urandom(KEY_SIZE)

    with pytest.raises(FileEncryptionException, match="No such file or directory"):
        encrypt_file(str(input_file), str(output_file), key)


def test_decrypt_file_error(tmp_path):
    input_file = tmp_path / "nonexistent.enc"  # File does not exist
    output_file = tmp_path / "output.txt"
    key = os.urandom(KEY_SIZE)

    with pytest.raises(FileDecryptionException, match="No such file or directory"):
        decrypt_file(str(input_file), str(output_file), key)


def test_decrypt_file_invalid_content(tmp_path):
    input_file = tmp_path / "invalid.enc"
    output_file = tmp_path / "output.txt"
    key = os.urandom(KEY_SIZE)

    # Write invalid encrypted content to the input file
    input_file.write_text("not a valid encrypted file", encoding="utf-8")

    with pytest.raises(
        FileDecryptionException,
        match=r"Error: Failed to decrypt the file\.\nDetails: Expecting value: line 1 column 1 \(char 0\)",
    ):
        decrypt_file(str(input_file), str(output_file), key)
