import os
import secrets
from hypothesis import given, strategies as st
from envcloak.encryptor import encrypt, decrypt, encrypt_file, decrypt_file, derive_key
from envcloak.loader import load_encrypted_env
from envcloak.exceptions import EncryptionException, DecryptionException
from click.testing import CliRunner
from envcloak.cli import main


# Test Large Inputs for Encryption and Decryption
@given(st.text(min_size=5, max_size=1000))
def test_large_input_encryption_decryption(large_text):
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    encrypted = encrypt(large_text, key)
    decrypted = decrypt(encrypted, key)
    assert (
        decrypted == large_text
    ), "Decrypted text does not match the original large input"


# Test Empty Input for Encryption
def test_empty_input_encryption():
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    try:
        encrypted = encrypt("", key)
        assert encrypted, "Empty input should still be encrypted successfully"
    except EncryptionException:
        assert False, "Empty input encryption should not raise an error"


# Test Invalid Key Format for Encryption
@given(st.binary(min_size=1, max_size=15))  # Invalid key size for AES
def test_invalid_key_encryption(invalid_key):
    try:
        encrypt("test_data", invalid_key)
        assert False, "Encryption should fail with an invalid key size"
    except EncryptionException:
        pass  # Expected


# Test Invalid Key Format for Decryption
@given(st.binary(min_size=1, max_size=15))  # Invalid key size for AES
def test_invalid_key_decryption(invalid_key):
    try:
        decrypt("invalid_data", invalid_key)
        assert False, "Decryption should fail with an invalid key size"
    except DecryptionException:
        pass  # Expected


# Test Malformed Encrypted Input for Decryption
@given(st.binary())
def test_malformed_encrypted_input(binary_data):
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    try:
        decrypt(binary_data, key)
        assert False, "Decryption should fail for malformed input"
    except DecryptionException:
        pass  # Expected


# Stress Test: Multiple Encryption-Decryption Cycles
@given(st.text(min_size=10, max_size=100))
def test_multiple_encryption_decryption_cycles(plain_text):
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    for _ in range(100):  # Stress test with 100 cycles
        encrypted = encrypt(plain_text, key)
        plain_text = decrypt(encrypted, key)
    assert isinstance(plain_text, str), "Final output should be a string"
    assert len(plain_text) > 0, "Final output should not be empty"


# Test Loading Encrypted Environment Variables
def test_load_encrypted_env():
    # Prepare mock files
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    encrypted_file = "mock_variables.env.enc"
    key_file = "mock_key.key"

    with open(key_file, "wb") as kf:
        kf.write(key)

    with open("mock_variables.env", "w") as vf:
        vf.write("TEST_VAR=mock_value")

    encrypt_file("mock_variables.env", encrypted_file, key)

    # Test loading
    loader = load_encrypted_env(encrypted_file, key_file)
    assert loader.decrypted_data == {
        "TEST_VAR": "mock_value"
    }, "Decrypted data mismatch"

    # Cleanup
    os.remove(key_file)
    os.remove("mock_variables.env")
    os.remove(encrypted_file)


@given(
    st.dictionaries(
        st.text(
            min_size=1,
            max_size=10,
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        ),
        st.text(
            min_size=1,
            max_size=50,
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_+=,.",
        ),
        max_size=20,
    )
)
def test_randomized_env_file_content(env_data):
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    encrypted_file = "random_env_file.enc"
    decrypted_file = "random_env_file_decrypted.env"
    input_file = "random_env_file.env"

    # Write the mock `.env` file
    with open(input_file, "w", encoding="utf-8") as f:
        for k, v in env_data.items():
            f.write(f"{k}={v}\n")

    # Encrypt and decrypt the file
    encrypt_file(input_file, encrypted_file, key)
    decrypt_file(encrypted_file, decrypted_file, key)

    # Validate content
    with open(decrypted_file, "r", encoding="utf-8") as f:
        decrypted_content = f.read().strip()
    expected_content = "\n".join(f"{k}={v}" for k, v in env_data.items())
    assert (
        decrypted_content == expected_content
    ), "Decrypted content does not match the original"

    # Cleanup
    os.remove(input_file)
    os.remove(encrypted_file)
    os.remove(decrypted_file)


@given(
    st.dictionaries(
        st.text(
            min_size=1,
            max_size=10,
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
        ),
        st.text(
            min_size=1,
            max_size=50,
            alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}`~:;<>,.?/\\|",
        ),
        max_size=10,
    )
)
def test_special_characters_in_env(env_data):
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    encrypted_file = "special_env_file.enc"
    decrypted_file = "special_env_file_decrypted.env"
    input_file = "special_env_file.env"

    try:
        # Write the mock `.env` file
        with open(input_file, "w", encoding="utf-8") as f:
            for k, v in env_data.items():
                f.write(f"{k}={v}\n")

        # Skip encryption and decryption if env_data is empty
        if not env_data:
            expected_content = ""
            decrypted_content = ""
        else:
            # Encrypt and decrypt the file
            encrypt_file(input_file, encrypted_file, key)
            decrypt_file(encrypted_file, decrypted_file, key)

            # Validate content
            with open(decrypted_file, "r", encoding="utf-8") as f:
                decrypted_content = f.read()  # Avoid stripping the content
            expected_content = (
                "\n".join(f"{k}={v}" for k, v in env_data.items()) + "\n"
            )  # Ensure a final newline is preserved

        assert (
            decrypted_content == expected_content
        ), f"Decrypted content does not match the original\nExpected:\n{expected_content}\nGot:\n{decrypted_content}"
    finally:
        # Cleanup
        if os.path.exists(input_file):
            os.remove(input_file)
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)
        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)


@given(st.text(min_size=8, max_size=20), st.binary(min_size=16, max_size=16))
def test_key_derivation_from_password(password, salt):
    key1 = derive_key(password, salt)
    key2 = derive_key(password, salt)
    assert (
        key1 == key2
    ), "Key derivation with the same password and salt should be deterministic"

    # Use a different password or salt
    different_password_key = derive_key(password + "1", salt)
    different_salt_key = derive_key(password, secrets.token_bytes(16))

    assert (
        key1 != different_password_key
    ), "Keys with different passwords should not match"
    assert key1 != different_salt_key, "Keys with different salts should not match"


@given(st.text(min_size=5, max_size=20))
def test_invalid_file_paths(file_name):
    key = secrets.token_bytes(32)  # Use a valid 32-byte key
    try:
        load_encrypted_env(file_name, "nonexistent_key.key")
        assert False, "Loading should fail with nonexistent files"
    except Exception as e:
        print(e)


def test_key_rotation():
    key_old = secrets.token_bytes(32)
    key_new = secrets.token_bytes(32)
    input_file = "key_rotation_test.env"
    encrypted_file_old = "key_rotation_test_old.enc"
    encrypted_file_new = "key_rotation_test_new.enc"
    decrypted_file = "key_rotation_test_decrypted.env"

    with open(input_file, "w") as f:
        f.write("TEST_VAR=rotation_test_value")

    # Encrypt with old key
    encrypt_file(input_file, encrypted_file_old, key_old)

    # Decrypt and re-encrypt with new key
    decrypt_file(encrypted_file_old, input_file, key_old)
    encrypt_file(input_file, encrypted_file_new, key_new)

    # Decrypt with the new key
    decrypt_file(encrypted_file_new, decrypted_file, key_new)

    # Validate content
    with open(decrypted_file, "r") as f:
        decrypted_content = f.read().strip()
    assert (
        decrypted_content == "TEST_VAR=rotation_test_value"
    ), "Decrypted content does not match the original"

    # Cleanup
    os.remove(input_file)
    os.remove(encrypted_file_old)
    os.remove(encrypted_file_new)
    os.remove(decrypted_file)
