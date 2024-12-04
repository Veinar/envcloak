import os
import secrets
import json
from unittest.mock import patch
from click.testing import CliRunner
import pytest
from envcloak.cli import main

# Fixtures imported from conftest.py
# `runner` and `isolated_mock_files`


@patch("envcloak.commands.rotate_keys.decrypt_file")
@patch("envcloak.commands.rotate_keys.encrypt_file")
def test_rotate_keys(mock_encrypt_file, mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `rotate-keys` CLI command.
    """
    encrypted_file = isolated_mock_files / "variables.env.enc"
    temp_decrypted_file = isolated_mock_files / "temp_variables.decrypted"
    key_file = isolated_mock_files / "mykey.key"
    temp_new_key_file = key_file.with_name("temp_newkey.key")
    temp_new_key_file.write_bytes(secrets.token_bytes(32))

    tmp_file = str(temp_decrypted_file) + ".tmp"

    def mock_decrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Encrypted file does not exist"
        with open(output_path, "w") as f:
            f.write("Decrypted content")

    def mock_encrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Decrypted file does not exist"
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "re-encrypted_data"}))

    mock_decrypt_file.side_effect = mock_decrypt
    mock_encrypt_file.side_effect = mock_encrypt

    result = runner.invoke(
        main,
        [
            "rotate-keys",
            "--input",
            str(encrypted_file),
            "--old-key-file",
            str(key_file),
            "--new-key-file",
            str(temp_new_key_file),
            "--output",
            str(temp_decrypted_file),
        ],
    )

    assert "Keys rotated" in result.output
    mock_decrypt_file.assert_called_once_with(
        str(encrypted_file), tmp_file, key_file.read_bytes()
    )
    mock_encrypt_file.assert_called_once_with(
        tmp_file, str(temp_decrypted_file), temp_new_key_file.read_bytes()
    )

    # Ensure temporary file was cleaned up
    assert not os.path.exists(tmp_file), f"Temporary file {tmp_file} was not deleted"

    # Cleanup
    if temp_decrypted_file.exists():
        temp_decrypted_file.unlink()
    if temp_new_key_file.exists():
        temp_new_key_file.unlink()
