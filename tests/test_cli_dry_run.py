import os
from pathlib import Path
import pytest
import shutil
import tempfile
import secrets
from click.testing import CliRunner
from envcloak.cli import main



@pytest.fixture
def mock_files(isolated_mock_files):
    """
    Fixture for using isolated mock files for dry-run tests.
    """
    input_file = isolated_mock_files / "variables.env"
    encrypted_file = isolated_mock_files / "variables.env.enc"
    key_file = isolated_mock_files / "mykey.key"
    directory = isolated_mock_files
    return input_file, encrypted_file, key_file, directory


def test_encrypt_dry_run_single_file(runner, mock_files):
    """
    Test the `encrypt` CLI command with a single input file in dry-run mode.
    """
    input_file, _, key_file, _ = mock_files
    output_file = str(input_file) + ".enc"  # This file already exists in mock_files

    result = runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(input_file),
            "--output",
            output_file,
            "--key-file",
            str(key_file),
            "--dry-run",
        ],
    )

    assert "Output path already exists" in result.output


def test_encrypt_dry_run_directory(runner, mock_files):
    """
    Test the `encrypt` CLI command with a directory in dry-run mode.
    """
    _, _, key_file, directory = mock_files
    output_directory = directory / "output"

    result = runner.invoke(
        main,
        [
            "encrypt",
            "--directory",
            str(directory),
            "--output",
            str(output_directory),
            "--key-file",
            str(key_file),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Dry-run checks passed successfully." in result.output
    assert f"Input directory does not exist: {directory}" not in result.output


def test_decrypt_dry_run_single_file(runner, mock_files):
    """
    Test the `decrypt` CLI command with a single input file in dry-run mode.
    """
    _, encrypted_file, key_file, _ = mock_files
    output_file = str(encrypted_file).replace(".enc", ".decrypted")

    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(encrypted_file),
            "--output",
            output_file,
            "--key-file",
            str(key_file),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Dry-run checks passed successfully." in result.output
    assert f"Encrypted file does not exist: {encrypted_file}" not in result.output


def test_generate_key_dry_run(runner, isolated_mock_files):
    """
    Test the `generate-key` CLI command in dry-run mode.
    """
    key_file = isolated_mock_files / "random.key"

    result = runner.invoke(
        main,
        [
            "generate-key",
            "--output",
            str(key_file),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Dry-run checks passed successfully." in result.output
    assert f"Output path already exists: {key_file}" not in result.output


def test_generate_key_from_password_dry_run(runner, isolated_mock_files, read_variable):
    """
    Test the `generate-key-from-password` CLI command in dry-run mode.
    """
    key_file = isolated_mock_files / "password.key"
    password = read_variable("pass4")
    salt = "a3b4c5d6e7f8f9a0a1b2c3d4e5f6a7b8"  # Valid 16-byte hex string

    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            salt,
            "--output",
            str(key_file),
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Dry-run checks passed successfully." in result.output


def test_rotate_keys_dry_run(runner, mock_files):
    """
    Test the `rotate-keys` CLI command in dry-run mode.
    """
    _, encrypted_file, key_file, directory = mock_files
    new_key_file = directory / "newkey.key"
    new_key_file.write_bytes(secrets.token_bytes(32))
    output_file = str(encrypted_file).replace(".enc", ".rotated")

    result = runner.invoke(
        main,
        [
            "rotate-keys",
            "--input",
            str(encrypted_file),
            "--old-key-file",
            str(key_file),
            "--new-key-file",
            str(new_key_file),
            "--output",
            output_file,
            "--dry-run",
        ],
    )

    assert result.exit_code == 0
    assert "Dry-run checks passed successfully." in result.output
    assert f"Encrypted file does not exist: {encrypted_file}" not in result.output
