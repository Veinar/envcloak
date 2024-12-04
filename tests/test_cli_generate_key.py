import os
import secrets
from unittest.mock import patch
from click.testing import CliRunner
import pytest
from envcloak.cli import main

# Fixtures imported from conftest.py
# `runner` and `isolated_mock_files`


@patch("envcloak.commands.generate_key.add_to_gitignore")
@patch("envcloak.commands.generate_key.generate_key_file")
def test_generate_key_with_gitignore(
    mock_generate_key_file, mock_add_to_gitignore, runner, isolated_mock_files
):
    """
    Test the `generate-key` CLI command with default behavior (adds to .gitignore).
    """

    # Simulate file creation in the mock
    def mock_create_key_file(output_path):
        output_path.touch()  # Simulate key file creation

    mock_generate_key_file.side_effect = mock_create_key_file

    # Path to the temporary key file
    temp_key_file = isolated_mock_files / "temp_random.key"

    # Run the CLI command
    result = runner.invoke(main, ["generate-key", "--output", str(temp_key_file)])

    # Assertions
    mock_generate_key_file.assert_called_once_with(temp_key_file)
    mock_add_to_gitignore.assert_called_once_with(
        temp_key_file.parent, temp_key_file.name
    )

    # Cleanup
    if temp_key_file.exists():
        temp_key_file.unlink()


@patch("envcloak.utils.add_to_gitignore")
@patch("envcloak.commands.generate_key.generate_key_file")
def test_generate_key_no_gitignore(
    mock_generate_key_file, mock_add_to_gitignore, runner, isolated_mock_files
):
    """
    Test the `generate-key` CLI command with the `--no-gitignore` flag.
    """

    # Simulate file creation in the mock
    def mock_create_key_file(output_path):
        output_path.touch()  # Simulate key file creation

    mock_generate_key_file.side_effect = mock_create_key_file

    # Path to the temporary key file
    temp_key_file = isolated_mock_files / "temp_random.key"

    # Run the CLI command
    result = runner.invoke(
        main, ["generate-key", "--output", str(temp_key_file), "--no-gitignore"]
    )

    # Assertions
    mock_generate_key_file.assert_called_once_with(temp_key_file)
    mock_add_to_gitignore.assert_not_called()

    # Cleanup
    if temp_key_file.exists():
        temp_key_file.unlink()


@patch("envcloak.commands.generate_key_from_password.add_to_gitignore")
@patch("envcloak.commands.generate_key_from_password.generate_key_from_password_file")
def test_generate_key_from_password_with_gitignore(
    mock_generate_key_from_password_file,
    mock_add_to_gitignore,
    runner,
    isolated_mock_files,
    read_variable,
):
    """
    Test the `generate-key-from-password` CLI command with default behavior (adds to .gitignore).
    """

    # Simulate file creation in the mock
    def mock_create_key_from_password(password, output_path, salt):
        output_path.touch()  # Simulate key file creation

    mock_generate_key_from_password_file.side_effect = mock_create_key_from_password

    temp_key_file = isolated_mock_files / "temp_password_key.key"  # Temporary key file
    password = read_variable("pass1")
    salt = "e3a1c8b0d4f6e2c7a5b9d6f0c3e8f1a2"

    # Run the CLI command
    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            salt,
            "--output",
            str(temp_key_file),
        ],
    )

    # Assertions
    mock_generate_key_from_password_file.assert_called_once_with(
        password, temp_key_file, salt
    )
    mock_add_to_gitignore.assert_called_once_with(
        temp_key_file.parent, temp_key_file.name
    )

    # Cleanup
    if temp_key_file.exists():
        temp_key_file.unlink()


@patch("envcloak.utils.add_to_gitignore")
@patch("envcloak.commands.generate_key_from_password.generate_key_from_password_file")
def test_generate_key_from_password_no_gitignore(
    mock_generate_key_from_password_file,
    mock_add_to_gitignore,
    runner,
    isolated_mock_files,
    read_variable,
):
    """
    Test the `generate-key-from-password` CLI command with the `--no-gitignore` flag.
    """

    # Simulate file creation in the mock
    def mock_create_key_from_password(password, output_path, salt):
        output_path.touch()  # Simulate key file creation

    mock_generate_key_from_password_file.side_effect = mock_create_key_from_password

    # Use isolated mock files for the test
    temp_dir = isolated_mock_files
    temp_key_file = temp_dir / "temp_password_key.key"  # Temporary key file
    password = read_variable("pass1")
    salt = "e3a1c8b0d4f6e2c7a5b9d6f0c3e8f1a2"

    # Run the CLI command
    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            salt,
            "--output",
            str(temp_key_file),
            "--no-gitignore",
        ],
    )

    # Assertions
    mock_generate_key_from_password_file.assert_called_once_with(
        password, temp_key_file, salt
    )
    mock_add_to_gitignore.assert_not_called()

    # Cleanup
    if temp_key_file.exists():
        temp_key_file.unlink()


@patch("envcloak.generator.secrets.token_bytes")
@patch("envcloak.generator.derive_key")
def test_generate_key_from_password_random_salt(
    mock_derive_key,
    mock_urandom,
    runner,
    isolated_mock_files,
    read_variable,
):
    """
    Test the `generate-key-from-password` CLI command without providing a salt.
    A random salt should be generated.
    """

    # Mock random salt generation
    mock_salt = b"\xa1\xb2\xc3\xd4\xe5\xf6\x78\x90\x12\x34\x56\x78\x9a\xbc\xde\xf0"
    mock_urandom.return_value = mock_salt

    # Mock key derivation
    expected_key = b"mocked_key_data"
    mock_derive_key.return_value = expected_key

    temp_key_file = isolated_mock_files / "temp_password_key.key"
    password = read_variable("pass5")

    # Run the CLI command without a salt
    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--output",
            str(temp_key_file),
        ],
    )

    # Verify behavior
    assert temp_key_file.exists(), "The key file should be created."
    assert (
        temp_key_file.read_bytes() == expected_key
    ), "The key file should contain the derived key."
    mock_urandom.assert_called_once_with(16)
    mock_derive_key.assert_called_once_with(password, mock_salt)


def test_generate_key_from_password_invalid_salt(
    runner,
    isolated_mock_files,
    read_variable,
):
    """
    Test the `generate-key-from-password` CLI command with an invalid salt (not 32 hex characters).
    """

    temp_key_file = isolated_mock_files / "temp_password_key.key"
    password = read_variable("pass5")
    invalid_salt = "a1b2c3"  # Not 32 hex characters

    # Run the CLI command with an invalid salt
    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            invalid_salt,
            "--output",
            str(temp_key_file),
        ],
    )

    # Verify behavior
    assert "Salt must be a 16-byte hex string (32 characters)." in result.output
    assert not temp_key_file.exists(), "The key file should not be created."


@patch("envcloak.generator.derive_key")
def test_generate_key_from_password_valid_salt(
    mock_derive_key,
    runner,
    isolated_mock_files,
    read_variable,
):
    """
    Test the `generate-key-from-password` CLI command with a valid salt.
    """

    # Mock key derivation
    valid_salt = b"\xa1\xb2\xc3\xd4\xe5\xf6\x78\x90\x12\x34\x56\x78\x9a\xbc\xde\xf0"
    expected_key = b"mocked_key_data"
    mock_derive_key.return_value = expected_key

    temp_key_file = isolated_mock_files / "temp_password_key.key"
    password = read_variable("pass5")
    salt_hex = valid_salt.hex()

    # Run the CLI command with a valid salt
    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            salt_hex,
            "--output",
            str(temp_key_file),
        ],
    )

    # Verify behavior
    assert temp_key_file.exists(), "The key file should be created."
    assert (
        temp_key_file.read_bytes() == expected_key
    ), "The key file should contain the derived key."
    mock_derive_key.assert_called_once_with(password, valid_salt)


@patch("envcloak.generator.derive_key")
def test_generate_key_from_password_file_creation(
    mock_derive_key,
    runner,
    isolated_mock_files,
    read_variable,
):
    """
    Test the `generate-key-from-password` CLI command ensures the output file is created.
    """

    # Mock key derivation
    expected_key = b"mocked_key_data"
    mock_derive_key.return_value = expected_key

    # Define a non-existent directory and file for the test
    temp_dir = isolated_mock_files / "non_existent_directory"
    temp_key_file = temp_dir / "temp_password_key.key"
    password = read_variable("pass5")
    salt = "a1b2c3d4e5f67890123456789abcdef0"

    # Run the CLI command
    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            salt,
            "--output",
            str(temp_key_file),
        ],
    )

    # Verify behavior
    assert temp_key_file.exists(), "The key file should be created."
    assert (
        temp_key_file.read_bytes() == expected_key
    ), "The key file should contain the derived key."
    mock_derive_key.assert_called_once_with(password, bytes.fromhex(salt))
