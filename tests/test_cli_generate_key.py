import os
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
):
    """
    Test the `generate-key-from-password` CLI command with default behavior (adds to .gitignore).
    """

    # Simulate file creation in the mock
    def mock_create_key_from_password(password, output_path, salt):
        output_path.touch()  # Simulate key file creation

    mock_generate_key_from_password_file.side_effect = mock_create_key_from_password

    temp_key_file = isolated_mock_files / "temp_password_key.key"  # Temporary key file
    password = "JustGiveItATry"
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
    password = "JustGiveItATry"
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
