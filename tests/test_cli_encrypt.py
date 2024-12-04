import os
import json
from unittest.mock import patch
from click.testing import CliRunner
import pytest
from envcloak.cli import main


@patch("envcloak.commands.encrypt.encrypt_file")
def test_encrypt(mock_encrypt_file, runner, isolated_mock_files):
    """
    Test the `encrypt` CLI command.
    """
    input_file = isolated_mock_files / "variables.env"
    encrypted_file = isolated_mock_files / "variables.temp.enc"
    key_file = isolated_mock_files / "mykey.key"

    def mock_encrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Input file does not exist"
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "encrypted_data"}))

    mock_encrypt_file.side_effect = mock_encrypt

    result = runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(input_file),
            "--output",
            str(encrypted_file),
            "--key-file",
            str(key_file),
        ],
    )

    assert "File" in result.output
    mock_encrypt_file.assert_called_once_with(
        str(input_file), str(encrypted_file), key_file.read_bytes()
    )


@patch("envcloak.commands.encrypt.encrypt_file")
def test_encrypt_with_force(mock_encrypt_file, runner, isolated_mock_files):
    """
    Test the `encrypt` CLI command with the `--force` flag.
    """
    input_file = isolated_mock_files / "variables.env"
    existing_encrypted_file = (
        isolated_mock_files / "variables.temp.enc"
    )  # Existing file
    key_file = isolated_mock_files / "mykey.key"

    # Create a mock existing encrypted file
    existing_encrypted_file.write_text("existing content")

    def mock_encrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Input file does not exist"
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "encrypted_data"}))

    mock_encrypt_file.side_effect = mock_encrypt

    # Invoke with --force
    result = runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(input_file),
            "--output",
            str(existing_encrypted_file),
            "--key-file",
            str(key_file),
            "--force",
        ],
    )

    assert "Overwriting existing file" in result.output
    mock_encrypt_file.assert_called_once_with(
        str(input_file), str(existing_encrypted_file), key_file.read_bytes()
    )

    # Ensure the file was overwritten
    with open(existing_encrypted_file, "r") as f:
        assert json.load(f)["ciphertext"] == "encrypted_data"


@patch("envcloak.commands.encrypt.encrypt_file")
def test_encrypt_with_force_directory(mock_encrypt_file, runner, isolated_mock_files):
    """
    Test the `encrypt` CLI command with the `--force` flag for a directory.
    """
    directory = isolated_mock_files / "mock_directory"
    output_directory = isolated_mock_files / "output_directory"
    key_file = isolated_mock_files / "mykey.key"

    # Create mock files in the directory
    directory.mkdir()
    (directory / "file1.env").write_text("content1")
    (directory / "file2.env").write_text("content2")

    # Create a mock existing output directory
    output_directory.mkdir()
    (output_directory / "file1.env.enc").write_text("existing encrypted content")

    def mock_encrypt(input_path, output_path, key):
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "encrypted_data"}))

    mock_encrypt_file.side_effect = mock_encrypt

    # Invoke with --force
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
            "--force",
        ],
    )

    assert "Overwriting existing directory" in result.output
    mock_encrypt_file.assert_any_call(
        str(directory / "file1.env"),
        str(output_directory / "file1.env.enc"),
        key_file.read_bytes(),
    )
    mock_encrypt_file.assert_any_call(
        str(directory / "file2.env"),
        str(output_directory / "file2.env.enc"),
        key_file.read_bytes(),
    )


def test_encrypt_without_force_conflict(runner, isolated_mock_files):
    """
    Test the `encrypt` CLI command without the `--force` flag when a conflict exists.
    """
    input_file = isolated_mock_files / "variables.env"
    existing_encrypted_file = isolated_mock_files / "variables.temp.enc"
    key_file = isolated_mock_files / "mykey.key"

    # Create a mock existing encrypted file
    existing_encrypted_file.write_text("existing content")

    # Invoke without --force
    result = runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(input_file),
            "--output",
            str(existing_encrypted_file),
            "--key-file",
            str(key_file),
        ],
    )

    assert "already exists" in result.output
