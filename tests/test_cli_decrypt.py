import os
import json
from unittest.mock import patch
from click.testing import CliRunner
import pytest
from envcloak.cli import main
from envcloak.exceptions import FileDecryptionException

# Fixtures imported from conftest.py
# `mock_files` and `runner`


@patch("envcloak.commands.decrypt.decrypt_file")
def test_decrypt(mock_decrypt_file, runner, mock_files):
    """
    Test the `decrypt` CLI command.
    """
    _, encrypted_file, decrypted_file, key_file = mock_files

    # Use a unique temporary output file
    temp_decrypted_file = decrypted_file.with_name("variables.temp.decrypted")

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        print(
            f"mock_decrypt called with: {input_path}, {output_path}, {key}, {validate_integrity}"
        )
        assert os.path.exists(input_path), "Encrypted file does not exist"
        assert isinstance(
            validate_integrity, bool
        ), "validate_integrity must be a boolean"
        with open(output_path, "w") as f:
            f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")

    mock_decrypt_file.side_effect = mock_decrypt

    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(encrypted_file),
            "--output",
            str(temp_decrypted_file),
            "--key-file",
            str(key_file),
            "--skip-sha-validation",
        ],
    )

    assert "File" in result.output
    mock_decrypt_file.assert_called_once_with(
        str(encrypted_file),
        str(temp_decrypted_file),
        key_file.read_bytes(),
        validate_integrity=False,
    )

    # Clean up: Remove temp decrypted file
    if temp_decrypted_file.exists():
        temp_decrypted_file.unlink()


@patch("envcloak.commands.decrypt.decrypt_file")
def test_decrypt_with_force(mock_decrypt_file, runner, mock_files):
    """
    Test the `decrypt` CLI command with the `--force` flag.
    """
    _, encrypted_file, decrypted_file, key_file = mock_files

    # Create a mock existing decrypted file
    decrypted_file.write_text("existing content")

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        assert os.path.exists(input_path), "Encrypted file does not exist"
        with open(output_path, "w") as f:
            f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")

    mock_decrypt_file.side_effect = mock_decrypt

    # Invoke with --force
    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(encrypted_file),
            "--output",
            str(decrypted_file),
            "--key-file",
            str(key_file),
            "--force",
            "--skip-sha-validation",
        ],
    )

    assert "Overwriting existing file" in result.output
    mock_decrypt_file.assert_called_once_with(
        str(encrypted_file),
        str(decrypted_file),
        key_file.read_bytes(),
        validate_integrity=False,
    )

    # Ensure the file was overwritten
    with open(decrypted_file, "r") as f:
        assert f.read() == "DB_USERNAME=example_user\nDB_PASSWORD=example_pass"


@patch("envcloak.commands.decrypt.decrypt_file")
def test_decrypt_with_force_directory(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `decrypt` CLI command with the `--force` flag for a directory.
    """
    directory = isolated_mock_files / "mock_directory"
    output_directory = isolated_mock_files / "output_directory"
    key_file = isolated_mock_files / "mykey.key"

    # Create mock encrypted files in the directory
    directory.mkdir()
    (directory / "file1.env.enc").write_text("encrypted content1")
    (directory / "file2.env.enc").write_text("encrypted content2")

    # Create a mock existing output directory
    output_directory.mkdir()
    (output_directory / "file1.env").write_text("existing decrypted content")

    # Write a mock key file
    key_file.write_bytes(b"mock_key")

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        with open(output_path, "w") as f:
            f.write("decrypted content")

    mock_decrypt_file.side_effect = mock_decrypt

    # Invoke with --force and --recursion
    result = runner.invoke(
        main,
        [
            "decrypt",
            "--directory",
            str(directory),
            "--output",
            str(output_directory),
            "--key-file",
            str(key_file),
            "--force",
            "--recursion",  # Enable recursion
            "--skip-sha-validation",
            "--debug",
        ],
    )

    # Check that output mentions overwriting existing files
    assert "Overwriting existing directory" in result.output

    # Verify that decrypt_file was called for each input file
    mock_decrypt_file.assert_any_call(
        str(directory / "file1.env.enc"),
        str(output_directory / "file1.env"),
        b"mock_key",
        validate_integrity=False,
    )
    mock_decrypt_file.assert_any_call(
        str(directory / "file2.env.enc"),
        str(output_directory / "file2.env"),
        b"mock_key",
        validate_integrity=False,
    )
    # Ensure the output is clean and correct
    assert (output_directory / "file1.env").read_text() == "decrypted content"
    assert (output_directory / "file2.env").read_text() == "decrypted content"


def test_decrypt_without_force_conflict(runner, mock_files):
    """
    Test the `decrypt` CLI command without the `--force` flag when a conflict exists.
    """
    _, encrypted_file, decrypted_file, key_file = mock_files

    # Create a mock existing decrypted file
    decrypted_file.write_text("existing content")

    # Invoke without --force
    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(encrypted_file),
            "--output",
            str(decrypted_file),
            "--key-file",
            str(key_file),
            "--skip-sha-validation",
        ],
    )

    assert "already exists" in result.output


@patch("envcloak.commands.decrypt.decrypt_file")
def test_decrypt_sha_file(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `decrypt` CLI command for a file encrypted with SHA.
    """
    sha_file = isolated_mock_files / "sha_variables.env.enc"
    decrypted_file = isolated_mock_files / "sha_variables_decrypted.env"
    key_file = isolated_mock_files / "mykey.key"

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        assert validate_integrity is True, "SHA validation must be enabled"
        with open(output_path, "w") as f:
            f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")

    mock_decrypt_file.side_effect = mock_decrypt

    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(sha_file),
            "--output",
            str(decrypted_file),
            "--key-file",
            str(key_file),
        ],
    )

    assert "File" in result.output
    mock_decrypt_file.assert_called_once_with(
        str(sha_file),
        str(decrypted_file),
        key_file.read_bytes(),
        validate_integrity=True,
    )


@patch("envcloak.commands.decrypt.decrypt_file")
def test_decrypt_sha_file_skip_validation(
    mock_decrypt_file, runner, isolated_mock_files
):
    """
    Test the `decrypt` CLI command for a file encrypted with SHA with `--skip-sha-validation`.
    """
    sha_file = isolated_mock_files / "sha_variables.env.enc"
    decrypted_file = isolated_mock_files / "sha_variables_decrypted.env"
    key_file = isolated_mock_files / "mykey.key"

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        assert validate_integrity is False, "SHA validation must be skipped"
        with open(output_path, "w") as f:
            f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")

    mock_decrypt_file.side_effect = mock_decrypt

    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(sha_file),
            "--output",
            str(decrypted_file),
            "--key-file",
            str(key_file),
            "--skip-sha-validation",
        ],
    )

    assert "File" in result.output
    mock_decrypt_file.assert_called_once_with(
        str(sha_file),
        str(decrypted_file),
        key_file.read_bytes(),
        validate_integrity=False,
    )


@patch("envcloak.commands.decrypt.decrypt_file")
def test_decrypt_modified_sha_file(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `decrypt` CLI command for a modified SHA file.
    """
    modified_sha_file = isolated_mock_files / "sha_variables_modified.env.enc"
    decrypted_file = isolated_mock_files / "sha_variables_decrypted.env"
    key_file = isolated_mock_files / "mykey.key"

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        raise FileDecryptionException(
            details="Integrity check failed! The file may have been tampered with or corrupted."
        )

    mock_decrypt_file.side_effect = mock_decrypt

    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(modified_sha_file),
            "--output",
            str(decrypted_file),
            "--key-file",
            str(key_file),
        ],
    )

    assert (
        "Error during decryption: Error: Failed to decrypt the file.\n"
        "Details: Integrity check failed! The file may have been tampered with or corrupted."
        in result.output
    )


@patch("envcloak.commands.decrypt.decrypt_file")
def test_decrypt_different_file_types_with_sha(
    mock_decrypt_file, runner, isolated_mock_files
):
    """
    Test the `decrypt` CLI command for various file types with SHA validation.
    """
    file_types = ["json", "yaml", "xml"]
    for file_type in file_types:
        sha_file = isolated_mock_files / f"sha_variables.{file_type}.enc"
        decrypted_file = isolated_mock_files / f"sha_variables_decrypted.{file_type}"
        key_file = isolated_mock_files / "mykey.key"

        def mock_decrypt(input_path, output_path, key, validate_integrity=True):
            assert validate_integrity is True, "SHA validation must be enabled"
            with open(output_path, "w") as f:
                f.write(f"Decrypted content of {file_type}")

        mock_decrypt_file.side_effect = mock_decrypt

        result = runner.invoke(
            main,
            [
                "decrypt",
                "--input",
                str(sha_file),
                "--output",
                str(decrypted_file),
                "--key-file",
                str(key_file),
            ],
        )

        assert f"File {sha_file} decrypted -> {decrypted_file}" in result.output
        mock_decrypt_file.assert_any_call(
            str(sha_file),
            str(decrypted_file),
            key_file.read_bytes(),
            validate_integrity=True,
        )
