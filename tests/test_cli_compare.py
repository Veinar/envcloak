import os
import uuid
from unittest.mock import patch
from click.testing import CliRunner
import pytest
from envcloak.cli import main

# Fixtures imported from conftest.py
# `runner` and `isolated_mock_files`


@patch("envcloak.commands.decrypt.decrypt_file")
def test_compare_files(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `compare` CLI command for two encrypted files.
    """
    file1 = isolated_mock_files / "variables1.env"
    file2 = isolated_mock_files / "variables2.env"
    enc_file1 = isolated_mock_files / "variables1.env.enc"
    enc_file2 = isolated_mock_files / "variables2.env.enc"
    key_file = isolated_mock_files / "mykey.key"

    # Create plaintext files with different content
    file1.write_text("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")
    file2.write_text("DB_USERNAME=example_user\nDB_PASSWORD=wrong_pass")

    # Generate the key using the CLI
    runner.invoke(main, ["generate-key", "--output", str(key_file)])

    # Encrypt the plaintext files using the CLI
    runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(file1),
            "--output",
            str(enc_file1),
            "--key-file",
            str(key_file),
        ],
    )
    runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(file2),
            "--output",
            str(enc_file2),
            "--key-file",
            str(key_file),
        ],
    )

    # Mock decryption behavior
    def mock_decrypt(input_path, output_path, key):
        if "variables1" in str(input_path):
            with open(output_path, "w") as f:
                f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")
        elif "variables2" in str(input_path):
            with open(output_path, "w") as f:
                f.write("DB_USERNAME=example_user\nDB_PASSWORD=wrong_pass")

    mock_decrypt_file.side_effect = mock_decrypt

    # Invoke the compare command
    result = runner.invoke(
        main,
        [
            "compare",
            "--file1",
            str(enc_file1),
            "--file2",
            str(enc_file2),
            "--key1",
            str(key_file),
        ],
    )

    assert "DB_PASSWORD=example_pass" in result.output
    assert "DB_PASSWORD=wrong_pass" in result.output


@patch("envcloak.commands.decrypt.decrypt_file")
def test_compare_directories(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `compare` CLI command for two encrypted directories.
    """
    dir1 = isolated_mock_files / "dir1"
    dir2 = isolated_mock_files / "dir2"
    key_file = isolated_mock_files / f"mykey_{uuid.uuid4().hex}.key"

    # Create directories
    dir1.mkdir()
    dir2.mkdir()

    # Create plaintext files
    (dir1 / "file1.env").write_text(
        "DB_USERNAME=example_user\nDB_PASSWORD=example_pass"
    )
    (dir1 / "file2.env").write_text(
        "DB_USERNAME=example_user\nDB_PASSWORD=another_pass"
    )
    (dir2 / "file1.env").write_text(
        "DB_USERNAME=example_user\nDB_PASSWORD=example_pass"
    )
    (dir2 / "file3.env").write_text(
        "DB_USERNAME=example_user\nDB_PASSWORD=missing_pass"
    )

    try:
        # Generate the key
        runner.invoke(main, ["generate-key", "--output", str(key_file)])

        # Encrypt files in both directories
        for file in dir1.iterdir():
            enc_file = dir1 / (file.name + ".enc")
            runner.invoke(
                main,
                [
                    "encrypt",
                    "--input",
                    str(file),
                    "--output",
                    str(enc_file),
                    "--key-file",
                    str(key_file),
                ],
            )
            file.unlink()  # Remove plaintext file

        for file in dir2.iterdir():
            enc_file = dir2 / (file.name + ".enc")
            runner.invoke(
                main,
                [
                    "encrypt",
                    "--input",
                    str(file),
                    "--output",
                    str(enc_file),
                    "--key-file",
                    str(key_file),
                ],
            )
            file.unlink()  # Remove plaintext file

        # Mock decryption behavior
        def mock_decrypt(input_path, output_path, key):
            if "file1" in str(input_path):
                with open(output_path, "w") as f:
                    f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")
            elif "file2" in str(input_path):
                with open(output_path, "w") as f:
                    f.write("DB_USERNAME=example_user\nDB_PASSWORD=another_pass")
            elif "file3" in str(input_path):
                with open(output_path, "w") as f:
                    f.write("DB_USERNAME=example_user\nDB_PASSWORD=missing_pass")

        mock_decrypt_file.side_effect = mock_decrypt

        # Invoke the compare command
        result = runner.invoke(
            main,
            [
                "compare",
                "--file1",
                str(dir1),
                "--file2",
                str(dir2),
                "--key1",
                str(key_file),
            ],
        )

        # Verify output
        expected_output = "\n".join(
            [
                "File present in File1 but missing in File2: file2.env.enc",
                "File present in File2 but missing in File1: file3.env.enc",
            ]
        )
        assert expected_output in result.output
    finally:
        # Cleanup the key file
        key_file.unlink(missing_ok=True)


@patch("envcloak.commands.decrypt.decrypt_file")
def test_compare_non_compliant_files(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `compare` CLI command for non-compliant (invalid encryption) files.
    """
    file1 = isolated_mock_files / "invalid1.env.enc"
    file2 = isolated_mock_files / "invalid2.env.enc"
    key_file = isolated_mock_files / f"mykey_{uuid.uuid4().hex}.key"

    # Create non-compliant encrypted files (invalid encryption data)
    file1.write_text("non-compliant content1")
    file2.write_text("non-compliant content2")

    try:
        # Generate the key
        runner.invoke(main, ["generate-key", "--output", str(key_file)])

        # Mock decryption behavior to raise an exception for invalid encryption
        def mock_decrypt(input_path, output_path, key):
            raise Exception("Failed to decrypt the file.")

        mock_decrypt_file.side_effect = mock_decrypt

        # Invoke the compare command
        result = runner.invoke(
            main,
            [
                "compare",
                "--file1",
                str(file1),
                "--file2",
                str(file2),
                "--key1",
                str(key_file),
            ],
        )

        # Verify output
        assert "Failed to decrypt the file." in result.output
    finally:
        # Cleanup the key file
        key_file.unlink(missing_ok=True)


@patch("envcloak.commands.decrypt.decrypt_file")
def test_compare_partially_same_files(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `compare` CLI command for files with partially matching content.
    """
    file1 = isolated_mock_files / "variables1.env"
    file2 = isolated_mock_files / "variables2.env"
    enc_file1 = isolated_mock_files / "variables1.env.enc"
    enc_file2 = isolated_mock_files / "variables2.env.enc"
    key_file = isolated_mock_files / "mykey.key"

    # Create plaintext files with partially matching content
    file1.write_text("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")
    file2.write_text("DB_USERNAME=example_user\nDB_PASSWORD=different_pass")

    # Generate the key
    runner.invoke(main, ["generate-key", "--output", str(key_file)])

    # Encrypt both files
    runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(file1),
            "--output",
            str(enc_file1),
            "--key-file",
            str(key_file),
        ],
    )
    runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(file2),
            "--output",
            str(enc_file2),
            "--key-file",
            str(key_file),
        ],
    )

    # Mock decryption behavior
    def mock_decrypt(input_path, output_path, key):
        if "variables1" in str(input_path):
            with open(output_path, "w") as f:
                f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")
        elif "variables2" in str(input_path):
            with open(output_path, "w") as f:
                f.write("DB_USERNAME=example_user\nDB_PASSWORD=different_pass")

    mock_decrypt_file.side_effect = mock_decrypt

    # Invoke the compare command
    result = runner.invoke(
        main,
        [
            "compare",
            "--file1",
            str(enc_file1),
            "--file2",
            str(enc_file2),
            "--key1",
            str(key_file),
        ],
    )

    assert "DB_PASSWORD=example_pass" in result.output
    assert "DB_PASSWORD=different_pass" in result.output


@patch("envcloak.commands.decrypt.decrypt_file")
def test_key_file_not_found_exception(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `compare` CLI command raises KeyFileNotFoundException when the key file is missing.
    """
    enc_file1 = isolated_mock_files / "variables.env.enc"
    enc_file2 = isolated_mock_files / "variables_modified.env.enc"
    missing_key = isolated_mock_files / "missing.key"  # Non-existent key file

    # Invoke the compare command with a missing key file
    result = runner.invoke(
        main,
        [
            "compare",
            "--file1",
            str(enc_file1),
            "--file2",
            str(enc_file2),
            "--key1",
            str(missing_key),
        ],
    )

    # Verify that the appropriate error is raised
    assert "Key file not found" in result.output


@patch("envcloak.commands.decrypt.decrypt_file")
def test_encrypted_file_not_found_exception(
    mock_decrypt_file, runner, isolated_mock_files
):
    """
    Test the `compare` CLI command raises EncryptedFileNotFoundException when a file is missing.
    """
    missing_file = (
        isolated_mock_files / "missing_file.env.enc"
    )  # Non-existent encrypted file
    valid_key = isolated_mock_files / "mykey.key"  # Existing key file

    # Invoke the compare command with a missing encrypted file
    result = runner.invoke(
        main,
        [
            "compare",
            "--file1",
            str(missing_file),
            "--file2",
            str(missing_file),
            "--key1",
            str(valid_key),
        ],
    )

    # Verify that the appropriate error is raised
    assert "Encrypted file validation error: Error: Invalid input path" in result.output


@patch("envcloak.commands.decrypt.decrypt_file")
def test_invalid_path_exception(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `compare` CLI command raises EncryptedFileNotFoundException for invalid paths.
    """
    invalid_path = isolated_mock_files / "invalid_path"  # Non-existent path
    valid_key = isolated_mock_files / "mykey.key"  # Existing key file

    # Invoke the compare command with an invalid path
    result = runner.invoke(
        main,
        [
            "compare",
            "--file1",
            str(invalid_path),
            "--file2",
            str(invalid_path),
            "--key1",
            str(valid_key),
        ],
    )

    # Verify that the appropriate error is raised
    assert "Invalid input path" in result.output


@patch("envcloak.commands.decrypt.decrypt_file")
def test_directory_not_found_exception(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `compare` CLI command raises EncryptedFileNotFoundException when a directory is missing.
    """
    missing_directory = (
        isolated_mock_files / "missing_directory"
    )  # Non-existent directory
    valid_key = isolated_mock_files / "mykey.key"  # Existing key file

    # Invoke the compare command with a missing directory
    result = runner.invoke(
        main,
        [
            "compare",
            "--file1",
            str(missing_directory),
            "--file2",
            str(missing_directory),
            "--key1",
            str(valid_key),
        ],
    )

    # Verify that the appropriate error is raised
    assert "Encrypted file validation error: Error: Invalid input path" in result.output
