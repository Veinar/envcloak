import os
from unittest.mock import patch
import json
from pathlib import Path
from click.testing import CliRunner
import pytest
from unittest.mock import call
from envcloak.cli import main


@patch("envcloak.commands.encrypt.encrypt_file")
def test_recursive_encrypt(mock_encrypt_file, runner, isolated_mock_files):
    """
    Test recursive encryption using the `--recursion` flag.
    """
    directory = isolated_mock_files / "mock_directory"
    output_directory = isolated_mock_files / "output_directory"
    key_file = isolated_mock_files / "mykey.key"

    # Create nested mock files in the directory
    (directory / "subdir").mkdir(parents=True)
    (directory / "file1.env").write_text("content1")
    (directory / "subdir" / "file2.env").write_text("content2")

    def mock_encrypt(input_path, output_path, key):
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "encrypted_data"}))

    mock_encrypt_file.side_effect = mock_encrypt

    # Invoke with --recursion
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
            "--recursion",
        ],
    )

    # Assert encryption succeeded and files were processed recursively
    assert "All files in directory" in result.output
    mock_encrypt_file.assert_any_call(
        str(directory / "file1.env"),
        str(output_directory / "file1.env.enc"),
        key_file.read_bytes(),
    )
    mock_encrypt_file.assert_any_call(
        str(directory / "subdir" / "file2.env"),
        str(output_directory / "subdir" / "file2.env.enc"),
        key_file.read_bytes(),
    )


@patch("envcloak.commands.encrypt.encrypt_file")
def test_recursive_encrypt_without_recursion(
    mock_encrypt_file, runner, isolated_mock_files
):
    """
    Test that `--recursion` is required for nested files during encryption.
    """
    directory = isolated_mock_files / "mock_directory"
    output_directory = isolated_mock_files / "output_directory"
    key_file = isolated_mock_files / "mykey.key"

    # Create nested mock files in the directory
    (directory / "subdir").mkdir(parents=True)
    (directory / "file1.env").write_text("content1")
    (directory / "subdir" / "file2.env").write_text("content2")

    def mock_encrypt(input_path, output_path, key):
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "encrypted_data"}))

    mock_encrypt_file.side_effect = mock_encrypt

    # Invoke without --recursion
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
        ],
    )

    # Assert only top-level files are processed
    assert result.exit_code == 0
    assert "All files in directory" in result.output

    # Ensure the top-level file is processed
    mock_encrypt_file.assert_any_call(
        str(directory / "file1.env"),
        str(output_directory / "file1.env.enc"),
        key_file.read_bytes(),
    )

    # Ensure the nested file is not processed
    assert (
        call(
            str(directory / "subdir" / "file2.env"),
            str(output_directory / "subdir" / "file2.env.enc"),
            key_file.read_bytes(),
        )
        not in mock_encrypt_file.call_args_list
    )
