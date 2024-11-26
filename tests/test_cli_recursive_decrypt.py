import os
from unittest.mock import patch
from pathlib import Path
from click.testing import CliRunner
import pytest
from unittest.mock import call
from envcloak.cli import main


@patch("envcloak.commands.decrypt.decrypt_file")
def test_recursive_decrypt(mock_decrypt_file, runner, isolated_mock_files):
    """
    Test recursive decryption using the `--recursion` flag.
    """
    directory = isolated_mock_files / "mock_directory"
    output_directory = isolated_mock_files / "output_directory"
    key_file = isolated_mock_files / "mykey.key"

    # Create nested mock encrypted files in the directory
    (directory / "subdir").mkdir(parents=True)
    (directory / "file1.env.enc").write_text("encrypted content1")
    (directory / "subdir" / "file2.env.enc").write_text("encrypted content2")

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        with open(output_path, "w") as f:
            f.write("decrypted content")

    mock_decrypt_file.side_effect = mock_decrypt

    # Invoke with --recursion
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
            "--recursion",
        ],
    )

    # Assert decryption succeeded and files were processed recursively
    assert result.exit_code == 0
    assert "All files in directory" in result.output
    mock_decrypt_file.assert_any_call(
        str(directory / "file1.env.enc"),
        str(output_directory / "file1.env"),
        key_file.read_bytes(),
        validate_integrity=True,
    )
    mock_decrypt_file.assert_any_call(
        str(directory / "subdir" / "file2.env.enc"),
        str(output_directory / "subdir" / "file2.env"),
        key_file.read_bytes(),
        validate_integrity=True,
    )


@patch("envcloak.commands.decrypt.decrypt_file")
def test_recursive_decrypt_without_recursion(
    mock_decrypt_file, runner, isolated_mock_files
):
    """
    Test that `--recursion` is required for nested files during decryption.
    """
    directory = isolated_mock_files / "mock_directory"
    output_directory = isolated_mock_files / "output_directory"
    key_file = isolated_mock_files / "mykey.key"

    # Create nested mock encrypted files in the directory
    (directory / "subdir").mkdir(parents=True)
    (directory / "file1.env.enc").write_text("encrypted content1")
    (directory / "subdir" / "file2.env.enc").write_text("encrypted content2")

    def mock_decrypt(input_path, output_path, key, validate_integrity=True):
        with open(output_path, "w") as f:
            f.write("decrypted content")

    mock_decrypt_file.side_effect = mock_decrypt

    # Invoke without --recursion
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
        ],
    )

    # Assert only top-level files are processed
    assert "All files in directory" in result.output

    # Ensure the top-level file is processed
    mock_decrypt_file.assert_any_call(
        str(directory / "file1.env.enc"),
        str(output_directory / "file1.env"),
        key_file.read_bytes(),
        validate_integrity=True,
    )

    # Ensure the nested file is not processed
    assert (
        call(
            str(directory / "subdir" / "file2.env.enc"),
            str(output_directory / "subdir" / "file2.env"),
            key_file.read_bytes(),
            validate_integrity=True,
        )
        not in mock_decrypt_file.call_args_list
    )
