import pytest
from click.testing import CliRunner
from envcloak.commands.encrypt import encrypt


def test_preview_with_directory(runner, isolated_mock_files):
    """
    Test the --preview flag with a directory.
    Ensures that files in the directory are listed correctly without errors.
    """
    result = runner.invoke(
        encrypt,
        [
            "--directory",
            str(isolated_mock_files),
            "--key-file",
            str(isolated_mock_files / "mykey.key"),
            "--preview",
        ],
    )
    assert result.exit_code == 0, f"Command failed with output: {result.output}"
    assert "Files to be processed in directory" in result.output


def test_preview_with_single_file_error(runner, isolated_mock_files):
    """
    Test the --preview flag with a single file (using --input).
    Ensures that an error is raised when --preview is used with --input.
    """
    result = runner.invoke(
        encrypt,
        [
            "--input",
            str(isolated_mock_files / "variables.env"),
            "--key-file",
            str(isolated_mock_files / "mykey.key"),
            "--preview",
        ],
    )
    assert (
        "The --preview option cannot be used with a single file (--input)."
        in result.output
    )


def test_preview_with_empty_directory(runner, test_dir):
    """
    Test the --preview flag with an empty directory.
    Ensures that a message indicating no files are found is displayed.
    """
    empty_dir = test_dir / "empty_dir"
    empty_dir.mkdir()
    result = runner.invoke(
        encrypt,
        [
            "--directory",
            str(empty_dir),
            "--key-file",
            str(test_dir / "mykey.key"),
            "--preview",
        ],
    )
    assert "ℹ️ No files found in directory" in result.output
