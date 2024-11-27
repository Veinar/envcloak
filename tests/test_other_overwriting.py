import pytest
from pathlib import Path
from envcloak.validation import check_directory_overwrite
from envcloak.exceptions import OutputFileExistsException


def test_check_directory_overwrite_existing_with_files(tmp_path):
    """
    Test that check_directory_overwrite raises an exception for a directory with files.
    """
    dir_with_files = tmp_path / "dir_with_files"
    dir_with_files.mkdir()
    (dir_with_files / "file1.txt").touch()

    with pytest.raises(
        OutputFileExistsException, match="Directory already exists and contains files"
    ):
        check_directory_overwrite(str(dir_with_files))


def test_check_directory_overwrite_existing_empty(tmp_path):
    """
    Test that check_directory_overwrite does not raise an exception for an empty directory.
    """
    empty_dir = tmp_path / "empty_dir"
    empty_dir.mkdir()

    try:
        check_directory_overwrite(str(empty_dir))
    except OutputFileExistsException:
        pytest.fail(
            "check_directory_overwrite raised an exception for an empty directory."
        )


def test_check_directory_overwrite_nonexistent(tmp_path):
    """
    Test that check_directory_overwrite does not raise an exception for a nonexistent directory.
    """
    nonexistent_dir = tmp_path / "nonexistent_dir"

    try:
        check_directory_overwrite(str(nonexistent_dir))
    except OutputFileExistsException:
        pytest.fail(
            "check_directory_overwrite raised an exception for a nonexistent directory."
        )
