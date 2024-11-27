import pytest
from pathlib import Path
from envcloak.validation import check_path_conflict


def test_check_path_conflict_overlapping_paths(tmp_path):
    """
    Test that check_path_conflict raises a ValueError for overlapping paths.
    """
    input_path = tmp_path / "input_dir"
    output_path = input_path / "subdir"
    input_path.mkdir(parents=True)
    output_path.mkdir(parents=True)

    with pytest.raises(ValueError, match="Input and output paths overlap"):
        check_path_conflict(str(input_path), str(output_path))


def test_check_path_conflict_non_overlapping_paths(tmp_path):
    """
    Test that check_path_conflict does not raise a ValueError for non-overlapping paths.
    """
    input_path = tmp_path / "input_dir"
    output_path = tmp_path / "output_dir"
    input_path.mkdir(parents=True)
    output_path.mkdir(parents=True)

    try:
        check_path_conflict(str(input_path), str(output_path))
    except ValueError:
        pytest.fail(
            "check_path_conflict raised a ValueError for non-overlapping paths."
        )


def test_check_path_conflict_same_path(tmp_path):
    """
    Test that check_path_conflict raises a ValueError if input and output paths are the same.
    """
    input_path = tmp_path / "input_dir"
    input_path.mkdir(parents=True)

    with pytest.raises(ValueError, match="Input and output paths overlap"):
        check_path_conflict(str(input_path), str(input_path))
