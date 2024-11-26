import pytest
from pathlib import Path
from envcloak.utils import add_to_gitignore


def test_add_to_gitignore_existing_file(tmp_path, capsys):
    """
    Test that add_to_gitignore appends a filename to an existing .gitignore
    if it's not already listed.
    """
    directory = tmp_path
    gitignore_path = directory / ".gitignore"
    filename = "testfile.txt"

    # Create an existing .gitignore with some content
    existing_content = "existingfile.txt\nanotherfile.txt\n"
    gitignore_path.write_text(existing_content, encoding="utf-8")

    # Call the function to add a new filename
    add_to_gitignore(str(directory), filename)

    # Verify that the filename was appended
    updated_content = gitignore_path.read_text(encoding="utf-8")
    assert filename in updated_content, f"{filename} should be in .gitignore"
    # Normalize the content to ignore extra newlines
    normalized_content = (
        "\n".join(line for line in updated_content.splitlines() if line.strip()) + "\n"
    )
    expected_content = f"{existing_content.strip()}\n{filename}\n"
    assert (
        normalized_content == expected_content
    ), f"Expected content:\n{expected_content}\nGot:\n{normalized_content}"

    # Verify the printed message
    captured = capsys.readouterr()
    assert f"Added '{filename}' to {gitignore_path}" in captured.out


def test_add_to_gitignore_already_listed(tmp_path, capsys):
    """
    Test that add_to_gitignore does not append a filename if it is already listed in .gitignore.
    """
    directory = tmp_path
    gitignore_path = directory / ".gitignore"
    filename = "testfile.txt"

    # Create an existing .gitignore with the filename already listed
    existing_content = f"existingfile.txt\n{filename}\nanotherfile.txt\n"
    gitignore_path.write_text(existing_content, encoding="utf-8")

    # Call the function
    add_to_gitignore(str(directory), filename)

    # Verify that the content remains unchanged
    updated_content = gitignore_path.read_text(encoding="utf-8")
    assert (
        updated_content == existing_content
    ), ".gitignore content should remain unchanged"

    # Verify no additional output
    captured = capsys.readouterr()
    assert f"Added '{filename}'" not in captured.out
