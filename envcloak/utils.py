import os
import hashlib
from pathlib import Path
import click


def add_to_gitignore(directory: str, filename: str):
    """
    Add a filename to the .gitignore file in the specified directory.

    :param directory: Directory where the .gitignore file is located.
    :param filename: Name of the file to add to .gitignore.
    """
    gitignore_path = Path(directory) / ".gitignore"

    if gitignore_path.exists():
        # Append the filename if not already listed
        with open(gitignore_path, "r+", encoding="utf-8") as gitignore_file:
            content = gitignore_file.read()
            if filename not in content:
                gitignore_file.write(f"\n{filename}")
                print(f"Added '{filename}' to {gitignore_path}")
    else:
        # Create a new .gitignore file and add the filename
        with open(gitignore_path, "w", encoding="utf-8") as gitignore_file:
            gitignore_file.write(f"{filename}\n")
        print(f"Created {gitignore_path} and added '{filename}'")


def calculate_required_space(input=None, directory=None):
    """
    Calculate the required disk space based on the size of the input file or directory.

    :param input: Path to the file to calculate size.
    :param directory: Path to the directory to calculate total size.
    :return: Size in bytes.
    """
    if input and directory:
        raise ValueError(
            "Both `input` and `directory` cannot be specified at the same time."
        )

    if input:
        return os.path.getsize(input)

    if directory:
        total_size = sum(
            file.stat().st_size for file in Path(directory).rglob("*") if file.is_file()
        )
        return total_size

    return 0


def list_files_to_encrypt(directory, recursion):
    """
    List files in a directory that would be encrypted.

    :param directory: Path to the directory to scan.
    :param recursion: Whether to scan directories recursively.
    :return: List of file paths.
    """
    path = Path(directory)
    if not path.is_dir():
        raise click.UsageError(f"The specified path {directory} is not a directory.")

    files = []
    if recursion:
        files = list(path.rglob("*"))  # Recursive glob
    else:
        files = list(path.glob("*"))  # Non-recursive glob

    # Filter only files
    files = [str(f) for f in files if f.is_file()]
    return files


def debug_log(message, debug):
    """
    Print message only if debug is true

    :param message: message to print
    :param debug: flag to turn debug mode on
    :return: None
    """
    if debug:
        print(message)


def compute_sha256(data: str) -> str:
    """
    Compute SHA-256 hash of the given data.

    :param data: Input data as a string.
    :return: SHA-256 hash as a hex string.
    """
    return hashlib.sha3_256(data.encode()).hexdigest()
