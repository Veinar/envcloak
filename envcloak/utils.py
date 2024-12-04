"""
utils.py

This module provides helper functions and common utilities to support various operations
in the `envcloak` package, such as logging, checksum calculation, and general-purpose tools.
"""

import os
import hashlib
from pathlib import Path
import click
from envcloak.validation import (
    check_file_exists,
    check_directory_exists,
    check_permissions,
    check_directory_not_empty,
)


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


def validate_paths(input=None, directory=None, key_file=None, output=None, debug=False):
    """Perform validation for common parameters."""
    if input and directory:
        raise click.UsageError(
            "You must provide either --input or --directory, not both."
        )
    if not input and not directory:
        raise click.UsageError("You must provide either --input or --directory.")
    if key_file:
        debug_log(f"Debug: Validating key file {key_file}.", debug)
        check_file_exists(key_file)
        check_permissions(key_file)
    if directory:
        debug_log(f"Debug: Validating directory {directory}.", debug)
        check_directory_exists(directory)
        check_directory_not_empty(directory)


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


def read_key_file(key_file, debug):
    """
    Reads a cryptographic key from a file and logs the operation if debugging is enabled.

    Args:
        key_file (str or Path): The path to the file containing the cryptographic key.
        debug (bool): If True, logs debugging information about the operation.

    Returns:
        bytes: The binary content of the key file.
    """
    with open(key_file, "rb") as kf:
        key = kf.read()
        debug_log(f"Debug: Key file {key_file} read successfully.", debug)
        return key
