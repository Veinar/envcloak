"""
validation.py

This module offers robust validation utilities for checking user inputs, file paths, permissions,
and other constraints required for secure and reliable operations.
"""

import os
from pathlib import Path
import shutil
from envcloak.exceptions import (
    KeyFileNotFoundException,
    InvalidSaltException,
    OutputFileExistsException,
    DirectoryEmptyException,
    DiskSpaceException,
)


def validate_salt(salt: str):
    """Check if the provided salt is a valid hex string of the correct length."""
    if not salt:
        return  # Valid if no salt is provided
    if len(salt) != 32 or not all(c in "0123456789abcdefABCDEF" for c in salt):
        raise InvalidSaltException(
            details="Salt must be a 16-byte hex string (32 characters)."
        )


def check_file_exists(file_path: str):
    """Check if a file exists."""
    if not Path(file_path).is_file():
        raise KeyFileNotFoundException(details=f"File not found: {file_path}")


def check_directory_exists(directory_path: str):
    """Check if a directory exists."""
    if not Path(directory_path).is_dir():
        raise FileNotFoundError(f"Directory does not exist: {directory_path}")


def check_directory_not_empty(directory_path: str):
    """Check if a directory is not empty."""
    dir_path = Path(directory_path)
    if not any(file.is_file() for file in dir_path.iterdir()):
        raise DirectoryEmptyException(
            details=f"The directory is empty: {directory_path}"
        )


def check_output_not_exists(output_path: str):
    """Check if an output file or directory does not already exist."""
    if Path(output_path).exists():
        raise OutputFileExistsException(
            details=f"Output path already exists: {output_path}"
        )


def check_directory_overwrite(directory_path: str):
    """
    Check if a directory exists and contains files that may be overwritten.
    """
    dir_path = Path(directory_path)
    if dir_path.is_dir() and any(file.is_file() for file in dir_path.iterdir()):
        raise OutputFileExistsException(
            details=f"Directory already exists and contains files: {directory_path}"
        )


def check_permissions(file_path: str, write: bool = False):
    """Check if a file or directory has read/write permissions."""
    path = Path(file_path)
    if write and not os.access(path, os.W_OK):
        raise PermissionError(f"Write permission denied: {file_path}")
    if not write and not os.access(path, os.R_OK):
        raise PermissionError(f"Read permission denied: {file_path}")


def check_disk_space(output_path: str, required_space: int):
    """Check if there is enough disk space at the output path."""
    output_dir = Path(output_path).parent
    if not output_dir.exists():
        return  # Assume enough space if directory doesn't exist yet
    _, _, free = shutil.disk_usage(output_dir)
    if free < required_space:
        raise DiskSpaceException(
            details=f"Available: {free} bytes, Required: {required_space} bytes."
        )


def check_path_conflict(input_path: str, output_path: str):
    """Ensure input and output paths don't overlap."""
    input_abs = Path(input_path).resolve()
    output_abs = Path(output_path).resolve()
    if output_abs.is_relative_to(input_abs):
        raise ValueError("Input and output paths overlap. This may cause issues.")
