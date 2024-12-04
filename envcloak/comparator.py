"""
comparator.py

This module contains utilities for comparing files, directories, or cryptographic properties.
It ensures integrity and helps detect discrepancies in encrypted data.
"""

import os
import tempfile
from pathlib import Path
import difflib
from envcloak.encryptor import decrypt_file
from envcloak.exceptions import (
    FileDecryptionException,
    KeyFileNotFoundException,
    EncryptedFileNotFoundException,
)
from envcloak.validation import check_file_exists, check_directory_exists


def compare_files_or_directories(
    file1, file2, key1, key2, skip_sha_validation=False, debug=False, debug_log=print
):
    """
    Compare two encrypted files or directories after decrypting them.
    Returns the differences as a list of strings.

    :param file1: Path to the first encrypted file or directory.
    :param file2: Path to the second encrypted file or directory.
    :param key1: Path to the decryption key for the first file/directory.
    :param key2: Path to the decryption key for the second file/directory. Defaults to key1.
    :param skip_sha_validation: Skip SHA validation during decryption if True.
    :param debug: Enable debug logging if True.
    :param debug_log: Function to log debug messages. Defaults to print.
    :return: List of differences or messages as strings.
    """
    debug_log("Debug: Validating existence of input files and keys.", debug)
    key2 = key2 or key1

    try:
        validate_paths(file1, file2, key1, key2)
    except KeyFileNotFoundException as exc:
        raise ValueError(f"Key file validation error: {exc}") from exc
    except EncryptedFileNotFoundException as exc:
        raise ValueError(f"Encrypted file validation error: {exc}") from exc

    debug_log(f"Debug: Reading encryption keys from {key1} and {key2}.", debug)
    key1_bytes, key2_bytes = read_keys(key1, key2)

    if Path(file1).is_file() and Path(file2).is_file():
        debug_log("Debug: Both inputs are files. Comparing files.", debug)
        return compare_files(
            file1, file2, key1_bytes, key2_bytes, skip_sha_validation, debug, debug_log
        )
    if Path(file1).is_dir() and Path(file2).is_dir():
        debug_log("Debug: Both inputs are directories. Comparing directories.", debug)
        return compare_directories(
            file1, file2, key1_bytes, key2_bytes, skip_sha_validation, debug, debug_log
        )

    raise ValueError("Both inputs must either be files or directories.")


def validate_paths(file1, file2, key1, key2):
    """
    Validate the existence of files, directories, and keys.

    :raises KeyFileNotFoundException: If a key file is missing.
    :raises EncryptedFileNotFoundException: If an encrypted file or directory is missing.
    """
    if Path(file1).is_file():
        try:
            check_file_exists(file1)
        except FileNotFoundError as exc:
            raise EncryptedFileNotFoundException(
                f"Encrypted file not found: {file1}"
            ) from exc
    elif Path(file1).is_dir():
        try:
            check_directory_exists(file1)
        except FileNotFoundError as exc:
            raise EncryptedFileNotFoundException(
                f"Directory not found: {file1}"
            ) from exc
    else:
        raise EncryptedFileNotFoundException(f"Invalid input path: {file1}")

    if Path(file2).is_file():
        try:
            check_file_exists(file2)
        except FileNotFoundError as exc:
            raise EncryptedFileNotFoundException(
                f"Encrypted file not found: {file2}"
            ) from exc
    elif Path(file2).is_dir():
        try:
            check_directory_exists(file2)
        except FileNotFoundError as exc:
            raise EncryptedFileNotFoundException(
                f"Directory not found: {file2}"
            ) from exc
    else:
        raise EncryptedFileNotFoundException(f"Invalid input path: {file2}")

    try:
        check_file_exists(key1)
    except FileNotFoundError as exc:
        raise KeyFileNotFoundException(f"Key file not found: {key1}") from exc

    try:
        check_file_exists(key2)
    except FileNotFoundError as exc:
        raise KeyFileNotFoundException(f"Key file not found: {key2}") from exc


def read_keys(key1, key2):
    """
    Read decryption keys from the provided files.
    """
    with open(key1, "rb") as kf1, open(key2, "rb") as kf2:
        key1_bytes = kf1.read()
        key2_bytes = kf2.read()
    return key1_bytes, key2_bytes


def compare_files(
    file1, file2, key1_bytes, key2_bytes, skip_sha_validation, debug, debug_log
):
    """
    Compare two encrypted files after decrypting them.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        file1_decrypted = os.path.join(temp_dir, "file1_decrypted")
        file2_decrypted = os.path.join(temp_dir, "file2_decrypted")

        try:
            decrypt_file(
                file1,
                file1_decrypted,
                key1_bytes,
                validate_integrity=not skip_sha_validation,
            )
            decrypt_file(
                file2,
                file2_decrypted,
                key2_bytes,
                validate_integrity=not skip_sha_validation,
            )
        except FileDecryptionException as exc:
            raise ValueError(f"Decryption failed: {exc}") from exc

        with (
            open(file1_decrypted, "r", encoding="utf-8") as f1,
            open(file2_decrypted, "r", encoding="utf-8") as f2,
        ):
            content1 = f1.readlines()
            content2 = f2.readlines()

        debug_log("Debug: Comparing file contents using difflib.", debug)
        return list(
            difflib.unified_diff(
                content1, content2, lineterm="", fromfile="File1", tofile="File2"
            )
        )


def compare_directories(
    file1, file2, key1_bytes, key2_bytes, skip_sha_validation, debug, debug_log
):
    """
    Compare two encrypted directories after decrypting their contents.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        file1_decrypted = os.path.join(temp_dir, "file1_decrypted")
        file2_decrypted = os.path.join(temp_dir, "file2_decrypted")

        os.makedirs(file1_decrypted, exist_ok=True)
        os.makedirs(file2_decrypted, exist_ok=True)

        file1_files = {
            file.name: file
            for file in Path(file1).iterdir()
            if file.is_file() and file.suffix == ".enc"
        }
        file2_files = {
            file.name: file
            for file in Path(file2).iterdir()
            if file.is_file() and file.suffix == ".enc"
        }

        diff = []
        for filename, file1_path in file1_files.items():
            file1_dec = os.path.join(file1_decrypted, filename.replace(".enc", ""))
            if filename in file2_files:
                file2_dec = os.path.join(file2_decrypted, filename.replace(".enc", ""))
                try:
                    decrypt_file(
                        str(file1_path),
                        file1_dec,
                        key1_bytes,
                        validate_integrity=not skip_sha_validation,
                    )
                    decrypt_file(
                        str(file2_files[filename]),
                        file2_dec,
                        key2_bytes,
                        validate_integrity=not skip_sha_validation,
                    )
                except FileDecryptionException as exc:
                    raise ValueError(
                        f"Decryption failed for {filename}: {exc}"
                    ) from exc

                with (
                    open(file1_dec, "r", encoding="utf-8") as f1,
                    open(file2_dec, "r", encoding="utf-8") as f2,
                ):
                    content1 = f1.readlines()
                    content2 = f2.readlines()

                diff.extend(
                    difflib.unified_diff(
                        content1,
                        content2,
                        lineterm="",
                        fromfile=f"File1/{filename}",
                        tofile=f"File2/{filename}",
                    )
                )
            else:
                debug_log(
                    f"Debug: File {filename} exists in File1 but not in File2.", debug
                )
                diff.append(f"File present in File1 but missing in File2: {filename}")

        for filename in file2_files:
            if filename not in file1_files:
                debug_log(
                    f"Debug: File {filename} exists in File2 but not in File1.", debug
                )
                diff.append(f"File present in File2 but missing in File1: {filename}")

        return diff
