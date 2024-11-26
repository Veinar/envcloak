import os
import tempfile
from pathlib import Path
import difflib
from envcloak.encryptor import decrypt_file
from envcloak.exceptions import FileDecryptionException
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
    # Validate paths
    debug_log("Debug: Validating existence of input files and keys.", debug)
    try:
        if Path(file1).is_file():
            check_file_exists(file1)
        elif Path(file1).is_dir():
            check_directory_exists(file1)
        else:
            raise ValueError(f"Invalid input path: {file1}")

        if Path(file2).is_file():
            check_file_exists(file2)
        elif Path(file2).is_dir():
            check_directory_exists(file2)
        else:
            raise ValueError(f"Invalid input path: {file2}")

        check_file_exists(key1)
        key2 = key2 or key1
        check_file_exists(key2)
    except FileNotFoundError as e:
        raise ValueError(str(e))

    # Read decryption keys
    debug_log(f"Debug: Reading encryption keys from {key1} and {key2}.", debug)
    with open(key1, "rb") as kf1, open(key2, "rb") as kf2:
        key1_bytes = kf1.read()
        key2_bytes = kf2.read()

    # Temporary directory for decrypted files
    with tempfile.TemporaryDirectory() as temp_dir:
        file1_decrypted = os.path.join(temp_dir, "file1_decrypted")
        file2_decrypted = os.path.join(temp_dir, "file2_decrypted")

        # Compare two files
        if Path(file1).is_file() and Path(file2).is_file():
            debug_log("Debug: Both inputs are files. Decrypting files.", debug)
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
            except FileDecryptionException as e:
                raise ValueError(f"Decryption failed: {e}")

            with (
                open(file1_decrypted, "r", encoding="utf-8") as f1,
                open(file2_decrypted, "r", encoding="utf-8") as f2,
            ):
                content1 = f1.readlines()
                content2 = f2.readlines()
            debug_log("Debug: Comparing file contents using difflib.", debug)
            diff = list(
                difflib.unified_diff(
                    content1, content2, lineterm="", fromfile="File1", tofile="File2"
                )
            )
        # Compare two directories
        elif Path(file1).is_dir() and Path(file2).is_dir():
            debug_log(
                "Debug: Both inputs are directories. Decrypting directory contents.",
                debug,
            )
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
                    file2_dec = os.path.join(
                        file2_decrypted, filename.replace(".enc", "")
                    )
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
                    except FileDecryptionException as e:
                        raise ValueError(f"Decryption failed for {filename}: {e}")

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
                        f"Debug: File {filename} exists in File1 but not in File2.",
                        debug,
                    )
                    diff.append(
                        f"File present in File1 but missing in File2: {filename}"
                    )

            for filename in file2_files:
                if filename not in file1_files:
                    debug_log(
                        f"Debug: File {filename} exists in File2 but not in File1.",
                        debug,
                    )
                    diff.append(
                        f"File present in File2 but missing in File1: {filename}"
                    )
        else:
            raise ValueError("Both inputs must either be files or directories.")

        return diff
