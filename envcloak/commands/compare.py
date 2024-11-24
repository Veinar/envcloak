import os
import tempfile
import difflib
from pathlib import Path
import click
from click import style
from envcloak.utils import debug_log, debug_option
from envcloak.validation import check_file_exists, check_directory_exists
from envcloak.encryptor import decrypt_file
from envcloak.exceptions import FileDecryptionException


@click.command()
@click.option(
    "--file1",
    "-f1",
    required=True,
    help="Path to the first encrypted file or directory.",
)
@click.option(
    "--file2",
    "-f2",
    required=True,
    help="Path to the second encrypted file or directory.",
)
@click.option(
    "--key1", "-k1", required=True, help="Path to the decryption key file for file1."
)
@click.option(
    "--key2",
    "-k2",
    required=False,
    help="Path to the decryption key file for file2. If omitted, key1 is used.",
)
@click.option(
    "--output",
    "-o",
    required=False,
    help="Path to save the comparison result as a file.",
)
@debug_option
def compare(file1, file2, key1, key2, output, debug):
    """
    Compare two encrypted environment files or directories.
    """
    try:
        # Validate existence of files/directories and keys using helper functions
        debug_log("Debug: Validating existence of input files and keys.", debug)
        try:
            if Path(file1).is_file():
                check_file_exists(file1)
            elif Path(file1).is_dir():
                check_directory_exists(file1)
            else:
                raise click.ClickException(f"Invalid input path: {file1}")

            if Path(file2).is_file():
                check_file_exists(file2)
            elif Path(file2).is_dir():
                check_directory_exists(file2)
            else:
                raise click.ClickException(f"Invalid input path: {file2}")

            check_file_exists(key1)
            key2 = key2 or key1
            check_file_exists(key2)
        except FileNotFoundError as e:
            raise click.ClickException(str(e))

        if key1 == key2:
            debug_log(
                "Debug: Keys are identical or Key2 not specified. Using Key1 for both files.",
                debug,
            )

        # Read decryption keys
        debug_log(f"Debug: Reading encryption keys from {key1} and {key2}.", debug)
        with open(key1, "rb") as kf1, open(key2, "rb") as kf2:
            key1_bytes = kf1.read()
            key2_bytes = kf2.read()

        # Create a temporary directory for decrypted files
        with tempfile.TemporaryDirectory() as temp_dir:
            file1_decrypted = os.path.join(temp_dir, "file1_decrypted")
            file2_decrypted = os.path.join(temp_dir, "file2_decrypted")

            debug_log(
                "Debug: Preparing to decrypt and compare files or directories.", debug
            )
            if Path(file1).is_file() and Path(file2).is_file():
                debug_log("Debug: Both inputs are files. Decrypting files.", debug)
                try:
                    decrypt_file(file1, file1_decrypted, key1_bytes)
                    decrypt_file(file2, file2_decrypted, key2_bytes)
                except FileDecryptionException as e:
                    raise click.ClickException(f"Decryption failed: {e}")

                with (
                    open(file1_decrypted, "r", encoding="utf-8") as f1,
                    open(file2_decrypted, "r", encoding="utf-8") as f2,
                ):
                    content1 = f1.readlines()
                    content2 = f2.readlines()
                debug_log("Debug: Comparing file contents using difflib.", debug)
                diff = list(
                    difflib.unified_diff(
                        content1,
                        content2,
                        lineterm="",
                        fromfile="File1",
                        tofile="File2",
                    )
                )
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
                    file1_dec = os.path.join(
                        file1_decrypted, filename.replace(".enc", "")
                    )
                    if filename in file2_files:
                        file2_dec = os.path.join(
                            file2_decrypted, filename.replace(".enc", "")
                        )
                        try:
                            decrypt_file(str(file1_path), file1_dec, key1_bytes)
                            decrypt_file(
                                str(file2_files[filename]), file2_dec, key2_bytes
                            )
                        except FileDecryptionException as e:
                            raise click.ClickException(
                                f"Decryption failed for {filename}: {e}"
                            )

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
                raise click.UsageError(
                    "Both inputs must either be files or directories."
                )

            # Output the comparison result
            diff_text = "\n".join(diff)
            if output:
                with open(output, "w", encoding="utf-8") as outfile:
                    outfile.write(diff_text)
                click.echo(f"Comparison result saved to {output}")
            else:
                if diff:
                    click.echo(
                        style("⚠️  Warning: Files or directories differ.", fg="yellow")
                    )
                    click.echo(diff_text)
                else:
                    click.echo("The files/directories are identical.")
    except click.ClickException as e:
        click.echo(f"Error: {e}")
    except Exception as e:
        click.echo(f"Unexpected error during comparison: {e}")
