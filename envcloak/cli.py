import os
from pathlib import Path
import shutil
import difflib
import tempfile
import click
from click import style
from envcloak.encryptor import encrypt_file, decrypt_file
from envcloak.generator import generate_key_file, generate_key_from_password_file
from envcloak.utils import (
    add_to_gitignore,
    calculate_required_space,
    debug_option,
    debug_log,
)
from envcloak.validation import (
    check_file_exists,
    check_directory_exists,
    check_directory_not_empty,
    check_output_not_exists,
    check_permissions,
    check_disk_space,
    validate_salt,
)
from envcloak.exceptions import (
    OutputFileExistsException,
    DiskSpaceException,
    InvalidSaltException,
    FileEncryptionException,
    FileDecryptionException,
)


@click.group()
@click.version_option(prog_name="EnvCloak")
def main():
    """
    EnvCloak: Securely manage encrypted environment variables.
    """
    # No unnecessary pass here


@click.command()
@debug_option
@click.option(
    "--input", "-i", required=False, help="Path to the input file (e.g., .env)."
)
@click.option(
    "--directory",
    "-d",
    required=False,
    help="Path to the directory of files to encrypt.",
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Path to the output file or directory for encrypted files.",
)
@click.option(
    "--key-file", "-k", required=True, help="Path to the encryption key file."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
@click.option(
    "--force",
    is_flag=True,
    help="Force overwrite of existing encrypted files or directories.",
)
def encrypt(input, directory, output, key_file, dry_run, force, debug):
    """
    Encrypt environment variables from a file or all files in a directory.
    """
    try:
        # debug mode
        debug_log("Debug mode is enabled", debug)

        debug_log("Debug: Validating input and directory parameters.", debug)
        # Always perform validation
        if not input and not directory:
            raise click.UsageError("You must provide either --input or --directory.")
        if input and directory:
            raise click.UsageError(
                "You must provide either --input or --directory, not both."
            )
        if input:
            debug_log(f"Debug: Validating input file {input}.", debug)
            check_file_exists(input)
            check_permissions(input)
        if directory:
            debug_log(f"Debug: Validating directory {directory}.", debug)
            check_directory_exists(directory)
            check_directory_not_empty(directory)
        debug_log(f"Debug: Validating key file {key_file}.", debug)
        check_file_exists(key_file)
        check_permissions(key_file)

        # Handle overwrite with --force
        debug_log("Debug: Handling overwrite logic with force flag.", debug)
        if not force:
            check_output_not_exists(output)
        else:
            if os.path.exists(output):
                debug_log(
                    f"Debug: File or directory {output} exists, proceeding with overwrite.",
                    debug,
                )
                click.echo(
                    style(
                        f"⚠️  Warning: Overwriting existing file or directory {output} (--force used).",
                        fg="yellow",
                    )
                )
                if os.path.isdir(output):
                    debug_log(f"Debug: Removing existing directory {output}.", debug)
                    shutil.rmtree(output)  # Remove existing directory
                else:
                    debug_log(f"Debug: Removing existing file {output}.", debug)
                    os.remove(output)  # Remove existing file

        debug_log(
            f"Debug: Calculating required space for input {input} and output directory {directory}.",
            debug,
        )
        required_space = calculate_required_space(input, directory)
        check_disk_space(output, required_space)

        if dry_run:
            debug_log(
                "Debug: Dry-run flag is set. Skipping actual encryption process.",
                debug,
            )
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual encryption logic
        with open(key_file, "rb") as kf:
            key = kf.read()
            debug_log(f"Debug: Key file {key_file} read successfully.", debug)

        if input:
            debug_log(
                f"Debug: Encrypting file {input} -> {output} using key {key_file}.",
                debug,
            )
            encrypt_file(input, output, key)
            click.echo(f"File {input} encrypted -> {output} using key {key_file}")
        elif directory:
            input_dir = Path(directory)
            output_dir = Path(output)
            if not output_dir.exists():
                debug_log(
                    f"Debug: Output directory {output_dir} does not exist. Creating it.",
                    debug,
                )
                output_dir.mkdir(parents=True)

            for file in input_dir.iterdir():
                if file.is_file():  # Skip directories
                    output_file = output_dir / (file.name + ".enc")
                    debug_log(
                        f"Debug: Encrypting file {file} -> {output_file} using key {key_file}.",
                        debug,
                    )
                    encrypt_file(str(file), str(output_file), key)
                    click.echo(
                        f"File {file} encrypted -> {output_file} using key {key_file}"
                    )
    except (
        OutputFileExistsException,
        DiskSpaceException,
        FileEncryptionException,
    ) as e:
        click.echo(f"Error during encryption: {str(e)}")


@click.command()
@debug_option
@click.option(
    "--input",
    "-i",
    required=False,
    help="Path to the encrypted input file (e.g., .env.enc).",
)
@click.option(
    "--directory",
    "-d",
    required=False,
    help="Path to the directory of encrypted files.",
)
@click.option(
    "--output",
    "-o",
    required=True,
    help="Path to the output file or directory for decrypted files.",
)
@click.option(
    "--key-file", "-k", required=True, help="Path to the decryption key file."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
@click.option(
    "--force",
    is_flag=True,
    help="Force overwrite of existing decrypted files or directories.",
)
def decrypt(input, directory, output, key_file, dry_run, force, debug):
    """
    Decrypt environment variables from a file or all files in a directory.
    """
    try:
        debug_log("Debug mode is enabled", debug)

        # Always perform validation
        debug_log("Debug: Validating input and directory parameters.", debug)
        if not input and not directory:
            raise click.UsageError("You must provide either --input or --directory.")
        if input and directory:
            raise click.UsageError(
                "You must provide either --input or --directory, not both."
            )
        if input:
            debug_log(f"Debug: Validating input file {input}.", debug)
            check_file_exists(input)
            check_permissions(input)
        if directory:
            debug_log(f"Debug: Validating directory {directory}.", debug)
            check_directory_exists(directory)
            check_directory_not_empty(directory)
        debug_log(f"Debug: Validating key file {key_file}.", debug)
        check_file_exists(key_file)
        check_permissions(key_file)

        # Handle overwrite with --force
        debug_log("Debug: Handling overwrite logic with force flag.", debug)
        if not force:
            check_output_not_exists(output)
        else:
            if os.path.exists(output):
                debug_log(
                    f"Debug: Existing file or directory found at {output}. Overwriting due to --force.",
                    debug,
                )
                click.echo(
                    style(
                        f"⚠️  Warning: Overwriting existing file or directory {output} (--force used).",
                        fg="yellow",
                    )
                )
                if os.path.isdir(output):
                    debug_log(f"Debug: Removing existing directory {output}.", debug)
                    shutil.rmtree(output)  # Remove existing directory
                else:
                    debug_log(f"Debug: Removing existing file {output}.", debug)
                    os.remove(output)  # Remove existing file

        debug_log(
            f"Debug: Calculating required space for input {input} or directory {directory}.",
            debug,
        )
        required_space = calculate_required_space(input, directory)
        check_disk_space(output, required_space)

        if dry_run:
            debug_log("Debug: Dry-run flag set. Skipping actual decryption.", debug)
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual decryption logic
        with open(key_file, "rb") as kf:
            key = kf.read()
            debug_log(f"Debug: Key file {key_file} read successfully.", debug)

        if input:
            debug_log(
                f"Debug: Decrypting file {input} -> {output} using key {key_file}.",
                debug,
            )
            decrypt_file(input, output, key)
            click.echo(f"File {input} decrypted -> {output} using key {key_file}")
        elif directory:
            input_dir = Path(directory)
            output_dir = Path(output)
            if not output_dir.exists():
                debug_log(
                    f"Debug: Output directory {output_dir} does not exist. Creating it.",
                    debug,
                )
                output_dir.mkdir(parents=True)

            for file in input_dir.iterdir():
                if file.is_file() and file.suffix == ".enc":  # Only decrypt .enc files
                    output_file = output_dir / file.stem  # Remove .enc from filename
                    debug_log(
                        f"Debug: Decrypting file {file} -> {output_file} using key {key_file}.",
                        debug,
                    )
                    decrypt_file(str(file), str(output_file), key)
                    click.echo(
                        f"File {file} decrypted -> {output_file} using key {key_file}"
                    )
    except (
        OutputFileExistsException,
        DiskSpaceException,
        FileDecryptionException,
    ) as e:
        click.echo(f"Error during decryption: {str(e)}")


@click.command()
@debug_option
@click.option(
    "--output", "-o", required=True, help="Path to save the generated encryption key."
)
@click.option(
    "--no-gitignore", is_flag=True, help="Skip adding the key file to .gitignore."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
def generate_key(output, no_gitignore, dry_run, debug):
    """
    Generate a new encryption key.
    """
    try:
        debug_log("Debug mode is enabled", debug)

        # Always perform validation
        debug_log(f"Debug: Validating output path {output}.", debug)
        check_output_not_exists(output)

        debug_log(
            f"Debug: Checking disk space for output {output}, required space = 32 bytes.",
            debug,
        )
        check_disk_space(output, required_space=32)

        if dry_run:
            debug_log("Debug: Dry-run flag set. Skipping actual key generation.", debug)
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual key generation logic
        debug_log(f"Debug: Generating key file at {output}.", debug)
        output_path = Path(output)
        generate_key_file(output_path)
        if not no_gitignore:
            debug_log(
                f"Debug: Adding {output_path.name} to .gitignore in parent directory {output_path.parent}.",
                debug,
            )
            add_to_gitignore(output_path.parent, output_path.name)
    except (OutputFileExistsException, DiskSpaceException) as e:
        click.echo(f"Error during key generation: {str(e)}")


@click.command()
@debug_option
@click.option(
    "--password", "-p", required=True, help="Password to derive the encryption key."
)
@click.option(
    "--salt", "-s", required=False, help="Salt for key derivation (16 bytes as hex)."
)
@click.option(
    "--output", "-o", required=True, help="Path to save the derived encryption key."
)
@click.option(
    "--no-gitignore", is_flag=True, help="Skip adding the key file to .gitignore."
)
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
def generate_key_from_password(password, salt, output, no_gitignore, dry_run, debug):
    """
    Derive an encryption key from a password and salt.
    """
    try:
        debug_log("Debug mode is enabled", debug)
        # Always perform validation
        debug_log(f"Debug: Validating output path {output}.", debug)
        check_output_not_exists(output)
        debug_log(
            f"Debug: Checking disk space for output {output}, required space = 32 bytes.",
            debug,
        )
        check_disk_space(output, required_space=32)
        if salt:
            debug_log(f"Debug: Validating salt: {salt}.", debug)
            validate_salt(salt)

        if dry_run:
            debug_log("Debug: Dry-run flag set. Skipping actual key derivation.", debug)
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual key derivation logic
        debug_log(f"Debug: Deriving key from password for output file {output}.", debug)
        output_path = Path(output)
        generate_key_from_password_file(password, output_path, salt)
        if not no_gitignore:
            debug_log(
                f"Debug: Adding {output_path.name} to .gitignore in parent directory {output_path.parent}.",
                debug,
            )
            add_to_gitignore(output_path.parent, output_path.name)
    except (OutputFileExistsException, DiskSpaceException, InvalidSaltException) as e:
        click.echo(f"Error during key derivation: {str(e)}")


@click.command()
@debug_option
@click.option(
    "--input", "-i", required=True, help="Path to the encrypted file to re-encrypt."
)
@click.option(
    "--old-key-file", "-ok", required=True, help="Path to the old encryption key."
)
@click.option(
    "--new-key-file", "-nk", required=True, help="Path to the new encryption key."
)
@click.option("--output", "-o", required=True, help="Path to the re-encrypted file.")
@click.option(
    "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
)
def rotate_keys(input, old_key_file, new_key_file, output, dry_run, debug):
    """
    Rotate encryption keys by re-encrypting a file with a new key.
    """
    try:
        debug_log("Debug mode is enabled", debug)
        # Always perform validation
        check_file_exists(input)
        check_permissions(input)
        check_file_exists(old_key_file)
        check_permissions(old_key_file)
        check_file_exists(new_key_file)
        check_permissions(new_key_file)
        check_output_not_exists(output)
        check_disk_space(output, required_space=1024 * 1024)

        if dry_run:
            click.echo("Dry-run checks passed successfully.")
            return

        # Actual key rotation logic
        debug_log(f"Debug: Reading old key from {old_key_file}.", debug)
        with open(old_key_file, "rb") as okf:
            old_key = okf.read()
        debug_log(f"Debug: Reading new key from {new_key_file}.", debug)
        with open(new_key_file, "rb") as nkf:
            new_key = nkf.read()

        temp_decrypted = f"{output}.tmp"
        debug_log(
            f"Debug: Decrypting file {input} to temporary file {temp_decrypted} using old key.",
            debug,
        )
        decrypt_file(input, temp_decrypted, old_key)
        debug_log(
            f"Debug: Encrypting decrypted file {temp_decrypted} to {output} using new key.",
            debug,
        )
        encrypt_file(temp_decrypted, output, new_key)

        debug_log(f"Debug: Removing temporary decrypted file {temp_decrypted}.", debug)
        os.remove(temp_decrypted)  # Clean up temporary file
        click.echo(f"Keys rotated for {input} -> {output}")
    except (
        OutputFileExistsException,
        DiskSpaceException,
        FileDecryptionException,
        FileEncryptionException,
    ) as e:
        click.echo(f"Error during key rotation: {str(e)}")


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
        # Validate existence of files/directories and keys
        debug_log("Debug: Validating existence of input files and keys.", debug)
        if not os.path.exists(file1):
            raise click.ClickException(f"File or directory not found: {file1}")
        if not os.path.exists(file2):
            raise click.ClickException(f"File or directory not found: {file2}")
        if not os.path.exists(key1):
            raise click.ClickException(f"Key file not found: {key1}")

        key2 = key2 or key1
        if key1 == key2:
            debug_log(
                "Debug: Key1 and Key2 are identical or Key2 not specified. Using Key1 for both files.",
                debug,
            )
        if not os.path.exists(key2):
            raise click.ClickException(f"Key file not found: {key2}")

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
            if os.path.isfile(file1) and os.path.isfile(file2):
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
            elif os.path.isdir(file1) and os.path.isdir(file2):
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


# Add all commands to the main group
main.add_command(encrypt)
main.add_command(decrypt)
main.add_command(generate_key)
main.add_command(generate_key_from_password)
main.add_command(rotate_keys)
main.add_command(compare)


if __name__ == "__main__":
    main()
