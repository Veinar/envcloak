import os
import shutil
from pathlib import Path
import click
from click import style
from envcloak.utils import debug_log, calculate_required_space
from envcloak.decorators.common_decorators import (
    debug_option,
    force_option,
    dry_run_option,
    recursion,
)
from envcloak.validation import (
    check_file_exists,
    check_directory_exists,
    check_directory_not_empty,
    check_output_not_exists,
    check_permissions,
    check_disk_space,
)
from envcloak.encryptor import encrypt_file, traverse_and_process_files
from envcloak.exceptions import (
    OutputFileExistsException,
    DiskSpaceException,
    FileEncryptionException,
)


@click.command()
@debug_option
@dry_run_option
@force_option
@recursion
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
def encrypt(input, directory, output, key_file, dry_run, force, debug, recursion):
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
            traverse_and_process_files(
                directory,
                output,
                key,
                dry_run,
                debug,
                process_file=lambda src, dest, key, dbg: encrypt_file(
                    str(src), str(dest) + ".enc", key
                ),
                recursion=recursion,
            )
            click.echo(f"All files in directory {directory} encrypted -> {output}")
    except (
        OutputFileExistsException,
        DiskSpaceException,
        FileEncryptionException,
    ) as e:
        click.echo(f"Error during encryption: {str(e)}")
