import os
import shutil
from pathlib import Path
import click
from click import style
from envcloak.utils import (
    debug_log,
    calculate_required_space,
    list_files_to_encrypt,
    handle_overwrite,
    validate_paths,
)
from envcloak.decorators.common_decorators import (
    debug_option,
    force_option,
    dry_run_option,
    recursion,
)
from envcloak.validation import (
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
    required=False,
    help="Path to the output file or directory for encrypted files.",
)
@click.option(
    "--key-file", "-k", required=True, help="Path to the encryption key file."
)
@click.option(
    "--preview",
    is_flag=True,
    help="List files that will be encrypted (only applicable for directories).",
)
def encrypt(
    input, directory, output, key_file, dry_run, force, debug, recursion, preview
):
    """
    Encrypt environment variables from a file or all files in a directory.
    """
    try:
        # Debug mode
        debug_log("Debug mode is enabled", debug)

        # Raise error if --preview is used with --input
        if input and preview:
            raise click.UsageError(
                "The --preview option cannot be used with a single file (--input)."
            )

        # Handle preview mode for directories
        if directory and preview:
            debug_log(
                f"Debug: Listing files for preview. Recursive = {recursion}.", debug
            )
            files = list_files_to_encrypt(directory, recursion)
            if not files:
                click.echo(
                    style(f"ℹ️ No files found in directory {directory}.", fg="blue")
                )
                return
            else:
                click.echo(
                    style(
                        f"ℹ️ Files to be encrypted in directory {directory}:", fg="green"
                    )
                )
                for file in files:
                    click.echo(file)
                return  # Exit early after preview

        # Validate input, directory, key file, and output
        validate_paths(input=input, directory=directory, key_file=key_file, debug=debug)

        if input:
            output = output or f"{input}.enc"
            debug_log(f"Debug: Output set to {output}.", debug)

        handle_overwrite(output, force, debug)

        required_space = calculate_required_space(input, directory)
        check_disk_space(output, required_space)

        if dry_run:
            debug_log(
                "Debug: Dry-run flag is set. Skipping actual encryption process.",
                debug,
            )
            click.echo("Dry-run checks passed successfully.")
            return

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
            debug_log(f"Debug: Encrypting files in directory {directory}.", debug)
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
    except OutputFileExistsException as e:
        click.echo(
            f"Error: The specified output file or directory already exists.\nDetails: {e}",
            err=True,
        )
    except DiskSpaceException as e:
        click.echo(
            f"Error: Insufficient disk space for operation.\nDetails: {e}",
            err=True,
        )
    except FileEncryptionException as e:
        click.echo(
            f"Error: An error occurred during file encryption.\nDetails: {e}",
            err=True,
        )
    except click.UsageError as e:
        click.echo(f"Usage Error: {e}", err=True)
    except Exception as e:
        debug_log(f"Unexpected error occurred: {str(e)}", debug)
        raise
