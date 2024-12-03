import os
import shutil
from pathlib import Path
import click
from click import style
from envcloak.utils import debug_log, calculate_required_space, handle_overwrite, list_files_to_encrypt
from envcloak.decorators.common_decorators import (
    debug_option,
    dry_run_option,
    force_option,
    no_sha_validation_option,
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
from envcloak.encryptor import decrypt_file, traverse_and_process_files
from envcloak.exceptions import (
    OutputFileExistsException,
    DiskSpaceException,
    FileDecryptionException,
)


@click.command()
@debug_option
@dry_run_option
@force_option
@no_sha_validation_option
@recursion
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
    "--preview",
    is_flag=True,
    help="List files that will be decrypted (only applicable for directories).",
)
def decrypt(
    input,
    directory,
    output,
    key_file,
    dry_run,
    force,
    debug,
    skip_sha_validation,
    recursion,
    preview,
):
    """
    Decrypt environment variables from a file or all files in a directory.
    """
    try:
        debug_log("Debug mode is enabled", debug)

        if not input and not directory:
            raise click.UsageError("You must provide either --input or --directory.")
        if input and directory:
            raise click.UsageError(
                "You must provide either --input or --directory, not both."
            )

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
                        f"ℹ️ Files to be decrypted in directory {directory}:", fg="green"
                    )
                )
                for file in files:
                    click.echo(file)
                return

        debug_log(f"Debug: Validating key file {key_file}.", debug)
        check_file_exists(key_file)
        check_permissions(key_file)

        if input:
            debug_log(f"Debug: Validating input file {input}.", debug)
            check_file_exists(input)
            check_permissions(input)
        if directory:
            debug_log(f"Debug: Validating directory {directory}.", debug)
            check_directory_exists(directory)
            check_directory_not_empty(directory)

        handle_overwrite(output, force, debug)

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

        with open(key_file, "rb") as kf:
            key = kf.read()
            debug_log(f"Debug: Key file {key_file} read successfully.", debug)

        if input:
            debug_log(
                f"Debug: Decrypting file {input} -> {output} using key {key_file}.",
                debug,
            )
            decrypt_file(input, output, key, validate_integrity=not skip_sha_validation)
            click.echo(f"File {input} decrypted -> {output} using key {key_file}")
        elif directory:
            debug_log(f"Debug: Decrypting files in directory {directory}.", debug)
            traverse_and_process_files(
                directory,
                output,
                key,
                dry_run,
                debug,
                process_file=lambda src, dest, key, dbg:
                    decrypt_file(
                        str(src),
                        str(dest).replace(".enc", ""),  # Ensure `.enc` is removed
                        key,
                        validate_integrity=not skip_sha_validation,
                    ),
                recursion=recursion,
            )
            click.echo(f"All files in directory {directory} decrypted -> {output}")
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
    except FileDecryptionException as e:
        click.echo(
            f"Error during decryption: Error: Failed to decrypt the file.\nDetails: {e.details}",
            err=True,
        )
    except click.UsageError as e:
        click.echo(f"Usage Error: {e}", err=True)
    except Exception as e:
        debug_log(f"Unexpected error occurred: {str(e)}", debug)
        raise
