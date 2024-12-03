"""
decrypt.py

This module provides logic for decrypt command of EnvCloak
"""

import click
from envcloak.utils import (
    debug_log,
    calculate_required_space,
    list_files_to_encrypt,
    read_key_file,
)
from envcloak.handlers import (
    handle_directory_preview,
    handle_overwrite,
    handle_common_exceptions,
)
from envcloak.decorators.common_decorators import (
    debug_option,
    dry_run_option,
    force_option,
    no_sha_validation_option,
    recursion_option,
    preview_option,
)
from envcloak.validation import (
    check_file_exists,
    check_directory_exists,
    check_directory_not_empty,
    check_permissions,
    check_disk_space,
)
from envcloak.encryptor import decrypt_file, traverse_and_process_files
from envcloak.exceptions import (
    FileDecryptionException,
)


@click.command()
@debug_option
@dry_run_option
@force_option
@no_sha_validation_option
@recursion_option
@preview_option
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
            handle_directory_preview(directory, recursion, debug, list_files_to_encrypt)
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

        key = read_key_file(key_file, debug)

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
                process_file=lambda src, dest, key, dbg: decrypt_file(
                    str(src),
                    str(dest).replace(".enc", ""),
                    key,
                    validate_integrity=not skip_sha_validation,
                ),
                recursion=recursion,
            )
            click.echo(f"All files in directory {directory} decrypted -> {output}")
    except FileDecryptionException as e:
        click.echo(
            f"Error during decryption: Error: Failed to decrypt the file.\nDetails: {e.details}",
            err=True,
        )
    except click.UsageError as e:
        click.echo(f"Usage Error: {e}", err=True)
    except Exception as e:
        handle_common_exceptions(e, debug)
        raise
