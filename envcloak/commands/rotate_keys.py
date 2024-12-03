"""
rotate_keys.py

This module provides logic for key rotating using EnvCloak command.
"""

import os
import click
from envcloak.utils import debug_log
from envcloak.decorators.common_decorators import debug_option, dry_run_option
from envcloak.validation import (
    check_file_exists,
    check_permissions,
    check_output_not_exists,
    check_disk_space,
)
from envcloak.encryptor import encrypt_file, decrypt_file
from envcloak.exceptions import (
    OutputFileExistsException,
    DiskSpaceException,
    FileDecryptionException,
    FileEncryptionException,
)


@click.command()
@debug_option
@dry_run_option
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
    "--preview",
    is_flag=True,
    help="Preview the key rotation process without making changes.",
)
def rotate_keys(input, old_key_file, new_key_file, output, dry_run, debug, preview):
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

        # Handle Preview or Dry-run modes
        if preview:
            click.secho(
                f"""
Preview of Key Rotation:
- Old key: {old_key_file} will no longer be valid for this encrypted file.
- New key: {new_key_file} will be used to decrypt the encrypted file.
- Encrypted file: {input} will be re-encrypted to {output}.
                """,
                fg="cyan",
            )
            return
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
