"""
generate_key_from_password.py

This module provides logic for generating key using password or password and salt via command of EnvCloak
"""

from pathlib import Path
import click
from envcloak.validation import check_output_not_exists, check_disk_space, validate_salt
from envcloak.generator import generate_key_from_password_file
from envcloak.utils import debug_log, add_to_gitignore
from envcloak.decorators.common_decorators import debug_option, dry_run_option
from envcloak.exceptions import (
    OutputFileExistsException,
    DiskSpaceException,
    InvalidSaltException,
)


@click.command()
@debug_option
@dry_run_option
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
