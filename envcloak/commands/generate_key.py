"""
generate_key.py

This module provides logic for key generation via command of EnvCloak
"""

from pathlib import Path
import click
from envcloak.validation import check_output_not_exists, check_disk_space
from envcloak.generator import generate_key_file
from envcloak.utils import add_to_gitignore, debug_log
from envcloak.decorators.common_decorators import debug_option, dry_run_option
from envcloak.exceptions import OutputFileExistsException, DiskSpaceException


@click.command()
@debug_option
@dry_run_option
@click.option(
    "--output", "-o", required=True, help="Path to save the generated encryption key."
)
@click.option(
    "--no-gitignore", is_flag=True, help="Skip adding the key file to .gitignore."
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
