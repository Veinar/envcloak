"""
handlers.py

This module defines handlers for processing application events, errors with/without logging.
It facilitates seamless interaction between components and ensures proper error handling.
"""

import os
import shutil
import click
from envcloak.utils import debug_log
from envcloak.validation import check_output_not_exists
from envcloak.exceptions import OutputFileExistsException, DiskSpaceException


def handle_overwrite(output: str, force: bool, debug: bool):
    """Handle overwriting existing files or directories."""
    if not force:
        check_output_not_exists(output)
    else:
        if os.path.exists(output):
            if os.path.isdir(output):
                debug_log(f"Debug: Removing existing directory {output}.", debug)
                click.secho(
                    f"⚠️  Warning: Overwriting existing directory {output} (--force used).",
                    fg="yellow",
                )
                shutil.rmtree(output)
            else:
                debug_log(f"Debug: Removing existing file {output}.", debug)
                click.secho(
                    f"⚠️  Warning: Overwriting existing file {output} (--force used).",
                    fg="yellow",
                )
                os.remove(output)


def handle_directory_preview(directory, recursion, debug, list_files_func):
    """
    Handles listing files in a directory for preview purposes.

    :param directory: Path to the directory.
    :param recursion: Whether to include files recursively.
    :param debug: Debug flag for verbose logging.
    :param list_files_func: Function to list files in the directory.
    """
    debug_log(f"Debug: Listing files for preview. Recursive = {recursion}.", debug)
    files = list_files_func(directory, recursion)
    if not files:
        click.secho(f"ℹ️ No files found in directory {directory}.", fg="blue")
    else:
        click.secho(f"ℹ️ Files to be processed in directory {directory}:", fg="green")
        for file in files:
            click.echo(file)
    return files


def handle_common_exceptions(exception, debug):
    """
    Handles common exceptions and provides user-friendly error messages.

    This function processes known exceptions and displays appropriate error
    messages to the user via `click.echo`. If the exception is not recognized,
    it logs the error message (if debug mode is enabled) and re-raises the exception.

    Args:
        exception (Exception): The exception to handle. Supported exceptions include:
            - OutputFileExistsException: Raised when an output file or directory already exists.
            - DiskSpaceException: Raised when there is insufficient disk space.
            - click.UsageError: Raised for invalid command-line usage.
        debug (bool): If True, debug information is logged for unexpected exceptions.

    Raises:
        Exception: Re-raises unexpected exceptions after logging them.

    Outputs:
        Prints user-friendly error messages to the console for known exceptions.
    """
    if isinstance(exception, OutputFileExistsException):
        click.echo(
            f"Error: The specified output file or directory already exists.\nDetails: {exception}",
            err=True,
        )
    elif isinstance(exception, DiskSpaceException):
        click.echo(
            f"Error: Insufficient disk space for operation.\nDetails: {exception}",
            err=True,
        )
    elif isinstance(exception, click.UsageError):
        click.echo(f"Usage Error: {exception}", err=True)
    else:
        debug_log(f"Unexpected error occurred: {str(exception)}", debug)
