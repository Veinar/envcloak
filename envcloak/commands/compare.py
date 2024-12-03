"""
compare.py

This module provides logic for compare command of EnvCloak
"""

import click
from click import style
from envcloak.comparator import compare_files_or_directories
from envcloak.utils import debug_log
from envcloak.decorators.common_decorators import debug_option, no_sha_validation_option


@click.command()
@debug_option
@no_sha_validation_option
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
def compare(file1, file2, key1, key2, output, skip_sha_validation, debug):
    """
    Compare two encrypted environment files or directories.
    """

    try:
        diff = compare_files_or_directories(
            file1, file2, key1, key2, skip_sha_validation, debug, debug_log
        )

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
    except Exception as e:
        click.echo(f"Error: {e}")
