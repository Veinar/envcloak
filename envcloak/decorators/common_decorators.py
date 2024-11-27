import click


def dry_run_option(func):
    """
    Add a `--dry-run` flag to a Click command.
    """
    return click.option(
        "--dry-run", is_flag=True, help="Perform a dry run without making any changes."
    )(func)


def debug_option(func):
    """
    Add a `--debug` flag to a Click command.
    """
    return click.option(
        "--debug", is_flag=True, help="Enable debug mode for detailed logs."
    )(func)


def force_option(func):
    """
    Add a `--force` flag to a Click command.
    """
    return click.option(
        "--force",
        is_flag=True,
        help="Force overwrite of existing files or directories.",
    )(func)


def no_sha_validation_option(func):
    """
    Add a `--no-sha-validation` flag to a Click command.
    """
    return click.option(
        "--skip-sha-validation",
        is_flag=True,
        default=False,
        help="Skip SHA3 integrity validation checks during decryption.",
    )(func)


def recursion(func):
    """
    Add `--recursion` and `-r` flags to a Click command.
    """
    return click.option(
        "--recursion",
        "-r",
        is_flag=True,
        help="Enable recursion to process files in subdirectories.",
    )(func)
