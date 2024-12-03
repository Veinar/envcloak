"""
cli.py

This module defines the command-line interface for interacting with the `envcloak` package.
It provides commands for encrypting, decrypting, and managing environment variables.
"""

import click
from envcloak.commands.encrypt import encrypt
from envcloak.commands.decrypt import decrypt
from envcloak.commands.generate_key import generate_key
from envcloak.commands.generate_key_from_password import generate_key_from_password
from envcloak.commands.rotate_keys import rotate_keys
from envcloak.commands.compare import compare
from envcloak.version_check import warn_if_outdated
from envcloak import __version__

# Warn About Outdated Versions
warn_if_outdated()


@click.group()
@click.version_option(version=__version__, prog_name="EnvCloak")
def main():
    """
    EnvCloak: Securely manage encrypted environment variables.
    """


# Add all commands to the main group
main.add_command(encrypt)
main.add_command(decrypt)
main.add_command(generate_key)
main.add_command(generate_key_from_password)
main.add_command(rotate_keys)
main.add_command(compare)


if __name__ == "__main__":
    main()
