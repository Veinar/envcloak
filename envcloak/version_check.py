"""
version_check.py

This module includes functionality to check for the latest version of the `envcloak` package on PyPI.
It helps users stay updated with the newest features, enhancements, and fixes.
"""

import requests
import click
from packaging.version import Version, InvalidVersion
from envcloak import __version__


def get_latest_version():
    """
    Fetches the latest version of the 'envcloak' package from PyPI.

    This function sends a request to the PyPI API to retrieve the latest version
    information for the 'envcloak' package.

    Returns:
        str: The latest version as a string if successful.
        None: If an error occurs during the request.

    Outputs:
        Prints error messages to the console if the request fails or times out.
    """
    url = "https://pypi.org/pypi/envcloak/json"
    try:
        # Send a GET request to the PyPI API
        response = requests.get(url, timeout=5)

        # Raise an error if the response was not successful
        response.raise_for_status()

        # Extract the latest version from JSON response
        data = response.json()
        latest_version = data["info"]["version"]
        return latest_version
    except requests.exceptions.Timeout:
        click.secho("The request timed out.", fg="red")
    except requests.exceptions.RequestException as e:
        # Handle network-related errors or invalid responses
        click.secho(f"Error fetching the latest version for envcloak: {e}", fg="red")

    # Explicitly return None if an exception occurs
    return None


def warn_if_outdated():
    """
    Warns the user if the installed version of 'envcloak' is outdated.

    This function compares the installed version of 'envcloak' with the latest version
    available on PyPI. If the installed version is older, it displays a warning and
    provides instructions to upgrade.

    Outputs:
        Prints a warning message with upgrade instructions if a newer version is available.
        Prints an error message if version comparison fails or the latest version cannot be determined.
    """
    latest_version = get_latest_version()
    current_version = __version__

    if latest_version:
        try:
            # Use packaging.version to ensure proper version comparison
            if Version(latest_version) > Version(current_version):
                click.secho(
                    f"WARNING: You are using envcloak version {current_version}. "
                    f"A newer version ({latest_version}) is available.",
                    fg="yellow",
                )
                click.secho(
                    "Please update by running: pip install --upgrade envcloak",
                    fg="green",
                )
        except InvalidVersion as e:
            click.secho(
                f"Version comparison failed due to invalid version format: {e}",
                fg="red",
            )
    else:
        click.secho(
            "Could not determine the latest version. Please check manually.", fg="red"
        )
