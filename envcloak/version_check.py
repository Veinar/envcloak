import requests
import click
from packaging.version import Version, InvalidVersion
from envcloak import __version__


def get_latest_version():
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
