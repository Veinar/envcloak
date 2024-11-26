from envcloak import __version__
import requests
def get_latest_version():
    url="https://pypi.org/pypi/envcloak/json"
    try:
        #Send a GET request to the PyPI API
        response=requests.get(url)

        #Raise an error if the response was not successful
        response.raise_for_status()

        #Extract the latest version from JSON response
        data=response.json()
        latest_version=data['info']['version']
        return latest_version
    except requests.exceptions.RequestException as e:
        # Handle network-related errors or invalid responses
        return f"Error fetching the latest version for envcloak: {e}"

def warn_if_outdated():
    latest_version=get_latest_version()
    current_version=__version__

    if latest_version and latest_version!=current_version:
        print(f"WARNING: You are using envcloak version {current_version}. "
              f"A newer version ({latest_version}) is available. Please update!")