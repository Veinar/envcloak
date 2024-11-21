import os
import pytest
from pathlib import Path
from unittest.mock import patch
from envcloak.loader import EncryptedEnvLoader


@pytest.fixture
def mock_dir():
    """
    Returns the path to the mock files directory.
    """
    return Path(__file__).parent / "mock"


@pytest.fixture
def key_file(mock_dir):
    """
    Fixture for the key file.
    """
    return mock_dir / "mykey.key"


@pytest.fixture
def encrypted_files(mock_dir):
    """
    Fixture for encrypted files in various formats.
    """
    return {
        "env": mock_dir / "variables.env.enc",
        "json": mock_dir / "variables.json.enc",
        "yaml": mock_dir / "variables.yaml.enc",
        "xml": mock_dir / "variables.xml.enc",
    }


@pytest.fixture
def plaintext_files(mock_dir):
    """
    Fixture for plaintext files in various formats.
    """
    return {
        "env": mock_dir / "variables.env",
        "json": mock_dir / "variables.json",
        "yaml": mock_dir / "variables.yaml",
        "xml": mock_dir / "variables.xml",
    }


@pytest.mark.parametrize("file_format", ["env", "json", "yaml", "xml"])
@patch("envcloak.loader.decrypt_file")
def test_load_decrypts_and_parses(
    mock_decrypt, encrypted_files, plaintext_files, key_file, file_format
):
    """
    Test that the EncryptedEnvLoader can decrypt and parse various file formats correctly.
    """

    # Mock the decryption process to return the corresponding plaintext file
    def mock_decrypt_file(input_file, output_file, key):
        with open(plaintext_files[file_format], "r", encoding="utf-8") as f_in:
            with open(output_file, "w", encoding="utf-8") as f_out:
                f_out.write(f_in.read())

    mock_decrypt.side_effect = mock_decrypt_file

    # Test the loader
    loader = EncryptedEnvLoader(
        file_path=encrypted_files[file_format], key_file=key_file
    )
    loader.load()

    # Assertions for specific variables
    assert loader.decrypted_data["DB_USERNAME"] == "example_username"
    assert loader.decrypted_data["DB_PASSWORD"] == "example_password"
    assert loader.decrypted_data["API_KEY"] == "example_api_key"


@pytest.mark.parametrize("file_format", ["env", "json", "yaml", "xml"])
@patch("envcloak.loader.decrypt_file")
def test_to_os_env(
    mock_decrypt, encrypted_files, plaintext_files, key_file, file_format
):
    """
    Test that to_os_env loads variables into os.environ for various file formats.
    """

    # Mock the decryption process to return the corresponding plaintext file
    def mock_decrypt_file(input_file, output_file, key):
        with open(plaintext_files[file_format], "r", encoding="utf-8") as f_in:
            with open(output_file, "w", encoding="utf-8") as f_out:
                f_out.write(f_in.read())

    mock_decrypt.side_effect = mock_decrypt_file

    # Test the loader
    loader = EncryptedEnvLoader(
        file_path=encrypted_files[file_format], key_file=key_file
    )
    loader.load().to_os_env()

    # Assertions for specific environment variables
    assert os.getenv("DB_USERNAME") == "example_username"
    assert os.getenv("DB_PASSWORD") == "example_password"
    assert os.getenv("API_KEY") == "example_api_key"
