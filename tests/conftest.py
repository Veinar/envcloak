import os
import shutil
import tempfile
from pathlib import Path
import pytest
from click.testing import CliRunner
from envcloak.generator import derive_key


@pytest.fixture
def runner():
    """
    Fixture for Click CLI Runner.
    Provides an isolated CLI runner instance for each test.
    """
    return CliRunner()


@pytest.fixture
def isolated_mock_files():
    """
    Provide isolated mock files in a temporary directory for each test.
    Prevents modification of the original mock files.
    """
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_dir_path = Path(temp_dir)
        mock_dir = Path("tests/mock")

        # Copy all mock files to the temporary directory
        for file in mock_dir.iterdir():
            if file.is_file():
                shutil.copy(file, temp_dir_path / file.name)

        yield temp_dir_path
        # Cleanup is handled automatically by TemporaryDirectory


@pytest.fixture(scope="module")
def test_dir():
    """
    Create a temporary directory for tests and ensure cleanup after all tests.
    """
    temp_dir = Path("tests/temp")
    temp_dir.mkdir(parents=True, exist_ok=True)
    yield temp_dir
    shutil.rmtree(temp_dir)


@pytest.fixture
def mock_files(test_dir):
    """
    Fixture for creating and managing mock files within the `tests/temp` directory.
    """
    mock_dir = Path("tests/mock")
    input_file = mock_dir / "variables.env"
    encrypted_file = mock_dir / "variables.env.enc"
    decrypted_file = test_dir / "variables.env.decrypted"
    key_file = test_dir / "mykey.key"
    password = "JustGiveItATry"
    salt = "e3a1c8b0d4f6e2c7a5b9d6f0c3e8f1a2"

    # Derive the key using the password and salt
    derived_key = derive_key(password, bytes.fromhex(salt))
    key_file.write_bytes(derived_key)

    return input_file, encrypted_file, decrypted_file, key_file
