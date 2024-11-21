import os
import json
import shutil
import tempfile
from pathlib import Path
import pytest
from click.testing import CliRunner
from unittest.mock import patch
from envcloak.cli import main
from envcloak.generator import derive_key


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
    Fixture for mock files within the `tests/temp` directory.
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


@pytest.fixture
def runner():
    """
    Fixture for Click CLI Runner.
    """
    return CliRunner()


@patch("envcloak.cli.encrypt_file")
def test_encrypt(mock_encrypt_file, runner, isolated_mock_files):
    """
    Test the `encrypt` CLI command.
    """
    input_file = isolated_mock_files / "variables.env"
    encrypted_file = isolated_mock_files / "variables.env.enc"
    key_file = isolated_mock_files / "mykey.key"

    def mock_encrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Input file does not exist"
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "encrypted_data"}))

    mock_encrypt_file.side_effect = mock_encrypt

    result = runner.invoke(
        main,
        [
            "encrypt",
            "--input",
            str(input_file),
            "--output",
            str(encrypted_file),
            "--key-file",
            str(key_file),
        ],
    )

    assert result.exit_code == 0
    assert "File" in result.output
    mock_encrypt_file.assert_called_once_with(
        str(input_file), str(encrypted_file), key_file.read_bytes()
    )


@patch("envcloak.cli.decrypt_file")
def test_decrypt(mock_decrypt_file, runner, mock_files):
    """
    Test the `decrypt` CLI command.
    """
    _, encrypted_file, decrypted_file, key_file = mock_files

    def mock_decrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Encrypted file does not exist"
        with open(output_path, "w") as f:
            f.write("DB_USERNAME=example_user\nDB_PASSWORD=example_pass")

    mock_decrypt_file.side_effect = mock_decrypt

    result = runner.invoke(
        main,
        [
            "decrypt",
            "--input",
            str(encrypted_file),
            "--output",
            str(decrypted_file),
            "--key-file",
            str(key_file),
        ],
    )

    assert result.exit_code == 0
    assert "File" in result.output
    mock_decrypt_file.assert_called_once_with(
        str(encrypted_file), str(decrypted_file), key_file.read_bytes()
    )


@patch("envcloak.cli.add_to_gitignore")
@patch("envcloak.cli.generate_key_file")
def test_generate_key_with_gitignore(
    mock_generate_key_file, mock_add_to_gitignore, runner, test_dir
):
    """
    Test the `generate-key` CLI command with default behavior (adds to .gitignore).
    """
    key_file = test_dir / "random.key"

    # Simulate CLI behavior
    result = runner.invoke(main, ["generate-key", "--output", str(key_file)])

    # Assert CLI ran without errors
    assert result.exit_code == 0

    # Ensure the `generate_key_file` was called
    mock_generate_key_file.assert_called_once_with(key_file)

    # Verify `add_to_gitignore` was called
    mock_add_to_gitignore.assert_called_once_with(key_file.parent, key_file.name)


@patch("envcloak.cli.add_to_gitignore")
@patch("envcloak.cli.generate_key_file")
def test_generate_key_no_gitignore(
    mock_generate_key_file, mock_add_to_gitignore, runner, test_dir
):
    """
    Test the `generate-key` CLI command with the `--no-gitignore` flag.
    """
    key_file = test_dir / "random.key"

    # Simulate CLI behavior with `--no-gitignore`
    result = runner.invoke(
        main, ["generate-key", "--output", str(key_file), "--no-gitignore"]
    )

    # Assert CLI ran without errors
    assert result.exit_code == 0

    # Verify the `generate_key_file` was called correctly
    mock_generate_key_file.assert_called_once_with(key_file)

    # Ensure `add_to_gitignore` was NOT called
    mock_add_to_gitignore.assert_not_called()


@patch("envcloak.cli.add_to_gitignore")
@patch("envcloak.cli.generate_key_from_password_file")
def test_generate_key_from_password_with_gitignore(
    mock_generate_key_from_password_file, mock_add_to_gitignore, runner, mock_files
):
    """
    Test the `generate-key-from-password` CLI command with default behavior (adds to .gitignore).
    """
    _, _, _, key_file = mock_files
    password = "JustGiveItATry"
    salt = "e3a1c8b0d4f6e2c7a5b9d6f0c3e8f1a2"

    # Simulate CLI behavior
    mock_generate_key_from_password_file.return_value = None
    mock_add_to_gitignore.side_effect = lambda parent, name: None

    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            salt,
            "--output",
            str(key_file),
        ],
    )

    # Assert CLI ran without errors
    assert result.exit_code == 0

    # Verify the `generate_key_from_password_file` was called correctly
    mock_generate_key_from_password_file.assert_called_once_with(
        password, key_file, salt
    )

    # Verify `add_to_gitignore` was called
    mock_add_to_gitignore.assert_called_once_with(key_file.parent, key_file.name)


@patch("envcloak.cli.add_to_gitignore")
@patch("envcloak.cli.generate_key_from_password_file")
def test_generate_key_from_password_no_gitignore(
    mock_generate_key_from_password_file, mock_add_to_gitignore, runner, mock_files
):
    """
    Test the `generate-key-from-password` CLI command with the `--no-gitignore` flag.
    """
    _, _, _, key_file = mock_files
    password = "JustGiveItATry"
    salt = "e3a1c8b0d4f6e2c7a5b9d6f0c3e8f1a2"

    result = runner.invoke(
        main,
        [
            "generate-key-from-password",
            "--password",
            password,
            "--salt",
            salt,
            "--output",
            str(key_file),
            "--no-gitignore",
        ],
    )

    assert result.exit_code == 0

    # Check `generate_key_from_password_file` call
    mock_generate_key_from_password_file.assert_called_once_with(
        password, key_file, salt
    )

    # Ensure `add_to_gitignore` was NOT called
    mock_add_to_gitignore.assert_not_called()


@patch("envcloak.cli.decrypt_file")
@patch("envcloak.cli.encrypt_file")
def test_rotate_keys(mock_encrypt_file, mock_decrypt_file, runner, isolated_mock_files):
    """
    Test the `rotate-keys` CLI command.
    """
    # Use isolated copies of the mock files
    encrypted_file = isolated_mock_files / "variables.env.enc"
    decrypted_file = isolated_mock_files / "variables.env.decrypted"
    key_file = isolated_mock_files / "mykey.key"
    new_key_file = key_file.with_name("newkey.key")
    new_key_file.write_bytes(os.urandom(32))

    tmp_file = str(decrypted_file) + ".tmp"

    def mock_decrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Encrypted file does not exist"
        with open(output_path, "w") as f:
            f.write("Decrypted content")  # Simulate decrypting the file

    def mock_encrypt(input_path, output_path, key):
        assert os.path.exists(input_path), "Decrypted file does not exist"
        with open(output_path, "w") as f:
            f.write(json.dumps({"ciphertext": "re-encrypted_data"}))

    mock_decrypt_file.side_effect = mock_decrypt
    mock_encrypt_file.side_effect = mock_encrypt

    # Simulate CLI behavior
    result = runner.invoke(
        main,
        [
            "rotate-keys",
            "--input",
            str(encrypted_file),
            "--old-key-file",
            str(key_file),
            "--new-key-file",
            str(new_key_file),
            "--output",
            str(decrypted_file),
        ],
    )

    assert result.exit_code == 0
    assert "Keys rotated" in result.output

    # Ensure `decrypt_file` was called to create the temporary file
    mock_decrypt_file.assert_called_once_with(
        str(encrypted_file), tmp_file, key_file.read_bytes()
    )

    # Ensure `encrypt_file` was called with the temporary file
    mock_encrypt_file.assert_called_once_with(
        tmp_file, str(decrypted_file), new_key_file.read_bytes()
    )

    # Confirm that the temporary file is deleted by the CLI
    assert not os.path.exists(tmp_file), f"Temporary file {tmp_file} was not deleted"
