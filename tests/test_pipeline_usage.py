import os
import base64
import tempfile
import pytest
from click.testing import CliRunner
from envcloak.commands.decrypt import decrypt

import os
import base64
import tempfile
import pytest
from click.testing import CliRunner
from envcloak.commands.decrypt import decrypt


def test_pipeline_usage():
    # Paths
    mock_dir = "./tests/mock"
    original_key_file = os.path.join(mock_dir, "mykey.key")
    encrypted_file = os.path.join(mock_dir, "variables.env.enc")
    expected_output_file = os.path.join(mock_dir, "variables.env")
    output_file = "./variables_decrypted_temp.env"

    # Ensure required files exist
    assert os.path.exists(
        original_key_file
    ), f"Key file {original_key_file} does not exist"
    assert os.path.exists(
        encrypted_file
    ), f"Encrypted file {encrypted_file} does not exist"
    assert os.path.exists(
        expected_output_file
    ), f"Expected output file {expected_output_file} does not exist"

    # Read the original key file as bytes
    with open(original_key_file, "rb") as f:
        original_key_bytes = f.read()

    # Encode the key in base64
    key_base64 = base64.b64encode(original_key_bytes)

    # This simulates storing keyfile as based64 string

    # Decode the base64 back to its original form
    key_decoded = base64.b64decode(key_base64)

    # Create a temporary file to hold the decoded key
    with tempfile.NamedTemporaryFile(delete=False) as temp_key_file:
        temp_key_file_name = temp_key_file.name
        temp_key_file.write(key_decoded)

    try:
        # Use Click's CliRunner to invoke the decrypt command
        runner = CliRunner()
        result = runner.invoke(
            decrypt,
            [
                "--input",
                encrypted_file,
                "--output",
                output_file,
                "--key-file",
                temp_key_file_name,
            ],
        )

        # Check if the command executed successfully
        assert result.exit_code == 0, f"Command failed: {result.output}"

        # Verify the output file was created
        assert os.path.exists(output_file), f"Output file {output_file} was not created"

        # Verify the decrypted file matches the expected content
        with (
            open(output_file, "r") as decrypted_file,
            open(expected_output_file, "r") as expected_file,
        ):
            decrypted_content = decrypted_file.read()
            expected_content = expected_file.read()
            assert (
                decrypted_content == expected_content
            ), "Decrypted content does not match expected content"

    finally:
        # Cleanup
        if os.path.exists(output_file):
            os.remove(output_file)
        if os.path.exists(temp_key_file_name):
            os.remove(temp_key_file_name)
