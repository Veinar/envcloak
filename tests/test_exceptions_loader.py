import pytest
import os
from pathlib import Path
from unittest.mock import patch, mock_open
from envcloak.loader import EncryptedEnvLoader
from envcloak.exceptions import (
    KeyFileNotFoundException,
    EncryptedFileNotFoundException,
    FileDecryptionException,
    EncryptedEnvLoaderException,
    UnsupportedFileFormatException,
)


def test_key_file_not_found():
    """
    Test that KeyFileNotFoundException is raised when the key file does not exist.
    """
    loader = EncryptedEnvLoader("test.enc", "missing_key_file.key")
    with pytest.raises(KeyFileNotFoundException, match="missing_key_file.key"):
        loader.load()


def test_encrypted_file_not_found():
    """
    Test that EncryptedFileNotFoundException is raised when the encrypted file does not exist.
    """
    loader = EncryptedEnvLoader("missing_file.enc", "tests/mock/mykey.key")

    # Mock Path.exists for key file and encrypted file
    def mock_exists(self):
        if str(self) == "tests/mock/mykey.key":
            return True  # Simulate key file exists
        if str(self) == "missing_file.enc":
            return False  # Simulate encrypted file does not exist
        return True

    with patch("pathlib.Path.exists", new=mock_exists):
        with pytest.raises(EncryptedFileNotFoundException, match="missing_file.enc"):
            loader.load()


def test_file_decryption_exception():
    """
    Test that EncryptedEnvLoaderException wraps FileDecryptionException when decryption fails.
    """
    loader = EncryptedEnvLoader("tests/mock/variables.env.enc", "tests/mock/mykey.key")

    with patch("pathlib.Path.exists", return_value=True), patch(
        "envcloak.loader.decrypt_file",
        side_effect=FileDecryptionException("Decryption error"),
    ), patch(
        "builtins.open", mock_open(read_data="fake_key")
    ):  # Simulate the key file
        with pytest.raises(EncryptedEnvLoaderException) as exc_info:
            loader.load()

        # Assert the exception message and details
        exception = exc_info.value
        assert "Decryption failed during file processing." in str(exception)
        assert "Error: Decryption error" in exception.details


def test_unsupported_file_format_exception():
    """
    Test that UnsupportedFileFormatException is raised for unsupported file formats.
    """
    loader = EncryptedEnvLoader("tests/mock/variables.unknown", "tests/mock/mykey.key")
    with patch("pathlib.Path.exists", return_value=True), patch(
        "envcloak.loader.decrypt_file"
    ), patch("builtins.open", mock_open(read_data="{}")), patch.object(
        Path, "suffix", ".unknown"
    ):  # Mock the suffix attribute
        with pytest.raises(
            UnsupportedFileFormatException, match="File format detected: .unknown"
        ):
            loader.load()


def test_unexpected_error():
    """
    Test that EncryptedEnvLoaderException is raised for unexpected errors.
    """
    loader = EncryptedEnvLoader("test.enc", "test.key")
    with patch("pathlib.Path.exists", return_value=True), patch(
        "envcloak.loader.decrypt_file"
    ), patch(
        "envcloak.loader.EncryptedEnvLoader._parse_file",
        side_effect=ValueError("Unexpected error"),
    ):
        with pytest.raises(
            EncryptedEnvLoaderException,
            match="An unexpected error occurred during the load process.",
        ):
            loader.load()


def test_parse_file_error():
    """
    Test that EncryptedEnvLoaderException is raised when parsing fails.
    """
    loader = EncryptedEnvLoader("test.json", "test.key")
    with patch("pathlib.Path.exists", return_value=True), patch(
        "envcloak.loader.decrypt_file"
    ), patch("envcloak.loader.open", mock_open(read_data="invalid json")), patch(
        "json.load", side_effect=ValueError("JSON parsing error")
    ):
        with pytest.raises(
            EncryptedEnvLoaderException, match="Failed to parse the decrypted file."
        ):
            loader.load()


def test_parse_xml_error():
    """
    Test that EncryptedEnvLoaderException is raised when XML parsing fails.
    """
    loader = EncryptedEnvLoader("tests/mock/variables.xml.enc", "tests/mock/mykey.key")
    with patch("pathlib.Path.exists", return_value=True), patch(
        "envcloak.loader.decrypt_file"
    ), patch(
        "envcloak.loader.safe_parse", side_effect=Exception("XML parsing error")
    ), patch(
        "builtins.open", mock_open(read_data="fake_key")
    ):  # Simulate the key file
        with pytest.raises(
            EncryptedEnvLoaderException, match="Failed to parse XML file."
        ):
            loader.load()
